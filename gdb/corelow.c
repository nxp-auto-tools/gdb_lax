/* Core dump and executable file functions below target vector, for GDB.
   Copyright 1986, 1987, 1989, 1991, 1992 Free Software Foundation, Inc.

This file is part of GDB.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include "defs.h"
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include "frame.h"  /* required by inferior.h */
#include "inferior.h"
#include "symtab.h"
#include "command.h"
#include "bfd.h"
#include "target.h"
#include "gdbcore.h"

static void
core_files_info PARAMS ((struct target_ops *));

#ifdef SOLIB_ADD
static int 
solib_add_stub PARAMS ((char *));
#endif

static void
core_close PARAMS ((int));

static void
get_core_registers PARAMS ((int));

/* Discard all vestiges of any previous core file
   and mark data and stack spaces as empty.  */

/* ARGSUSED */
static void
core_close (quitting)
     int quitting;
{
  inferior_pid = 0;		/* Avoid confusion from thread stuff */

  if (core_bfd) {
    free (bfd_get_filename (core_bfd));
    bfd_close (core_bfd);
    core_bfd = NULL;
#ifdef CLEAR_SOLIB
    CLEAR_SOLIB ();
#endif
    if (core_ops.to_sections) {
      free ((PTR)core_ops.to_sections);
      core_ops.to_sections = NULL;
      core_ops.to_sections_end = NULL;
    }
  }
}

#ifdef SOLIB_ADD
/* Stub function for catch_errors around shared library hacking. */

static int 
solib_add_stub (from_tty)
     char *from_tty;
{
    SOLIB_ADD (NULL, (int)from_tty, &core_ops);
    return 0;
}
#endif /* SOLIB_ADD */

/* Look for sections whose names start with `.reg/' so that we can extract the
   list of threads in a core file.  */

static void
add_to_thread_list (abfd, asect, reg_sect)
     bfd *abfd;
     asection *asect;
     asection *reg_sect;
{
  int thread_id;

  if (strncmp (bfd_section_name (abfd, asect), ".reg/", 5) != 0)
    return;

  thread_id = atoi (bfd_section_name (abfd, asect) + 5);

  add_thread (thread_id);

/* Warning, Will Robinson, looking at BFD private data! */

  if (asect->filepos == reg_sect->filepos) /* Did we find .reg? */
    inferior_pid = thread_id;	/* Yes, make it current */
}

/* This routine opens and sets up the core file bfd */

void
core_open (filename, from_tty)
     char *filename;
     int from_tty;
{
  const char *p;
  int siggy;
  struct cleanup *old_chain;
  char *temp;
  bfd *temp_bfd;
  int ontop;
  int scratch_chan;

  target_preopen (from_tty);
  if (!filename)
    {
      error (core_bfd? 
       "No core file specified.  (Use `detach' to stop debugging a core file.)"
     : "No core file specified.");
    }

  filename = tilde_expand (filename);
  if (filename[0] != '/') {
    temp = concat (current_directory, "/", filename, NULL);
    free (filename);
    filename = temp;
  }

  old_chain = make_cleanup (free, filename);

  scratch_chan = open (filename, write_files? O_RDWR: O_RDONLY, 0);
  if (scratch_chan < 0)
    perror_with_name (filename);

  temp_bfd = bfd_fdopenr (filename, gnutarget, scratch_chan);
  if (temp_bfd == NULL)
    {
      perror_with_name (filename);
    }

  if (!bfd_check_format (temp_bfd, bfd_core))
    {
      /* Do it after the err msg */
      make_cleanup (bfd_close, temp_bfd);
      error ("\"%s\" is not a core dump: %s", filename, bfd_errmsg(bfd_error));
    }

  /* Looks semi-reasonable.  Toss the old core file and work on the new.  */

  discard_cleanups (old_chain);		/* Don't free filename any more */
  unpush_target (&core_ops);
  core_bfd = temp_bfd;
  old_chain = make_cleanup (core_close, core_bfd);

  validate_files ();

  /* Find the data section */
  if (build_section_table (core_bfd, &core_ops.to_sections,
			   &core_ops.to_sections_end))
    error ("Can't find sections in `%s': %s", bfd_get_filename(core_bfd),
	   bfd_errmsg (bfd_error));

  ontop = !push_target (&core_ops);
  discard_cleanups (old_chain);

  p = bfd_core_file_failing_command (core_bfd);
  if (p)
    printf_filtered ("Core was generated by `%s'.\n", p);

  siggy = bfd_core_file_failing_signal (core_bfd);
  if (siggy > 0)
    printf_filtered ("Program terminated with signal %d, %s.\n", siggy,
	    safe_strsignal (siggy));

  /* Build up thread list from BFD sections. */

  init_thread_list ();
  bfd_map_over_sections (core_bfd, add_to_thread_list,
			 bfd_get_section_by_name (core_bfd, ".reg"));

  if (ontop) {
    /* Fetch all registers from core file */
    target_fetch_registers (-1);

    /* Add symbols and section mappings for any shared libraries */
#ifdef SOLIB_ADD
    catch_errors (solib_add_stub, (char *)from_tty, (char *)0,
		  RETURN_MASK_ALL);
#endif

    /* Now, set up the frame cache, and print the top of stack */
    set_current_frame (create_new_frame (read_fp (),
					 read_pc ()));
    select_frame (get_current_frame (), 0);
    print_stack_frame (selected_frame, selected_frame_level, 1);
  } else {
    warning (
"you won't be able to access this core file until you terminate\n\
your %s; do ``info files''", current_target->to_longname);
  }
}

void
core_detach (args, from_tty)
     char *args;
     int from_tty;
{
  if (args)
    error ("Too many arguments");
  unpush_target (&core_ops);
  reinit_frame_cache ();
  if (from_tty)
    printf_filtered ("No core file now.\n");
}

/* Get the registers out of a core file.  This is the machine-
   independent part.  Fetch_core_registers is the machine-dependent
   part, typically implemented in the xm-file for each architecture.  */

/* We just get all the registers, so we don't use regno.  */
/* ARGSUSED */
static void
get_core_registers (regno)
     int regno;
{
  sec_ptr reg_sec;
  unsigned size;
  char *the_regs;
  char secname[10];

  /* Thread support.  If inferior_pid is non-zero, then we have found a core
     file with threads (or multiple processes).  In that case, we need to
     use the appropriate register section, else we just use `.reg'. */

  /* XXX - same thing needs to be done for floating-point (.reg2) sections. */

  if (inferior_pid)
    sprintf (secname, ".reg/%d", inferior_pid);
  else
    strcpy (secname, ".reg");

  reg_sec = bfd_get_section_by_name (core_bfd, secname);
  if (!reg_sec) goto cant;
  size = bfd_section_size (core_bfd, reg_sec);
  the_regs = alloca (size);
  if (bfd_get_section_contents (core_bfd, reg_sec, the_regs, (file_ptr)0, size))
    {
      fetch_core_registers (the_regs, size, 0,
			    (unsigned) bfd_section_vma (abfd,reg_sec));
    }
  else
    {
cant:
      fprintf_filtered (stderr, "Couldn't fetch registers from core file: %s\n",
	       bfd_errmsg (bfd_error));
    }

  /* Now do it again for the float registers, if they exist.  */
  reg_sec = bfd_get_section_by_name (core_bfd, ".reg2");
  if (reg_sec) {
    size = bfd_section_size (core_bfd, reg_sec);
    the_regs = alloca (size);
    if (bfd_get_section_contents (core_bfd, reg_sec, the_regs, (file_ptr)0,
				  size))
      {
	fetch_core_registers (the_regs, size, 2,
			      (unsigned) bfd_section_vma (abfd,reg_sec));
      }
    else
      {
	fprintf_filtered (stderr, "Couldn't fetch register set 2 from core file: %s\n",
		 bfd_errmsg (bfd_error));
      }
  }
  registers_fetched();
}

static void
core_files_info (t)
  struct target_ops *t;
{
  print_section_info (t, core_bfd);
}

/* If mourn is being called in all the right places, this could be say
   `gdb internal error' (since generic_mourn calls breakpoint_init_inferior).  */

static int
ignore (addr, contents)
     CORE_ADDR addr;
     char *contents;
{
}

struct target_ops core_ops = {
	"core", "Local core dump file",
	"Use a core file as a target.  Specify the filename of the core file.",
	core_open, core_close,
	find_default_attach, core_detach, 0, 0, /* resume, wait */
	get_core_registers, 
	0, 0, /* store_regs, prepare_to_store */
	xfer_memory, core_files_info,
	ignore, ignore, /* core_insert_breakpoint, core_remove_breakpoint, */
	0, 0, 0, 0, 0, /* terminal stuff */
	0, 0, 0, /* kill, load, lookup sym */
	find_default_create_inferior, 0, /* mourn_inferior */
	0, /* can_run */
	0, /* notice_signals */
	core_stratum, 0, /* next */
	0, 1, 1, 1, 0,	/* all mem, mem, stack, regs, exec */
	0, 0,			/* section pointers */
	OPS_MAGIC,		/* Always the last thing */
};

void
_initialize_corelow()
{
  add_target (&core_ops);
}
