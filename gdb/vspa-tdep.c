/* Target-dependent code for the VSPA.

   Copyright (C) 2015-2016 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "arch-utils.h"
#include "dis-asm.h"
#include "floatformat.h"
#include "frame.h"
#include "frame-base.h"
#include "frame-unwind.h"
#include "gdbcore.h"
#include "gdbtypes.h"
#include "osabi.h"
#include "regcache.h"
#include "regset.h"
#include "trad-frame.h"
#include "dwarf2-frame.h"
#include "value.h"
#include "vspa-tdep.h"

#include "features/lax.c"
#include "features/vspa2.c"
#include "features/vspa1.c"
#include "target.h"
#include "objfiles.h"

extern "C" {
#include "elf/vspa.h"
}
/* Return the name of register REGNUM.  */
static char *vspa3_register_names[] =
{
  "g0", "g1", "g2", "g3", "g4",            /*  0  1  2  3  4 */
  "g5", "g6", "g7", "g8", "g9",            /*  5  6  7  8  9 */
  "g10", "g11", "a4", "a5", "a6",          /* 10 11 12 13 14 */
  "a7", "a8", "a9", "a10", "a11",          /* 15 16 17 18 19 */
  "a12", "a13", "a14", "a15", "a16",       /* 20 21 22 23 24 */
  "a17", "a18", "a19", "a0",  "a1",        /* 25 26 27 28 29 */
  "a2",  "a3",  "sp",  "pc"   		       /* 30 31 32 33 */
};

static char *vspa2_register_names[] =
{
  "g0", "g1", "g2", "g3", "g4",            /*  0  1  2  3  4 */
  "g5", "g6", "g7", "g8", "g9",            /*  5  6  7  8  9 */
  "g10", "g11", "a4", "a5", "a6",          /* 10 11 12 13 14 */
  "a7", "a8", "a9", "a10", "a11",          /* 15 16 17 18 19 */
  "a12", "a13", "a14", "a15", "a16",       /* 20 21 22 23 24 */
  "a17", "a18", "a19", "a0",  "a1",        /* 25 26 27 28 29 */
  "a2",  "a3",  "sp",  "pc"                /* 30 31 32 33 */
};

static char *vspa1_register_names[] =
{
  "g0", "g1", "g2", "g3", "g4",            /*  0  1  2  3  4 */
  "g5", "g6", "g7", "g8", "g9",            /*  5  6  7  8  9 */
  "g10", "g11", "as0", "as1", "as2",       /* 10 11 12 13 14 */
  "as3", "as4", "as5", "as6", "as7",       /* 15 16 17 18 19 */
  "as8", "as9", "as10", "as11", "as12",    /* 20 21 22 23 24 */
  "as13", "as14", "as15", "a0",  "a1",     /* 25 26 27 28 29 */
  "a2",  "a3",  "sp",  "pc"                /* 30 31 32 33 */
};

static const char *
vspa3_register_name (struct gdbarch *gdbarch, int regnum)
{
  if (regnum >= 0 && regnum < ARRAY_SIZE (vspa3_register_names))
    return vspa3_register_names[regnum];

  return NULL;
}

static const char *
vspa2_register_name (struct gdbarch *gdbarch, int regnum)
{
  if (regnum >= 0 && regnum < ARRAY_SIZE (vspa2_register_names))
    return vspa2_register_names[regnum];

  return NULL;
}

static const char *
vspa1_register_name (struct gdbarch *gdbarch, int regnum)
{
  if (regnum >= 0 && regnum < ARRAY_SIZE (vspa1_register_names))
    return vspa1_register_names[regnum];

  return NULL;
}

/* Map a DWARF register REGNUM onto the appropriate GDB register
   number.  */

static int
vspa_dwarf_reg_to_regnum (struct gdbarch *gdbarch, int reg)
{
  /* General purpose, address and sp registers */
  if ((reg >= 0) && (reg <= 33))
    return reg;

  return -1;
}

/* Return the GDB type object for the "standard" data type of data in
   register REGNUM.  */

static struct type *
vspa_register_type (struct gdbarch *gdbarch, int regnum)
{
  return builtin_type (gdbarch)->builtin_int;
}

static const gdb_byte *
vspa_breakpoint_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pc, int *len)
{
  *len = 0;
  return NULL;
#if 0
  static CORE_ADDR instr = 0ULL;
  CORE_ADDR pc_value = *pc;
  CORE_ADDR breakMask = 1ULL;

  *len = 0;

  // get the breakpoint mask based on the PC value (odd or even)
  if ((pc_value % 2) == 0)
    {
      breakMask <<= 60;
    }
  else
    {
      breakMask <<= 61;
      pc_value -= 1;
    }

  if (target_read_memory (pc_value, (gdb_byte*)&instr, 8) != 0)
     return NULL;

  instr |= breakMask;
  *pc = pc_value;
  *len = 8;
  return (gdb_byte*)&instr;
#endif
}


static struct frame_id
vspa_dummy_id (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  return frame_id_build (get_frame_register_unsigned (this_frame,
			 VSPA_SP_REGNUM), get_frame_pc (this_frame));
}

/* VSPA cache structure.  */
struct vspa_unwind_cache
{
  /* The frame's base, optionally used by the high-level debug info.  */
  CORE_ADDR base;

  /* The previous frame's inner most stack address.  Used as this
     frame ID's stack_ baddr.  */
  CORE_ADDR cfa;

  /* The address of the first instruction in this function */
  CORE_ADDR pc;

  /* The offset of register saved on stack.  If register is not saved, the
     corresponding element is -1.  */
  CORE_ADDR reg_saved[VSPA_NUM_REGS];
};

static void
vspa_setup_default (struct vspa_unwind_cache *cache)
{
  int i;

  for (i = 0; i < VSPA_NUM_REGS; i++)
    cache->reg_saved[i] = -1;
}


/*The LAX hardware used hw callstack with ras and ras_depth reisters instead of regular lr register.
 * Also it has feature thar ras_depth register updated not when the command been executed but when pc points on it.
 * To support regular call stack unwinding mechanizm, we should analize our code and if we stay on jsr resgister or on it delay slots, 
 * remove first ras register from usage and reduce number of available returns*/ 
static int
vspa_skip_frame(struct frame_info *this_frame){
    int ret = false;
    
    CORE_ADDR current_pc,func_pc;
    LONGEST insn;
    LONGEST mask = 0xEFC00000; //jsr opcode mask
    int i = 3;
    struct gdbarch *gdbarch = get_frame_arch (this_frame);
    enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
    
    
    //move till frame level 0
    while(this_frame != NULL && frame_relative_level(this_frame) != 0){
        this_frame = get_next_frame(this_frame);
    }
    
    func_pc = get_frame_func (this_frame);
    current_pc = get_frame_pc (this_frame)&~1;
    
    while(i>0){
        insn = read_memory_unsigned_integer (current_pc, 8/*64bit*/, byte_order);
        insn = (insn >>32) & mask;
        if (insn == 0x42000000 || insn == 0x42800000 ||
            insn == 0x43000000 || insn == 0x43800000)
        {//jsr instruction opcodes
            ret = 1;
            break;
        }
        
        current_pc -= 2;
        
        if (current_pc < func_pc){
            break;
        }
        i = i - 1;
    }
    
    return ret;
}

/*During stack unwinding we may have situation when we have inline frames in call stack, in sucj case we must skip it from the calculation of the ras_depth register*/
static int
vspa_num_inline_frames(struct frame_info *this_frame){
    int ret = 0;

    struct frame_info* next = get_next_frame(this_frame);
    while(next !=NULL && get_frame_type(next) != SENTINEL_FRAME){
        if (get_frame_type(next) == INLINE_FRAME){
            ret++;
        }
        next = get_next_frame(next);
    }

    return ret;
}


/* Do a full analysis of the prologue at START_PC and update CACHE accordingly.
   Bail out early if CURRENT_PC is reached.  Returns the address of the first
   instruction after the prologue.  */

static CORE_ADDR
vspa_analyze_prologue (struct gdbarch *gdbarch,
		       CORE_ADDR start_pc, CORE_ADDR current_pc,
		       struct vspa_unwind_cache *cache,
		       struct frame_info *this_frame)
{
  // TODO: it is not implemented yet!
  CORE_ADDR pc = start_pc;
  CORE_ADDR return_pc = start_pc;
  int frame_base_offset_to_sp = 0;

  if (start_pc >= current_pc)
    return_pc = current_pc;

  if (cache)
  {
    cache->base = 0;

    if (this_frame)
      {
	cache->base = get_frame_register_unsigned (this_frame, VSPA_SP_REGNUM);
	cache->cfa = cache->base + frame_base_offset_to_sp;
      }
  }

  return return_pc;
}

/* Implement the "skip_prologue" gdbarch method.  */

static CORE_ADDR
vspa_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  unsigned long inst;
  CORE_ADDR skip_pc;
  CORE_ADDR func_addr, limit_pc;
  struct symtab_and_line sal;

  /* See if we can determine the end of the prologue via the symbol
     table.  If so, then return either PC, or the PC after the
     prologue, whichever is greater.  */
  if (find_pc_partial_function (pc, NULL, &func_addr, NULL))
    {
      CORE_ADDR post_prologue_pc =
	skip_prologue_using_sal (gdbarch, func_addr);

      if (post_prologue_pc != 0)
	return max (pc, post_prologue_pc);
    }

   return pc;
}


/* Frame base handling.  */

static struct vspa_unwind_cache *
vspa_frame_unwind_cache (struct frame_info *this_frame, void **this_cache)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  struct vspa_unwind_cache *cache;
  CORE_ADDR current_pc;

  if (*this_cache != NULL)
    return (struct vspa_unwind_cache *) *this_cache;

  cache = FRAME_OBSTACK_ZALLOC (struct vspa_unwind_cache);
  (*this_cache) = cache;

  vspa_setup_default (cache);

  cache->pc = get_frame_func (this_frame);
  current_pc = get_frame_pc (this_frame);

  /* Prologue analysis does the rest...  */
  if ((cache->pc & 0xFFFFFFFF) != 0)
    vspa_analyze_prologue (gdbarch, cache->pc, current_pc, cache, this_frame);

  return cache;
}

/* Implement the "stop_reason" frame_unwind method.  */

static enum unwind_stop_reason
vspa_frame_unwind_stop_reason (struct frame_info *this_frame,
					   void **this_cache)
{
  struct vspa_unwind_cache *cache
    = vspa_frame_unwind_cache (this_frame, this_cache);

  /* We've hit a wall, stop.  */
  if (cache->base == 0)
    return UNWIND_OUTERMOST;

  return UNWIND_NO_REASON;
}

static void
vspa_frame_this_id (struct frame_info *this_frame,
			  void **this_cache, struct frame_id *this_id)
{
  struct vspa_unwind_cache *cache =
     vspa_frame_unwind_cache (this_frame, this_cache);

  /* This marks the outermost frame.  */
  if (cache->base == 0)
    return;

  (*this_id) = frame_id_build (cache->cfa, cache->pc);
}

/* Implement the previous PC register. */
static struct value *
vspa_prev_pc_register(struct frame_info *this_frame)
{
  CORE_ADDR hw_stack;
  int frame_level, jsr_stub_frame, num_inline_frames;
  static bool skipped;

  hw_stack = frame_unwind_register_unsigned (this_frame, VSPA_RAS_DEPTH_REGNUM);
  frame_level = frame_relative_level(this_frame);
  jsr_stub_frame = vspa_skip_frame(this_frame);
  num_inline_frames = vspa_num_inline_frames(this_frame);
  
  if (frame_level - num_inline_frames>=0 && frame_level - num_inline_frames<=15 && frame_level - num_inline_frames<hw_stack - jsr_stub_frame){
      CORE_ADDR prev_pc = frame_unwind_register_unsigned (this_frame, VSPA_RAS1_REGNUM + frame_level - num_inline_frames + jsr_stub_frame)*2;
      return frame_unwind_got_constant (this_frame, VSPA_PC_REGNUM, prev_pc);
  }else{
      return frame_unwind_got_optimized (this_frame, VSPA_PC_REGNUM);
  }
 
}

/* Implement the "prev_register" frame_unwind method.  */

static struct value *
vspa_frame_prev_register (struct frame_info *this_frame,
			  void **this_cache, int regnum)
{
  struct vspa_unwind_cache *cache =
	vspa_frame_unwind_cache (this_frame, this_cache);
  CORE_ADDR noFrame;
  int i;

  /* If we are asked to unwind the PC, then we need to return the RASx
     instead. */
  if (regnum == VSPA_PC_REGNUM)
      return vspa_prev_pc_register(this_frame);

  if (regnum == VSPA_SP_REGNUM && cache->cfa)
    return frame_unwind_got_constant (this_frame, regnum, cache->cfa);

  /* If we've worked out where a register is stored then load it from
     there.  */
  if (regnum < VSPA_NUM_REGS && cache->reg_saved[regnum] != -1)
    return frame_unwind_got_memory (this_frame, regnum,
				    cache->reg_saved[regnum]);

  return frame_unwind_got_register (this_frame, regnum, regnum);
}

static CORE_ADDR
vspa_frame_base_address (struct frame_info *this_frame, void **this_cache)
{
  struct vspa_unwind_cache *info
	= vspa_frame_unwind_cache (this_frame, this_cache);
  return info->base;
}

/* VSPA prologue unwinder.  */
static const struct frame_unwind vspa_frame_unwind =
{
  NORMAL_FRAME,
  vspa_frame_unwind_stop_reason,
  vspa_frame_this_id,
  vspa_frame_prev_register,
  NULL,
  default_frame_sniffer
};

static enum unwind_stop_reason
vspa_lastframe_unwind_stop_reason (struct frame_info *this_frame,
					   void **this_cache)
{
  /* We've hit a wall, stop.  */
  return UNWIND_OUTERMOST;
}

static void
vspa_lastframe_this_id (struct frame_info *this_frame,
			  void **this_cache, struct frame_id *this_id)
{
  /* This marks the outermost frame.  */
  return;
}


static int
vspa_lastframe_sniffer (const struct frame_unwind *self,
		 struct frame_info *this_frame, void **this_prologue_cache)
{
  CORE_ADDR hw_stack;
  int num_inline_frames,jsr_stub_frame, frame_level;

  frame_level = frame_relative_level(this_frame);
  hw_stack = get_frame_register_unsigned (this_frame, VSPA_RAS_DEPTH_REGNUM);
  
  num_inline_frames = vspa_num_inline_frames(this_frame);
  jsr_stub_frame = (hw_stack !=0) ? vspa_skip_frame(this_frame) : 0;//workaround for situation when pc is set by command on jsr instruction.
  
  
  if ( frame_level !=0 && frame_level - num_inline_frames == 0)
      return 0;//Workaround in other case will crash.
 
  
  if (num_inline_frames == 0 && jsr_stub_frame == 0){
      return (frame_level>=0 && frame_level<=15 && frame_level<hw_stack) ? 0 : 1;
  }else if (num_inline_frames == 0 && jsr_stub_frame == 1){
      return (frame_level>=0 && frame_level<=15 && frame_level < hw_stack -jsr_stub_frame) ? 0 : 1;
  }else if (num_inline_frames != 0 && jsr_stub_frame == 0){
      return (frame_level - num_inline_frames >=0 && frame_level-num_inline_frames <=15 && frame_level - num_inline_frames <= hw_stack) ? 0 : 1;
  }else{
      return (frame_level - num_inline_frames >=0 && frame_level-num_inline_frames <=15 && frame_level - num_inline_frames <= hw_stack-jsr_stub_frame) ? 0 : 1;
  }
  

}

/* VSPA stop unwinder.  */
static const struct frame_unwind vspa_lastframe_unwind =
{
  NORMAL_FRAME,
  vspa_lastframe_unwind_stop_reason,
  vspa_lastframe_this_id,
  vspa_frame_prev_register,
  NULL,
  vspa_lastframe_sniffer
};

/* Return the value of the REGNUM register in the previous frame of
   *THIS_FRAME.  */

static struct value *
vspa_dwarf2_prev_register (struct frame_info *this_frame,
			   void **this_cache, int regnum)
{
  switch (regnum)
    {
    case VSPA_PC_REGNUM:
      return vspa_prev_pc_register(this_frame);

    default:
      internal_error (__FILE__, __LINE__,
		      _("Unexpected register %d"), regnum);
    }
}

/* Implement the "init_reg" dwarf2_frame_ops method.  */
static void
vspa_dwarf2_frame_init_reg (struct gdbarch *gdbarch, int regnum,
			    struct dwarf2_frame_state_reg *reg,
			    struct frame_info *this_frame)
{

  switch (regnum)
    {
    case VSPA_PC_REGNUM:
      reg->how = DWARF2_FRAME_REG_FN;
      reg->loc.fn = vspa_dwarf2_prev_register;
      break;
    case VSPA_SP_REGNUM:
      reg->how = DWARF2_FRAME_REG_CFA;
      break;
    }
}

static const struct frame_base vspa_frame_base =
{
  &vspa_frame_unwind,
  vspa_frame_base_address,
  vspa_frame_base_address,
  vspa_frame_base_address
};

static CORE_ADDR
vspa_read_pc (struct regcache *regcache)
{
  ULONGEST pc_value;

  regcache_cooked_read_unsigned (regcache, VSPA_PC_REGNUM, &pc_value);
  //if PC register value doesn't have prefix, it means that is in VCPU_PRAM
  if ((pc_value & 0xFFFFFFFF00000000ULL) != (kRUBY_RAWMEMSPACE_IPPU_PRAM<<32))
	  VSPA_VMA_PUT_PREFIX(pc_value, kRUBY_RAWMEMSPACE_VCPU_PRAM_GDB);
  return pc_value;
}

static void
vspa_write_pc (struct regcache *regcache, CORE_ADDR new_pc)
{
  new_pc &= 0xffffffffULL;

  regcache_cooked_write_unsigned (regcache, VSPA_PC_REGNUM, new_pc);
}

static CORE_ADDR
vspa_unwind_pc (struct gdbarch *gdbarch, struct frame_info *next_frame)
{
  CORE_ADDR pc_value =  frame_unwind_register_unsigned (next_frame, VSPA_PC_REGNUM);
  //if PC value doesn't have prefix it means that is in VCPU_PRAM
  if ((pc_value & 0xFFFFFFFF00000000ULL) != (kRUBY_RAWMEMSPACE_IPPU_PRAM<<32))
	  VSPA_VMA_PUT_PREFIX(pc_value, kRUBY_RAWMEMSPACE_VCPU_PRAM_GDB);
  return pc_value;
}

static CORE_ADDR
vspa3_adjust_dwarf2_data_uoffset (CORE_ADDR uoffset)
{
  uoffset /= 1;
  return uoffset;
}

static int64_t
vspa3_adjust_dwarf2_data_offset (int64_t offset)
{
  offset /= 1;
  return offset;
}

static CORE_ADDR
vspa2_adjust_dwarf2_data_uoffset (CORE_ADDR uoffset)
{
  uoffset /= 2;
  return uoffset;
}

static int64_t
vspa2_adjust_dwarf2_data_offset (int64_t offset)
{
  offset /= 2;
  return offset;
}
static CORE_ADDR
vspa1_adjust_dwarf2_data_uoffset (CORE_ADDR uoffset)
{
  uoffset /= 4;
  return uoffset;
}

static int64_t
vspa1_adjust_dwarf2_data_offset (int64_t offset)
{
  offset /= 4;
  return offset;
}

static CORE_ADDR
vspa3_adjust_dwarf2_data_addr (CORE_ADDR data_addr)
{
  if (data_addr & 0xFFFFFFFF00000000ULL)
    return data_addr;
  else
    if (data_addr < 0x7FFFFFFULL)
      return vspa_elf_put_prefix_of_address (bfd_mach_vspa3, data_addr, kRUBY_RAWMEMSPACE_VCPU_DRAM);
    else
      return vspa_elf_put_prefix_of_address (bfd_mach_vspa3, data_addr, kRUBY_RAWMEMSPACE_OCRAM_DATA);
}

static CORE_ADDR
vspa2_adjust_dwarf2_data_addr (CORE_ADDR data_addr)
{
  if (data_addr & 0xFFFFFFFF00000000ULL)
    return data_addr;
  else
    if (data_addr < 0x7FFFFFFULL)
      return vspa_elf_put_prefix_of_address (bfd_mach_vspa2, data_addr, kRUBY_RAWMEMSPACE_VCPU_DRAM);
    else
      return vspa_elf_put_prefix_of_address (bfd_mach_vspa2, data_addr, kRUBY_RAWMEMSPACE_OCRAM_DATA);
}

static CORE_ADDR
vspa1_adjust_dwarf2_data_addr (CORE_ADDR data_addr)
{
  if (data_addr & 0xFFFFFFFF00000000ULL)
    return data_addr;
  else
    if (data_addr < 0x7FFFFFFULL)
      return vspa_elf_put_prefix_of_address (bfd_mach_vspa1, data_addr, kRUBY_RAWMEMSPACE_VCPU_DRAM);
    else
      return vspa_elf_put_prefix_of_address (bfd_mach_vspa1, data_addr, kRUBY_RAWMEMSPACE_OCRAM_DATA);
}

static CORE_ADDR
vspa3_adjust_dwarf2_addr (CORE_ADDR pc)
{
  if (pc & 0xFFFFFFFF00000000ULL)
    {
      gdb_assert ((pc & 0xFFFFFFFF00000000ULL) == (kRUBY_RAWMEMSPACE_VCPU_PRAM_GDB<<32) || (pc & 0xFFFFFFFF00000000ULL) == (kRUBY_RAWMEMSPACE_IPPU_PRAM<<32));
      return pc;
    }
  else
    {
      return vspa_elf_put_prefix_of_address (bfd_mach_vspa3, pc, kRUBY_RAWMEMSPACE_VCPU_PRAM);
    }
}

static CORE_ADDR
vspa2_adjust_dwarf2_addr (CORE_ADDR pc)
{
  if (pc & 0xFFFFFFFF00000000ULL)
    {
      gdb_assert ((pc & 0xFFFFFFFF00000000ULL) == (kRUBY_RAWMEMSPACE_VCPU_PRAM_GDB<<32));
      return pc;
    }
  else
    {
      return vspa_elf_put_prefix_of_address (bfd_mach_vspa2, pc, kRUBY_RAWMEMSPACE_VCPU_PRAM);
    }
}

static CORE_ADDR
vspa1_adjust_dwarf2_addr (CORE_ADDR pc)
{
  if (pc & 0xFFFFFFFF00000000ULL)
    {
      gdb_assert ((pc & 0xFFFFFFFF00000000ULL) == (kRUBY_RAWMEMSPACE_VCPU_PRAM_GDB<<32));
      return pc;
    }
  else
    {
      return vspa_elf_put_prefix_of_address (bfd_mach_vspa1, pc, kRUBY_RAWMEMSPACE_VCPU_PRAM);
    }
}

static CORE_ADDR
vspa3_adjust_dwarf2_line (CORE_ADDR addr, int rel)
{
  if (rel == 0)
    {
      if (addr & 0xFFFFFFFF00000000ULL)
      {
    	  gdb_assert(FALSE);
    	  return addr;
      }
      else
    	  return vspa_elf_put_prefix_of_address (bfd_mach_vspa3, addr, kRUBY_RAWMEMSPACE_VCPU_PRAM);
    }
  else
    {
      CORE_ADDR rel_value = vspa_elf_put_prefix_of_address (bfd_mach_vspa3, addr, kRUBY_RAWMEMSPACE_VCPU_PRAM);
      rel_value &= 0xFFFFFFFFULL;
      return rel_value;
    }
}

static CORE_ADDR
vspa2_adjust_dwarf2_line (CORE_ADDR addr, int rel)
{
  if (rel == 0)
    {
      if (addr & 0xFFFFFFFF00000000ULL)
      {
	gdb_assert(FALSE);
	return addr;
      }
      else
	return vspa_elf_put_prefix_of_address (bfd_mach_vspa2, addr, kRUBY_RAWMEMSPACE_VCPU_PRAM);
    }
  else
    {
      CORE_ADDR rel_value = vspa_elf_put_prefix_of_address (bfd_mach_vspa2, addr, kRUBY_RAWMEMSPACE_VCPU_PRAM);
      rel_value &= 0xFFFFFFFFULL;
      return rel_value;
    }
}

static CORE_ADDR
vspa1_adjust_dwarf2_line (CORE_ADDR addr, int rel)
{
  if (rel == 0)
    {
      if (addr & 0xFFFFFFFF00000000ULL)
      {
	gdb_assert(FALSE);
	return addr;
      }
      else
	return vspa_elf_put_prefix_of_address (bfd_mach_vspa1, addr, kRUBY_RAWMEMSPACE_VCPU_PRAM);
    }
  else
    {
      CORE_ADDR rel_value = vspa_elf_put_prefix_of_address (bfd_mach_vspa1, addr, kRUBY_RAWMEMSPACE_VCPU_PRAM);
      rel_value &= 0xFFFFFFFFULL;
      return rel_value;
    }
}

static int
vspa_dwarf2_frame_adjust_return_address_reg (struct gdbarch *gdbarch,
					     int regnum, int eh_frame_p)
{
  return VSPA_PC_REGNUM;
}

static LONGEST
vspa3_dwarf2_frame_adjust_offset (struct gdbarch *gdbarch, LONGEST offset)
{
  LONGEST offset_value = vspa_elf_put_prefix_of_address (bfd_mach_vspa3, offset, kRUBY_RAWMEMSPACE_VCPU_DRAM);
  offset_value &= 0xFFFFFFFFULL;
  return offset_value;
}

static LONGEST
vspa2_dwarf2_frame_adjust_offset (struct gdbarch *gdbarch, LONGEST offset)
{
  LONGEST offset_value = vspa_elf_put_prefix_of_address (bfd_mach_vspa2, offset, kRUBY_RAWMEMSPACE_VCPU_DRAM);
  offset_value &= 0xFFFFFFFFULL;
  return offset_value;
}

static LONGEST
vspa1_dwarf2_frame_adjust_offset (struct gdbarch *gdbarch, LONGEST offset)
{
  LONGEST offset_value = vspa_elf_put_prefix_of_address (bfd_mach_vspa1, offset, kRUBY_RAWMEMSPACE_VCPU_DRAM);
  offset_value &= 0xFFFFFFFFULL;
  return offset_value;
}

static CORE_ADDR
vspa3_dwarf2_frame_adjust_line (struct gdbarch *gdbarch, CORE_ADDR addr, int rel)
{
  return vspa3_adjust_dwarf2_line(addr, rel);
}

static CORE_ADDR
vspa2_dwarf2_frame_adjust_line (struct gdbarch *gdbarch, CORE_ADDR addr, int rel)
{
  return vspa2_adjust_dwarf2_line(addr, rel);
}

static CORE_ADDR
vspa1_dwarf2_frame_adjust_line (struct gdbarch *gdbarch, CORE_ADDR addr, int rel)
{
  return vspa1_adjust_dwarf2_line(addr, rel);
}

/* Convert from address to pointer and vice-versa.  */

static void
vspa_address_to_pointer (struct gdbarch *gdbarch,
			struct type *type, gdb_byte *buf, CORE_ADDR addr)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);

  /* Is it a code address?  */
  if (TYPE_CODE (TYPE_TARGET_TYPE (type)) == TYPE_CODE_FUNC
	   || TYPE_CODE (TYPE_TARGET_TYPE (type)) == TYPE_CODE_METHOD)
    {
      store_unsigned_integer (buf, TYPE_LENGTH (type), byte_order,
			      vspa_convert_vcpu_pram_to_raw (addr));
    }
  else
    {
      /* Is it a data address in kRUBY_RAWMEMSPACE_VCPU_DRAM?  */
      if (vspa_vcpu_dram(addr))
	{
	  store_unsigned_integer (buf, TYPE_LENGTH (type), byte_order,
	      vspa_convert_vcpu_dram_to_raw (addr));
	}
      else
	{
	    /* It is a data address in kRUBY_RAWMEMSPACE_VCPU_OCRAM */
	    store_unsigned_integer (buf, TYPE_LENGTH (type), byte_order,
	      vspa_convert_vcpu_ocram_to_raw (addr));
	}
    }
}

static CORE_ADDR
vspa_pointer_to_address (struct gdbarch *gdbarch,
			 struct type *type, const gdb_byte *buf)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR addr
    = extract_unsigned_integer (buf, TYPE_LENGTH (type), byte_order);

  /* Is it a code address?  */
  if (TYPE_CODE (TYPE_TARGET_TYPE (type)) == TYPE_CODE_FUNC
	|| TYPE_CODE (TYPE_TARGET_TYPE (type)) == TYPE_CODE_METHOD
	|| TYPE_CODE_SPACE (TYPE_TARGET_TYPE (type)))
    {
      return vspa_make_vcpu_pram_addr (addr);
    }
  else
    {
      /* Is it a data address in kRUBY_RAWMEMSPACE_VCPU_DRAM?  */
      if (vspa_vcpu_dram(addr))
	{
	  return vspa_make_vcpu_dram_addr (addr);
	}
      else
	{
	   /* It is a data address in kRUBY_RAWMEMSPACE_VCPU_OCRAM */
	   return vspa_make_vcpu_ocram_addr (addr);
	}
    }
}

static CORE_ADDR
vspa_integer_to_address (struct gdbarch *gdbarch,
			 struct type *type, const gdb_byte *buf)
{
  ULONGEST addr = unpack_long (type, buf);
#if 0
  /* Is it a code address?  */
  if (TYPE_CODE (TYPE_TARGET_TYPE (type)) == TYPE_CODE_FUNC
	|| TYPE_CODE (TYPE_TARGET_TYPE (type)) == TYPE_CODE_METHOD
	|| TYPE_CODE_SPACE (TYPE_TARGET_TYPE (type)))
    {
      return addr;
    }
  else
    {
      /* Is it a data address in kRUBY_RAWMEMSPACE_VCPU_DRAM?  */
      if (vspa_vcpu_dram(addr))
	{
	  return (addr);
	}
      else
	{
	   /* It is a data address in kRUBY_RAWMEMSPACE_VCPU_OCRAM */
	   return  (addr);
	}
    }
#endif
  return addr;
}

/* Implementation of `address_class_type_flags' gdbarch method.

   This method maps DW_AT_address_class attributes to a
   type_instance_flag_value.  */

static int
vspa_address_class_type_flags (int byte_size, int dwarf2_addr_class)
{
  return 0;
}

/* Implementation of `address_class_type_flags_to_name' gdbarch method.

   Convert a type_instance_flag_value to an address space qualifier.  */

static const char*
vspa_address_class_type_flags_to_name (struct gdbarch *gdbarch, int type_flags)
{
   return NULL;
}

/* Implementation of `address_class_name_to_type_flags' gdbarch method.

   Convert an address space qualifier to a type_instance_flag_value.  */

static int
vspa_address_class_name_to_type_flags (struct gdbarch *gdbarch,
				       const char* name,
				       int *type_flags_ptr)
{
  return 0;
}

/* Default method for gdbarch_addressable_memory_unit_size.  By default, a memory byte has
   a size of 1 octet.  */

static int
vspa_addressable_memory_unit_size (struct gdbarch *gdbarch)
{
  return 1;
}

static int
vspa3_adjust_addressable_memory_unit_size (struct gdbarch *gdbarch, CORE_ADDR addr, int memory_unit_size)
{
  if ((addr & (7ULL<<32)) == (1ULL<<32)) // VCPU_DRAM
    return 1;
  else
    if ((addr & (7ULL<<32)) == (2ULL<<32)) // IPPU_PRAM
      return 4;
  else
    if ((addr & (7ULL<<32)) == (3ULL<<32)) // IPPU_DRAM
      return 1;
  else
    if ((addr & (7ULL<<32)) == (4ULL<<32)) // OCRAM_DATA
      return 1;
  else    if ((addr & (7ULL<<32)) == (6ULL<<32)) // VCPU_PRAM
      return 4;

  if (memory_unit_size == 1)
	  return 1;
  else
	  return 2;
}

static int
vspa2_adjust_addressable_memory_unit_size (struct gdbarch *gdbarch, CORE_ADDR addr, int memory_unit_size)
{
  if ((addr & (1ULL<<32)) == (1ULL<<32)) // VCPU_DRAM
    return 2;
  else
    if ((addr & (2ULL<<32)) == (2ULL<<32)) // IPPU_PRAM
      return 4;
  else
    if ((addr & (3ULL<<32)) == (3ULL<<32)) // IPPU_DRAM
      return 2;
  else
    if ((addr & (4ULL<<32)) == (4ULL<<32)) // OCRAM_DATA
      return 1;
  else    if ((addr & (6ULL<<32)) == (6ULL<<32)) // VCPU_PRAM
      return 4;

  return 2;
}

static int
vspa1_adjust_addressable_memory_unit_size (struct gdbarch *gdbarch, CORE_ADDR addr, int memory_unit_size)
{
  if ((addr & (1ULL<<32)) == (1ULL<<32)) // VCPU_DRAM
    return 4;
  else
    if ((addr & (2ULL<<32)) == (2ULL<<32)) // IPPU_PRAM
      return 4;
  else
    if ((addr & (3ULL<<32)) == (3ULL<<32)) // IPPU_DRAM
      return 4;
  else
    if ((addr & (4ULL<<32)) == (4ULL<<32)) // OCRAM_DATA
      return 1;
  else    if ((addr & (6ULL<<32)) == (6ULL<<32)) // VCPU_PRAM
      return 4;

  return 4;
}

int
gdb_print_insn_vspa (bfd_vma addr, disassemble_info *info)
{
    int ret = 0;

    // set decoded instruction to none (and reset also the subroutine call address)
    info->insn_type = dis_noninsn;
    info->target = 0;
    // call decoder
    ret = print_insn_vspa(addr, info);
    // if the insn is jsr, print also the function name
    if (ret > 0)
    {
        // append here the function name for jsr calls
        if ((info->insn_type == dis_jsr) ||
                (info->insn_type == dis_branch))
        {
            CORE_ADDR target_addr = 0x600000000ull | info->target;
            struct bound_minimal_symbol msym = lookup_minimal_symbol_by_pc (target_addr);
            if (msym.minsym != NULL)
             {
                CORE_ADDR start_pc = BMSYMBOL_VALUE_ADDRESS (msym);
                if (((target_addr  - start_pc) & 0x0FFFFFFFFull) > 0ull)
                    (*info->fprintf_func)(info->stream, "\t< %s + 0x%x >", MSYMBOL_PRINT_NAME (msym.minsym), (target_addr  - start_pc));
                else
                    (*info->fprintf_func)(info->stream, "\t< %s >", MSYMBOL_PRINT_NAME (msym.minsym));
             }
        }
    }
    return ret;

}

enum return_value_convention
vspa_return_value (struct gdbarch *gdbarch, struct value *function, struct type *valtype, struct regcache *regcache, gdb_byte *readbuf, const gdb_byte *writebuf)
{
	// TODO: this should return the value return by the function
	// return this now, so that it doesn't crash at finish
	return RETURN_VALUE_STRUCT_CONVENTION;
}

/* Initialize the current architecture based on INFO.  If possible, re-use an
   architecture from ARCHES, which is a list of architectures already created
   during this debugging session.

   Called e.g. at program startup, when reading a core file, and when reading
   a binary file.  */

static struct gdbarch *
vspa_gdbarch_init (struct gdbarch_info info, struct gdbarch_list *arches)
{
  struct gdbarch *gdbarch;
  struct tdesc_arch_data *tdesc_data = NULL;
  const struct target_desc *tdesc = info.target_desc;
  const struct tdesc_feature *feature;
  int valid_p, i, mach, has_feature;
  /* If there is already a candidate, use it.  */

  arches = gdbarch_list_lookup_by_info (arches, &info);
  if (arches != NULL)
    return arches->gdbarch;

   if (info.bfd_arch_info != NULL)
     mach = info.bfd_arch_info->mach;
  else
     mach = bfd_mach_vspa1; // vspa1 by default

   /* Ensure we always have a target descriptor.  */
  if (!tdesc_has_registers (tdesc)) 
  {
    if (mach == bfd_mach_vspa3)
        tdesc = tdesc_vspa3;
    else if(mach == bfd_mach_vspa2)
        tdesc = tdesc_vspa2;
    else 
        tdesc = tdesc_vspa1;
   }
   
   gdb_assert (tdesc);

   // check any target description for validity
  tdesc_data = tdesc_data_alloc ();
  valid_p = 1;
  has_feature = 0;
  if (tdesc_has_registers (tdesc)) 
  {
    feature = tdesc_find_feature (tdesc, "vspa1-core-regs");
    if (feature != NULL) 
    {
        has_feature = 1;
        for (i = 0; i < VSPA_NUM_REGS; i++)
            valid_p &= tdesc_numbered_register (feature, tdesc_data, i,
                vspa1_register_names[i]);
    }
    
    feature = tdesc_find_feature (tdesc, "vspa2-core-regs");
    if (feature != NULL)
    {
        has_feature = 1;
        // check validity for the gpr registers - these apply for all vspa versions
        for (i = 0; i < VSPA_NUM_REGS; i++)
           valid_p &= tdesc_numbered_register (feature, tdesc_data, i,
                vspa2_register_names[i]);
    }

    feature = tdesc_find_feature (tdesc, "lax-core-regs");
    if (feature != NULL)
    {
        has_feature = 1;
        // check validity for the gpr registers - these apply for all vspa versions
        for (i = 0; i < VSPA_NUM_REGS; i++)
           valid_p &= tdesc_numbered_register (feature, tdesc_data, i,
                vspa3_register_names[i]);
    }

    if(!has_feature)
       return NULL;

  }
  
  if (!valid_p) 
  {
    tdesc_data_cleanup (tdesc_data);
    return NULL;
  }

  gdbarch = gdbarch_alloc (&info, NULL);

  if (mach == bfd_mach_vspa3) 
  {
    set_gdbarch_adjust_dwarf2_data_uoffset (gdbarch, vspa3_adjust_dwarf2_data_uoffset);
    set_gdbarch_adjust_dwarf2_data_offset (gdbarch, vspa3_adjust_dwarf2_data_offset);
    set_gdbarch_adjust_dwarf2_data_addr (gdbarch, vspa3_adjust_dwarf2_data_addr);
    set_gdbarch_adjust_dwarf2_addr (gdbarch, vspa3_adjust_dwarf2_addr);
    set_gdbarch_adjust_dwarf2_line (gdbarch, vspa3_adjust_dwarf2_line);
  }
  else if (mach == bfd_mach_vspa2) 
  {
    set_gdbarch_adjust_dwarf2_data_uoffset (gdbarch, vspa2_adjust_dwarf2_data_uoffset);
    set_gdbarch_adjust_dwarf2_data_offset (gdbarch, vspa2_adjust_dwarf2_data_offset);
    set_gdbarch_adjust_dwarf2_data_addr (gdbarch, vspa2_adjust_dwarf2_data_addr);
    set_gdbarch_adjust_dwarf2_addr (gdbarch, vspa2_adjust_dwarf2_addr);
    set_gdbarch_adjust_dwarf2_line (gdbarch, vspa2_adjust_dwarf2_line);
  }
  else
  {
    set_gdbarch_adjust_dwarf2_data_uoffset (gdbarch, vspa1_adjust_dwarf2_data_uoffset);
    set_gdbarch_adjust_dwarf2_data_offset (gdbarch, vspa1_adjust_dwarf2_data_offset);
    set_gdbarch_adjust_dwarf2_data_addr (gdbarch, vspa1_adjust_dwarf2_data_addr);
    set_gdbarch_adjust_dwarf2_addr (gdbarch, vspa1_adjust_dwarf2_addr);
    set_gdbarch_adjust_dwarf2_line (gdbarch, vspa1_adjust_dwarf2_line);
  }
  set_gdbarch_addr_bit (gdbarch, 36);
  set_gdbarch_ptr_bit (gdbarch, 36);
  set_gdbarch_dwarf2_addr_size (gdbarch, 4);

  /* Register info */
  set_gdbarch_num_regs (gdbarch, VSPA_NUM_REGS);
  if (mach == bfd_mach_vspa3) 
  {
    set_gdbarch_register_name (gdbarch, vspa3_register_name);
    set_tdesc_pseudo_register_name (gdbarch, vspa3_register_name);
  }
  else if (mach == bfd_mach_vspa2) 
  {
    set_gdbarch_register_name (gdbarch, vspa2_register_name);
    set_tdesc_pseudo_register_name (gdbarch, vspa2_register_name);
  }
  else 
  {
    set_gdbarch_register_name (gdbarch, vspa1_register_name);
    set_tdesc_pseudo_register_name (gdbarch, vspa1_register_name);
  }
  set_gdbarch_register_type (gdbarch, vspa_register_type);
  tdesc_use_registers (gdbarch, tdesc, tdesc_data);

  /* Internal <-> external register number maps.  */
  set_gdbarch_dwarf2_reg_to_regnum (gdbarch, vspa_dwarf_reg_to_regnum);
  set_gdbarch_sp_regnum (gdbarch, VSPA_SP_REGNUM);
  set_gdbarch_pc_regnum (gdbarch, VSPA_PC_REGNUM);

  /* Frame and stack info */
  set_gdbarch_skip_prologue (gdbarch, vspa_skip_prologue);

  /* Stack grows upward - stack address is increasing.  */
  set_gdbarch_inner_than (gdbarch, core_addr_greaterthan);

  /* Return value info */
  set_gdbarch_return_value(gdbarch, vspa_return_value);

  /* Call dummy code.  */
  /*This target does not support function calls*/
  set_gdbarch_push_dummy_call (gdbarch, NULL /*vspa_push_dummy_call*/);
  set_gdbarch_dummy_id (gdbarch, vspa_dummy_id);

  /* Breakpoint info */
  set_gdbarch_breakpoint_from_pc (gdbarch, vspa_breakpoint_from_pc);

  set_gdbarch_read_pc (gdbarch, vspa_read_pc);
  set_gdbarch_write_pc (gdbarch, vspa_write_pc);
  set_gdbarch_unwind_pc (gdbarch, vspa_unwind_pc);

  // Disassembly
  set_gdbarch_print_insn (gdbarch, gdb_print_insn_vspa); 
 
  /* Unwinding.  */
  dwarf2_append_unwinders (gdbarch);
  frame_unwind_append_unwinder (gdbarch, &vspa_frame_unwind);
  frame_base_set_default (gdbarch, &vspa_frame_base);
  frame_unwind_prepend_unwinder (gdbarch, &vspa_lastframe_unwind);
  dwarf2_frame_set_init_reg (gdbarch, vspa_dwarf2_frame_init_reg);
  dwarf2_frame_set_adjust_return_address_reg (gdbarch, vspa_dwarf2_frame_adjust_return_address_reg);
  if (mach == bfd_mach_vspa3) 
  {
    dwarf2_frame_set_adjust_offset (gdbarch, vspa3_dwarf2_frame_adjust_offset);
    dwarf2_frame_set_adjust_line (gdbarch, vspa3_dwarf2_frame_adjust_line);
  }
  else if (mach == bfd_mach_vspa2) 
  {
    dwarf2_frame_set_adjust_offset (gdbarch, vspa2_dwarf2_frame_adjust_offset);
    dwarf2_frame_set_adjust_line (gdbarch, vspa2_dwarf2_frame_adjust_line);   
  }
  else 
  {
    dwarf2_frame_set_adjust_offset (gdbarch, vspa1_dwarf2_frame_adjust_offset);
    dwarf2_frame_set_adjust_line (gdbarch, vspa1_dwarf2_frame_adjust_line);   
  }
  /* Address handling.  */
  set_gdbarch_address_to_pointer (gdbarch, vspa_address_to_pointer);
  set_gdbarch_pointer_to_address (gdbarch, vspa_pointer_to_address);
  set_gdbarch_integer_to_address (gdbarch, vspa_integer_to_address);
  set_gdbarch_address_class_type_flags (gdbarch, vspa_address_class_type_flags);
  set_gdbarch_address_class_type_flags_to_name
    (gdbarch, vspa_address_class_type_flags_to_name);
  set_gdbarch_address_class_name_to_type_flags
    (gdbarch, vspa_address_class_name_to_type_flags);

  set_gdbarch_addressable_memory_unit_size (gdbarch, vspa_addressable_memory_unit_size);
  if (mach == bfd_mach_vspa3)
    set_gdbarch_adjust_addressable_memory_unit_size (gdbarch, vspa3_adjust_addressable_memory_unit_size);
  else if(mach == bfd_mach_vspa2) 
    set_gdbarch_adjust_addressable_memory_unit_size (gdbarch, vspa2_adjust_addressable_memory_unit_size);
  else
    set_gdbarch_adjust_addressable_memory_unit_size (gdbarch, vspa1_adjust_addressable_memory_unit_size);
  /* Hook in ABI-specific overrides, if they have been registered.  */
  gdbarch_init_osabi (info, gdbarch);

  return (gdbarch);
}

/* Provide a prototype to silence -Wmissing-prototypes.  */
void _initialize_vspa_tdep (void);


void
_initialize_vspa_tdep (void)
{
  gdbarch_register (bfd_arch_vspa, vspa_gdbarch_init, NULL);
  initialize_tdesc_vspa1 ();
  initialize_tdesc_vspa2 ();
  initialize_tdesc_vspa3 ();
}
