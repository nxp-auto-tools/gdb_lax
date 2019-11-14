/* BFD support for the Vspa processor.

   Copyright (C) 2015-2016 Free Software Foundation, Inc.

   This file is part of BFD, the Binary File Descriptor library.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor,
   Boston, MA 02110-1301, USA.  */

#include "sysdep.h"
#include "bfd.h"
#include "libbfd.h"

const bfd_arch_info_type bfd_vspa3_arch =
{
  32,				/* bits per word */
  32,				/* bits per address */
  8,				/* bits per byte */
  bfd_arch_vspa,		/* architecture */
  bfd_mach_vspa3,		/* machine */
  "vspa",			/* architecture name */
  "vspa3",			/* printable name */
  2,				/* section align power */
  FALSE,				/* the default ? */
  bfd_default_compatible,	/* architecture comparison fn */
  bfd_default_scan,		/* string to architecture convert fn */
  bfd_arch_default_fill,	/* default fill */
  NULL			/* next in list */
};

const bfd_arch_info_type bfd_vspa2_arch =
{
  32,				/* bits per word */
  32,				/* bits per address */
  8,				/* bits per byte */
  bfd_arch_vspa,		/* architecture */
  bfd_mach_vspa2,		/* machine */
  "vspa",			/* architecture name */
  "vspa2",			/* printable name */
  2,				/* section align power */
  FALSE,				/* the default ? */
  bfd_default_compatible,	/* architecture comparison fn */
  bfd_default_scan,		/* string to architecture convert fn */
  bfd_arch_default_fill,	/* default fill */
  &bfd_vspa3_arch			/* next in list */
};

const bfd_arch_info_type bfd_vspa_arch =
{
  32,				/* bits per word */
  32,				/* bits per address */
  8,				/* bits per byte */
  bfd_arch_vspa,		/* architecture */
  bfd_mach_vspa1,		/* machine */
  "vspa",			/* architecture name */
  "vspa1",			/* printable name */
  2,				/* section align power */
  FALSE,				/* the default ? */
  bfd_default_compatible,	/* architecture comparison fn */
  bfd_default_scan,		/* string to architecture convert fn */
  bfd_arch_default_fill,	/* default fill */
  &bfd_vspa2_arch				/* next in list */
};