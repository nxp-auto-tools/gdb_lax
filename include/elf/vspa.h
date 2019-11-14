/* VSPA ELF support for BFD.

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
   along with this program; if not, write to the Free Software Foundation,
   Inc., 51 Franklin Street - Fifth Floor, Boston, MA 02110-1301, USA.  */

#ifndef _ELF_VSPA_H
#define _ELF_VSPA_H

#include "elf/reloc-macros.h"

/* Processor specific flags for the ELF header e_flags field.  */
#define EF_VSPA_ARCH_VSPA2   0x02

/* Relocations.  */
START_RELOC_NUMBERS (elf_vspa_reloc_type)
  RELOC_NUMBER (R_VSPA_NONE, 0)
END_RELOC_NUMBERS(R_VSPA_max)

extern const bfd_vma kUNKNOWN_RAWMEMSPACE;
extern const bfd_vma kRUBY_RAWMEMSPACE_VCPU_PRAM;
extern const bfd_vma kRUBY_RAWMEMSPACE_VCPU_DRAM;
extern const bfd_vma kRUBY_RAWMEMSPACE_IPPU_PRAM;
extern const bfd_vma kRUBY_RAWMEMSPACE_IPPU_DRAM;
extern const bfd_vma kRUBY_RAWMEMSPACE_OCRAM_DATA;
extern const bfd_vma kRUBY_RAWMEMSPACE_LUT;
extern const bfd_vma kRUBY_RAWMEMSPACE_VCPU_PRAM_GDB;
#define VSPA_VMA_PUT_PREFIX(x, m) x |= m << 32
extern bfd_vma vspa_elf_put_prefix_of_address(bfd_vma arch_type, bfd_vma addr, bfd_vma memspace_id);
extern bfd_vma vspa_elf_convert_word_address(bfd_vma arch_type, bfd_vma addr, bfd_vma memspace_id);
extern bfd_vma vspa_convert_vcpu_pram_to_raw(bfd_vma addr);
extern bfd_vma vspa_convert_vcpu_dram_to_raw(bfd_vma addr);
extern bfd_vma vspa_convert_vcpu_ocram_to_raw(bfd_vma addr);
extern bfd_vma vspa_make_vcpu_pram_addr(bfd_vma addr);
extern bfd_vma vspa_make_vcpu_dram_addr(bfd_vma addr);
extern bfd_vma vspa_make_vcpu_ocram_addr(bfd_vma addr);
extern int vspa_vcpu_dram(bfd_vma addr);
extern bfd_vma  vspa_vma_get_dram_size(bfd_vma vspa_arch_type);
//#define VSPA_VMA_GET_DRAM_BIT_SIZE(x) ( (bfd_mach_vspa2 == x)  ? 2 : 4 )
#define ELF_EF_VSPA_CORE(f)       ( (f) & 0xffUL )


#endif /* _ELF_VSPA_H */
