/* Vspa-specific support for 32-bit ELF.

   Copyright (C) 2003-2015 Free Software Foundation, Inc.

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
#include "sysdep.h"
#include "libbfd.h"
#include "elf-bfd.h"
#include "elf/vspa.h"

const bfd_vma kUNKNOWN_RAWMEMSPACE = (bfd_vma)-1;
const bfd_vma kRUBY_RAWMEMSPACE_VCPU_PRAM = (bfd_vma)0;
const bfd_vma kRUBY_RAWMEMSPACE_VCPU_DRAM = (bfd_vma)1;
const bfd_vma kRUBY_RAWMEMSPACE_IPPU_PRAM = (bfd_vma)2;
const bfd_vma kRUBY_RAWMEMSPACE_IPPU_DRAM = (bfd_vma)3;
const bfd_vma kRUBY_RAWMEMSPACE_OCRAM_DATA = (bfd_vma)4;
const bfd_vma kRUBY_RAWMEMSPACE_LUT = (bfd_vma)5;
const bfd_vma kRUBY_RAWMEMSPACE_VCPU_PRAM_GDB = (bfd_vma)6;


static reloc_howto_type vspa_elf_howto_table[] = {
  /* This reloc does nothing.  */
  HOWTO (R_VSPA_NONE,		/* type */
	 0,			/* rightshift */
	 3,			/* size (0 = byte, 1 = short, 2 = long) */
	 0,			/* bitsize */
	 FALSE,			/* pc_relative */
	 0,			/* bitpos */
	 complain_overflow_dont,	/* complain_on_overflow */
	 bfd_elf_generic_reloc,	/* special_function */
	 "R_VSPA_NONE",	/* name */
	 FALSE,			/* partial_inplace */
	 0,			/* src_mask */
	 0,			/* dst_mask */
	 FALSE),		/* pcrel_offset */
};


static reloc_howto_type *
vspa_reloc_type_lookup (bfd *abfd ATTRIBUTE_UNUSED,
			  bfd_reloc_code_real_type code)
{
  /* Note that the vspa_elf_howto_table is indexed by the R_
     constants. Thus, the order that the howto records appear in the
     table *must* match the order of the relocation types defined in
     include/elf/vspa.h.  */
  return &vspa_elf_howto_table[(int) R_VSPA_NONE];
}

static reloc_howto_type *
vspa_reloc_name_lookup (bfd *abfd ATTRIBUTE_UNUSED, const char *r_name)
{
  unsigned int i;

  for (i = 0;
       i < (sizeof (vspa_elf_howto_table)
	    / sizeof (vspa_elf_howto_table[0])); i++)
    if (vspa_elf_howto_table[i].name != NULL
	&& strcasecmp (vspa_elf_howto_table[i].name, r_name) == 0)
      return &vspa_elf_howto_table[i];

  return NULL;
}

/* Set the howto pointer for a VISIUM ELF reloc.  */

static void
vspa_info_to_howto_rela (bfd *abfd ATTRIBUTE_UNUSED, arelent *cache_ptr,
			 Elf_Internal_Rela *dst)
{
  unsigned int r_type = ELF32_R_TYPE (dst->r_info);

  switch (r_type)
    {
    default:
      if (r_type >= (unsigned int) R_VSPA_max)
	{
	  _bfd_error_handler (_("%B: invalid VSPA reloc number: %d"), abfd, r_type);
	  r_type = 0;
	}
      cache_ptr->howto = &vspa_elf_howto_table[r_type];
      break;
    }
}
//post process header if one wants to dump something
static void
vspa_elf_post_process_headers (bfd *abfd,
			       struct bfd_link_info *info ATTRIBUTE_UNUSED)
{
  Elf_Internal_Ehdr *i_ehdrp = elf_elfheader (abfd);
  i_ehdrp->e_ident[EI_OSABI] = ELFOSABI_STANDALONE;
  i_ehdrp->e_ident[EI_ABIVERSION] = 1;
}
//api provided by compiler in order to know how memoery map is associated with sections and segment -  an address is fit in memory
typedef struct _RawMemSpaceInfo
{
  bfd_vma lowAddressOfRawDataMemSpace;
  bfd_vma highAddressOfRawDataMemSpace;
  bfd_vma* sectionToMemSpace;
  bfd_vma* segmentToMemSpace;
}RawMemSpaceInfo;
static RawMemSpaceInfo sRawMemSpaceInfo = {(bfd_vma)-1,(bfd_vma)-1, NULL, NULL};

static bfd_boolean
vspa_reinit_raw_mem_space_info(bfd * abfd)
{
  RawMemSpaceInfo* rawMemSpaceInfo = &sRawMemSpaceInfo;

  rawMemSpaceInfo->lowAddressOfRawDataMemSpace = (bfd_vma)-1;
  rawMemSpaceInfo->highAddressOfRawDataMemSpace = (bfd_vma)-1;
  if (rawMemSpaceInfo->sectionToMemSpace)
    free (rawMemSpaceInfo->sectionToMemSpace);
  rawMemSpaceInfo->sectionToMemSpace = bfd_malloc (elf_elfheader(abfd)->e_shnum*sizeof(bfd_vma));
  BFD_ASSERT(rawMemSpaceInfo->sectionToMemSpace != NULL);
  memset(rawMemSpaceInfo->sectionToMemSpace, kUNKNOWN_RAWMEMSPACE, elf_elfheader(abfd)->e_shnum*sizeof(bfd_vma));
  if (rawMemSpaceInfo->segmentToMemSpace)
    free (rawMemSpaceInfo->segmentToMemSpace);
  rawMemSpaceInfo->segmentToMemSpace = bfd_malloc (elf_elfheader(abfd)->e_phnum*sizeof(bfd_vma));
  memset(rawMemSpaceInfo->segmentToMemSpace, kUNKNOWN_RAWMEMSPACE, elf_elfheader(abfd)->e_phnum*sizeof(bfd_vma));
  BFD_ASSERT(rawMemSpaceInfo->segmentToMemSpace != NULL);

  return TRUE;
}

static bfd_boolean
vspa_parse_raw_mem_space_info(bfd * abfd)
{
  asection *mw_info;
  RawMemSpaceInfo* rawMemSpaceInfo = &sRawMemSpaceInfo;

  BFD_ASSERT(vspa_reinit_raw_mem_space_info (abfd));

  mw_info =  bfd_get_section_by_name (abfd, ".mw_info");
  if (mw_info != NULL)
    {
      int i;
      unsigned int indx;
      bfd_byte* contents, *ptr;
      bfd_size_type size;
      bfd_size_type infoEntriesCount;
      bfd_boolean* infoEntries;

      size = bfd_get_section_size (mw_info);
      infoEntriesCount = elf_elfheader (abfd)->e_phnum + elf_elfheader (abfd)->e_shnum;
      if ((infoEntriesCount > 0) && (size > 0))
	{
	  unsigned char recType;
	  bfd_size_type recSize;
	  Elf_Internal_Shdr **i_shdrp;

	  i_shdrp = elf_elfsections (abfd);
	  infoEntries = bfd_zmalloc (infoEntriesCount*sizeof(bfd_boolean));
	  BFD_ASSERT(infoEntries != NULL);
	  for (indx = 0; indx < elf_elfheader (abfd)->e_shnum; indx++)
	    if (i_shdrp[indx]->sh_flags == 0)
	    {
	      infoEntries[indx] = TRUE;
	      rawMemSpaceInfo->sectionToMemSpace[indx] = kRUBY_RAWMEMSPACE_OCRAM_DATA;
	    }

	  contents = bfd_malloc (size);
	  BFD_ASSERT(contents != NULL);
	  BFD_ASSERT(bfd_get_section_contents (abfd, mw_info, contents, (file_ptr)0, size));
	  ptr = contents;
	  while (size > 0)
	    {
	      bfd_boolean needMore = FALSE;
	      for (i = infoEntriesCount -1; i >= 0; i--)
		{
		  if (infoEntries[i] == FALSE)
		    {
		      needMore = TRUE;
		      break;
		    }
		}
	      if (!needMore)
		break;

	      // read size of current record
	      recSize = bfd_get_32(abfd, ptr);
	      ptr += 4;
	      if (recSize == 0)
		break;
	      size -= recSize;

	      // read record type
	      recType = bfd_get_8(abfd, ptr);
	      ptr += 1;
	      switch (recType)
		{
		  case 14:
		    //we're interested in type 14, which is for define the memory space
		    {
		      bfd_vma memspace_address, memspace_size,memspace_namesz;
		      bfd_size_type memspace_id = bfd_get_32(abfd, ptr);
		      ptr += 4;
		      // ignores the flag information
		      ptr += 4;
		      memspace_address = bfd_get_32(abfd, ptr);
		      ptr += 4;
		      memspace_size = bfd_get_32(abfd, ptr);
		      ptr += 4;
		      memspace_namesz = bfd_get_32(abfd, ptr);
		      ptr += 4;
		      // ignores the name of the memory space
		      ptr += memspace_namesz;

		      if (memspace_id == kRUBY_RAWMEMSPACE_VCPU_DRAM)
			{
			  rawMemSpaceInfo->lowAddressOfRawDataMemSpace = memspace_address;
			  rawMemSpaceInfo->highAddressOfRawDataMemSpace = memspace_address + memspace_size;
			}
		    }
		    break;
		  case 15:
		    //we're interested in type 15, which is for mapping a section to a memory space
		    {
		      bfd_vma section_id, memspace_id;
		      section_id = bfd_get_32(abfd, ptr);
		      ptr += 4;
		      memspace_id = bfd_get_32(abfd, ptr);
		      ptr += 4;
		      BFD_ASSERT(section_id < elf_elfheader (abfd)->e_shnum);
		      rawMemSpaceInfo->sectionToMemSpace[section_id] = memspace_id;
		      infoEntries[section_id] = TRUE;
		    }
		    break;
		  case 16:
		    //we're interested in type 16, which is for mapping a segment to a memory space
		    {
		      bfd_vma segment_id, memspace_id;
		      segment_id = bfd_get_32(abfd, ptr);
		      ptr += 4;
		      memspace_id = bfd_get_32(abfd, ptr);
		      ptr += 4;
		      BFD_ASSERT(segment_id < elf_elfheader (abfd)->e_phnum);
		      rawMemSpaceInfo->segmentToMemSpace[segment_id] = memspace_id;
		      infoEntries[elf_elfheader(abfd)->e_shnum + segment_id] = TRUE;
		    }
		    break;
		  default:
		    {
		      ptr += recSize - 5;
		    }
		    break;
		}
	    }
	  free (infoEntries);
	  free (contents);
	}
    }

    return TRUE;
}

bfd_vma
vspa_convert_vcpu_pram_to_raw(bfd_vma addr)
{
  return  addr & 0xFFFFFFFFULL;
}

bfd_vma
vspa_convert_vcpu_dram_to_raw(bfd_vma addr)
{
  return  addr & 0xFFFFFFFFULL;
}

bfd_vma
vspa_convert_vcpu_ocram_to_raw(bfd_vma addr)
{
  return  addr & 0xFFFFFFFFULL;
}

bfd_vma
vspa_make_vcpu_pram_addr(bfd_vma addr)
{
  VSPA_VMA_PUT_PREFIX(addr, kRUBY_RAWMEMSPACE_VCPU_PRAM_GDB);
  return  addr;
}

bfd_vma
vspa_make_vcpu_dram_addr(bfd_vma addr)
{
  VSPA_VMA_PUT_PREFIX(addr, kRUBY_RAWMEMSPACE_VCPU_DRAM);
  return  addr;
}

bfd_vma
vspa_make_vcpu_ocram_addr(bfd_vma addr)
{
  VSPA_VMA_PUT_PREFIX(addr, kRUBY_RAWMEMSPACE_OCRAM_DATA);
  return  addr;
}

int
vspa_vcpu_dram(bfd_vma addr) //ORG
{
  RawMemSpaceInfo* rawMemSpaceInfo = &sRawMemSpaceInfo;
  bfd_vma addr2 = addr & 0xFFFFFFFFULL;

  if ((addr2 >= rawMemSpaceInfo->lowAddressOfRawDataMemSpace)
     && (addr2 <= rawMemSpaceInfo->highAddressOfRawDataMemSpace))
    return 1;
  else
    return 0;
}

bfd_vma
vspa_elf_put_prefix_of_address(bfd_vma vspa_arch_type, bfd_vma addr, bfd_vma memspace_id)
{
  switch (memspace_id)
  {
    case 0:
      //kRUBY_RAWMEMSPACE_VCPU_PRAM
      memspace_id = kRUBY_RAWMEMSPACE_VCPU_PRAM_GDB;
      addr /= 4;
      break;
    case 1:
      //kRUBY_RAWMEMSPACE_VCPU_DRAM
      addr /= vspa_vma_get_dram_size (vspa_arch_type);
      break;
    case 2:
      //kRUBY_RAWMEMSPACE_IPPU_PRAM
      addr /= 4;
      break;
    case 3:
      //kRUBY_RAWMEMSPACE_IPPU_DRAM
      addr /= vspa_vma_get_dram_size (vspa_arch_type);
      break;
    case 4:
      //kRUBY_RAWMEMSPACE_OCRAM_DATA
      break;
    case 5:
      //kRUBY_RAWMEMSPACE_LUT
      addr /= 2;
      break;
    default:
      BFD_ASSERT(FALSE);
      break;
  }
  VSPA_VMA_PUT_PREFIX(addr, memspace_id);
  return addr;
}

bfd_vma
vspa_elf_convert_word_address(bfd_vma vspa_arch_type, bfd_vma addr, bfd_vma memspace_id)
{
  addr &= 0xFFFFFFFFULL;
  switch (memspace_id)
  {
    case 0:
      //kRUBY_RAWMEMSPACE_VCPU_PRAM
      memspace_id = kRUBY_RAWMEMSPACE_VCPU_PRAM_GDB;
      addr *= 4;
      break;
    case 1:
      //kRUBY_RAWMEMSPACE_VCPU_DRAM
      addr *= vspa_vma_get_dram_size (vspa_arch_type);
      break;
    case 2:
      //kRUBY_RAWMEMSPACE_IPPU_PRAM
      addr *= 4;
      break;
    case 3:
      //kRUBY_RAWMEMSPACE_IPPU_DRAM
      addr *= vspa_vma_get_dram_size (vspa_arch_type);
      break;
    case 4:
      //kRUBY_RAWMEMSPACE_OCRAM_DATA
      break;
    case 5:
      //kRUBY_RAWMEMSPACE_LUT
      addr *= 2;
      break;
    default:
      BFD_ASSERT(FALSE);
      break;
  }

  return addr;
}

static bfd_boolean
vspa_elf_object_p (bfd * abfd)
{
  Elf_Internal_Phdr *i_phdr;
  Elf_Internal_Shdr **i_shdrp;
  unsigned int i;
  RawMemSpaceInfo* rawMemSpaceInfo = &sRawMemSpaceInfo;

  BFD_ASSERT(vspa_parse_raw_mem_space_info(abfd));
  elf_elfheader (abfd)->e_entry = vspa_elf_put_prefix_of_address(ELF_EF_VSPA_CORE (elf_elfheader (abfd)->e_flags) , elf_elfheader (abfd)->e_entry, kRUBY_RAWMEMSPACE_VCPU_PRAM);
  // update the address of section with memory space as prefix
  i_shdrp = elf_elfsections (abfd);
  for (i = 0; i < elf_elfheader (abfd)->e_shnum; i++)
   {
     if (i_shdrp[i]->sh_flags & SHF_ALLOC)
     {
       i_shdrp[i]->sh_addr = vspa_elf_put_prefix_of_address(ELF_EF_VSPA_CORE (elf_elfheader (abfd)->e_flags), i_shdrp[i]->sh_addr, rawMemSpaceInfo->sectionToMemSpace[i]);
       bfd_set_section_vma(abfd, i_shdrp[i]->bfd_section, i_shdrp[i]->sh_addr);
     }
   }

  // update the address of segment with memory space as prefix
  i_phdr = elf_tdata (abfd)->phdr;
  for (i = 0; i < elf_elfheader (abfd)->e_phnum; i++)
   {
     i_phdr[i].p_vaddr = vspa_elf_put_prefix_of_address(ELF_EF_VSPA_CORE (elf_elfheader (abfd)->e_flags), i_phdr[i].p_vaddr, rawMemSpaceInfo->segmentToMemSpace[i]);
     i_phdr[i].p_paddr = vspa_elf_put_prefix_of_address(ELF_EF_VSPA_CORE (elf_elfheader (abfd)->e_flags), i_phdr[i].p_paddr, rawMemSpaceInfo->segmentToMemSpace[i]);
   }

  return bfd_default_set_arch_mach (abfd, bfd_arch_vspa, ELF_EF_VSPA_CORE (elf_elfheader (abfd)->e_flags));
}

static bfd_boolean
elf32_vspa_swap_symbol_in (bfd * abfd,
			  const void *psrc,
			  const void *pshn,
			  Elf_Internal_Sym *dst)
{
  RawMemSpaceInfo* rawMemSpaceInfo = &sRawMemSpaceInfo;

  if (!bfd_elf32_swap_symbol_in (abfd, psrc, pshn, dst))
    return FALSE;

  // update the address of section with memory space as prefix
  if ((dst->st_shndx > 0) && (dst->st_shndx < elf_elfheader (abfd)->e_shnum))
    {
      dst->st_value = vspa_elf_put_prefix_of_address(ELF_EF_VSPA_CORE (elf_elfheader (abfd)->e_flags), dst->st_value, rawMemSpaceInfo->sectionToMemSpace[dst->st_shndx]);
      if (elf_elfheader (abfd)->e_flags & PF_X)
	{
	  dst->st_size = vspa_elf_put_prefix_of_address(ELF_EF_VSPA_CORE (elf_elfheader (abfd)->e_flags), dst->st_size, rawMemSpaceInfo->sectionToMemSpace[dst->st_shndx]);
	  dst->st_size &= 0xFFFFFFFFULL;
	}
    }
  else
    {
      dst->st_value = 0;
      dst->st_size = 0;
    }

  return TRUE;
}

static bfd_boolean vspa_get_section_contents(bfd *         abfd,
                                             sec_ptr       section,
                                             void *        location,
                                             file_ptr      offset,
                                             bfd_size_type count)
{
    int exec = (abfd->flags & EXEC_P) ? 1 : 0;
    int s_code = (section->flags & SEC_CODE) ? 1 : 0; 

    if (s_code & exec)
        offset = vspa_elf_convert_word_address(ELF_EF_VSPA_CORE (elf_elfheader (abfd)->e_flags), offset, 0);
    else
        offset = vspa_elf_convert_word_address(ELF_EF_VSPA_CORE (elf_elfheader (abfd)->e_flags), offset, 1);

    return _bfd_generic_get_section_contents (abfd, section, location, offset, count);
}

static bfd_boolean vspa_set_section_contents(bfd *         abfd,
                                             sec_ptr       section,
                                             void *        location,
                                             file_ptr      offset,
                                             bfd_size_type count)
{
    int exec = (abfd->flags & EXEC_P) ? 1 : 0;
    int s_code = (section->flags & SEC_CODE) ? 1 : 0;

    if (s_code & exec)
        offset = vspa_elf_convert_word_address(ELF_EF_VSPA_CORE (elf_elfheader (abfd)->e_flags), offset, 0);
    else
        offset = vspa_elf_convert_word_address(ELF_EF_VSPA_CORE (elf_elfheader (abfd)->e_flags), offset, 1);

    return _bfd_generic_set_section_contents (abfd, section, location, offset, count);
}

bfd_vma  vspa_vma_get_dram_size(bfd_vma vspa_arch_type) {

	switch (vspa_arch_type)
	{
	case bfd_mach_vspa3:
		return 1;
		break;

	case bfd_mach_vspa2:
		return 2;
		break;

	case bfd_mach_vspa1:
		return 4;
		break;
	}
}

/* We use this to override swap_symbol_in.  */
const struct elf_size_info elf32_vspa_size_info =
{
  sizeof (Elf32_External_Ehdr),
  sizeof (Elf32_External_Phdr),
  sizeof (Elf32_External_Shdr),
  sizeof (Elf32_External_Rel),
  sizeof (Elf32_External_Rela),
  sizeof (Elf32_External_Sym),
  sizeof (Elf32_External_Dyn),
  sizeof (Elf_External_Note),
  4,
  1,
  32, 2,
  ELFCLASS32, EV_CURRENT,
  bfd_elf32_write_out_phdrs,
  bfd_elf32_write_shdrs_and_ehdr,
  bfd_elf32_checksum_contents,
  bfd_elf32_write_relocs,
  elf32_vspa_swap_symbol_in,
  bfd_elf32_swap_symbol_out,
  bfd_elf32_slurp_reloc_table,
  bfd_elf32_slurp_symbol_table,
  bfd_elf32_swap_dyn_in,
  bfd_elf32_swap_dyn_out,
  bfd_elf32_swap_reloc_in,
  bfd_elf32_swap_reloc_out,
  bfd_elf32_swap_reloca_in,
  bfd_elf32_swap_reloca_out
};


#define ELF_ARCH		bfd_arch_vspa
#define ELF_MACHINE_CODE	EM_VSPA
#define ELF_MAXPAGESIZE		1

#define TARGET_LITTLE_SYM       vspa_elf32_vec
#define TARGET_LITTLE_NAME      "elf32-littlevspa"

#define elf_info_to_howto_rel			NULL
#define elf_info_to_howto			vspa_info_to_howto_rela
#define bfd_elf32_bfd_reloc_type_lookup		vspa_reloc_type_lookup
#define bfd_elf32_bfd_reloc_name_lookup		vspa_reloc_name_lookup
#define elf_backend_object_p			vspa_elf_object_p
#define elf_backend_post_process_headers	vspa_elf_post_process_headers
#define elf_backend_size_info			elf32_vspa_size_info
#define bfd_elf32_get_section_contents  vspa_get_section_contents
#define bfd_elf32_set_section_contents	vspa_set_section_contents

#include "elf32-target.h"
