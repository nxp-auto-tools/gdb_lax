/* Single instruction disassembler for the VSPA.

   Copyright (C) 2015-2016 Free Software Foundation, Inc.

   This file is part of the GNU opcodes library.

   This library is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3, or (at your option)
   any later version.

   It is distributed in the hope that it will be useful, but WITHOUT
   ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
   or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
   License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street - Fifth Floor, Boston,
   MA 02110-1301, USA.  */

#include "sysdep.h"
#include "dis-asm.h"
#include "opcode/vspa.h"
#include "vspa-dis.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <setjmp.h>

#define VCPU	0x0
#define IPPU	0x1
#define NONE	0xF

// defines used to determine the half word instructions
#define get_mask_half_word(x) ((x == bfd_mach_vspa1) ? (0x1ULL << 52) : (0x1ULL << 63))
#define get_mask_null(x) ((x == bfd_mach_vspa1) ? (0xFFULL << 44) : (0xFFULL << 52))
#define get_opcode_null(x) ((x == bfd_mach_vspa1) ? (0x3FULL << 44) : 0x0ull)

// get the processor: vcpu or ippu
#define is_ippu_pram(x) (((x & 0xf00000000ULL) == 0x200000000ULL) ? 1 : 0)
#define is_vcpu_pram(x) ((((x & 0xf00000000ULL) == 0x600000000ULL) || ((x & 0xf00000000ULL) == 0ULL)) ? 1 : 0)
#define get_processor(x) (is_ippu_pram(x) ? IPPU : (is_vcpu_pram(x) ? VCPU : NONE))
#define get_instr_size_for_proc(x) ((x == VCPU) ? 8 : 4)

// JSR detection parameters
#define get_jsr_bits(x) ((x == bfd_mach_vspa1) ? (0x00C00000000000ULL) : (0x4200000000000000ULL))
#define get_jmp_bits(x) ((x == bfd_mach_vspa1) ? (0x00D00000000000ULL) : (0x4240000000000000ULL))
#define get_jsr_mask(x) ((x == bfd_mach_vspa1) ? (0xFFF00000000000ULL) : (0xEFC0000000000000ULL))
#define is_jsr(x, y) ((y & get_jsr_mask(x)) == get_jsr_bits(x))
#define is_jmp(x, y) ((y & get_jsr_mask(x)) == get_jmp_bits(x))
#define get_jsr_target_addr(x, y) ((x == bfd_mach_vspa1) ? ((y & 0x00001FFFF00000ULL) >> 20) : ((y & 0x0001FFFFFF000000ULL) >> 24))

/* Print the VSPA instruction at address addr in debugged memory,
   on info->stream. Return length of the instruction, in bytes.  */
int
print_insn_vspa (bfd_vma addr, disassemble_info *info)
{
    bfd_byte instrbytes[8];
    int instr_length, instr_word;
    char instr_str[256];
    struct SYMTABLE symtable[] = {{"", 0}};
    int flags, status;
    unsigned int num_symbols = 0;
    int processor = get_processor(addr);

    instr_length =  get_instr_size_for_proc(processor);
    // read memory at location
    if (processor == VCPU)
    	status = (*info->read_memory_func) ((addr - addr % 2), instrbytes, instr_length, info);
    else
    	status = (*info->read_memory_func) (addr , instrbytes, instr_length, info);
    if (status != 0)
    {
      (*info->memory_error_func) (status, addr, info);
      return -1;
    }
    
    // get the bits
    bfd_vma data;
    data = bfd_get_bits (instrbytes, instr_length * 8, info->display_endian == BFD_ENDIAN_BIG);
    flags=DECODE_TYPE_NO_FLAG_PRINT;
    // decode the bits based on the processor: vcpu or ippu
    switch (processor)
    {
    case VCPU:
    {
        int hasSingleInstruction = !(data & get_mask_half_word(info->mach));
        int isNull = ((data & get_mask_null(info->mach)) == get_opcode_null(info->mach));
        int isHalfWord = !hasSingleInstruction && !isNull;
        unsigned char family = 0x0;
        unsigned int au_count = 16;
        instr_word = 2;
        if (isHalfWord)
        {
            if (addr % 2)
                flags |= DECODE_TYPE_UPPER_OPS;
            else
                flags |= DECODE_TYPE_LOWER_OPS;

            instr_word = 1;
        }

        if (!hasSingleInstruction && isNull)
            flags |= DECODE_TYPE_LOWER_OPS;

        switch(info->mach)
        {
        case bfd_mach_vspa1:
        	status = disassemble_instruction_vcpu(data, instr_str, 256, flags, symtable, num_symbols, &family, &au_count);
        	break;
        case bfd_mach_vspa2:
        	status = disassemble_instruction_vcpu2(data, instr_str, 256, flags, symtable, num_symbols, &family, &au_count);
        	break;
#ifdef _VSPA3_
        case bfd_mach_vspa3:
        	status = disassemble_instruction_vcpu3(data, instr_str, 256, flags, symtable, num_symbols, &family, &au_count);
        	break;
#endif
        }

        // check for jsr
        if (is_jsr(info->mach, data))
        {
            info->insn_type = dis_jsr;
            info->target = get_jsr_target_addr(info->mach, data);
        }
        else
        {
            if (is_jmp(info->mach, data))
            {
                info->insn_type = dis_branch;
                info->target = get_jsr_target_addr(info->mach, data);
            }
        }
        break;
    }
    case IPPU:
    {
    	instr_word = 1;
    	switch(info->mach)
    	{
    	case bfd_mach_vspa1:
    		status = disassemble_instruction_ippu(data, instr_str, 256, symtable, num_symbols);
    		break;

    	case bfd_mach_vspa2:
    	    status = disassemble_instruction_ippu2(data, instr_str, 256, symtable, num_symbols);
    	    break;
#ifdef _VSPA3_
    	case bfd_mach_vspa3:
    	    status = disassemble_instruction_ippu3(data, instr_str, 256, symtable, num_symbols);
    	    break;
#endif
    	}
        break;
    }
    default:
        instr_word = 2; // print the opcode with VCPU PCs
        status = 1; // the library returns 1 for fail
        break;
    }

    if (status == 0)
        (*info->fprintf_func) (info->stream, "%s", instr_str);
    else
        (*info->fprintf_func) (info->stream, ".word\t0x%08lx", data);

   return instr_word;
}

