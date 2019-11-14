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

#ifndef VSPA_TDEP_H
#define VSPA_TDEP_H

extern struct target_desc *tdesc_vspa1;
extern struct target_desc *tdesc_vspa2;
extern struct target_desc *tdesc_vspa3;

/* Register numbers of various important registers.  */

enum vspa_regnum
{
  VSPA_G0_REGNUM = 0,
  VSPA_G1_REGNUM = 1,
  VSPA_G2_REGNUM = 2,
  VSPA_G3_REGNUM = 3,
  VSPA_G4_REGNUM = 4,
  VSPA_G5_REGNUM = 5,
  VSPA_G6_REGNUM = 6,
  VSPA_G7_REGNUM = 7,
  VSPA_G8_REGNUM = 8,
  VSPA_G9_REGNUM = 9,
  VSPA_G10_REGNUM = 10,
  VSPA_G11_REGNUM = 11,
  VSPA_A4_REGNUM = 12,
  VSPA_A5_REGNUM = 13,
  VSPA_A6_REGNUM = 14,
  VSPA_A7_REGNUM = 15,
  VSPA_A8_REGNUM = 16,
  VSPA_A9_REGNUM = 17,
  VSPA_A10_REGNUM = 18,
  VSPA_A11_REGNUM = 19,
  VSPA_A12_REGNUM = 20,
  VSPA_A13_REGNUM = 21,
  VSPA_A14_REGNUM = 22,
  VSPA_A15_REGNUM = 23,
  VSPA_A16_REGNUM = 24,
  VSPA_A17_REGNUM = 25,
  VSPA_A18_REGNUM = 26,
  VSPA_A19_REGNUM = 27,
  VSPA_A0_REGNUM = 28,
  VSPA_A1_REGNUM = 29,
  VSPA_A2_REGNUM = 30,
  VSPA_A3_REGNUM = 31,
  VSPA_SP_REGNUM = 32,
  VSPA_PC_REGNUM = 33,
  VSPA_RA_REGNUM = 33,
  VSPA_NUM_REGS = 33,
  VSPA_RAS_DEPTH_REGNUM = 34,
  VSPA_RAS1_REGNUM = 35
};

#endif /* vspa-tdep.h */
