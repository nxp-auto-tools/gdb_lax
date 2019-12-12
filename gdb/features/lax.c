/* THIS FILE IS GENERATED.  -*- buffer-read-only: t -*- vi:set ro:
  Original: vspa2.xml */

#include "defs.h"
#include "osabi.h"
#include "target-descriptions.h"

struct target_desc *tdesc_vspa3;
static void
initialize_tdesc_vspa3 (void)
{
  struct target_desc *result = allocate_target_description ();
  struct tdesc_feature *feature;

  set_tdesc_architecture (result, bfd_scan_arch ("lax"));

  feature = tdesc_create_feature (result, "lax-core-regs");
  tdesc_create_reg (feature, "g0", 0, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "g1", 1, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "g2", 2, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "g3", 3, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "g4", 4, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "g5", 5, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "g6", 6, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "g7", 7, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "g8", 8, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "g9", 9, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "g10", 10, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "g11", 11, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a4", 12, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a5", 13, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a6", 14, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a7", 15, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a8", 16, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a9", 17, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a10", 18, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a11", 19, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a12", 20, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a13", 21, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a14", 22, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a15", 23, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a16", 24, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a17", 25, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a18", 26, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a19", 27, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a0", 28, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a1", 29, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a2", 30, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "a3", 31, 1, NULL, 32, "uint32");
  tdesc_create_reg (feature, "sp", 32, 1, NULL, 32, "data_ptr");
  tdesc_create_reg (feature, "pc", 33, 1, NULL, 32, "code_ptr");
  tdesc_create_reg (feature, "ras_depth", 34, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras1", 35, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras2", 36, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras3", 37, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras4", 38, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras5", 39, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras6", 40, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras7", 41, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras8", 42, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras9", 43, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras10", 44, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras11", 45, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras12", 46, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras13", 47, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras14", 48, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras15", 49, 1, NULL, 32, "int");
  tdesc_create_reg (feature, "ras16", 50, 1, NULL, 32, "int");
  tdesc_vspa3 = result;
}
