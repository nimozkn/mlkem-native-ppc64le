/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#include "../../../../common.h"

#if defined(MLK_FIPS202_PPC64LE) && !defined(MLK_CONFIG_MULTILEVEL_NO_SHARED)
#include "keccakf1600_ppc64le.h"
#include "macros.h"

/* MLK_STATE_SIZE = 25 lanes (each lane is 64 bits = 8 bytes) */

/************************************************************************************
 * MLK_NAMESPACE(keccakf1600x4_permute_ppc64le): Process 4 Keccak states in
 * parallel
 *
 * Strategy:
 *  -> Split 4 states into 2 pairs,
 *  -> process each pair using SIMD 2x function
 *
 * Input: Array of 4 consecutive Keccak states (4 × 25 × 8 bytes = 800 bytes)
 * steps:
 *   1. Split into pointers to each of the 4 states (st0, st1, st2, st3)
 *   2. Process first pair (st0, st1) in parallel using SIMD
 *   3. Process second pair (st2, st3) in parallel using SIMD
 *
 * NOTE: This achieves 4x throughput by doing 2 parallel operations on 2 states
 * each!!
 **************************************************************************************/
void mlk_keccakf1600x4_permute_ppc64le(uint64_t *states)
{
  uint64_t *st0, *st1, *st2, *st3;

  /* Point to each of the 4 states (each state is 25 uint64_t = 200 bytes) */
  st0 = states + MLK_STATE_SIZE * 0; /* State 0: bytes 0-199 */
  st1 = states + MLK_STATE_SIZE * 1; /* State 1: bytes 200-399 */
  st2 = states + MLK_STATE_SIZE * 2; /* State 2: bytes 400-599 */
  st3 = states + MLK_STATE_SIZE * 3; /* State 3: bytes 600-799 */

  /* process first pair in parallel */
  mlk_keccakf_1600_2x_ppc64le(st0, st1);

  /* process second pair in parallel */
  mlk_keccakf_1600_2x_ppc64le(st2, st3);
}

#else /* MLK_FIPS202_PPC64LE && !MLK_CONFIG_MULTILEVEL_NO_SHARED */

MLK_EMPTY_CU(fips202_ppc64le_keccakf1600)

#endif /* !(MLK_FIPS202_PPC64LE && !MLK_CONFIG_MULTILEVEL_NO_SHARED) */
