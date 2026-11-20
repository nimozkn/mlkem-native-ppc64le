/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#ifndef MLK_FIPS202_NATIVE_PPC64LE_X4_PPC64LE_H
#define MLK_FIPS202_NATIVE_PPC64LE_X4_PPC64LE_H

/* Part of backend API */
#define MLK_USE_NATIVE_FIPS202_X4

#if !defined(__ASSEMBLER__)
#include "../api.h"
#include "src/keccakf1600_ppc64le.h"

MLK_MUST_CHECK_RETURN_VALUE
static MLK_INLINE int mlk_keccak_f1600_x4_native(uint64_t *state)
{
  mlk_keccakf1600x4_permute_ppc64le(state);
  return MLK_NATIVE_FUNC_SUCCESS;
}
#endif /* !__ASSEMBLER__ */

#endif /* !MLK_FIPS202_NATIVE_PPC64LE_X4_PPC64LE_H */
