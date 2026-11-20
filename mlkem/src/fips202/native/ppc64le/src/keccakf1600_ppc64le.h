/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#ifndef MLK_FIPS202_NATIVE_PPC64LE_SRC_KECCAKF1600_PPC64LE_H
#define MLK_FIPS202_NATIVE_PPC64LE_SRC_KECCAKF1600_PPC64LE_H

#include "../../../../common.h"

#define mlk_keccakf1600x4_permute_ppc64le \
  MLK_NAMESPACE_K(keccakf1600x4_permute_ppc64le)
void mlk_keccakf1600x4_permute_ppc64le(uint64_t *states);

#endif /* !MLK_FIPS202_NATIVE_PPC64LE_SRC_KECCAKF1600_PPC64LE_H */
