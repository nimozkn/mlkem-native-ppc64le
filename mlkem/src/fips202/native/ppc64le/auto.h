/*
 * Copyright (c) The mlkem-native project authors
 * SPDX-License-Identifier: Apache-2.0 OR ISC OR MIT
 */

#ifndef MLK_FIPS202_NATIVE_PPC64LE_AUTO_H
#define MLK_FIPS202_NATIVE_PPC64LE_AUTO_H

/* Default FIPS202 assembly profile for PPC64LE systems */

/*
 * Keccak-f1600x4 for PowerPC 64-bit Little Endian
 *
 * This implementation uses AltiVec/VSX SIMD instructions to process
 * 4 Keccak states in parallel (implemented as 2x2 using vector operations).
 *
 * Requirements:
 * - POWER8 or later (for VSX/AltiVec support)
 * - Little-endian mode (ppc64le)
 *
 * The implementation is enabled when:
 * - __powerpc64__ is defined (64-bit PowerPC)
 * - __LITTLE_ENDIAN__ is defined (little-endian mode)
 * - __ALTIVEC__ is defined (AltiVec/VSX support)
 */

#if defined(powerpc64) && defined(LITTLE_ENDIAN) && defined(ALTIVEC)
#define MLK_FIPS202_PPC64LE
#endif

#if defined(MLK_FIPS202_PPC64LE)
#include "x4_ppc64le.h"
#endif

#endif /* !MLK_FIPS202_NATIVE_PPC64LE_AUTO_H */
