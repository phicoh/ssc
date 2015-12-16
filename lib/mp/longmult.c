/*
 * This is version 1.1 of CryptoLib
 *
 * The authors of this software are Jack Lacy, Don Mitchell and Matt Blaze
 *              Copyright (c) 1991, 1992, 1993, 1994, 1995 by AT&T.
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * NOTE:
 * Some of the algorithms in cryptolib may be covered by patents.
 * It is the responsibility of the user to ensure that any required
 * licenses are obtained.
 *
 *
 * SOME PARTS OF CRYPTOLIB MAY BE RESTRICTED UNDER UNITED STATES EXPORT
 * REGULATIONS.
 *
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHORS NOR AT&T MAKE ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */

/*
 *      32 bit by 32 bit multiplication primitives.
 *      Jack Lacy
 *      Copyright (c) 1993 AT&T Bell Laboratories
 *	For several architectures, the routines in this file are encoded in assembly
 *	language as (ARCH)_longmult.s or, for windows and NT as LMULT32.asm.
 *	To take advantage of 32x32 bit mult instructions, if your arch is not covered
 *	here, you should consider writing these functions in assembly, and if
 *	you're willing, pass them along to other users of CryptoLib.
 */
#include "longlong.h"
#include <stdint.h>

typedef uint32_t Ulong;

#ifdef MSVC20

__inline static Ulong umul32(Ulong *hi, Ulong a, Ulong b)
{
	_asm {
		push ebx
		mov eax, a
		mov edx, b
		mov ebx, hi
		mul edx
		mov [ebx], edx
		pop ebx
	}
}

#endif

#ifdef MSVC20
#define mul32(a, b, c, d) b = umul32(&a, c, d)
#else
#define mul32(a, b, c, d) umul_ppmm(a, b, c, d)
#endif

#define LONGMULSTEP(i,dst,src) {{ \
 mul32(sumh, suml, m, (src)[(i)]); \
 add32(sumh, suml, 0, carry, sumh, suml); \
 add32(carry, (dst)[(i)], sumh, suml, 0, (dst)[(i)]); \
}}

#define add32(sh, sl, ah, al, bh, bl) {{ \
 Ulong __c; \
 __c = (al) + (bl); \
 (sh) = (ah) + (bh) + (__c < (al)); \
 (sl) = __c; \
}}

#define LO(x) ((Ushort) (x))
#define HI(x) ((x) >> 16)
#define UHI(x) (((Ulong) (x)) >> 16)


#ifdef K_AND_R
Ulong
LMULT(dst, m, src, N)
  Ulong *dst, m, *src;
  int N;
#else
Ulong
LMULT(Ulong *dst,
      Ulong m,
      Ulong *src,
      int N)
#endif
{
	Ulong sumh, suml;
	Ulong carry, *ap, *cp, mm;
	int i;
	
	ap = src;
	cp = dst;
	mm = m;
	
	carry = 0;
	for (i=0; i<N; i++) {
		mul32(sumh, suml, mm, ap[i]);
		
		suml += carry;
		sumh += (suml < carry);
		
		cp[i] += suml;
		carry = sumh + (cp[i] < suml);
#if 0
printf("LMULT: mm 0x%x, ap[%d] 0x%x -> sumh 0x%x, suml 0x%x, cp[%d] 0x%x, carry %d\n",
	mm, i, ap[i], sumh, suml, i, cp[i], carry);
#endif
		
	}
	
	return carry;
	
}


#define SQRSTEP() {{ \
 sum = (Ulong)m*(Ulong)m; \
 cp[0] = (Ushort)sum; \
 cp[1] = (Ushort)(sum >> 16); \
}}

#ifdef K_AND_R
void
BUILDDIAG(dst, src, N)
  Ulong *dst, *src;
  int N;
#else
void
BUILDDIAG(Ulong *dst,
	  Ulong *src,
	  int N)
#endif
{
	Ulong *ap, *cp, m;
	int i;
	
	ap = src;
	cp = dst;
	
	i = 0;
	do {
		m = ap[i];
		mul32(cp[1], cp[0], m, m);
		cp += 2;
	} while (++i < N);
	
}


#ifdef K_AND_R
void
SQUAREINNERLOOP(dst, m, src, start, end)
  Ulong *dst, m, *src;
  int start, end;
#else
void
SQUAREINNERLOOP(Ulong *dst,
		Ulong m,
		Ulong *src,
		int start,
		int end)
#endif
{
	Ulong *ap, *cp;
	int j;
	Ulong prodhi, prodlo;
	Ulong sumh, suml, carry;
	
	cp = dst;
	ap = src;
	carry = 0;
	j = start;
	
	do {
		mul32(prodhi, prodlo, m, ap[j]);
		
		add32(sumh, suml, 0, prodlo, 0, prodlo);
		add32(carry, cp[0], sumh, suml, carry, cp[0]);
		
		add32(sumh, suml, 0, prodhi, 0, prodhi);
		add32(sumh, suml, sumh, suml, 0, cp[1]);
		add32(carry, cp[1], sumh, suml, 0, carry);
		cp++;
	} while (++j<end);
	cp++;
	
	while ((carry != 0) && (j<2*end)) {
		add32(carry, cp[0], 0, cp[0], 0, carry);
		cp++;
		j++;
	}
}



