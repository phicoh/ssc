#define __ll_B 0x10000
#define __ll_lowpart(t) ((Ulong) (t) & 0xFFFF)
#define __ll_highpart(t) ((Ulong) (t) >> 16)

/* Define 32 bit multiplication asm macros (useful only with gnu-cc).

   umul_ppmm(high_prod, low_prod, multiplier, multiplicand)
   multiplies two unsigned long integers multiplier and multiplicand,
   and generates a two unsigned word product in high_prod and
   low_prod.

*/

/* The CPUs come in alphabetical order below.

   Please add support for more CPUs here, or improve the current support
   for the CPUs below!
   (E.g. WE32100, HP-PA (xmpyu?), i960, IBM360.)  */

#if defined (__GNUC__) && !defined (NO_ASM)

#if defined (__a29k__) || defined (___AM29K__)
#define umul_ppmm(xh, xl, m0, m1) \
  do {									\
    Ulong __m0 = (m0), __m1 = (m1);				\
    __asm__ ("multiplu %0,%1,%2" : "=r" ((Ulong)(xl))	\
	     : "r" (__m0), "r" (__m1));					\
    __asm__ ("multmu %0,%1,%2" : "=r" ((Ulong)(xh))		\
	     : "r" (__m0), "r" (__m1));					\
  } while (0)
#endif /* __a29k__ */

#if defined (__gmicro__)
#define umul_ppmm(ph, pl, m0, m1) \
  __asm__ ("mulx %3,%0,%1"						\
	: "=g" ((Ulong)(ph)), "=r" ((Ulong)(pl))\
	: "%0" ((Ulong)(m0)), "g" ((Ulong)(m1)))
#endif

#if defined (__i386__) || defined (__i486__)
#define umul_ppmm(w1, w0, u, v) \
  __asm__ ("mull %3"							\
	: "=a" ((unsigned int)(w0)), "=d" ((unsigned int)(w1))\
	: "%0" ((unsigned int)(u)), "rm" ((unsigned int)(v)))
#endif /* __i386__ */

#if defined (___IBMR2__) /* IBM RS6000 */
#define umul_ppmm(xh, xl, m0, m1) \
  do {									\
    Ulong __m0 = (m0), __m1 = (m1);				\
    __asm__ ("mul %0,%2,%3"						\
	: "=r" ((Ulong)(xh)), "=q" ((Ulong)(xl))\
	: "r" (__m0), "r" (__m1));					\
    (xh) += ((((signed long int) __m0 >> 31) & __m1)			\
	     + (((signed long int) __m1 >> 31) & __m0));		\
  } while (0)
#endif /* ___IBMR2__ */

#if defined (__ns32000__)
#define __umulsidi3(u, v) \
  ({long long int __w;							\
      __asm__ ("meid %2,%0" : "=g" (__w)				\
	: "%0" ((Ulong)(u)), "g" ((Ulong)(v)));	\
      __w; })
#endif /* __ns32000__ */

#if defined (__vax__)
#define umul_ppmm(xh, xl, m0, m1) \
  do {									\
    union {long long int ll;struct {unsigned long int l, h;} i;} __xx;	\
    unsigned long int __m0 = (m0), __m1 = (m1);				\
    __asm__ ("emul %1,%2,$0,%0"						\
	 : "=r" (__xx.ll) : "g" (__m0), "g" (__m1));			\
    (xh) = __xx.i.h; (xl) = __xx.i.l;					\
    (xh) += ((((signed long int) __m0 >> 31) & __m1)			\
	     + (((signed long int) __m1 >> 31) & __m0));		\
  } while (0)
#endif /* __vax__ */

#endif /* __GNUC__ */

/* If this machine has no inline assembler, use C macros.  */

#if !defined (umul_ppmm)
#if !defined (NO_KARAT)
/* Lacy implementation of Karatsuba 32x32 bit mult 5/26/93 */
#define umul_ppmm(ph, pl, a, b)						\
    do {								\
        Ulong __pmidh, __pmidl;					\
        Ulong __ahi, __bhi, __alo, __blo;			\
	long __carry;							\
									\
	__ahi = ((a) >> 16);						\
	__alo = (a) & 0xFFFF;						\
	__bhi = ((b) >> 16);						\
	__blo = (b) & 0xFFFF;						\
									\
	(ph) = __ahi * __bhi;						\
	(pl) = __alo * __blo;						\
	__ahi -= __alo;							\
	__blo -= __bhi;							\
	__pmidh = __ahi * __blo;					\
	__carry = (__pmidh)?-((__ahi ^ __blo) & 0x10000):0;		\
									\
	__pmidh += (ph);						\
	__carry += (__pmidh < (ph))?0x10000:0;				\
	__pmidh += (pl);						\
	__carry += (__pmidh < (pl))?0x10000:0;				\
	__pmidl = __pmidh << 16;					\
	__pmidh >>= 16;							\
									\
	(pl) += __pmidl;						\
	__carry += ((pl) < __pmidl);					\
									\
	(ph) += __carry + __pmidh;					\
    } while (0)

#else
#define umul_ppmm(w1, w0, u, v)					\
  do {									\
    Ulong __x0, __x1, __x2, __x3;				\
    unsigned int __ul, __vl, __uh, __vh;				\
									\
    __ul = __ll_lowpart (u);						\
    __uh = __ll_highpart (u);						\
    __vl = __ll_lowpart (v);						\
    __vh = __ll_highpart (v);						\
									\
    __x0 = (Ulong) __ul * __vl;				\
    __x1 = (Ulong) __ul * __vh;				\
    __x2 = (Ulong) __uh * __vl;				\
    __x3 = (Ulong) __uh * __vh;				\
									\
    __x1 += __ll_highpart (__x0);/* this can't give carry */		\
    __x1 += __x2;		/* but this indeed can */		\
    if (__x1 < __x2)		/* did we get it? */			\
      __x3 += __ll_B;		/* yes, add it in the proper pos. */	\
									\
    (w1) = __x3 + __ll_highpart (__x1);					\
    (w0) = __ll_lowpart (__x1) * __ll_B + __ll_lowpart (__x0);		\
  } while (0)
#endif
#endif

#if !defined (__umulsidi3)
#define __umulsidi3(u, v) \
  ({long_long __w;							\
    umul_ppmm (__w.s.high, __w.s.low, u, v);				\
    __w.ll; })
#endif

