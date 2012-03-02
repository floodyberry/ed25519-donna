/*
	Public domain by Andrew M. <liquidsun@gmail.com>
	Modified from the amd64-51-30k implementation by
		Daniel J. Bernstein
		Niels Duif
		Tanja Lange
		Peter Schwabe
		Bo-Yin Yang
*/


#include "ed25519-donna-portable.h"

#if defined(ED25519_SSE2)
#include "curve25519-donna-sse2.h"
#elif defined(CPU_64BITS)
#include "curve25519-donna-64bit.h"
#else
#include "curve25519-donna-32bit.h"
#endif

#include "curve25519-donna-helpers.h"

#if defined(CPU_64BITS)
#include "modm-donna-64bit.h"
#else
#include "modm-donna-32bit.h"
#endif

typedef unsigned char hash_512bits[64];

/*
	Timing safe memory compare
*/
static int
ed25519_verify(const unsigned char *x, const unsigned char *y, size_t len) {
	size_t differentbits = 0;
	while (len--)
		differentbits |= (*x++ ^ *y++);
	return (1 & ((differentbits - 1) >> 8));
}


/*
 * Arithmetic on the twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2
 * with d = -(121665/121666) = 37095705934669439343138083508754565189542113879843219016388785533085940283555
 * Base point: (15112221349535400772501151409588531511454012693041857206046113283949847762202,46316835694926478169428394003475163141307993866256225615783033603165251855960);
 */
 
typedef struct ge25519_t {
	MM16 bignum25519 x, y, z, t;
} ge25519;

typedef struct ge25519_p1p1_t {
	MM16 bignum25519 x, z, y, t;
} ge25519_p1p1;

typedef struct ge25519_niels_t {
	MM16 bignum25519 ysubx, xaddy, t2d;
} ge25519_niels;

typedef struct ge25519_pniels_t {
	MM16 bignum25519 ysubx, xaddy, z, t2d;
} ge25519_pniels;

#if defined(ED25519_64BIT_TABLES)
#include "ed25519-donna-64bit-tables.h"
#else
#include "ed25519-donna-32bit-tables.h"
#endif

static void DONNA_INLINE
ge25519_p1p1_to_partial(ge25519 *r, const ge25519_p1p1 *p) {
	curve25519_mul(r->x, p->x, p->t);
	curve25519_mul(r->y, p->y, p->z);
	curve25519_mul(r->z, p->z, p->t); 
}

static void DONNA_INLINE
ge25519_p1p1_to_full(ge25519 *r, const ge25519_p1p1 *p) {
	curve25519_mul(r->x, p->x, p->t);
	curve25519_mul(r->y, p->y, p->z);
	curve25519_mul(r->z, p->z, p->t); 
	curve25519_mul(r->t, p->x, p->y); 
}

static void DONNA_INLINE
ge25519_double_p1p1(ge25519_p1p1 *r, const ge25519 *p) {
	MM16 bignum25519 a,b,c,d;

	curve25519_square_times(a, p->x, 1);
	curve25519_square_times(b, p->y, 1);
	curve25519_square_times(c, p->z, 1);
	curve25519_add_reduce(c, c);
	curve25519_neg(d, a);

	/* E */
	curve25519_copy(r->x, p->x);
	curve25519_add(r->x, p->y);
	curve25519_square_times(r->x, r->x, 1);
	curve25519_subtract_reduce(r->x, a);
	curve25519_subtract(r->x, b);

	/* H */
	curve25519_copy(r->y, d);
	curve25519_subtract(r->y, b);

	/* G */
	curve25519_copy(r->z, d);
	curve25519_add_reduce(r->z, b);

	/* F */
	curve25519_copy(r->t, r->z);
	curve25519_subtract(r->t, c);
}

static void DONNA_INLINE
ge25519_p1p1_to_pniels(ge25519_pniels *r, const ge25519_p1p1 *p) {
	MM16 bignum25519 x;

	curve25519_mul(r->xaddy, p->x, p->t);
	curve25519_mul(r->ysubx, p->y, p->z);
	curve25519_mul(r->z, p->z, p->t); 
	curve25519_mul(r->t2d, p->x, p->y);

	curve25519_copy(x, r->xaddy);
	curve25519_add(r->xaddy, r->ysubx);
	curve25519_subtract(r->ysubx, x);
	curve25519_mul(r->t2d, r->t2d, ge25519_ec2d);	
}

static void
ge25519_pnielsadd_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_pniels *q) {
	MM16 bignum25519 a,b,c;

	curve25519_copy(a, p->y);
	curve25519_copy(b, a);
	curve25519_subtract(a, p->x);
	curve25519_add(b, p->x);
	curve25519_mul(a, a, q->ysubx);
	curve25519_mul(r->x, b, q->xaddy);
	curve25519_copy(r->y, r->x);
	curve25519_add(r->y, a);
	curve25519_subtract(r->x, a);
	curve25519_mul(c, p->t, q->t2d);
	curve25519_mul(r->t, p->z, q->z);
	curve25519_add_reduce(r->t, r->t);
	curve25519_copy(r->z, r->t);
	curve25519_subtract(r->t, c);
	curve25519_add(r->z, c);
}
static void DONNA_INLINE
ge25519_pnielsadd(ge25519_pniels *r, const ge25519 *p, const ge25519_pniels *q) {
	ge25519_p1p1 p1p1;
	ge25519_pnielsadd_p1p1(&p1p1, p, q);
	ge25519_p1p1_to_pniels(r, &p1p1);
}

static void
ge25519_nielsadd2_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_niels *q) {
	MM16 bignum25519 a,b,c;

	curve25519_copy(a, p->y);
	curve25519_copy(b, a);
	curve25519_subtract(a, p->x);
	curve25519_add(b, p->x);
	curve25519_mul(a, a, q->ysubx);
	curve25519_mul(r->x, b, q->xaddy);
	curve25519_copy(r->y, r->x);
	curve25519_add(r->y, a);
	curve25519_subtract(r->x, a);
	curve25519_mul(c, p->t, q->t2d);
	curve25519_copy(r->t, p->z);
	curve25519_add_reduce(r->t, r->t);
	curve25519_copy(r->z, r->t);
	curve25519_add(r->z, c);
	curve25519_subtract(r->t, c);
}

static void
ge25519_double(ge25519 *r, const ge25519 *p) {
	ge25519_p1p1 t;
	ge25519_double_p1p1(&t, p);
	ge25519_p1p1_to_full(r, &t);
}

static void
ge25519_double_partial(ge25519 *r, const ge25519 *p) {
	ge25519_p1p1 t;
	ge25519_double_p1p1(&t, p);
	ge25519_p1p1_to_partial(r, &t);
}

static void
ge25519_nielsadd2(ge25519 *r, const ge25519_niels *q) {
	MM16 bignum25519 a,b,c,e,f,g,h;

	curve25519_copy(a, r->y);
	curve25519_copy(b, a);
	curve25519_subtract(a, r->x);
	curve25519_add(b, r->x);
	curve25519_mul(a, a, q->ysubx);
	curve25519_mul(e, b, q->xaddy);
	curve25519_copy(h, e);
	curve25519_add(h, a);
	curve25519_subtract(e, a);
	curve25519_mul(c, r->t, q->t2d);
	curve25519_copy(f, r->z);
	curve25519_add_reduce(f, f);
	curve25519_copy(g, f);
	curve25519_add(g, c);
	curve25519_subtract(f, c);
	curve25519_mul(r->x, e, f);
	curve25519_mul(r->y, h, g);
	curve25519_mul(r->z, g, f);
	curve25519_mul(r->t, e, h);
}

/* return 1 on success, 0 otherwise */
static int 
ge25519_unpack_negative_vartime(ge25519 *r, const unsigned char p[32]) {
	static const MM16 bignum25519 one = {1};
	unsigned char parity = p[31] >> 7;
	unsigned char numerator[32], verify[32];
	MM16 bignum25519 t, num, den, d2, d4, d6;
	int valid;

	curve25519_copy(r->z, one);
	curve25519_expand(r->y, p);
	curve25519_square_times(num, r->y, 1); /* x = y^2 */
	curve25519_mul(den, num, ge25519_ecd); /* den = dy^2 */
	curve25519_subtract_reduce(num, r->z); /* x = y^1 - 1 */
	curve25519_add(den, r->z); /* den = dy^2 + 1 */
	curve25519_contract(numerator, num);

	/* Computation of sqrt(num/den) */
	/* 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8) */

	curve25519_square_times(d2, den, 1);
	curve25519_square_times(d4, d2, 1);
	curve25519_mul(d6, d4, d2);
	curve25519_mul(t, d6, num);
	curve25519_mul(t, t, den);
	curve25519_pow_two252m3(t, t);

	/* 2. computation of r->x = t * num * den^3 */
	curve25519_mul(t, t, num);
	curve25519_mul(t, t, den);
	curve25519_mul(t, t, den);
	curve25519_mul(r->x, t, den);
	
	/* 3. Check whether sqrt computation gave correct result, multiply by sqrt(-1) if not: */
	curve25519_square_times(t, r->x, 1);
	curve25519_mul(t, t, den);
	curve25519_contract(verify, t);
	curve25519_copy(t, ge25519_sqrtneg1);
	curve25519_move_conditional(t, one, ed25519_verify(numerator, verify, 32));
	curve25519_mul(r->x, r->x, t);

	/* 4. Now we have one of the two square roots, except if input was not a square */
	curve25519_square_times(t, r->x, 1);
	curve25519_mul(t, t, den);
	curve25519_contract(verify, t);
	valid = ed25519_verify(numerator, verify, 32);

	/* 5. Choose the desired square root according to parity: */
	curve25519_contract(verify, r->x);
	memset(t, 0, sizeof(bignum25519));
	curve25519_swap_conditional(r->x, t, ((verify[0] ^ parity) & 1) ^ 1);
	curve25519_subtract_reduce(r->x, t);
	curve25519_mul(r->t, r->x, r->y);
	
	return valid;
}

static void 
ge25519_pack(unsigned char r[32], const ge25519 *p) {
	MM16 bignum25519 tx, ty, zi;
	unsigned char parity[32];
	curve25519_recip(zi, p->z);
	curve25519_mul(tx, p->x, zi);
	curve25519_mul(ty, p->y, zi);
	curve25519_contract(r, ty);
	curve25519_contract(parity, tx);
	r[31] ^= ((parity[0] & 1) << 7);
}

#define S1_SWINDOWSIZE 6
#define PRE1_SIZE (1<<(S1_SWINDOWSIZE-2))
#define S2_SWINDOWSIZE 7
#define PRE2_SIZE (1<<(S2_SWINDOWSIZE-2))

/* computes [s1]p1 + [s2]basepoint */
static void 
ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const bignum256modm s2) {
	signed char slide1[256], slide2[256];
	ge25519_pniels pre1[PRE1_SIZE], neg;
	ge25519 d1;
	ge25519_niels niels_neg;
	const ge25519_niels *np;
	const ge25519_pniels *p;
	ge25519_p1p1 t;	
	int32_t i;

	contract256_slidingwindow_modm(slide1, s1, S1_SWINDOWSIZE);
	contract256_slidingwindow_modm(slide2, s2, S2_SWINDOWSIZE);

	ge25519_double(&d1, p1);
	
	/* convert p1 to projective Niels representation */
	curve25519_copy(pre1[0].ysubx, p1->y);
	curve25519_subtract(pre1[0].ysubx, p1->x);
	curve25519_copy(pre1[0].xaddy, p1->x);
	curve25519_add(pre1[0].xaddy, p1->y);
	curve25519_copy(pre1[0].z, p1->z);
	curve25519_mul(pre1[0].t2d, p1->t, ge25519_ec2d);
	for (i = 0; i < PRE1_SIZE - 1; i++)
		ge25519_pnielsadd(&pre1[i+1], &d1, &pre1[i]);

	/* set neutral */
	memset(r, 0, sizeof(ge25519));
	r->y[0] = 1;
	r->z[0] = 1;

	i = 255;
	while ((i >= 0) && !(slide1[i] | slide2[i]))
		i--;

	for (; i >= 0; i--) {
		ge25519_double_p1p1(&t, r);
		if (slide1[i] > 0) {
			ge25519_p1p1_to_full(r, &t);
			ge25519_pnielsadd_p1p1(&t, r, &pre1[slide1[i] / 2]);
		} else if (slide1[i] < 0) {
			ge25519_p1p1_to_full(r, &t);
			p = &pre1[-slide1[i] / 2];
			curve25519_copy(neg.ysubx, p->xaddy);
			curve25519_copy(neg.xaddy, p->ysubx);
			curve25519_copy(neg.z, p->z);
			curve25519_neg(neg.t2d, p->t2d);
			ge25519_pnielsadd_p1p1(&t, r, &neg);
		}

		if (slide2[i] > 0) {
			ge25519_p1p1_to_full(r, &t);
			ge25519_nielsadd2_p1p1(&t, r, &ge25519_niels_sliding_multiples[slide2[i] / 2]);
		} else if (slide2[i] < 0) {
			ge25519_p1p1_to_full(r, &t);
			np = &ge25519_niels_sliding_multiples[-slide2[i] / 2];
			curve25519_copy(niels_neg.ysubx, np->xaddy);
			curve25519_copy(niels_neg.xaddy, np->ysubx);
			curve25519_neg(niels_neg.t2d, np->t2d);
			ge25519_nielsadd2_p1p1(&t, r, &niels_neg);
		}

		ge25519_p1p1_to_partial(r, &t);
	}
}



static uint32_t
ge25519_windowb_equal(uint32_t b, uint32_t c) {
	return ((b ^ c) - 1) >> 31;
}

static void DONNA_INLINE
ge25519_move_conditional_niels(ge25519_niels *a, const ge25519_niels *b, uint32_t flag) {
	curve25519_move_conditional(a->ysubx, b->ysubx, flag);
	curve25519_move_conditional(a->xaddy, b->xaddy, flag);
	curve25519_move_conditional(a->t2d, b->t2d, flag);
}

static void
ge25519_scalarmult_base_choose_niels(ge25519_niels *t, uint32_t pos, signed char b) {
	bignum25519 neg;
	uint32_t sign = (uint32_t)((unsigned char)b >> 7);
	uint32_t mask = ~(sign - 1);
	uint32_t u = (b + mask) ^ mask;
	uint32_t i;
	memset(t, 0, sizeof(ge25519_niels));
	t->xaddy[0] = 1;
	t->ysubx[0] = 1;

	for (i = 0; i < 8; i++)
		ge25519_move_conditional_niels(t, &ge25519_niels_base_multiples[(pos*8) + i], ge25519_windowb_equal(u, i + 1));

	curve25519_swap_conditional(t->ysubx, t->xaddy, sign);	
	curve25519_neg(neg, t->t2d);
	curve25519_move_conditional(t->t2d, neg, sign);
}


/* computes [s]basepoint */
static void
ge25519_scalarmult_base_niels(ge25519 *r, const bignum256modm s) {
	signed char b[64];
	uint32_t i;
	ge25519_niels t;

	contract256_window4_modm(b, s);
	
	ge25519_scalarmult_base_choose_niels(&t, 0, b[1]);
	curve25519_copy(r->x, t.xaddy);
	curve25519_copy(r->y, t.xaddy);
	curve25519_subtract_reduce(r->x, t.ysubx);	
	curve25519_add_reduce(r->y, t.ysubx);
	memset(r->z, 0, sizeof(bignum25519));
	r->z[0] = 2;
	curve25519_copy(r->t, t.t2d);
	for (i = 3; i < 64; i += 2) {
		ge25519_scalarmult_base_choose_niels(&t, i / 2, b[i]);
		ge25519_nielsadd2(r, &t);
	}
	ge25519_double_partial(r, r);
	ge25519_double_partial(r, r);
	ge25519_double_partial(r, r);
	ge25519_double(r, r);
	ge25519_scalarmult_base_choose_niels(&t, 0, b[0]);
	curve25519_mul(t.t2d, t.t2d, ge25519_ecd);
	ge25519_nielsadd2(r, &t);
	for(i = 2; i < 64; i += 2) {
		ge25519_scalarmult_base_choose_niels(&t, i / 2, b[i]);
		ge25519_nielsadd2(r, &t);
	}
}

