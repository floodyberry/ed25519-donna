/*
	Public domain by Andrew M. <liquidsun@gmail.com>
	See: https://github.com/floodyberry/curve25519-donna

	SSE2 curve25519 implementation
*/

#include <emmintrin.h>
typedef __m128i xmmi;

/* 10 elements + an extra 2 to fit in 3 xmm registers */
typedef uint32_t bignum25519[12];

/* carry mask for 64 bit pairs */
const MM16 uint32_t curve25519mask2625_sse2[4] = {0x3ffffff,0,0x1ffffff,0};

/* mask off the top or bottom pairs */
const MM16 uint32_t curve25519topmask_sse2[4] = {0,0,0xffffffff,0xffffffff};
const MM16 uint32_t curve25519bottommask_sse2[4] = {0xffffffff,0xffffffff,0,0};

/* multipliers for reduction */
const MM16 uint32_t curve25519nineteen_sse2[4] = {19,0,19,0};
const MM16 uint32_t curve25519nineteen2x_sse2[4] = {19*2,0,19,0};

/* (2^255 - 19) = 0 mod p */
const MM16 uint32_t curve25519zeromodp0_sse2[4] = {0x7ffffda,0x3fffffe,0x7fffffe,0x3fffffe};
const MM16 uint32_t curve25519zeromodp1_sse2[4] = {0x7fffffe,0x3fffffe,0x7fffffe,0x3fffffe};
const MM16 uint32_t curve25519zeromodp2_sse2[4] = {0x7fffffe,0x3fffffe,0,0};

const MM16 bignum25519 curve25519one_sse2 = {1};
const MM16 bignum25519 curve25519offset_sse2 = {(1<<26)-19,(1<<25)-1,(1<<26)-1,(1<<25)-1,(1<<26)-1,(1<<25)-1,(1<<26)-1,(1<<25)-1,(1<<26)-1,(1<<25)-1};

/* Copy a bignum25519 to another: out = in */
static void DONNA_INLINE
curve25519_copy(bignum25519 out, const bignum25519 in) {
	xmmi x0,x1,x2;
	x0 = _mm_load_si128((xmmi*)in + 0);
	x1 = _mm_load_si128((xmmi*)in + 1);
	x2 = _mm_load_si128((xmmi*)in + 2);
	_mm_store_si128((xmmi*)out + 0, x0);
	_mm_store_si128((xmmi*)out + 1, x1);
	_mm_store_si128((xmmi*)out + 2, x2);
}

static void DONNA_INLINE
curve25519_move_conditional(bignum25519 out, const bignum25519 in, uint32_t flag) {
	xmmi a0,a1,a2,b0,b1,b2;
	const uint32_t nb = flag - 1;
	xmmi masknb = _mm_shuffle_epi32(_mm_cvtsi32_si128(nb),0);
	a0 = _mm_load_si128((xmmi *)in + 0);
	a1 = _mm_load_si128((xmmi *)in + 1);
	a2 = _mm_load_si128((xmmi *)in + 2);
	b0 = _mm_load_si128((xmmi *)out + 0);
	b1 = _mm_load_si128((xmmi *)out + 1);
	b2 = _mm_load_si128((xmmi *)out + 2);
	a0 = _mm_andnot_si128(masknb, a0);
	b0 = _mm_and_si128(masknb, b0);
	a1 = _mm_andnot_si128(masknb, a1);
	b1 = _mm_and_si128(masknb, b1);
	a2 = _mm_andnot_si128(masknb, a2);
	b2 = _mm_and_si128(masknb, b2);
	a0 = _mm_or_si128(a0, b0);
	a1 = _mm_or_si128(a1, b1);
	a2 = _mm_or_si128(a2, b2);
	_mm_store_si128((xmmi*)out + 0, a0);
	_mm_store_si128((xmmi*)out + 1, a1);
	_mm_store_si128((xmmi*)out + 2, a2);
}


/* Sum two numbers: out += in */
static void DONNA_INLINE
curve25519_add(bignum25519 out, const bignum25519 in) {
	xmmi a0,a1,a2,b0,b1,b2;
	a0 = _mm_load_si128((xmmi*)in + 0);
	a1 = _mm_load_si128((xmmi*)in + 1);
	a2 = _mm_load_si128((xmmi*)in + 2);
	b0 = _mm_load_si128((xmmi*)out + 0);
	b1 = _mm_load_si128((xmmi*)out + 1);
	b2 = _mm_load_si128((xmmi*)out + 2);
	a0 = _mm_add_epi32(a0, b0);
	a1 = _mm_add_epi32(a1, b1);
	a2 = _mm_add_epi32(a2, b2);
	_mm_store_si128((xmmi*)out + 0, a0);
	_mm_store_si128((xmmi*)out + 1, a1);
	_mm_store_si128((xmmi*)out + 2, a2);
}

static void DONNA_INLINE
curve25519_add_reduce(bignum25519 out, const bignum25519 in) {
	uint32_t c;
	out[0] += in[0]    ; c = (out[0] >> 26); out[0] &= 0x3ffffff;
	out[1] += in[1] + c; c = (out[1] >> 25); out[1] &= 0x1ffffff;
	out[2] += in[2] + c; c = (out[2] >> 26); out[2] &= 0x3ffffff;
	out[3] += in[3] + c; c = (out[3] >> 25); out[3] &= 0x1ffffff;
	out[4] += in[4] + c; c = (out[4] >> 26); out[4] &= 0x3ffffff;
	out[5] += in[5] + c; c = (out[5] >> 25); out[5] &= 0x1ffffff;
	out[6] += in[6] + c; c = (out[6] >> 26); out[6] &= 0x3ffffff;
	out[7] += in[7] + c; c = (out[7] >> 25); out[7] &= 0x1ffffff;
	out[8] += in[8] + c; c = (out[8] >> 26); out[8] &= 0x3ffffff;
	out[9] += in[9] + c; c = (out[9] >> 25); out[9] &= 0x1ffffff;
	out[10] = 0;
	out[11] = 0;
	out[0] +=    19 * c;
}

#define curve25519_subtract_reduce curve25519_subtract
static void DONNA_INLINE
curve25519_subtract(bignum25519 out, const bignum25519 in) {
	uint32_t c;

	xmmi a0,a1,a2,b0,b1,b2;
	a0 = _mm_load_si128((xmmi*)out + 0);
	a1 = _mm_load_si128((xmmi*)out + 1);
	a2 = _mm_load_si128((xmmi*)out + 2);
	b0 = _mm_load_si128((xmmi*)curve25519zeromodp0_sse2);
	b1 = _mm_load_si128((xmmi*)curve25519zeromodp1_sse2);
	b2 = _mm_load_si128((xmmi*)curve25519zeromodp2_sse2);
	a0 = _mm_add_epi32(a0, b0);
	a1 = _mm_add_epi32(a1, b1);
	a2 = _mm_add_epi32(a2, b2);
	b0 = _mm_load_si128((xmmi*)in + 0);
	b1 = _mm_load_si128((xmmi*)in + 1);
	b2 = _mm_load_si128((xmmi*)in + 2);
	a0 = _mm_sub_epi32(a0, b0);
	a1 = _mm_sub_epi32(a1, b1);
	a2 = _mm_sub_epi32(a2, b2);
	_mm_store_si128((xmmi*)out + 0, a0);
	_mm_store_si128((xmmi*)out + 1, a1);
	_mm_store_si128((xmmi*)out + 2, a2);

	             c = (out[0] >> 26); out[0] &= 0x3ffffff;
	out[1] += c; c = (out[1] >> 25); out[1] &= 0x1ffffff;
	out[2] += c; c = (out[2] >> 26); out[2] &= 0x3ffffff;
	out[3] += c; c = (out[3] >> 25); out[3] &= 0x1ffffff;
	out[4] += c; c = (out[4] >> 26); out[4] &= 0x3ffffff;
	out[5] += c; c = (out[5] >> 25); out[5] &= 0x1ffffff;
	out[6] += c; c = (out[6] >> 26); out[6] &= 0x3ffffff;
	out[7] += c; c = (out[7] >> 25); out[7] &= 0x1ffffff;
	out[8] += c; c = (out[8] >> 26); out[8] &= 0x3ffffff;
	out[9] += c; c = (out[9] >> 25); out[9] &= 0x1ffffff;
	out[0] += 19 * c;
}


/* Multiply two numbers: out = in2 * in */
static void 
curve25519_mul(bignum25519 out, const bignum25519 r, const bignum25519 s) {
	xmmi m0,m01,m23,m45,m67,m89;
	xmmi m0123,m4567;
	xmmi s0123,s4567;
	xmmi s01,s23,s45,s67,s89;
	xmmi s12,s34,s56,s78,s9;
	xmmi r0,r2,r4,r6,r8;
	xmmi r1,r3,r5,r7,r9;
	xmmi r119,r219,r319,r419,r519,r619,r719,r819,r919;
	xmmi maskhi,maskcarry,times19_19;

	maskhi = _mm_load_si128((xmmi*)curve25519topmask_sse2);
	maskcarry = _mm_load_si128((xmmi*)curve25519mask2625_sse2);
	times19_19 = _mm_load_si128((xmmi*)curve25519nineteen_sse2);

	s0123 = _mm_load_si128((xmmi*)s + 0);
	s01 = _mm_shuffle_epi32(s0123,_MM_SHUFFLE(3,1,2,0));
	s12 = _mm_shuffle_epi32(s0123, _MM_SHUFFLE(2,2,1,1));
	s23 = _mm_shuffle_epi32(s0123,_MM_SHUFFLE(3,3,2,2));
	s4567 = _mm_load_si128((xmmi*)s + 1);
	s34 = _mm_unpacklo_epi64(_mm_srli_si128(s0123,12),s4567);
	s45 = _mm_shuffle_epi32(s4567,_MM_SHUFFLE(3,1,2,0));
	s56 = _mm_shuffle_epi32(s4567, _MM_SHUFFLE(2,2,1,1));
	s67 = _mm_shuffle_epi32(s4567,_MM_SHUFFLE(3,3,2,2));
	s89 = _mm_load_si128((xmmi*)s + 2);
	s78 = _mm_unpacklo_epi64(_mm_srli_si128(s4567,12),s89);	
	s89 = _mm_shuffle_epi32(s89,_MM_SHUFFLE(3,1,2,0));
	s9 = _mm_shuffle_epi32(s89, _MM_SHUFFLE(3,3,2,2));

	r0 = _mm_load_si128((xmmi*)r + 0);
	r1 = _mm_shuffle_epi32(r0, _MM_SHUFFLE(1,1,1,1));
	r1 = _mm_add_epi64(r1, _mm_and_si128(r1, maskhi));
	r2 = _mm_shuffle_epi32(r0, _MM_SHUFFLE(2,2,2,2));
	r3 = _mm_shuffle_epi32(r0, _MM_SHUFFLE(3,3,3,3));
	r3 = _mm_add_epi64(r3, _mm_and_si128(r3, maskhi));
	r0 = _mm_shuffle_epi32(r0, _MM_SHUFFLE(0,0,0,0));
	r4 = _mm_load_si128((xmmi*)r + 1);
	r5 = _mm_shuffle_epi32(r4, _MM_SHUFFLE(1,1,1,1));
	r5 = _mm_add_epi64(r5, _mm_and_si128(r5, maskhi));
	r6 = _mm_shuffle_epi32(r4, _MM_SHUFFLE(2,2,2,2));
	r7 = _mm_shuffle_epi32(r4, _MM_SHUFFLE(3,3,3,3));
	r7 = _mm_add_epi64(r7, _mm_and_si128(r7, maskhi));
	r4 = _mm_shuffle_epi32(r4, _MM_SHUFFLE(0,0,0,0));
	r8 = _mm_load_si128((xmmi*)r + 2);
	r9 = _mm_shuffle_epi32(r8, _MM_SHUFFLE(3,1,3,1));
	r9 = _mm_add_epi64(r9, _mm_and_si128(r9, maskhi));
	r8 = _mm_shuffle_epi32(r8, _MM_SHUFFLE(3,0,3,0));

	m01 = _mm_mul_epu32(r1,s01);
	m23 = _mm_mul_epu32(r1,s23);
	m23 = _mm_add_epi64(m23,_mm_mul_epu32(r3,s01));
	m45 = _mm_mul_epu32(r1,s45);
	m45 = _mm_add_epi64(m45,_mm_mul_epu32(r3,s23));
	m45 = _mm_add_epi64(m45,_mm_mul_epu32(r5,s01));
	m67 = _mm_mul_epu32(r1,s67);
	m67 = _mm_add_epi64(m67,_mm_mul_epu32(r3,s45));
	m67 = _mm_add_epi64(m67,_mm_mul_epu32(r5,s23));
	m67 = _mm_add_epi64(m67,_mm_mul_epu32(r7,s01));
	m89 = _mm_mul_epu32(r1,s89);
	m89 = _mm_add_epi64(m89,_mm_mul_epu32(r3,s67));
	m89 = _mm_add_epi64(m89,_mm_mul_epu32(r5,s45));
	m89 = _mm_add_epi64(m89,_mm_mul_epu32(r7,s23));
	m89 = _mm_add_epi64(m89,_mm_mul_epu32(r9,s01));

	/* shift up */
	m89 = _mm_unpackhi_epi64(m67,_mm_slli_si128(m89,8));
	m67 = _mm_unpackhi_epi64(m45,_mm_slli_si128(m67,8));
	m45 = _mm_unpackhi_epi64(m23,_mm_slli_si128(m45,8));
	m23 = _mm_unpackhi_epi64(m01,_mm_slli_si128(m23,8));
	m01 = _mm_unpackhi_epi64(_mm_setzero_si128(),_mm_slli_si128(m01,8));

	m01 = _mm_add_epi64(m01,_mm_mul_epu32(r0,s01));
	m23 = _mm_add_epi64(m23,_mm_mul_epu32(r0,s23));
	m23 = _mm_add_epi64(m23,_mm_mul_epu32(r2,s01));
	m45 = _mm_add_epi64(m45,_mm_mul_epu32(r0,s45));
	m45 = _mm_add_epi64(m45,_mm_mul_epu32(r4,s01));
	m45 = _mm_add_epi64(m45,_mm_mul_epu32(r2,s23));
	m67 = _mm_add_epi64(m67,_mm_mul_epu32(r0,s67));
	m67 = _mm_add_epi64(m67,_mm_mul_epu32(r4,s23));
	m67 = _mm_add_epi64(m67,_mm_mul_epu32(r2,s45));	
	m67 = _mm_add_epi64(m67,_mm_mul_epu32(r6,s01));
	m89 = _mm_add_epi64(m89,_mm_mul_epu32(r0,s89));
	m89 = _mm_add_epi64(m89,_mm_mul_epu32(r8,s01));
	m89 = _mm_add_epi64(m89,_mm_mul_epu32(r6,s23));
	m89 = _mm_add_epi64(m89,_mm_mul_epu32(r4,s45));	
	m89 = _mm_add_epi64(m89,_mm_mul_epu32(r2,s67));

	r219 = _mm_mul_epu32(r2, times19_19);
	r419 = _mm_mul_epu32(r4, times19_19);
	r619 = _mm_mul_epu32(r6, times19_19);
	r819 = _mm_mul_epu32(r8, times19_19);
	r119 = _mm_shuffle_epi32(r1,_MM_SHUFFLE(0,0,2,2)); r119 = _mm_mul_epu32(r119, times19_19);
	r319 = _mm_shuffle_epi32(r3,_MM_SHUFFLE(0,0,2,2)); r319 = _mm_mul_epu32(r319, times19_19);
	r519 = _mm_shuffle_epi32(r5,_MM_SHUFFLE(0,0,2,2)); r519 = _mm_mul_epu32(r519, times19_19);
	r719 = _mm_shuffle_epi32(r7,_MM_SHUFFLE(0,0,2,2)); r719 = _mm_mul_epu32(r719, times19_19);
	r919 = _mm_shuffle_epi32(r9,_MM_SHUFFLE(0,0,2,2)); r919 = _mm_mul_epu32(r919, times19_19);

	m01 = _mm_add_epi64(m01,_mm_mul_epu32(r919,s12));
	m01 = _mm_add_epi64(m01,_mm_mul_epu32(r719,s34));
	m01 = _mm_add_epi64(m01,_mm_mul_epu32(r519,s56));
	m01 = _mm_add_epi64(m01,_mm_mul_epu32(r319,s78));
	m01 = _mm_add_epi64(m01,_mm_mul_epu32(r119,s9));
	m01 = _mm_add_epi64(m01,_mm_mul_epu32(r219,s89));
	m01 = _mm_add_epi64(m01,_mm_mul_epu32(r819,s23));
	m01 = _mm_add_epi64(m01,_mm_mul_epu32(r619,s45));
	m01 = _mm_add_epi64(m01,_mm_mul_epu32(r419,s67));
	
	m23 = _mm_add_epi64(m23,_mm_mul_epu32(r919,s34));
	m01 = _mm_add_epi64(m01, _mm_slli_si128(_mm_srli_epi64(m01, 26), 8));
	m23 = _mm_add_epi64(m23,_mm_mul_epu32(r719,s56));
	m23 = _mm_add_epi64(m23,_mm_mul_epu32(r519,s78));
	m23 = _mm_add_epi64(m23,_mm_mul_epu32(r319,s9));
	m23 = _mm_add_epi64(m23,_mm_mul_epu32(r819,s45));
	m23 = _mm_add_epi64(m23,_mm_mul_epu32(r619,s67));
	m23 = _mm_add_epi64(m23,_mm_mul_epu32(r419,s89));
	
	m45 = _mm_add_epi64(m45,_mm_mul_epu32(r919,s56));
	m23 = _mm_add_epi64(m23, _mm_srli_si128(_mm_srli_epi64(m01, 25), 8));
	m45 = _mm_add_epi64(m45,_mm_mul_epu32(r719,s78));
	m23 = _mm_add_epi64(m23, _mm_slli_si128(_mm_srli_epi64(m23, 26), 8));
	m45 = _mm_add_epi64(m45,_mm_mul_epu32(r519,s9));
	m45 = _mm_add_epi64(m45,_mm_mul_epu32(r819,s67));
	m45 = _mm_add_epi64(m45,_mm_mul_epu32(r619,s89));
	
	m67 = _mm_add_epi64(m67,_mm_mul_epu32(r919,s78));
	m45 = _mm_add_epi64(m45, _mm_srli_si128(_mm_srli_epi64(m23, 25), 8));
	m67 = _mm_add_epi64(m67,_mm_mul_epu32(r719,s9));
	m45 = _mm_add_epi64(m45, _mm_slli_si128(_mm_srli_epi64(m45, 26), 8));
	m67 = _mm_add_epi64(m67,_mm_mul_epu32(r819,s89));
	m67 = _mm_add_epi64(m67, _mm_srli_si128(_mm_srli_epi64(m45, 25), 8));
	m67 = _mm_add_epi64(m67, _mm_slli_si128(_mm_srli_epi64(m67, 26), 8));
	
	m89 = _mm_add_epi64(m89,_mm_mul_epu32(r919,s9));
	m89 = _mm_add_epi64(m89, _mm_srli_si128(_mm_srli_epi64(m67, 25), 8));
	m89 = _mm_add_epi64(m89, _mm_slli_si128(_mm_srli_epi64(m89, 26), 8));
	m0 = _mm_mul_epu32(_mm_srli_si128(_mm_srli_epi64(m89, 25), 8), times19_19);
	m01 = _mm_and_si128(m01, maskcarry);
	m23 = _mm_and_si128(m23, maskcarry);
	m45 = _mm_and_si128(m45, maskcarry);
	m67 = _mm_and_si128(m67, maskcarry);
	m89 = _mm_and_si128(m89, maskcarry);
	m01 = _mm_add_epi64(m01, m0);

	m01 = _mm_add_epi64(m01, _mm_slli_si128(_mm_srli_epi64(m01, 26), 8));
	m01 = _mm_and_si128(m01, _mm_shuffle_epi32(maskcarry, _MM_SHUFFLE(1,0,1,0)));

	m0123 = _mm_shuffle_epi32(m23, _MM_SHUFFLE(2,0,3,3));
	m4567 = _mm_shuffle_epi32(m67, _MM_SHUFFLE(2,0,3,3));
	m0123 = _mm_or_si128(m0123, _mm_shuffle_epi32(m01, _MM_SHUFFLE(3,3,2,0)));
	m4567 = _mm_or_si128(m4567, _mm_shuffle_epi32(m45, _MM_SHUFFLE(3,3,2,0)));
	m89 = _mm_shuffle_epi32(m89, _MM_SHUFFLE(3,3,2,0));

	_mm_store_si128((xmmi*)out + 0, m0123);
	_mm_store_si128((xmmi*)out + 1, m4567);
	_mm_store_si128((xmmi*)out + 2, m89);
}

static void
curve25519_square_times(bignum25519 r, const bignum25519 in, int count) {
	xmmi m0,m01,m23,m45,m67,m89,m0123,m4567;
	xmmi r0,r1,r2,r3,r4,r5,r6,r7,r8,r9;
	xmmi r0a,r1a,r2a,r3a,r7a,r9a;
	xmmi r0123,r4567;
	xmmi r01,r23,r45,r67,r6x,r89,r8x;
	xmmi r12,r34,r56,r78,r9x;

	xmmi masklo, maskhi,maskcarry;
	xmmi times19_19,times19x2_19;

	curve25519_copy(r, in);

	masklo = _mm_load_si128((xmmi*)curve25519bottommask_sse2);
	maskhi = _mm_load_si128((xmmi*)curve25519topmask_sse2);
	maskcarry = _mm_load_si128((xmmi*)curve25519mask2625_sse2);
	times19_19 = _mm_load_si128((xmmi*)curve25519nineteen_sse2);
	times19x2_19 = _mm_load_si128((xmmi*)curve25519nineteen2x_sse2);

	do {
		r0123 = _mm_load_si128((xmmi*)r + 0);
		r01 = _mm_shuffle_epi32(r0123,_MM_SHUFFLE(3,1,2,0));
		r12 = _mm_shuffle_epi32(r0123, _MM_SHUFFLE(2,2,1,1));
		r23 = _mm_shuffle_epi32(r0123,_MM_SHUFFLE(3,3,2,2));
		r0 = _mm_shuffle_epi32(r0123, _MM_SHUFFLE(0,0,0,0));
		r1 = _mm_shuffle_epi32(r0123, _MM_SHUFFLE(1,1,1,1));
		r2 = _mm_shuffle_epi32(r0123, _MM_SHUFFLE(2,2,2,2));
		r3 = _mm_shuffle_epi32(r0123, _MM_SHUFFLE(3,3,3,3));
		r4567 = _mm_load_si128((xmmi*)r + 1);
		r34 = _mm_unpacklo_epi64(_mm_srli_si128(r0123,12),r4567);
		r45 = _mm_shuffle_epi32(r4567,_MM_SHUFFLE(3,1,2,0));
		r56 = _mm_shuffle_epi32(r4567, _MM_SHUFFLE(2,2,1,1));
		r67 = _mm_shuffle_epi32(r4567,_MM_SHUFFLE(3,3,2,2));
		r6x = _mm_and_si128(r67, masklo);
		r4 = _mm_shuffle_epi32(r4567, _MM_SHUFFLE(0,0,0,0));
		r5 = _mm_shuffle_epi32(r4567, _MM_SHUFFLE(1,1,1,1));
		r5 = _mm_mul_epu32(r5, times19_19);
		r5 = _mm_and_si128(r5, masklo);
		r6 = _mm_shuffle_epi32(r4567, _MM_SHUFFLE(2,2,2,2));
		r6 = _mm_mul_epu32(r6, times19_19);
		r7 = _mm_shuffle_epi32(r4567, _MM_SHUFFLE(3,3,3,3));
		r7 = _mm_mul_epu32(r7, times19x2_19);
		r7a = _mm_and_si128(_mm_shuffle_epi32(r7, _MM_SHUFFLE(2,2,2,2)), masklo);
		r89 = _mm_load_si128((xmmi*)r + 2);
		r78 = _mm_unpacklo_epi64(_mm_srli_si128(r4567,12),r89);
		r8x = _mm_and_si128(r89, masklo);
		r8 = _mm_shuffle_epi32(r89, _MM_SHUFFLE(0,0,0,0));
		r8 = _mm_mul_epu32(r8, times19_19);
		r9  = _mm_shuffle_epi32(r89, _MM_SHUFFLE(1,1,1,1));
		r9x  = _mm_slli_epi32(_mm_shuffle_epi32(r89, _MM_SHUFFLE(3,3,3,1)), 1);
		r9 = _mm_mul_epu32(r9, times19x2_19);
		r9a = _mm_shuffle_epi32(r9, _MM_SHUFFLE(2,2,2,2));
		r89 = _mm_shuffle_epi32(r89,_MM_SHUFFLE(3,1,2,0));


		r0 = _mm_add_epi64(r0, _mm_and_si128(r0, maskhi));
		r0a = _mm_shuffle_epi32(r0,_MM_SHUFFLE(3,2,1,2));
		r2 = _mm_add_epi64(r2, _mm_and_si128(r2, maskhi));
		r2a = _mm_shuffle_epi32(r2,_MM_SHUFFLE(3,2,1,2));
		r4 = _mm_add_epi64(r4, _mm_and_si128(r4, maskhi));

		m01 = _mm_mul_epu32(r01, r0); 
		m23 = _mm_mul_epu32(r23, r0a);
		m45 = _mm_mul_epu32(r45, r0a);
		m45 = _mm_add_epi64(m45, _mm_mul_epu32(r23, r2));
		m67 = _mm_mul_epu32(r67, r0a);
		m67 = _mm_add_epi64(m67, _mm_mul_epu32(r45, r2a));
		m89 = _mm_mul_epu32(r89, r0a);
		m89 = _mm_add_epi64(m89, _mm_mul_epu32(r67, r2a));
		m89 = _mm_add_epi64(m89, _mm_mul_epu32(r45, r4));

		r1 = _mm_slli_epi32(r1, 1);
		r3 = _mm_slli_epi32(r3, 1);
		r1a = _mm_add_epi64(r1, _mm_and_si128(r1, masklo));
		r3a = _mm_add_epi64(r3, _mm_and_si128(r3, masklo));

		m23 = _mm_add_epi64(m23, _mm_mul_epu32(r12, r1));
		m45 = _mm_add_epi64(m45, _mm_mul_epu32(r34, r1a));
		m67 = _mm_add_epi64(m67, _mm_mul_epu32(r56, r1a));
		m67 = _mm_add_epi64(m67, _mm_mul_epu32(r34, r3));
		m89 = _mm_add_epi64(m89, _mm_mul_epu32(r78, r1a));
		m89 = _mm_add_epi64(m89, _mm_mul_epu32(r56, r3a));

		r12 = _mm_slli_epi32(r12, 1);
		r23 = _mm_slli_epi32(r23, 1);
		r34 = _mm_slli_epi32(r34, 1);
		r45 = _mm_slli_epi32(r45, 1);
		r56 = _mm_slli_epi32(r56, 1);
		r67 = _mm_slli_epi32(r67, 1);
		r78 = _mm_slli_epi32(r78, 1);

		m01 = _mm_add_epi64(m01, _mm_mul_epu32(r12, r9));
		m01 = _mm_add_epi64(m01, _mm_mul_epu32(r34, r7)); 
		m01 = _mm_add_epi64(m01, _mm_mul_epu32(r56, r5)); 
		m01 = _mm_add_epi64(m01, _mm_mul_epu32(r23, r8));
		m01 = _mm_add_epi64(m01, _mm_mul_epu32(r45, r6));
		m01 = _mm_add_epi64(m01, _mm_slli_si128(_mm_srli_epi64(m01, 26), 8));

		m23 = _mm_add_epi64(m23, _mm_mul_epu32(r34, r9));
		m23 = _mm_add_epi64(m23, _mm_mul_epu32(r56, r7)); 		
		m23 = _mm_add_epi64(m23, _mm_mul_epu32(r45, r8));
		m23 = _mm_add_epi64(m23, _mm_mul_epu32(r6x, r6));
		m23 = _mm_add_epi64(m23, _mm_srli_si128(_mm_srli_epi64(m01, 25), 8));
		m23 = _mm_add_epi64(m23, _mm_slli_si128(_mm_srli_epi64(m23, 26), 8));

		m45 = _mm_add_epi64(m45, _mm_mul_epu32(r56, r9));
		m45 = _mm_add_epi64(m45, _mm_mul_epu32(r78, r7a));
		m45 = _mm_add_epi64(m45, _mm_mul_epu32(r67, r8));
		m45 = _mm_add_epi64(m45, _mm_srli_si128(_mm_srli_epi64(m23, 25), 8));
		m45 = _mm_add_epi64(m45, _mm_slli_si128(_mm_srli_epi64(m45, 26), 8));

		m67 = _mm_add_epi64(m67, _mm_mul_epu32(r78, r9));
		m67 = _mm_add_epi64(m67, _mm_mul_epu32(r8x, r8));
		m67 = _mm_add_epi64(m67, _mm_srli_si128(_mm_srli_epi64(m45, 25), 8));
		m67 = _mm_add_epi64(m67, _mm_slli_si128(_mm_srli_epi64(m67, 26), 8));

		m89 = _mm_add_epi64(m89, _mm_mul_epu32(r9x, r9a));
		m89 = _mm_add_epi64(m89, _mm_srli_si128(_mm_srli_epi64(m67, 25), 8));
		m89 = _mm_add_epi64(m89, _mm_slli_si128(_mm_srli_epi64(m89, 26), 8));
		m0 = _mm_mul_epu32(_mm_srli_si128(_mm_srli_epi64(m89, 25), 8), times19_19);
		m01 = _mm_and_si128(m01, maskcarry);
		m23 = _mm_and_si128(m23, maskcarry);
		m45 = _mm_and_si128(m45, maskcarry);
		m67 = _mm_and_si128(m67, maskcarry);
		m89 = _mm_and_si128(m89, maskcarry);
		m01 = _mm_add_epi64(m01, m0);

		m01 = _mm_add_epi64(m01, _mm_slli_si128(_mm_srli_epi64(m01, 26), 8));
		m01 = _mm_and_si128(m01, _mm_shuffle_epi32(maskcarry, _MM_SHUFFLE(1,0,1,0)));

		m0123 = _mm_shuffle_epi32(m23, _MM_SHUFFLE(2,0,3,3));
		m4567 = _mm_shuffle_epi32(m67, _MM_SHUFFLE(2,0,3,3));
		m0123 = _mm_or_si128(m0123, _mm_shuffle_epi32(m01, _MM_SHUFFLE(3,3,2,0)));
		m4567 = _mm_or_si128(m4567, _mm_shuffle_epi32(m45, _MM_SHUFFLE(3,3,2,0)));
		m89 = _mm_shuffle_epi32(m89, _MM_SHUFFLE(3,3,2,0));

		_mm_store_si128((xmmi*)r + 0, m0123);
		_mm_store_si128((xmmi*)r + 1, m4567);
		_mm_store_si128((xmmi*)r + 2, m89);
	} while (--count);
}

/* Take a little-endian, 32-byte number and expand it into polynomial form */
static void DONNA_INLINE
curve25519_expand(bignum25519 out, const unsigned char in[32]) {
	#define F(n,start,shift,mask) \
		out[n] = \
			((((uint32_t) in[start + 0]) | \
			((uint32_t) in[start + 1]) << 8 | \
			((uint32_t) in[start + 2]) << 16 | \
			((uint32_t) in[start + 3]) << 24) >> shift) & mask;

	F(0, 0, 0, 0x3ffffff);
	F(1, 3, 2, 0x1ffffff);
	F(2, 6, 3, 0x3ffffff);
	F(3, 9, 5, 0x1ffffff);
	F(4, 12, 6, 0x3ffffff);
	F(5, 16, 0, 0x1ffffff);
	F(6, 19, 1, 0x3ffffff);
	F(7, 22, 3, 0x1ffffff);
	F(8, 25, 4, 0x3ffffff);
	F(9, 28, 6, 0x1ffffff);
	#undef F

	out[10] = 0;
	out[11] = 0;
}

/* Take a fully reduced polynomial form number and contract it into a
 * little-endian, 32-byte array
 */
static void DONNA_INLINE
curve25519_contract(unsigned char out[32], const bignum25519 in) {
	MM16 bignum25519 f;
	curve25519_copy(f, in);

	#define carry_pass() \
		f[1] += f[0] >> 26; f[0] &= 0x3ffffff; \
		f[2] += f[1] >> 25; f[1] &= 0x1ffffff; \
		f[3] += f[2] >> 26; f[2] &= 0x3ffffff; \
		f[4] += f[3] >> 25; f[3] &= 0x1ffffff; \
		f[5] += f[4] >> 26; f[4] &= 0x3ffffff; \
		f[6] += f[5] >> 25; f[5] &= 0x1ffffff; \
		f[7] += f[6] >> 26; f[6] &= 0x3ffffff; \
		f[8] += f[7] >> 25; f[7] &= 0x1ffffff; \
		f[9] += f[8] >> 26; f[8] &= 0x3ffffff;

	#define carry_pass_full() \
		carry_pass() \
		f[0] += 19 * (f[9] >> 25); f[9] &= 0x1ffffff;

	#define carry_pass_final() \
		carry_pass() \
		f[9] &= 0x1ffffff;

	carry_pass_full()
	carry_pass_full()

	/* now t is between 0 and 2^255-1, properly carried. */
	/* case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1. */
	f[0] += 19;
	carry_pass_full()

	/* now between 19 and 2^255-1 in both cases, and offset by 19. */
	f[0] += (1 << 26) - 19;
	f[1] += (1 << 25) - 1;
	f[2] += (1 << 26) - 1;
	f[3] += (1 << 25) - 1;
	f[4] += (1 << 26) - 1;
	f[5] += (1 << 25) - 1;
	f[6] += (1 << 26) - 1;
	f[7] += (1 << 25) - 1;
	f[8] += (1 << 26) - 1;
	f[9] += (1 << 25) - 1;

	/* now between 2^255 and 2^256-20, and offset by 2^255. */
	carry_pass_final()

	#undef carry_pass
	#undef carry_full
	#undef carry_final

	f[1] <<= 2;
	f[2] <<= 3;
	f[3] <<= 5;
	f[4] <<= 6;
	f[6] <<= 1;
	f[7] <<= 3;
	f[8] <<= 4;
	f[9] <<= 6;

	#define F(i, s) \
		out[s+0] |= (unsigned char )(f[i] & 0xff); \
		out[s+1] = (unsigned char )((f[i] >> 8) & 0xff); \
		out[s+2] = (unsigned char )((f[i] >> 16) & 0xff); \
		out[s+3] = (unsigned char )((f[i] >> 24) & 0xff);

	out[0] = 0;
	out[16] = 0;
	F(0,0);
	F(1,3);
	F(2,6);
	F(3,9);
	F(4,12);
	F(5,16);
	F(6,19);
	F(7,22);
	F(8,25);
	F(9,28);
	#undef F
}

/*
 * Maybe swap the contents of two felem arrays (@a and @b), each 5 elements
 * long. Perform the swap iff @swap is non-zero.
 */
static void DONNA_INLINE
curve25519_swap_conditional(bignum25519 a, bignum25519 b, uint32_t iswap) {
	const uint32_t swap = (uint32_t)(-(int32_t)iswap);
	xmmi a0,a1,a2,b0,b1,b2,x0,x1,x2;
	xmmi mask = _mm_cvtsi32_si128(swap);
	mask = _mm_shuffle_epi32(mask, 0);
	a0 = _mm_load_si128((xmmi *)a + 0);
	a1 = _mm_load_si128((xmmi *)a + 1);
	b0 = _mm_load_si128((xmmi *)b + 0);
	b1 = _mm_load_si128((xmmi *)b + 1);
	b0 = _mm_xor_si128(a0, b0);
	b1 = _mm_xor_si128(a1, b1);
	x0 = _mm_and_si128(b0, mask);
	x1 = _mm_and_si128(b1, mask);
	x0 = _mm_xor_si128(x0, a0);
	x1 = _mm_xor_si128(x1, a1);
	a0 = _mm_xor_si128(x0, b0);
	a1 = _mm_xor_si128(x1, b1);
	_mm_store_si128((xmmi *)a + 0, x0);
	_mm_store_si128((xmmi *)a + 1, x1);	
	_mm_store_si128((xmmi *)b + 0, a0);
	_mm_store_si128((xmmi *)b + 1, a1);

	a2 = _mm_load_si128((xmmi *)a + 2);
	b2 = _mm_load_si128((xmmi *)b + 2);
	b2 = _mm_xor_si128(a2, b2);
	x2 = _mm_and_si128(b2, mask);
	x2 = _mm_xor_si128(x2, a2);
	a2 = _mm_xor_si128(x2, b2);	
	_mm_store_si128((xmmi *)b + 2, a2);
	_mm_store_si128((xmmi *)a + 2, x2);
}


