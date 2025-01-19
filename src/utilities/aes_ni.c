/*   
   GeckoCass: Lightweight and Scalable Secure Range Search on Cassandra


   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#include "aes_ni.h"

#define KE2(NK,OK,RND) NK = OK; \
    NK = _mm_xor_si128(NK, _mm_slli_si128(NK, 4));  \
    NK = _mm_xor_si128(NK, _mm_slli_si128(NK, 4));  \
    NK = _mm_xor_si128(NK, _mm_slli_si128(NK, 4));  \
    NK = _mm_xor_si128(NK, _mm_shuffle_epi32(_mm_aeskeygenassist_si128(OK, RND), 0xff)); // BAD INSTRUCTION HERE ////////////////////

void offline_prg(uint8_t * dest, uint8_t * src, __m128i * ri) {
	__m128i rr = _mm_loadu_si128((__m128i *)src);
    __m128i mr = _mm_xor_si128(rr, ri[0]);

    mr = _mm_aesenc_si128(mr, ri[1]);
    mr = _mm_aesenc_si128(mr, ri[2]);
    mr = _mm_aesenc_si128(mr, ri[3]);
    mr = _mm_aesenc_si128(mr, ri[4]);
    mr = _mm_aesenc_si128(mr, ri[5]);
    mr = _mm_aesenc_si128(mr, ri[6]);
    mr = _mm_aesenc_si128(mr, ri[7]);
    mr = _mm_aesenc_si128(mr, ri[8]);
    mr = _mm_aesenc_si128(mr, ri[9]);
    mr = _mm_aesenclast_si128(mr, ri[10]);
    mr = _mm_xor_si128(mr, rr);
    _mm_storeu_si128((__m128i *)dest, mr);
}

__m128i * offline_prg_keyschedule(uint8_t * src) {
	__m128i * r = malloc(11*sizeof(__m128i));

    r[0] = _mm_load_si128((__m128i *) src);

	KE2(r[1], r[0], 0x01)
	KE2(r[2], r[1], 0x02)
	KE2(r[3], r[2], 0x04)
	KE2(r[4], r[3], 0x08)
	KE2(r[5], r[4], 0x10)
	KE2(r[6], r[5], 0x20)
	KE2(r[7], r[6], 0x40)
	KE2(r[8], r[7], 0x80)
	KE2(r[9], r[8], 0x1b)
	KE2(r[10], r[9], 0x36)

	return r;
}

void prg_aes_ni(Lint* destination, uint8_t * seed, __m128i * key){
	uint8_t res[16] = {};

	offline_prg(res, seed, key);
	memset(seed, 0, 16);
	memset(destination, 0, sizeof(Lint));
	memcpy(seed, res, sizeof(Lint)); //cipher becomes new seed or key
	memcpy(destination, res, sizeof(Lint)); //cipher becomes new seed or key
}

void prg_aes_nsi(sLint* destination, uint8_t * seed, __m128i * key){
	uint8_t res[16] = {};

	offline_prg(res, seed, key);
	memset(seed, 0, 16);
	memset(destination, 0, sizeof(sLint));
	memcpy(seed, res, sizeof(sLint)); //cipher becomes new seed or key
	memcpy(destination, res, sizeof(sLint)); //cipher becomes new seed or key
}

void prg_aes_ni_byte(uint8_t* destination, uint8_t * seed, __m128i * key){
	uint8_t res[16] = {};

	offline_prg(res, seed, key);
	memset(seed, 0, 16);
	memset(destination, 0, sizeof(uint8_t));
	memcpy(seed, res, sizeof(uint8_t)); //cipher becomes new seed or key
	memcpy(destination, res, sizeof(uint8_t)); //cipher becomes new seed or key
}
void test_aes(){
	printf("AES test");
}


/*
** Using documented GCC type unsigned __int128 instead of undocumented
** obsolescent typedef name __uint128_t.  Works with GCC 4.7.1 but not
** GCC 4.1.2 (but __uint128_t works with GCC 4.1.2) on Mac OS X 10.7.4.
*/


/*      UINT64_MAX 18446744073709551615ULL */
#define P10_UINT64 10000000000000000000ULL   /* 19 zeroes */
#define E10_UINT64 19

#define STRINGIZER(x)   # x
#define TO_STRING(x)    STRINGIZER(x)

int print_u128_u(__uint128_t u128)
{
    int rc;
    if (u128 > UINT64_MAX)
    {
        __uint128_t leading  = u128 / P10_UINT64;
        __uint64_t  trailing = u128 % P10_UINT64;
        rc = print_u128_u(leading);
        rc += printf("%." TO_STRING(E10_UINT64) PRIu64, trailing);
    }
    else
    {
        uint64_t u64 = u128;
        rc = printf("%" PRIu64, u64);
    }
    return rc;
}

void print_128(__uint128_t *A, int size){
        int i;
	for(i = 0;i<size;i++){
	print_u128_u(A[i]);
	printf("\n");
	}
}

int print_u128_u2(__uint128_t x){
printf("__int128 max  %016"PRIx64"%016"PRIx64"\n",(uint64_t)(x>>64),(uint64_t)x);
return 0;
}

void print_1283(__uint128_t A){
	uint8_t plain[]      = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
	memcpy(plain, &A, 16);
		printf("128 is:");
        int i;
	for(i = 0; i<16; i++){

		printf("%d",plain[i]);
	}
	printf("\n");
}


