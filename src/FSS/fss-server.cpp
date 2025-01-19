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

// This is the server side code for FSS which does the evaluation

#include "fss-server.h"
#define num_keys_required 4

void initializeServer(Fss* fServer, Fss* fClient) {
    fServer->numKeys = fClient->numKeys;
    fServer->aes_keys = (AES_KEY*) malloc(sizeof(AES_KEY)*fClient->numKeys);
    memcpy(fServer->aes_keys, fClient->aes_keys, sizeof(AES_KEY)*fClient->numKeys);
    fServer->numBits = fClient->numBits;
    fServer->numParties = fClient->numParties;
}

// Evaluate whether x < value in function stored in key k
uint64_t evaluateLt(Fss* f, ServerKeyLt *k, __uint128_t x, uint32_t ecx) {
    uint32_t n = f->numBits;

    //int xi = getBit(x, (64-n+1));
    uint32_t pos = (n > 128) ? 127 : n - 1;
    uint32_t xi = getBit128(x, pos);
    unsigned char s[16];
    memcpy(s, k->s[xi], 16);
    unsigned char t = k->t[xi];
    uint64_t v = k->v[xi];

    unsigned char out[32];
    uint32_t numKeys = f->numKeys;
    AES_KEY* keys = f->aes_keys;
    __m128i key_vec = _mm_loadu_si128((__m128i*)(s));
    __m128i out_vec;

    if (num_keys_required > numKeys) {
        printf("Error: num_keys_required exceeds numKeys.\n");
        exit(1);
    }

    for (uint32_t i = 1; i < n; i++) {
        //xi = getBit(x, (64-n+i+1));
        pos = (n - i - 1 > 128) ? 127 - i : n - i - 1;
        xi = getBit128(x, pos);

        //prf(out, s, 64, keys, numKeys, ecx);
        #ifndef AESNI
            if (ecx & bit_AES) {
                aesni_encrypt(s, out, keys + xi);
                aesni_encrypt(s, out + 16, keys + 2 + xi);
                out_vec = _mm_loadu_si128((__m128i*)(out + 16));
                out_vec = _mm_xor_si128(out_vec, key_vec);
                _mm_storeu_si128((__m128i*)(out + 16), out_vec);
                out_vec = _mm_loadu_si128((__m128i*)(out));
                out_vec = _mm_xor_si128(out_vec, key_vec);
            } else {
                AES_encrypt(s, out, keys + xi);
                AES_encrypt(s, out + 16, keys + 2 + xi);
                out_vec = _mm_loadu_si128((__m128i*)(out + 16));
                out_vec = _mm_xor_si128(out_vec, key_vec);
                _mm_storeu_si128((__m128i*)(out + 16), out_vec);
                out_vec = _mm_loadu_si128((__m128i*)(out));
                out_vec = _mm_xor_si128(out_vec, key_vec);
            }
        #else
                aesni_encrypt(s, out, keys + xi);
                aesni_encrypt(s, out + 16, keys + 2 + xi);
                out_vec = _mm_loadu_si128((__m128i*)(out + 16));
                out_vec = _mm_xor_si128(out_vec, key_vec);
                _mm_storeu_si128((__m128i*)(out + 16), out_vec);
                out_vec = _mm_loadu_si128((__m128i*)(out));
                out_vec = _mm_xor_si128(out_vec, key_vec);
        #endif
        // Load the data into registers
        key_vec = _mm_loadu_si128((__m128i*)k->cw[t][i-1].cs[xi]);
        // Perform the XOR operation
        key_vec = _mm_xor_si128(key_vec, out_vec);    // s = s ^ k->cw[t][i-1].cs[xi]
        // Store the result back to the original array
        _mm_storeu_si128((__m128i*)s, key_vec);

        //temp_v = byteArr2Int64(out + 24);        
        //printf("%d: t: %d %d, ct: %d, bit: %d\n", i, temp[0], temp[1], k->cw[t][i-1].ct[xi], xi);
        //printf("temp_v: %lld\n", temp_v);
        v += byteArr2Int64(out + 24) + k->cw[t][i-1].cv[xi];
        t = (out[16] & 1) ^ k->cw[t][i-1].ct[xi];
    }
    return v;
}