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

#ifndef FSS_COMMON_H
#define FSS_COMMON_H

#include "openssl-aes.h"

#include <cpuid.h>
#include <gmp.h>
#include <gmpxx.h>
#include <iostream>
#include <immintrin.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <string>

using namespace std;

#define AESNI

const int initPRFLen = 4;

struct Fss {
    // store keys in fixedBlocks
    AES_KEY* aes_keys;
    uint32_t numBits; // number of bits in domain 
    uint32_t numParties; // used only in multiparty. Default is 3
    uint32_t numKeys;
};

struct CWLt {
    unsigned char cs[2][16];
    unsigned char ct[2];
    uint64_t cv[2];
};

struct ServerKeyLt {
    unsigned char s[2][16];
    unsigned char t[2];
    uint64_t v[2];
    CWLt* cw[2];
};

// Assumes integers are 64 bits
inline int getBit(uint64_t n, uint64_t pos) {
    //return (n & ( 1 << (64-pos))) >> (64-pos);
    return (n >> pos) & 1;
}

inline int getBit128(__uint128_t n, __int128_t pos) {
    //return (n & ( 1 << (64-pos))) >> (64-pos);
    return (n >> pos) & 1;
}

inline std::string int128ToBinary(__int128_t num) {
    std::string binaryStr = "";
    for (int i = sizeof(__int128_t) * 8 - 1; i >= 0; --i) {
        binaryStr += ((num >> i) & 1) ? '1' : '0';
    }
    return binaryStr;
}

// Converts byte array into 64-bit integer
inline uint64_t byteArr2Int64(const unsigned char* arr) { 
    // 使用 SIMD 内在函数进行加载和转换
    __m128i vec = _mm_loadu_si128((const __m128i*)arr);
    return _mm_cvtsi128_si64(vec);
}

// Converts byte array into 32-bit integer
inline uint32_t byteArr2Int32(unsigned char* arr)
{
    uint32_t a = uint32_t((unsigned char)(arr[0]) << 24 |
            (unsigned char)(arr[1]) << 16 |
            (unsigned char)(arr[2]) << 8 |
            (unsigned char)(arr[3]));
    return a;
}

inline int hardware_random_bytes(unsigned char *buf, size_t len) { 
    size_t i; 
    for (i = 0; i < len; i += 8) { 
        if (!_rdrand64_step((unsigned long long *)&buf[i])) 
        { 
            return 0; // 获取硬件随机数失败 
        } 
    }
    return 1; // 成功
}

AES_KEY* prfkey(unsigned char* out, unsigned char* key, uint32_t in_size, AES_KEY* aes_keys, uint32_t numKeys, uint32_t ecx);
void serialize(const Fss& fss, char* &buffer, size_t &buffer_size);
void deserialize(const char* buffer, Fss& fss, size_t &offset);
void destroyFSS(Fss* fss);

void serializeKey(const ServerKeyLt** key, size_t xkeySize, size_t ykeySize, uint32_t numBits, char* &buffer, size_t &buffer_size);
void deserializeKey(const char* buffer, uint32_t numBits, ServerKeyLt** &key, size_t xkeySize, size_t ykeySize, size_t &offset);
void destroyServerKeyLt(ServerKeyLt** key, size_t xkeySize, size_t ykeySize);

#endif
