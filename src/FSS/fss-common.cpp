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

#include "fss-common.h"

AES_KEY* prfkey(unsigned char* out, unsigned char* key, uint32_t in_size, AES_KEY* aes_keys, uint32_t numKeys, uint32_t ecx) {
/*#ifndef AESNI
    // check if there is aes-ni instruction
    uint32_t eax, ebx, ecx, edx;

    eax = ebx = ecx = edx = 0;
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
#endif*/
    unsigned char i;
    AES_KEY* temp_keys = aes_keys;
    // Do Matyas–Meyer–Oseas one-way compression function using different AES keys to get desired
    // output length
    uint32_t num_keys_required = in_size/16;
    if (num_keys_required > numKeys) {
        free(temp_keys);
        temp_keys = (AES_KEY*) malloc(sizeof(AES_KEY)*num_keys_required); 
        for (i = 0; i < num_keys_required; i++) {
            unsigned char rand_bytes[16];
            if (!hardware_random_bytes(rand_bytes, 16)) {
                printf("Random bytes failed.\n");
            }
#ifndef AESNI
            if (ecx & bit_AES) {
                aesni_set_encrypt_key(rand_bytes, 128, &(temp_keys[i]));
            } else {
                AES_set_encrypt_key(rand_bytes, 128, &(temp_keys[i]));
            }
#else
            aesni_set_encrypt_key(rand_bytes, 128, &(temp_keys[i]));
#endif
        }
    }
    for (i = 0; i < num_keys_required; i++) {
#ifndef AESNI
        if (ecx & bit_AES) {
            aesni_encrypt(key, out + (i*16), &temp_keys[i]);
        } else {
            AES_encrypt(key, out + (i*16), &temp_keys[i]);
        }
#else
        aesni_encrypt(key, out + (i*16), &temp_keys[i]);
#endif
    }
    __m128i key_vec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(key));
    for (i = 0; i < in_size; i += 16) {
        __m128i out_vec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&out[i]));
        out_vec = _mm_xor_si128(out_vec, key_vec);
        _mm_storeu_si128(reinterpret_cast<__m128i*>(&out[i]), out_vec);
    }
    return temp_keys;
}

void serialize(const Fss& fss, char* &buffer, size_t &buffer_size) {
    buffer_size = sizeof(fss.numBits) + sizeof(fss.numParties) + sizeof(fss.numKeys) + sizeof(AES_KEY)*initPRFLen;
    buffer = new char[buffer_size];

    size_t offset = 0;

    // 复制numBits
    std::memcpy(buffer + offset, &fss.numBits, sizeof(fss.numBits));
    offset += sizeof(fss.numBits);

    // 复制numParties
    std::memcpy(buffer + offset, &fss.numParties, sizeof(fss.numParties));
    offset += sizeof(fss.numParties);

    // 复制numKeys
    std::memcpy(buffer + offset, &fss.numKeys, sizeof(fss.numKeys));
    offset += sizeof(fss.numKeys);

    // 复制aes_keys
    std::memcpy(buffer + offset, fss.aes_keys, sizeof(AES_KEY)*initPRFLen);
}

void deserialize(const char* buffer, Fss& fss, size_t &offset) {
    fss.aes_keys = (AES_KEY*) malloc(sizeof(AES_KEY)*initPRFLen);

    // 复制numBits
    std::memcpy(&fss.numBits, buffer + offset, sizeof(fss.numBits));
    offset += sizeof(fss.numBits);

    // 复制numParties
    std::memcpy(&fss.numParties, buffer + offset, sizeof(fss.numParties));
    offset += sizeof(fss.numParties);

    // 复制numKeys
    std::memcpy(&fss.numKeys, buffer + offset, sizeof(fss.numKeys));
    offset += sizeof(fss.numKeys);

    // 复制aes_keys
    std::memcpy(fss.aes_keys, buffer + offset, sizeof(AES_KEY)*initPRFLen);
    offset += sizeof(AES_KEY)*initPRFLen;
}

void serializeKey(const ServerKeyLt** key, size_t xkeySize, size_t ykeySize, uint32_t numBits, char* &buffer, size_t &buffer_size) {
    buffer_size = (sizeof(key[0][0].s) + sizeof(key[0][0].t) + sizeof(key[0][0].v) + 2 * sizeof(CWLt) * (numBits-1)) * xkeySize * ykeySize;
    buffer = new char[buffer_size];

    size_t offset = 0;

    for(size_t i=0; i<xkeySize; i++){
        for(size_t k=0; k<ykeySize; k++){
            // 复制s
            std::memcpy(buffer + offset, key[i][k].s, sizeof(key[i][k].s));
            offset += sizeof(key[i][k].s);

            // 复制t
            std::memcpy(buffer + offset, key[i][k].t, sizeof(key[i][k].t));
            offset += sizeof(key[i][k].t);

            // 复制v
            std::memcpy(buffer + offset, key[i][k].v, sizeof(key[i][k].v));
            offset += sizeof(key[i][k].v);

            // 复制cw
            for (int j = 0; j < 2; ++j) {
                std::memcpy(buffer + offset, key[i][k].cw[j], sizeof(CWLt) * (numBits-1));
                offset += sizeof(CWLt) * (numBits-1);
            }
        }
    }
}

void deserializeKey(const char* buffer, uint32_t numBits, ServerKeyLt** &key, size_t xkeySize, size_t ykeySize, size_t &offset) {
    for(size_t i=0; i<xkeySize; i++){
        for(size_t k=0; k<ykeySize; k++){
            // 复制s
            std::memcpy(key[i][k].s, buffer + offset, sizeof(key[i][k].s));
            offset += sizeof(key[i][k].s);

            // 复制t
            std::memcpy(key[i][k].t, buffer + offset, sizeof(key[i][k].t));
            offset += sizeof(key[i][k].t);

            // 复制v
            std::memcpy(key[i][k].v, buffer + offset, sizeof(key[i][k].v));
            offset += sizeof(key[i][k].v);

            // 复制cw
            for (int j = 0; j < 2; ++j) {
                key[i][k].cw[j] = (CWLt*) malloc(sizeof(CWLt) * (numBits-1));
                std::memcpy(key[i][k].cw[j], buffer + offset, sizeof(CWLt) * (numBits-1));
                offset += sizeof(CWLt) * (numBits-1);
            }
        }
    }
}

void destroyFSS(Fss* fss) {
    free(fss->aes_keys);
}

void destroyServerKeyLt(ServerKeyLt** key, size_t xkeySize, size_t ykeySize){
    for(size_t i=0; i<xkeySize; i++){
        for(size_t k=0; k<ykeySize; k++){
            for (int j = 0; j < 2; ++j) {
                free(key[i][k].cw[j]);
            }
        }
    }
}