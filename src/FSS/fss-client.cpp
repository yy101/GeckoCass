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

// This is the client side code that does the key generation
#include "fss-client.h"

void initializeClient(Fss* f, uint32_t numBits, uint32_t numParties, uint32_t ecx) {
/*#ifndef AESNI
    // check if there is aes-ni instruction
    uint32_t eax, ebx, ecx, edx;

    eax = ebx = ecx = edx = 0;
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
#endif*/

    f->numBits = numBits;

    // Initialize keys for Matyas–Meyer–Oseas one-way compression function
    f->aes_keys = (AES_KEY*) malloc(sizeof(AES_KEY)*initPRFLen);
    unsigned char rand_bytes[16*initPRFLen];
    if (!hardware_random_bytes(rand_bytes, 16*initPRFLen)) {
        printf("Random bytes failed.\n");
    }
    for (int i = 0; i < initPRFLen; i++) {
#ifndef AESNI
        if (ecx & bit_AES) {
            aesni_set_encrypt_key(rand_bytes, 128, &(f->aes_keys[i]));
        } else {
            AES_set_encrypt_key(rand_bytes, 128, &(f->aes_keys[i]));
        }
#else
        aesni_set_encrypt_key(rand_bytes+i*16, 128, &(f->aes_keys[i]));
#endif
    }

    f->numParties = numParties;
    f->numKeys = initPRFLen;
}

// Generate keys for 2 party less than FSS 
void generateTreeLt(Fss* f, ServerKeyLt* k0, ServerKeyLt* k1, __uint128_t a_i, uint64_t b_i, uint32_t ecx){
    uint32_t n = f->numBits;

    // Set up num_bits and allocate memory
    k0->cw[0] = (CWLt*) malloc(sizeof(CWLt) * (n-1));
    k0->cw[1] = (CWLt*) malloc(sizeof(CWLt) * (n-1));
    k1->cw[0] = (CWLt*) malloc(sizeof(CWLt) * (n-1));
    k1->cw[1] = (CWLt*) malloc(sizeof(CWLt) * (n-1));

    // Figure out first relevant bit
    // n is the number of least significant bits to compare
    //int a = getBit(a_i, (64-n+1));
    uint32_t pos = n-1;
    if(n > 128)
        pos = 127;
    int a = getBit128(a_i, pos);
    int na = a ^ 1;

    // create arrays size (AES_key_size*2 + 2)
    unsigned char s0[32];
    unsigned char s1[32];
    unsigned char temp[2];
    // Set initial v's
    unsigned char temp_v[16];

    int aStart = 16 * a;
    int naStart = 16 *na;

    // Set initial seeds for PRF
    if(!hardware_random_bytes(s0 + aStart, 16) || !hardware_random_bytes(s1 + aStart, 16) || !hardware_random_bytes(s0 + naStart, 16) || !hardware_random_bytes(temp, 2) || !hardware_random_bytes(temp_v, 16)) {
        printf("Random bytes failed\n");
        exit(1);
    }
    memcpy(s1 + naStart, s0 + naStart, 16);

    unsigned char t0[2];
    unsigned char t1[2];
    
    // Figure out initial ts
    // Make sure t0a and t1a are different
    t0[a] = temp[0] & 1;
    t1[a] = (t0[a] + 1) & 1;

    // Make sure t0na = t1na
    t0[na] = temp[1] & 1;
    t1[na] = t0[na];

    k0->v[a] = byteArr2Int64(temp_v);
    k1->v[a] = k0->v[a];
    
    k0->v[na] = byteArr2Int64(temp_v+8);
    k1->v[na] = k0->v[na] - b_i*a;

    memcpy(k0->s[0], s0, 16);
    memcpy(k0->s[1], s0 + 16, 16);
    memcpy(k1->s[0], s1, 16);
    memcpy(k1->s[1], s1 + 16, 16);
    k0->t[0] = t0[0];
    k0->t[1] = t0[1];
    k1->t[0] = t1[0];
    k1->t[1] = t1[1];

    // Pick right keys to put into cipher
    unsigned char key0[16];
    unsigned char key1[16];
    memcpy(key0, s0 + aStart, 16);
    memcpy(key1, s1 + aStart, 16);

    unsigned char tbit0 = t0[a];
    unsigned char tbit1 = t1[a];

    unsigned char cs0[32];
    unsigned char cs1[32];
    unsigned char ct0[2];
    unsigned char ct1[2];
    unsigned char out0[64];
    unsigned char out1[64];

    uint64_t v0[2];
    uint64_t v1[2];
    uint64_t cv[2][2];
    unsigned char* cs;
    unsigned char* ct;
    uint32_t i,j;
    for (i = 0; i < n-1; i++) {
        //printf("s: ");
        //printByteArray(key0, 16);
        f->aes_keys = prfkey(out0, key0, 64, f->aes_keys, f->numKeys, ecx);
        f->aes_keys = prfkey(out1, key1, 64, f->aes_keys, f->numKeys, ecx);

        memcpy(s0, out0, 32);
        memcpy(s1, out1, 32);
        t0[0] = out0[32] & 1;
        t0[1] = out0[48] & 1;
        t1[0] = out1[32] & 1;
        t1[1] = out1[48] & 1;

        v0[0] = byteArr2Int64(out0 + 40);
        v0[1] = byteArr2Int64(out0 + 56);
        v1[0] = byteArr2Int64(out1 + 40);
        v1[1] = byteArr2Int64(out1 + 56);
        //printf("out0: %d %d\n", out0[32], out0[33]);

        // Reset a and na bits
        //a = getBit(a_i, (64-n+i+2));
        pos = n-i-2;
        if(pos > 128)
            pos = 126-i;
        a = getBit128(a_i, pos);
        na = a ^ 1;

        // Redefine aStart and naStart based on new a's
        aStart = 16 * a;
        naStart = 16 * na;

        // Create cs and ct for next bit
        if (!hardware_random_bytes(cs0 + aStart, 16) || !hardware_random_bytes(cs1 + aStart, 16) || !hardware_random_bytes(cs0 + naStart, 16) || !hardware_random_bytes(temp, 2) || !hardware_random_bytes(temp_v, 16)) {
            printf("Random bytes failed.\n");
            exit(1);
        }

        for (j = 0; j < 16; j++) {
            cs1[naStart+j] = s0[naStart+j] ^ s1[naStart+j] ^ cs0[naStart+j];
        }

        ct0[a] = temp[0] & 1;
        ct1[a] = ct0[a] ^ t0[a] ^ t1[a] ^ 1;

        ct0[na] = temp[1] & 1;
        ct1[na] = ct0[na] ^ t0[na] ^ t1[na];

        cv[tbit0][a] = byteArr2Int64(temp_v);
        cv[tbit1][a] = cv[tbit0][a] + v0[a] - v1[a];

        cv[tbit0][na] = byteArr2Int64(temp_v+8);
        cv[tbit1][na] = (cv[tbit0][na] + v0[na] - v1[na] - b_i*a);

        // Copy appropriate values into key
        memcpy(k0->cw[0][i].cs[0], cs0, 16);
        memcpy(k0->cw[0][i].cs[1], cs0 + 16, 16);
        k0->cw[0][i].ct[0] = ct0[0];
        k0->cw[0][i].ct[1] = ct0[1];
        memcpy(k0->cw[1][i].cs[0], cs1, 16);
        memcpy(k0->cw[1][i].cs[1], cs1 + 16, 16);
        k0->cw[1][i].ct[0] = ct1[0];
        k0->cw[1][i].ct[1] = ct1[1];

        k0->cw[0][i].cv[0] = cv[0][0];
        k0->cw[0][i].cv[1] = cv[0][1];
        k0->cw[1][i].cv[0] = cv[1][0];
        k0->cw[1][i].cv[1] = cv[1][1];

        memcpy(k1->cw[0][i].cs[0], cs0, 16);
        memcpy(k1->cw[0][i].cs[1], cs0 + 16, 16);
        k1->cw[0][i].ct[0] = ct0[0];
        k1->cw[0][i].ct[1] = ct0[1];
        memcpy(k1->cw[1][i].cs[0], cs1, 16);
        memcpy(k1->cw[1][i].cs[1], cs1 + 16, 16);
        k1->cw[1][i].ct[0] = ct1[0];
        k1->cw[1][i].ct[1] = ct1[1];

        k1->cw[0][i].cv[0] = cv[0][0];
        k1->cw[0][i].cv[1] = cv[0][1];
        k1->cw[1][i].cv[0] = cv[1][0];
        k1->cw[1][i].cv[1] = cv[1][1];

        if (tbit0 == 1) {
            cs = cs1;
            ct = ct1;
        } else {
            cs = cs0;
            ct = ct0;
        }

        for (j = 0; j < 16; j++) {
            key0[j] = s0[aStart+j] ^ cs[aStart+j];
        }
        tbit0 = t0[a] ^ ct[a];

        //printf("After XOR: ");
        //printByteArray(key0, 16);
        if (tbit1 == 1) {
            cs = cs1;
            ct = ct1;
        } else {
            cs = cs0;
            ct = ct0;

        }

        for (j = 0; j < 16; j++) {
            key1[j] = s1[aStart+j] ^ cs[aStart+j];
        }
        tbit1 = t1[a] ^ ct[a];
    }
}