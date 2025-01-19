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

#include "Open.h"

void Rss_Open(Lint *res, Lint **a, uint size, uint ring_size, NodeNetwork *nodeNet) {
    // a[0] will be sent to next neighbor map[0], res will be filled by the received
    // value from map[1] the r_size in the functions that including open
    // functionality (open_s, multpub) refers to the ring size that we are doing
    // computation over, this might be different from the basic ring_size. E.g., in
    // randbits, multpub is working over ring_size+2.
    // communication
    uint i;
    // uint bytes = (RING[ring_size] + 7)>>3;
    // for(i = 0; i<size; i++){
    // a[1] = a[1] & nodeNet->SHIFT[maskring_size];
    //}
    // }

    nodeNet->SendAndGetDataFromPeer(a[1], res, size);
    for (i = 0; i < size; i++) {
        res[i] = a[0][i] + a[1][i] + res[i];
        res[i] = res[i] & nodeNet->SHIFT[ring_size];
        // res[i] = bitExtracted(res[i], nodeNet->RING[ring_size]);
    }
}

void print128O(__int128_t x) {
    if (x < 0) {
        putchar('-');
        x = -x;
    }
    if (x > 9) print128O(x / 10);
    putchar(x % 10 + '0');
}

void Rss_Open_Signal(__int128_t *res, Lint *a, uint size, uint ring_size, NodeNetwork *nodeNet) {
    // a[0] will be sent to next neighbor map[0], res will be filled by the received
    // value from map[1] the r_size in the functions that including open
    // functionality (open_s, multpub) refers to the ring size that we are doing
    // computation over, this might be different from the basic ring_size. E.g., in
    // randbits, multpub is working over ring_size+2.
    // communication
    uint i;
    Lint *num1 = new Lint[size];
    //memset(num1, 0, sizeof(Lint) * (size));
    Lint *num2 = new Lint[size];
    //memset(num2, 0, sizeof(Lint) * (size));

    nodeNet->SendAndGetDataFromPeer(a, num1, size);
    nodeNet->SendAndGetDataFromPeer(num1, num2, size);
    Lint flag = (Lint)1 << (ring_size-1);
    Lint differ = flag * 2;
    Lint shift = nodeNet->SHIFT[ring_size];

    #pragma omp parallel for
    for (i = 0; i < size; i++) {
        res[i] = (a[i] + num1[i] + num2[i]) & shift;
        /*if(i<2){
            //print128O(res[i]);
            cout << int128ToBinary(res[i]) << endl;
            //print128O((a[0][i] + a[1][i] + num[i]));
            cout << int128ToBinary((a[0][i] + a[1][i] + num[i])) << endl;
            //print128O(nodeNet->SHIFT[ring_size]);
            cout << int128ToBinary(nodeNet->SHIFT[ring_size]) << endl;
        }*/
        //std::cout << num[index] << std::endl;

        if(res[i] > flag){
            res[i] -= differ;
        }
        // res[i] = bitExtracted(res[i], nodeNet->RING[ring_size]);
    }
    delete[] num1;
    delete[] num2;
}

bool Rss_Open_Verification(Lint **a, Lint **b, Lint r, uint size, uint ring_size, uint num_iterations, NodeNetwork *nodeNet, __m128i * key_prg_ver, uint8_t *key) {
    // a[0] will be sent to next neighbor map[0], res will be filled by the received
    // value from map[1] the r_size in the functions that including open
    // functionality (open_s, multpub) refers to the ring size that we are doing
    // computation over, this might be different from the basic ring_size. E.g., in
    // randbits, multpub is working over ring_size+2.
    // communication
    bool ret = true;
    uint i, j, k;
    Lint random = 0;
    Lint **Data = new Lint*[3];
    for (i = 0; i < 3; i++) {
        Data[i] = new Lint[3];
        memset(Data[i], 0, sizeof(Lint) * 3);
    }
    
    for (k=0; k < num_iterations; k++){
        for (j = 0; j < size; j++) {
            prg_aes_ni(&random, key, key_prg_ver);
            Data[0][0] += a[k][j]*random;
            Data[0][1] += b[k][j]*random;
        }
    }
    Data[0][2] = r;

    nodeNet->SendAndGetDataFromPeer(Data[0], Data[1], 3);
    nodeNet->SendAndGetDataFromPeer(Data[1], Data[2], 3);
    Lint u = Data[0][0] + Data[1][0] + Data[2][0];
    Lint w = Data[0][1] + Data[1][1] + Data[2][1];
    Lint R = Data[0][2] + Data[1][2] + Data[2][2];

    u = (u*R) & nodeNet->SHIFT[ring_size];
    w = w & nodeNet->SHIFT[ring_size];
    if(u != w){
        ret = false;
    }
    for (i = 0; i < 3; i++) {
        delete[] Data[i];
    }
    delete[] Data;

    /*std::cout << "Random: ";
    print128(R);
    cout << endl;*/

    return ret;
}

void generateCommonKey(uint8_t *key, uint ring_size, NodeNetwork *nodeNet){
    nodeNet->prg_getrandom(2, 1, 16, key);
    Lint* random = new Lint[4];
    Lint* randompeer1 = new Lint[4];
    Lint* randompeer2 = new Lint[4];
    memcpy(random, key, 16);
    nodeNet->SendAndGetDataFromPeer(random, randompeer1, 4);
    nodeNet->SendAndGetDataFromPeer(randompeer1, randompeer2, 4);
    for (int i = 0; i < 4; i++) {
        random[i] += randompeer1[i]+randompeer2[i];
        memcpy(key+i*4, random+i, 4);
    }
    /*for(int i=0; i<16; i++){
        printf("%02X ", key[i]);
    }
    printf("\n");*/
    delete[] random;
    delete[] randompeer1;
    delete[] randompeer2;
}

void Rss_Open_Byte(uint8_t *res, uint8_t **a, uint size, uint ring_size, NodeNetwork *nodeNet) {
    // a[0] will be sent to next neighbor map[0], res will be filled by the received
    // value from map[1] the r_size in the functions that including open
    // functionality (open_s, multpub) refers to the ring size that we are doing
    // computation over, this might be different from the basic ring_size. E.g., in
    // randbits, multpub is working over ring_size+2.
    // communication
    uint i;
    // uint bytes = (size+8-1)>>3;  //number of bytes need to be send/recv

    // uint bytes = (RING[ring_size] + 7)>>3;
    // for(i = 0; i<size; i++){
    // a[1] = a[1] & nodeNet->SHIFT[maskring_size];
    //}
    nodeNet->SendAndGetDataFromPeer_bit(a[1], res, size);
    for (i = 0; i < size; i++) {
        res[i] = a[0][i] ^ a[1][i] ^ res[i];
        // res[i] = res[i] & nodeNet->SHIFT[ring_size];
        // res[i] = bitExtracted(res[i], nodeNet->RING[ring_size]);
    }
}

void Rss_Open_Bitwise(Lint *res, Lint **a, uint size, uint ring_size, NodeNetwork *nodeNet) {
    // a[0] will be sent to next neighbor map[0], res will be filled by the received
    // value from map[1] the r_size in the functions that including open
    // functionality (open_s, multpub) refers to the ring size that we are doing
    // computation over, this might be different from the basic ring_size. E.g., in
    // randbits, multpub is working over ring_size+2.
    // communication
    uint i;
    // uint bytes = (RING[ring_size] + 7)>>3;
    // for(i = 0; i<size; i++){
    // a[1] = a[1] & nodeNet->SHIFT[maskring_size];
    //}
    nodeNet->SendAndGetDataFromPeer(a[1], res, size);
    for (i = 0; i < size; i++) {
        res[i] = a[0][i] ^ a[1][i] ^ res[i];
        res[i] = res[i] & nodeNet->SHIFT[ring_size];
        // res[i] = bitExtracted(res[i], nodeNet->RING[ring_size]);
    }
}