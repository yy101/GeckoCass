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

#include "Mult.h"

//  For party 1, a[0,1]=a_2,3; b[0,1]=b_2,3;  c[0,1] = c_2,3;
//  For party 2, a[0,1]=a_3,1; b[0,1]=b_3,1;  c[0,1] = c_3,1;
//  For party 3, a[0,1]=a_1,2; b[0,1]=b_1,2;  c[0,1] = c_1,2;
void Rss_Mult_Bitwise(Lint **c, Lint **a, Lint **b, uint size, uint ring_size, NodeNetwork *nodeNet) {
    // uint bytes = (nodeNet->RING[ring_size] + 7) >> 3;
    uint bytes = (ring_size + 7) >> 3;
    uint i;

    Lint *v = new Lint[size];

    uint8_t *buffer = new uint8_t[bytes * size];
    nodeNet->prg_getrandom(1, bytes, size, buffer);

    for (i = 0; i < size; i++) {
        // nodeNet->prg_getrandom(1, bytes, c[0]+i);
        memcpy(c[0] + i, buffer + i * bytes, bytes);

        v[i] = ((a[0][i] & b[0][i]) ^ (a[0][i] & b[1][i]) ^ (a[1][i] & b[0][i])) ^ c[0][i];
    }
    // communication
    nodeNet->SendAndGetDataFromPeer(v, c[1], size);
    nodeNet->prg_getrandom(0, bytes, size, buffer);

    for (i = 0; i < size; i++) {
        c[1][i] = c[1][i] ^ c[0][i];
        // nodeNet->prg_getrandom(0, bytes, c[0]+i);
        memcpy(c[0] + i, buffer + i * bytes, bytes);
        c[0][i] = c[0][i] ^ v[i];
    }

    // free
    delete[] v;
    delete[] buffer;
}

//  For party 1, a[0,1]=a_2,3; b[0,1]=b_2,3;  c[0,1] = c_2,3;
//  For party 2, a[0,1]=a_3,1; b[0,1]=b_3,1;  c[0,1] = c_3,1;
//  For party 3, a[0,1]=a_1,2; b[0,1]=b_1,2;  c[0,1] = c_1,2;
void Rss_Mult(Lint **c, Lint **a, Lint **b, uint size, uint ring_size, NodeNetwork *nodeNet) {
    // uint bytes = (nodeNet->RING[ring_size] + 7) >> 3;
    uint bytes = (ring_size + 7) >> 3;
    uint i;

    Lint *v = new Lint[size];

    uint8_t *buffer = new uint8_t[bytes * size];
    nodeNet->prg_getrandom(1, bytes, size, buffer);
    // memcpy(c[0], buffer, size*bytes);

    for (i = 0; i < size; i++) {
        memcpy(c[0] + i, buffer + i * bytes, bytes);
        v[i] = a[0][i] * b[0][i] + a[0][i] * b[1][i] + a[1][i] * b[0][i] - c[0][i];
    }
    // communication
    // nodeNet->SendAndGetDataFromPeer(v, c[1], size);

    //  struct timeval start;
    // struct timeval end;
    // unsigned long timer;

    // gettimeofday(&start, NULL); //start timer here
    nodeNet->SendAndGetDataFromPeer(v, c[1], size);
    // gettimeofday(&end, NULL); //stop timer here
    // timer = 1000000 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
    // printf("Runtime for Mult send with data size %d = %.6lf ms\n", size, (double)(timer * 0.001));

    nodeNet->prg_getrandom(0, bytes, size, buffer);

    for (i = 0; i < size; i++) {
        c[1][i] = c[1][i] + c[0][i];
        // nodeNet->prg_getrandom(0, bytes, c[0]+i);
        memcpy(c[0] + i, buffer + i * bytes, bytes);
        c[0][i] = c[0][i] + v[i];
        //std::cout << "c[0][i]=" << c[0][i] << std::endl;
        //std::cout << "c[1][i]=" << c[1][i] << std::endl;
    }

    // free
    delete[] v;
    delete[] buffer;
}

void Rss_nMult(Lint *c, Lint **a, Lint **b, uint size, uint batch_size, bool malicious, uint offset){
    #pragma omp parallel for
    for (uint i = 0; i < size; i++) {
        c[i] = a[1][i] * b[1][i*batch_size+offset] - a[0][i] * b[0][i*batch_size+offset];
        if(malicious){
            c[i+size] = a[1][i+size] * b[1][i*batch_size+offset] - a[0][i+size] * b[0][i*batch_size+offset];
        }
    }
}

void Rss_Reshare(Lint **a, uint size, NodeNetwork *nodeNet){
    nodeNet->SendAndGetDataFromPeer(a[0], a[1], size);
    uint i;
    /*for(i=0; i < size; i++){
        a[1][i] += a[0][i];
    }*/
    #pragma omp parallel for
    for (i=0; i < size; i += 2) {
        __m256i vec1 = _mm256_loadu_si256((__m256i*)&a[1][i]);
        __m256i vec0 = _mm256_loadu_si256((__m256i*)&a[0][i]);
        vec1 = _mm256_add_epi64(vec1, vec0);
        _mm256_storeu_si256((__m256i*)&a[1][i], vec1);
    }
}

void Rss_Mult_Reshare(Lint **c, Lint **a, Lint **b, uint size, uint ring_size, NodeNetwork *nodeNet) {
    uint i;
    uint bytes = (ring_size + 7) >> 3;
    Lint *v = new Lint[size];
    Lint *random = new Lint[size];
    uint8_t *buffer = new uint8_t[bytes * size];
    nodeNet->prg_getrandom(1, bytes, size, buffer);
    memcpy(random, buffer, bytes * size);
    
    #pragma omp parallel for
    for (i = 0; i < size; i++) {
        v[i] = a[1][i] * b[1][i] - a[0][i] * b[0][i] - random[i];
    }
    nodeNet->SendAndGetDataFromPeer(v, c[1], size);
    nodeNet->prg_getrandom(0, bytes, size, buffer);

    #pragma omp parallel for
    for (i = 0; i < size; i++) {
        c[1][i] += random[i];
        // nodeNet->prg_getrandom(0, bytes, c[0]+i);
        memcpy(random + i, buffer + i * bytes, bytes);
        c[0][i] = random[i]+v[i];
        c[1][i] += c[0][i];
    }

    delete[] v;
    delete[] random;
    delete[] buffer;
}

void Rss_Mult_Vec(Lint *c, Lint **a, Lint **b, uint size, uint batch_size, int ThreadNum, int ThreadId, Lint *v) {
    /*string dot1 = "-"+to_string(v[0])+"+d11*"+to_string(b[0][0])+"+d11*"+to_string(b[1][0])+"+d21*"+to_string(b[0][0]);
    string dot2 = "-"+to_string(v[1])+"+d12*"+to_string(b[0][1])+"+d12*"+to_string(b[1][1])+"+d22*"+to_string(b[0][1]);
    string dot3 = "-"+to_string(v[2])+"+d13*"+to_string(b[0][2])+"+d13*"+to_string(b[1][2])+"+d23*"+to_string(b[0][2]);
    string SelectQuery = "select "+dot1+" as dot1, "+dot2+" as dot2, "+dot3+" as dot3 from db_mpc"+to_string(pid)+".idx_s where section = ?";*/

    uint i,j;
    int indexa = 0;
    int indexc = 0;
    Lint sum;

    #pragma omp parallel for
    for (i = 0; i < size; i++) {
        sum = 0;
        indexa = i*ThreadNum*batch_size;
        indexc = i*ThreadNum;
        for(j = 0; j < batch_size; j++){
            sum += a[1][indexa+j] * b[1][j] - a[0][indexa+j] * b[0][j];
        }
        c[indexc] = sum - v[0] + v[1];
    }
}

void Rss_Mult_Random(Lint **c, uint size, uint batch_size, uint ring_size, NodeNetwork *nodeNet) {
    uint bytes = (ring_size + 7) >> 3;
    Lint *v = new Lint[batch_size];
    memset(v, 0, batch_size*sizeof(unsigned long));
    Lint *v1 = new Lint[batch_size];
    memset(v1, 0, batch_size*sizeof(unsigned long));
    
    uint8_t *buffer = new uint8_t[bytes * batch_size];
    nodeNet->prg_getrandom(1, bytes, batch_size, buffer);
    memcpy(v, buffer, batch_size*bytes);
    nodeNet->prg_getrandom(0, bytes, batch_size, buffer);
    memcpy(v1, buffer, batch_size*bytes);
    
    uint i,j;
    int index;
    for (i = 0; i < size; i++) {
        index = i*batch_size;
        for(j = 0; j < batch_size; j++){
            c[0][index+j] = c[0][index+j]-v[j]+v1[j];
        }
    }

    delete[] v;
    delete[] v1;
    delete[] buffer;
}

//  For party 1, a[0,1]=a_2,3; b[0,1]=b_2,3;  c[0,1] = c_2,3;
//  For party 2, a[0,1]=a_3,1; b[0,1]=b_3,1;  c[0,1] = c_3,1;
//  For party 3, a[0,1]=a_1,2; b[0,1]=b_1,2;  c[0,1] = c_1,2;
void Rss_MultPub(Lint *c, Lint **a, Lint **b, uint size, uint ring_size, NodeNetwork *nodeNet) {
    uint i; // used for loops

    // uint bytes = (nodeNet->RING[ring_size] +7) >> 3;
    uint bytes = (ring_size + 7) >> 3;

    Lint **sendbuf = new Lint *[3];
    Lint **recvbuf = new Lint *[3];
    for (i = 0; i < 3; i++) {
        sendbuf[i] = new Lint[size];
        memset(sendbuf[i], 0, sizeof(Lint) * size);
        recvbuf[i] = new Lint[size];
        memset(recvbuf[i], 0, sizeof(Lint) * size);
    }

    int pid = nodeNet->getID();
    Lint *v = new Lint[size];
    Lint *v_a = new Lint[size];

    Lint opa = 0;
    Lint opb = 0;
    switch (pid) {
    case 1:
        opa = 1;
        opb = 1;
        break;
    case 2:
        opa = -1;
        opb = 1;
        break;
    case 3:
        opa = -1;
        opb = -1;
        break;
    }

    uint8_t *buffer = new uint8_t[bytes * size];
    nodeNet->prg_getrandom(0, bytes, size, buffer);
    for (i = 0; i < size; i++) {
        memcpy(v_a + i, buffer + i * bytes, bytes);
    }
    nodeNet->prg_getrandom(1, bytes, size, buffer);
    for (i = 0; i < size; i++) {
        memcpy(c + i, buffer + i * bytes, bytes);
    }

    for (i = 0; i < size; i++) {
        v[i] = a[0][i] * b[0][i] + a[0][i] * b[1][i] + a[1][i] * b[0][i];
        c[i] = v[i] + opb * c[i] + opa * v_a[i];
    }

    // communication
    // move data into buf
    for (i = 1; i <= 3; i++) {
        if (i == (uint)pid)
            continue;
        memcpy(sendbuf[i - 1], c, sizeof(Lint) * size);
    }

    nodeNet->multicastToPeers(sendbuf, recvbuf, size, ring_size);

    memcpy(v_a, recvbuf[nodeNet->map_3pc[0] - 1], sizeof(Lint) * size);
    memcpy(v, recvbuf[nodeNet->map_3pc[1] - 1], sizeof(Lint) * size);

    for (i = 0; i < size; i++) {
        // mask here
        c[i] = c[i] + v_a[i] + v[i];
        c[i] = c[i] & nodeNet->SHIFT[ring_size];
    }

    // free
    delete[] v;
    delete[] v_a;
    delete[] buffer;
    for (i = 0; i < 3; i++) {
        delete[] sendbuf[i];
        delete[] recvbuf[i];
    }
    delete[] sendbuf;
    delete[] recvbuf;
}
