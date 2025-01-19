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

#ifndef NODENETWORK_H_
#define NODENETWORK_H_

#include "NodeConfiguration.h"
#include "ThreadPool.h"
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <iostream>
#include <map>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "openssl-aes.h"
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdint.h> //for int8_t
#include <stdio.h>
#include <string.h> //for memcmp
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <tmmintrin.h>
#include <unistd.h>
#include <vector>
#include <omp.h>
#include <wmmintrin.h> //for intrinsics for AES-NI
#include <x86intrin.h>

// #define GET_BIT(X, N) ( ( (X) >> (N) ) & Lint(1) ) //doesn't need to be Lint for AND
// #define RST_BIT(X, N) ( (X) & ~(Lint(1) << (N) ) )
// #define SET_BIT(X, N, B) (X & ~(Lint(1) << N)) | (B << N)

#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_RESET "\x1b[0m"
#define ANSI_COLOR_GREEN "\x1b[32m"
#define ANSI_COLOR_YELLOW "\033[33m"

#define KE2(NK, OK, RND)                           \
    NK = OK;                                       \
    NK = _mm_xor_si128(NK, _mm_slli_si128(NK, 4)); \
    NK = _mm_xor_si128(NK, _mm_slli_si128(NK, 4)); \
    NK = _mm_xor_si128(NK, _mm_slli_si128(NK, 4)); \
    NK = _mm_xor_si128(NK, _mm_shuffle_epi32(_mm_aeskeygenassist_si128(OK, RND), 0xff));

class NodeNetwork {
public:
    NodeNetwork(NodeConfiguration *nodeConfig, int nodeID, int num_threads, uint ring_size, uint num_parties, uint threshold);
    virtual ~NodeNetwork();

    // Send round data to a specific peer
    void sendDataToPeerEnc(int, Lint *, uint, uint, uint, AES_KEY*);
    void sendDataToPeer(int, uint, uint *);
    void sendDataToPeer(int, uint, unsigned char *);
    void sendDataToPeer(int, uint, Lint *, uint);
    
    // Get round data from a specific peer
    void getDataFromPeerDec(int, Lint *, uint, uint, uint, AES_KEY*);
    void getDataFromPeer(int, uint, uint *);
    void getDataFromPeer(int, uint, unsigned char *);
    void getDataFromPeer(int, uint, Lint *, uint);
    // void getDataFromPeer(int, int, long long*);

    void SendAndGetDataFromPeer(Lint *, Lint *, uint);
    void SendAndGetDataFromPeer_Mult(int *, int *, Lint *, Lint **, uint, uint);

    void multicastToPeers(Lint **, Lint **, uint, uint);

    void SendAndGetDataFromPeer_bit(int, int, uint8_t *, uint8_t *, uint);
    void SendAndGetDataFromPeer_bit(uint8_t *, uint8_t *, uint);
    void SendAndGetDataFromPeer_bit_Mult(int *, int *, uint8_t *, uint8_t **, uint);

    void sendDataToPeer_bit(int, uint8_t *, int, uint, uint);
    void getDataFromPeer_bit(int, uint8_t *, uint, uint, uint);
    void getRounds_bit(uint, uint *, uint *);

    void init_index_array();

    // Get the ID of the compute Node
    int getID();
    int getNumOfThreads();
    int getNumParties();
    int getThreshold();
    uint getNumShares();
    uint getTotalNumShares();
    unsigned long getCommunicationInBytes();
    void resetCommunication();

    // Encryption and Decryption
    void init_keys(int peer, int nRead);
    void gen_keyiv();
    void get_keyiv(char *key_iv);
    unsigned char *aes_encrypt(AES_KEY *aes_key, unsigned char *plaintext, uint *len);
    unsigned char *aes_decrypt(AES_KEY *aes_key, unsigned char *ciphertext, uint *len);

    // PRG
    void prgtest();
    __m128i *prg_keyschedule(uint8_t *);
    void prg_aes(uint8_t *, uint8_t *, __m128i *);
    void prg_setup();
    void prg_clean();
    void prg_getrandom(int keyID, uint size, uint length, uint8_t *dest);
    uint nCk(uint n, uint k);

    Lint *SHIFT;
    Lint *ODD;
    Lint *EVEN;
    uint RING;
    int map_3pc[2];

private:
    static int mode;
    static int numOfChangedNodes;
    static int isManagerAwake;

    int numOfThreads;
    void connectToPeers();
    void requestConnection(int);
    void acceptPeers(int);
    std::map<int, int> peer2sock;
    std::map<int, int> sock2peer;
    int serverSock;

    int numParties;      // n
    int threshold;       // t
    uint numShares;      // (n-1) choose t
    uint totalNumShares; // n choose t

    std::string privatekeyfile;

    uint8_t **random_container;
    int container_size;
    int *P_container;
    __m128i **prg_key;

    unsigned long numBytesSent; // used to measure communication
};

inline int NodeNetwork::getNumParties() {
    return numParties;
}

inline int NodeNetwork::getThreshold() {
    return threshold;
}

inline int NodeNetwork::getNumOfThreads() {
    return numOfThreads;
}

inline uint NodeNetwork::getNumShares() {
    return numShares;
}

inline uint NodeNetwork::getTotalNumShares() {
    return totalNumShares;
}

inline unsigned long NodeNetwork::getCommunicationInBytes() {
    return numBytesSent;
}

inline void NodeNetwork::resetCommunication() {
    numBytesSent = 0;
}

#endif /* NODENETWORK_H_ */
