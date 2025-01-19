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

#include "NodeNetwork.h"

NodeConfiguration *config;
AES_KEY *en, *de;
int MAX_BUFFER_SIZE = 229376; // in bytes
// int MAX_BUFFER_SIZE = 4194304;

std::map<int, AES_KEY *> peer2enlist;
std::map<int, AES_KEY *> peer2delist;
unsigned char *KeyIV;
unsigned char *peerKeyIV;

/************ STATIC VARIABLES INITIALIZATION ***************/
int NodeNetwork::mode = 0;              // -1 -- non-thread, 0 -- thread
int NodeNetwork::numOfChangedNodes = 0; // number of nodes that has changed modes so far
/************************************************************/

NodeNetwork::NodeNetwork(NodeConfiguration *nodeConfig, int nodeID, int num_threads, uint ring_size, uint num_parties, uint _threshold) {
    privatekeyfile = "private0" + std::to_string(nodeID) + ".pem";
    config = nodeConfig;
    connectToPeers();
    printf("connect done\n");
    numOfThreads = num_threads; // it should be read from parsing
    // int peers = config->getPeerCount();
    // int numb = 8 * sizeof(char);

    numParties = num_parties;
    threshold = _threshold;
    numShares = nCk(numParties - 1, threshold);  // shares PER PARTY
    totalNumShares = nCk(numParties, threshold); // total shares
    numBytesSent = 0;
    RING = ring_size; // setting last element to ring_size+2
    SHIFT = new Lint[ring_size + 22];
    ODD = new Lint[ring_size + 2];
    EVEN = new Lint[ring_size + 2];
    int pid = getID();

    for (Lint i = 0; i <= ring_size + 21; i++) {
        SHIFT[i] = (Lint(1) << Lint(i)) - Lint(1); // mod 2^i

        // this is needed to handle "undefined behavior" of << when we want
        // to shift by more than the size of the type (in bits)
        if (i == sizeof(Lint) * 8) {
            SHIFT[i] = -1;
        }
    }

    Lint temp = 0;
    for (Lint i = 0; i <= 8 * sizeof(Lint); i++) {
        temp = temp | Lint((i % 2 == 0));
        temp = temp << 1;
    }
    for (Lint i = 0; i < ring_size + 1; i++) {
        EVEN[i] = (temp >> 1) & SHIFT[i];
        ODD[i] = (temp)&SHIFT[i];
    }
    prg_setup();
    map_3pc[0] = ((pid + 2 - 1) % numParties + 1);
    map_3pc[1] = ((pid + 1 - 1) % numParties + 1);
    // init_index_array();
}

NodeNetwork::~NodeNetwork() {
    prg_clean();
    free(KeyIV);
    free(peerKeyIV);
    free(en);
    free(de);
    CRYPTO_cleanup_all_ex_data();
    // ERR_free_strings();
    // ERR_remove_state(0);
}

void NodeNetwork::sendDataToPeer(int id, uint size, Lint *data, uint flag) {
    // get rounds
    int peers = config->getPeerCount();
    uint count = MAX_BUFFER_SIZE / (peers + 1) / sizeof(Lint);
    uint rounds = (size + count - 1) / count - 1;
    AES_KEY *en_temp = peer2enlist[id];

    for (uint k = 0; k <= rounds; k++)
        sendDataToPeerEnc(id, data, k * count, count, size, en_temp);
}

// standard send/recv for 3pc
// uses fixed mapping, defined in constructor
void NodeNetwork::SendAndGetDataFromPeer(Lint *SendData, Lint *RecvData, uint size) {
    // compute the maximum size of data that can be communicated
    // get rounds
    int peers = config->getPeerCount();
    uint count = MAX_BUFFER_SIZE / (peers + 1) / sizeof(Lint);
    uint rounds = (size + count - 1) / count;
    int SendToID = map_3pc[0];
    int RecvFromID = map_3pc[1];
    AES_KEY *en_temp = peer2enlist[SendToID];
    AES_KEY *de_temp = peer2delist[RecvFromID];

    // printf("rounds = %u\n", rounds);
    // printf("count = %u\n", count);

    for (uint k = 0; k < rounds; k++) {
        sendDataToPeerEnc(SendToID, SendData, k * count, count, size, en_temp);
        getDataFromPeerDec(RecvFromID, RecvData, k * count, count, size, de_temp);
    }
    numBytesSent += size * sizeof(Lint);
}

// this is when we are sending to multiple peers and receiving from multiple peers
// this sends the same sendData to all sendtoIDs, but will receive DIFFERENT data from the recvfromIDs
// leverages the threshold member variable to know how many sendtoID's and recvfromIDs we have (this is sufficient for Mul and Open)

void NodeNetwork::SendAndGetDataFromPeer_Mult(int *sendtoIDs, int *RecvFromIDs, Lint *SendData, Lint **RecvData, uint size, uint flag) {
    // get rounds
    int peers = config->getPeerCount();
    uint count = MAX_BUFFER_SIZE / (peers + 1) / sizeof(Lint);
    uint rounds = (size + count - 1) / count - 1;

    for (int i = 0; i < threshold; i++) {
        AES_KEY *en_temp = peer2enlist[i];
        AES_KEY *de_temp = peer2delist[i];
        for (uint k = 0; k <= rounds; k++) {
            // printf("sendtoID   %u\n", sendtoIDs[i]);
            // for (int j = 0; j < size; j++) {
            //     printf("SendData[%i] --   %u\n", j, SendData[j]);
            // }

            sendDataToPeerEnc(sendtoIDs[i], SendData, k * count, count, size, en_temp);
            // printf("RecvFromIDs  %u\n", RecvFromIDs[i]);
            getDataFromPeerDec(RecvFromIDs[i], RecvData[i], k * count, count, size, de_temp);
            // for (int j = 0; j < size; j++) {
            //     printf("RecvData[%i][%i] --   %u\n", i, j, RecvData[i][j]);
            // }
        }
    }
    numBytesSent += size * sizeof(Lint) * threshold;
}

void NodeNetwork::getDataFromPeer(int id, uint size, Lint *buffer, uint flag) {
    // get rounds
    int peers = config->getPeerCount();
    uint count = MAX_BUFFER_SIZE / (peers + 1) / sizeof(Lint);
    uint rounds = (size + count - 1) / count - 1;
    memset(buffer, 0, sizeof(Lint) * size);
    AES_KEY *de_temp = peer2delist[id];
    for (uint k = 0; k <= rounds; k++)
        getDataFromPeerDec(id, buffer, k * count, count, size, de_temp);
}

void NodeNetwork::sendDataToPeerEnc(int id, Lint *data, uint start, uint amount, uint size, AES_KEY *en_temp) {
    try {
        uint read_amount = (start + amount > size) ? size - start : amount;
        uint buffer_size = sizeof(Lint) * read_amount;
        unsigned char *buffer = (unsigned char *)malloc(sizeof(unsigned char) * buffer_size);
        memcpy(buffer, data+start, buffer_size);
        unsigned char *encrypted = aes_encrypt(en_temp, buffer, &buffer_size);
        sendDataToPeer(id, 1, &buffer_size);
        sendDataToPeer(id, buffer_size, encrypted);
        free(buffer);
        free(encrypted);
    } catch (std::exception &e) {
        std::cout << "An exception (in Send Data To Peer) was caught: " << e.what() << "\n";
    }
}

void NodeNetwork::sendDataToPeer(int id, uint size, unsigned char *data) {
    try {
        unsigned char *p = data;
        int bytes_read = sizeof(unsigned char) * size;
        int sockfd = peer2sock[id];
        fd_set fds;
        while (bytes_read > 0) {
            int bytes_written = send(sockfd, p, bytes_read, MSG_DONTWAIT);
            if (bytes_written < 0) {
                FD_ZERO(&fds);
                FD_SET(sockfd, &fds);
                int n = select(sockfd + 1, NULL, &fds, NULL, NULL);
                if (n > 0)
                    continue;
            } else {
                bytes_read -= bytes_written;
                p += bytes_written;
            }
        }
    } catch (std::exception &e) {
        std::cout << "An exception (in Send Data To Peer) was caught: " << e.what() << "\n";
    }
}

void NodeNetwork::sendDataToPeer(int id, uint size, uint *data) {
    try {
        uint *p = data;
        int bytes_read = sizeof(uint) * size;
        int sockfd = peer2sock[id];
        fd_set fds;
        while (bytes_read > 0) {
            int bytes_written = send(sockfd, p, bytes_read, MSG_DONTWAIT);
            if (bytes_written < 0) {
                FD_ZERO(&fds);
                FD_SET(sockfd, &fds);
                int n = select(sockfd + 1, NULL, &fds, NULL, NULL);
                if (n > 0)
                    continue;
            } else {
                bytes_read -= bytes_written;
                p += (bytes_written / sizeof(uint));
            }
        }
    } catch (std::exception &e) {
        std::cout << "An exception (in Send Data To Peer) was caught: " << e.what() << "\n";
    }
}

void NodeNetwork::getDataFromPeer(int id, uint size, uint *buffer) {
    try {
        uint length = 0;
        int rbytes = 0;
        int total_length = sizeof(uint) * size;
        uint *tmp_buffer = (uint *)malloc(total_length);
        //memset(tmp_buffer, 0, total_length);
        fd_set fds;
        int sockfd = peer2sock[id];
        while (length < total_length) {
            rbytes = recv(sockfd, tmp_buffer, total_length - length, MSG_DONTWAIT);
            if (rbytes < 0) {
                FD_ZERO(&fds);
                FD_SET(sockfd, &fds);
                int n = select(sockfd + 1, &fds, NULL, NULL, NULL);
                if (n > 0)
                    continue;
            } else {
                memcpy(&buffer[length / sizeof(uint)], tmp_buffer, rbytes);
                length += rbytes;
            }
        }
        free(tmp_buffer);
    } catch (std::exception &e) {
        std::cout << "An exception (get Data From Peer) was caught: " << e.what() << "\n";
    }
}

void NodeNetwork::getDataFromPeer(int id, uint size, unsigned char *buffer) {
    try {
        uint length = 0;
        int rbytes = 0;
        int total_length = sizeof(unsigned char) * size;
        unsigned char *tmp_buffer = (unsigned char *)malloc(total_length);
        fd_set fds;
        int sockfd = peer2sock[id];
        while (length < total_length) {
            rbytes = recv(sockfd, tmp_buffer, total_length - length, MSG_DONTWAIT);
            if (rbytes < 0) {
                FD_ZERO(&fds);
                FD_SET(sockfd, &fds);
                int n = select(sockfd + 1, &fds, NULL, NULL, NULL);
                if (n > 0)
                    continue;
            } else {
                memcpy(&buffer[length], tmp_buffer, rbytes);
                length += rbytes;
            }
        }
        free(tmp_buffer);
    } catch (std::exception &e) {
        std::cout << "An exception (get Data From Peer) was caught: " << e.what() << "\n";
    }
}

void NodeNetwork::getDataFromPeerDec(int id, Lint *data, uint start, uint amount, uint size, AES_KEY *de_temp) {
    try {
        uint write_amount = (start + amount > size) ? size - start :  amount;
        uint length = 0;
        getDataFromPeer(id, 1, &length);
        unsigned char *buffer = (unsigned char *)malloc(sizeof(unsigned char) * length);
        getDataFromPeer(id, length, buffer);
        unsigned char *decrypted = aes_decrypt(de_temp, buffer, &length);
        memcpy(data+start, decrypted, sizeof(Lint) * write_amount);

        free(buffer);
        free(decrypted);
    } catch (std::exception &e) {
        std::cout << "An exception (get Data From Peer) was caught: " << e.what() << "\n";
    }
}

void NodeNetwork::multicastToPeers(Lint **data, Lint **buffers, uint size, uint flag) {
    int id = getID();
    int peers = config->getPeerCount();

    // compute the maximum size of data that can be communicated
    // get rounds
    uint count = MAX_BUFFER_SIZE / (peers + 1) / sizeof(Lint);
    uint rounds = (size + count - 1) / count - 1;
    // memset(buffer,0,sizeof(Lint)*size);

    for (uint k = 0; k <= rounds; k++) {

        for (int j = 1; j <= peers + 1; j++) {
            if (id == j)
                continue;
            AES_KEY *en_temp = peer2enlist[j];
            sendDataToPeerEnc(j, data[j - 1], k * count, count, size, en_temp);
            // printf("sending to %u\n", j);
        }
        for (int j = 1; j <= peers + 1; j++) {
            if (id == j)
                continue;
            AES_KEY *de_temp = peer2delist[j];
            getDataFromPeerDec(j, buffers[j - 1], k * count, count, size, de_temp);
            // printf("receiving from %u\n", j);
        }
    }
    numBytesSent += size * sizeof(Lint) * peers;
}

void NodeNetwork::connectToPeers() {
    int peers = config->getPeerCount();
    for (int i = 1; i <= peers + 1; i++)
        if (config->getID() == i) {
            if (i != (peers + 1))
                requestConnection(peers + 1 - i);
            if (i != 1)
                acceptPeers(i - 1);
        }
}

void NodeNetwork::requestConnection(int numOfPeers) {
    peerKeyIV = (unsigned char *)malloc(32); // freed in destructor
    int *sockfd = (int *)malloc(sizeof(int) * numOfPeers);
    int *portno = (int *)malloc(sizeof(int) * numOfPeers);
    struct sockaddr_in *serv_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in) * numOfPeers);
    struct hostent **server = (struct hostent **)malloc(sizeof(struct hostent *) * numOfPeers);
    int on = 1;

    for (int i = 0; i < numOfPeers; i++) {
        int ID = config->getID() + i + 1;
        portno[i] = config->getPeerPort(ID);
        sockfd[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd[i] < 0){
            perror("ERROR, opening socket");
        }
        // the function below might not work in certain
        // configurations, e.g., running all nodes from the
        // same VM. it is not used for single-threaded programs
        // and thus be commented out or replaced with an
        // equivalent function otherwise.
        fcntl(sockfd[i], F_SETFL);
        setsockopt(sockfd[i], SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
        setsockopt(sockfd[i], IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on));
        server[i] = gethostbyname((config->getPeerIP(ID)).c_str());
        if (server[i] == NULL)
            fprintf(stderr, "ERROR, no such hosts \n");
        bzero((char *)&serv_addr[i], sizeof(serv_addr[i]));
        serv_addr[i].sin_family = AF_INET;
        bcopy((char *)server[i]->h_addr, (char *)&serv_addr[i].sin_addr.s_addr, server[i]->h_length);
        serv_addr[i].sin_port = htons(portno[i]);

        int res, valopt = -1;
        fd_set myset;
        struct timeval tv;
        socklen_t lon;
        res = connect(sockfd[i], (struct sockaddr *)&serv_addr[i], sizeof(serv_addr[i]));
        if (res < 0) {
            if (errno == EINPROGRESS) {
                tv.tv_sec = 15;
                tv.tv_usec = 0;
                FD_ZERO(&myset);
                FD_SET(sockfd[i], &myset);
                if (select(sockfd[i] + 1, NULL, &myset, NULL, &tv) > 0) {
                    lon = sizeof(int);
                    getsockopt(sockfd[i], SOL_SOCKET, SO_ERROR, (void *)(&valopt), &lon);
                    if (valopt) {
                        fprintf(stderr, "Error in connection() %d - %s\n", valopt, strerror(valopt));
                        exit(0);
                    }
                } else {
                    fprintf(stderr, "Timeout or error() %d - %s\n", valopt, strerror(valopt));
                    exit(0);
                }
            } else {
                fprintf(stderr, "Error connecting %d - %s\n", errno, strerror(errno));
                exit(0);
            }
        }
        printf("Connected to node %d\n", ID);
        peer2sock.insert(std::pair<int, int>(ID, sockfd[i]));
        sock2peer.insert(std::pair<int, int>(sockfd[i], ID));

        FILE *prikeyfp = fopen(privatekeyfile.c_str(), "r");
        if (prikeyfp == NULL)
            printf("File Open %s error\n", privatekeyfile.c_str());
        RSA *priRkey = PEM_read_RSAPrivateKey(prikeyfp, NULL, NULL, NULL);
        if (priRkey == NULL)
            printf("Read Private Key for RSA Error\n");
        char *buffer = (char *)malloc(RSA_size(priRkey));
        int n = read(sockfd[i], buffer, RSA_size(priRkey));
        if (n < 0)
            printf("ERROR reading from socket \n");
        char *decrypt = (char *)malloc(n);
        memset(decrypt, 0x00, n);
        int dec_len = RSA_private_decrypt(n, (unsigned char *)buffer, (unsigned char *)decrypt, priRkey, RSA_PKCS1_OAEP_PADDING);
        if (dec_len < 1)
            printf("RSA private decrypt error\n");
        memcpy(peerKeyIV, decrypt, 32);
        init_keys(ID, 1);
        free(buffer);
        free(decrypt);
        fclose(prikeyfp);
    }

    // free(sockfd);
    free(portno);
    free(serv_addr);
    for (int i = 0; i < numOfPeers; i++) {
        // free(server[i]);
    }
    // free(server);
}

void NodeNetwork::acceptPeers(int numOfPeers) {
    KeyIV = (unsigned char *)malloc(32);
    int sockfd, maxsd, portno, on = 1;
    int *newsockfd = (int *)malloc(sizeof(int) * numOfPeers);
    socklen_t *clilen = (socklen_t *)malloc(sizeof(socklen_t) * numOfPeers);
    struct sockaddr_in serv_addr;
    struct sockaddr_in *cli_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in) * numOfPeers);

    fd_set master_set, working_set;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    // see comment for fcntl above
    fcntl(sockfd, F_SETFL);
    if (sockfd < 0)
        fprintf(stderr, "ERROR, opening socket\n");
    int rc = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on));
    rc = setsockopt(sockfd, IPPROTO_TCP, TCP_NODELAY, (char *)&on, sizeof(on));
    if (rc < 0)
        printf("setsockopt() or ioctl() failed\n");
    bzero((char *)&serv_addr, sizeof(serv_addr));
    // printf("getting port\n");
    portno = config->getPort();
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);
    // printf("binding\n");
    if ((bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr))) < 0)
        printf("ERROR, on binding \n");
    // printf("listening\n");
    listen(sockfd, 7);
    // start to accept connections
    // printf("fd_zero\n");
    FD_ZERO(&master_set);
    maxsd = sockfd;
    // printf("fd_set\n");
    FD_SET(sockfd, &master_set);
    // printf("fd_set\n");
    // printf("looping through peers\n");
    for (int i = 0; i < numOfPeers; i++) {
        memcpy(&working_set, &master_set, sizeof(master_set));
        rc = select(maxsd + 1, &working_set, NULL, NULL, NULL);
        if (rc <= 0)
            printf("select failed or time out \n");
        if (FD_ISSET(sockfd, &working_set)) {
            clilen[i] = sizeof(cli_addr[i]);
            newsockfd[i] = accept(sockfd, (struct sockaddr *)&cli_addr[i], &clilen[i]);
            if (newsockfd[i] < 0)
                fprintf(stderr, "ERROR, on accept\n");
            // see comment for fcntl above
            fcntl(newsockfd[i], F_SETFL);
            peer2sock.insert(std::pair<int, int>(config->getID() - (i + 1), newsockfd[i]));
            sock2peer.insert(std::pair<int, int>(newsockfd[i], config->getID() - (i + 1)));

            unsigned char key_iv[32];
            // printf("checking rand_Status\n");
            RAND_status();
            if (!RAND_bytes(key_iv, 32))
                printf("Key, iv generation error\n");
            memcpy(KeyIV, key_iv, 32);
            int peer = config->getID() - (i + 1);
            FILE *pubkeyfp = fopen((config->getPeerPubKey(peer)).c_str(), "r");
            if (pubkeyfp == NULL)
                printf("File Open %s error \n", (config->getPeerPubKey(peer)).c_str());
            RSA *publicRkey = PEM_read_RSA_PUBKEY(pubkeyfp, NULL, NULL, NULL);
            if (publicRkey == NULL)
                printf("Read Public Key for RSA Error\n");
            char *encrypt = (char *)malloc(RSA_size(publicRkey));
            memset(encrypt, 0x00, RSA_size(publicRkey));
            int enc_len = RSA_public_encrypt(32, KeyIV, (unsigned char *)encrypt, publicRkey, RSA_PKCS1_OAEP_PADDING);
            if (enc_len < 1)
                printf("RSA public encrypt error\n");
            int n = write(newsockfd[i], encrypt, enc_len);
            if (n < 0)
                printf("ERROR writing to socket \n");
            init_keys(peer, 0);
            free(encrypt);
            fclose(pubkeyfp);
        }
    }
    free(newsockfd);
    free(clilen);
    free(cli_addr);
}

void NodeNetwork::init_keys(int peer, int nRead) {
    unsigned char key[16];
    memset(key, 0x00, 16);
    if (0 == nRead) // useKey KeyIV
    {
        memcpy(key, KeyIV, 16);
    } else // getKey from peers
    {
        memcpy(key, peerKeyIV, 16);
    }
    en = (AES_KEY*) malloc(sizeof(AES_KEY)); 
    aesni_set_encrypt_key(key, 128, en);

    de = (AES_KEY*) malloc(sizeof(AES_KEY)); 
    aesni_set_decrypt_key(key, 128, de);
    peer2enlist.insert(std::pair<int, AES_KEY *>(peer, en));
    peer2delist.insert(std::pair<int, AES_KEY *>(peer, de));
}

int NodeNetwork::getID() {
    return config->getID();
}

unsigned char *NodeNetwork::aes_encrypt(AES_KEY *aes_key, unsigned char *plaintext, uint *len) {
    int c_len = *len + AES_BLOCK_SIZE;
    unsigned char *ciphertext = (unsigned char *)malloc(c_len);

    #pragma omp parallel for
    for (uint i = 0; i < *len; i += AES_BLOCK_SIZE) {
        aesni_encrypt(plaintext + i, ciphertext + i, aes_key);
    }

    return ciphertext;
}

unsigned char *NodeNetwork::aes_decrypt(AES_KEY *aes_key, unsigned char *ciphertext, uint *len) {
    int p_len = *len + AES_BLOCK_SIZE;
    unsigned char *plaintext = (unsigned char *)malloc(p_len);

    #pragma omp parallel for
    for (uint i = 0; i < *len; i += AES_BLOCK_SIZE) {
        aesni_decrypt(ciphertext + i, plaintext + i, aes_key);
    }

    return plaintext;
}

__m128i *NodeNetwork::prg_keyschedule(uint8_t *src) {
    __m128i *r = (__m128i *)malloc(11 * sizeof(__m128i));

    r[0] = _mm_load_si128((__m128i *)src);

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

void NodeNetwork::prg_aes(uint8_t *dest, uint8_t *src, __m128i *ri) {
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

void NodeNetwork::prg_setup() {
    // need to create numShares+1 keys, random containers, etc
    uint numKeys = numShares + 1;
    random_container = new uint8_t *[numKeys];
    for (uint i = 0; i < numKeys; i++) {
        random_container[i] = new uint8_t[16];
        memset(random_container[i], 0, sizeof(uint8_t) * 16);
    }

    prg_key = new __m128i *[numKeys];

    uint8_t tempKey_A[16];
    uint8_t tempKey_B[16];
    uint8_t tempKey_C[16]; // USED FOR OFFLINE, INDEPENDENT GENERATION

    uint8_t **tempKey = new uint8_t *[numKeys];
    for (uint i = 0; i < numKeys; i++) {
        tempKey[i] = new uint8_t[16];
    }

    uint8_t RandomData[64];
    FILE *fp = fopen("/dev/urandom", "r");
    // reading 48 bits to generate 2 keys
    // last 16 are to seed private key
    // increaseing to 48 so each party has a private key
    // that will be used for offline prg_aes_ni (non-interactive)
    if (fread(RandomData, 1, 64, fp) != 64) {
        fprintf(stderr, "Could not read random bytes.");
        exit(1);
    }
    fclose(fp);

    memcpy(random_container[0], RandomData, 16);
    memcpy(tempKey_A, RandomData + 16, 16);
    memcpy(tempKey_C, RandomData + 32, 16);
    memcpy(random_container[2], RandomData + 48, 16);

    int pid = getID();

    // sending to i + 2 mod n
    // receiving from i + 1 mod n
    // this depends on the threshold?
    // but we end up with two keys - one we generate and send, and one we receive
    int map[2];
    switch (pid) {
    case 1:
        map[0] = 3;
        map[1] = 2;
        break;
    case 2:
        map[0] = 1;
        map[1] = 3;
        break;
    case 3:
        map[0] = 2;
        map[1] = 1;
        break;
    }

    sendDataToPeer(map[0], 32, RandomData);
    getDataFromPeer(map[1], 32, RandomData);

    memcpy(random_container[1], RandomData, 16);
    memcpy(tempKey_B, RandomData + 16, 16);

    prg_key[0] = prg_keyschedule(tempKey_A);
    prg_key[1] = prg_keyschedule(tempKey_B);
    prg_key[2] = prg_keyschedule(tempKey_C);

    uint8_t res[16] = {};
    for (size_t i = 0; i < numKeys; i++) {
        prg_aes(res, random_container[i], prg_key[i]);
        memcpy(random_container[i], res, 16);
    }

    P_container = new int[numKeys];
    memset(P_container, 0, sizeof(int) * numKeys);

    container_size = 16;
    printf("prg setup\n");

    for (uint i = 0; i < numKeys; i++) {
        delete[] tempKey[i];
    }
    delete[] tempKey;
}

// This func no only cleans prg stuff, it will also take care of other things
void NodeNetwork::prg_clean() {
    for (uint i = 0; i < numShares + 1; i++) {
        delete[] random_container[i];
        free(prg_key[i]);
    }

    // delete[] index_array;
    delete[] random_container;
    delete[] prg_key;
    delete[] P_container;

    // delete [] RING;
    delete[] SHIFT;
    delete[] ODD;
    delete[] EVEN;
    printf("prg cleanup\n");
}

void NodeNetwork::prg_getrandom(int keyID, uint size, uint length, uint8_t *dest) {
    // we assume container_size is 16, so all *container_size are replaced as <<4
    // this size means how many random bytes we need
    // uint8_t *buffer = new uint8_t [size];
    // its always size * length
    // printf("curent P is %d \n",P_container[keyID]);
    uint rounds = ((size * length - container_size + P_container[keyID]) + 15) >> 4;
    // printf("rounds %u\n", rounds);
    if (rounds == 0) {
        memcpy(dest, random_container[keyID] + P_container[keyID], size * length);
        P_container[keyID] += size * length;
    } else {
        uint32_t offset = container_size - P_container[keyID];
        memcpy(dest, random_container[keyID] + P_container[keyID], offset);
        if (rounds >= 2) {
            prg_aes(dest + offset, random_container[keyID], prg_key[keyID]);
            for (uint i = 1; i < rounds - 1; i++) {
                // segfault in this loop for "large" size
                // printf("i : %u\n", i);
                prg_aes(dest + offset + (i << 4), dest + offset + ((i - 1) << 4), prg_key[keyID]);
            }
            prg_aes(random_container[keyID], dest + offset + ((rounds - 2) << 4), prg_key[keyID]);
            P_container[keyID] = size * length - ((rounds - 1) << 4) - offset;
            memcpy(dest + offset + ((rounds - 1) << 4), random_container[keyID], P_container[keyID]);
        } else {
            prg_aes(random_container[keyID], random_container[keyID], prg_key[keyID]);
            memcpy(dest + offset, random_container[keyID], size * length - offset);
            P_container[keyID] = size * length - offset;
        }
    }
}

void NodeNetwork::SendAndGetDataFromPeer_bit_Mult(int *sendtoIDs, int *RecvFromIDs, uint8_t *SendData, uint8_t **RecvData, uint size) {
    // sizes means number of bytes
    // compute the maximum size of data that can be communicated
    uint count = 0, rounds = 0;
    getRounds_bit(size, &count, &rounds);
    // printf("rounds = %u\n", rounds);

    for (int i = 0; i < threshold; i++) {
        for (uint k = 0; k <= rounds; k++) {
            // printf("sendtoID   %u\n",sendtoIDs[i]);
            sendDataToPeer_bit(sendtoIDs[i], SendData, k * count, count, size);
            // printf("RecvFromIDs  %u\n",RecvFromIDs[i]);
            getDataFromPeer_bit(RecvFromIDs[i], RecvData[i], k * count, count, size);
        }
    }
    numBytesSent += size * threshold;
}

// below funcs are added for bit operation
void NodeNetwork::SendAndGetDataFromPeer_bit(int sendtoID, int RecvFromID, uint8_t *SendData, uint8_t *RecvData, uint size) {
    // sizes means number of bytes
    // compute the maximum size of data that can be communicated
    uint count = 0, rounds = 0;
    getRounds_bit(size, &count, &rounds);
    // printf("rounds = %u\n", rounds);

    for (uint k = 0; k <= rounds; k++) {
        sendDataToPeer_bit(sendtoID, SendData, k * count, count, size);
        getDataFromPeer_bit(RecvFromID, RecvData, k * count, count, size);
    }
    numBytesSent += size * threshold;
}

void NodeNetwork::SendAndGetDataFromPeer_bit(uint8_t *SendData, uint8_t *RecvData, uint size) {
    // sizes means number of bytes
    // compute the maximum size of data that can be communicated
    uint count = 0, rounds = 0;
    getRounds_bit(size, &count, &rounds);
    // printf("rounds = %u\n", rounds);

    for (uint k = 0; k <= rounds; k++) {
        sendDataToPeer_bit(map_3pc[0], SendData, k * count, count, size);
        getDataFromPeer_bit(map_3pc[1], RecvData, k * count, count, size);
    }
    numBytesSent += size * threshold;
}

void NodeNetwork::sendDataToPeer_bit(int id, uint8_t *data, int start, uint amount, uint size) {
    try {
        int read_amount = 0;
        if (start + amount > size)
            read_amount = size - start;
        else
            read_amount = amount;
        int unit_size = 1;
        uint buffer_size = unit_size * read_amount;
        char *buffer = (char *)malloc(sizeof(char) * buffer_size);
        char *pointer = buffer;
        memset(buffer, 0, buffer_size);
        memcpy(pointer, &data[start], unit_size * read_amount);

        AES_KEY *en_temp = peer2enlist[id];
        unsigned char *encrypted = aes_encrypt(en_temp, (unsigned char *)buffer, &buffer_size);
        sendDataToPeer(id, 1, &buffer_size);
        sendDataToPeer(id, buffer_size, encrypted);
        free(buffer);
        free(encrypted);
    } catch (std::exception &e) {
        std::cout << "An exception (in Send Data To Peer) was caught: " << e.what() << "\n";
    }
}

void NodeNetwork::getDataFromPeer_bit(int id, uint8_t *data, uint start, uint amount, uint size) {
    try {
        int write_amount = 0;
        if (start + amount > size)
            write_amount = size - start;
        else
            write_amount = amount;
        int unit_size = 1;
        uint length = 0;
        getDataFromPeer(id, 1, &length);
        char *buffer = (char *)malloc(sizeof(char) * length);
        getDataFromPeer(id, length, (unsigned char *)buffer);
        AES_KEY *de_temp = peer2delist[id];
        char *decrypted = (char *)aes_decrypt(de_temp, (unsigned char *)buffer, &length);
        memset(&data[start], 0, sizeof(uint8_t) * write_amount);
        memcpy(&data[start], decrypted, unit_size * write_amount);
        free(buffer);
        free(decrypted);

    } catch (std::exception &e) {
        std::cout << "An exception (get Data From Peer) was caught: " << e.what() << "\n";
    }
}

void NodeNetwork::getRounds_bit(uint size, uint *count, uint *rounds) // size means number of bytes
{

    int peers = config->getPeerCount();
    *count = MAX_BUFFER_SIZE / (peers + 1);
    *rounds = (size + *count - 1) / *count - 1;
}

uint NodeNetwork::nCk(uint n, uint k) {

    if (k > n) {
        printf("Error: n must be >= k\n");
        return -1;
    } else {
        uint res = 1;
        // Since C(n, k) = C(n, n-k)
        if (k > n - k) {
            k = n - k;
        }
        // Calculate value of
        // [n * (n-1) *---* (n-k+1)] / [k * (k-1) *----* 1]
        for (uint i = 0; i < k; ++i) {
            res *= ((uint)n - i);
            res /= (i + (uint)1);
        }
        return res;
    }
}
