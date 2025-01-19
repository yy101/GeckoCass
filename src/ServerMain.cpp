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

#include "ServerMain.h"

NodeConfiguration *nodeConfig;
NodeNetwork *nNet;

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Incorrect input parameters\n");
        fprintf(stderr, "Usage: <id> <runtime-config> <parameters>\n");
        exit(1);
    }
    nodeConfig = new NodeConfiguration(atoi(argv[1]), argv[2], 128);
    std::cout << "Creating the NodeNetwork" << endl;
    printf("peer count = %u\n", nodeConfig->getPeerCount());
    uint numPeers = nodeConfig->getPeerCount();

    uint num_parties = numPeers + 1;
    uint threshold = num_parties / 2;
    std::ifstream configFile(argv[3]);
    if (!configFile.is_open()) {
        throw std::runtime_error("Could not open config file");
    }

    nlohmann::json jsonConfig;
    configFile >> jsonConfig;

    int thread_num = jsonConfig.at("thread_num").get<int>();
    bool malicious = jsonConfig.at("malicious").get<bool>();
    uint ring_size = jsonConfig.at("ring_size").get<uint>();
    uint batch_size = jsonConfig.at("vector_size").get<uint>();
    uint size = pow(2, jsonConfig.at("data_size (2^x)").get<int>());
    string IP = jsonConfig.at("Cass_IP").get<string>();
    string dc = jsonConfig.at("dc").get<string>();
    cout << "port = " << nodeConfig->getPort() << endl;
    cout << "num_parties = " << num_parties << endl;
    cout << "threshold = " << threshold << endl;
    cout << "thread_num = " << thread_num << endl;
    cout << "malicious = " << malicious << endl;
    cout << "ring_size = " << ring_size << endl;
    cout << "size = " << size << endl;
    cout << "batch_size = " << batch_size << endl;
    cout << "dc = " << dc << endl;

    nNet = new NodeNetwork(nodeConfig, atoi(argv[1]), 1, ring_size, num_parties, threshold);
    startServer(IP, nodeConfig->getPort()+10000, num_parties, size, batch_size, thread_num, malicious, dc);

    delete nodeConfig;
    return 0;
}

void startServer(string IP, int port, uint num_parties, uint size, uint batch_size, int thread_num, bool malicious, string dc) {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    int optval = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        perror("setsockopt failed");
        close(serverSocket);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);
    if(bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr))){
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    listen(serverSocket, 5);

    LibCass *cass = new LibCass();
    cass->connect(nodeConfig->getID(), IP, dc);

    uint8_t key_raw[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    __m128i* key_prg_ver = offline_prg_keyschedule(key_raw);

    omp_set_num_threads(thread_num);
    ThreadPool* pool = new ThreadPool(thread_num);

    char databuffer[4194304];
    char* receivedData;
    char* response;
    uint8_t *key = new uint8_t[16];

    uint32_t eax, ebx, ecx, edx;
    eax = ebx = ecx = edx = 0;
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);

    struct timeval start, end;
    unsigned long timer;
    int response_length, dataLength, currentLength;
    vector<string> subparams;
    string subparam;
    
    while (true) {
        generateCommonKey(key, nNet->RING, nNet);
        nNet->resetCommunication();
        int clientSocket = accept(serverSocket, nullptr, nullptr);
        if (clientSocket >= 0) {
            int bytesRead = read(clientSocket, &dataLength, sizeof(dataLength));
            //cout << dataLength << endl;
            if (bytesRead > 0) {
                receivedData = new char[dataLength];
                //memset(receivedData, 0, length);
                currentLength = 0;
                while(currentLength < dataLength){
                    //memset(databuffer, 0, 4194304);
                    bytesRead = read(clientSocket, databuffer, sizeof(databuffer));
                    //cout << bytesRead << endl;
                    if (bytesRead) {
                        memcpy(receivedData+currentLength, databuffer, bytesRead);
                        currentLength += bytesRead;
                    }
                }

                int request_length = 0;
                memcpy(&request_length, receivedData, sizeof(request_length));
                std::string receivedParam(receivedData+sizeof(request_length), receivedData+sizeof(request_length)+request_length+1);
                istringstream tokenStream(receivedParam);
                
                // 分割字符串
                while (getline(tokenStream, subparam, '!')) {
                    subparams.emplace_back(subparam);
                }

                // Process data
                response_length = 0;
                gettimeofday(&start, NULL);    // start timer here
                server_main(cass, num_parties, size, batch_size, subparams, receivedData+sizeof(request_length)+request_length, key_prg_ver, response, response_length, key, ecx, pool, thread_num, malicious);
                gettimeofday(&end, NULL);     // stop timer here
                timer = 1e6 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
                printf("server_main size: %i, cost: %.6lf ms,  %lu bytes\n", size, (double)(timer * 0.001), nNet->getCommunicationInBytes());

                // Send response
                if(response_length){
                    send(clientSocket, &response_length, sizeof(response_length), 0);
                    send(clientSocket, response, response_length, 0);
                }
                
                if(dataLength) {
                    delete[] receivedData;
                }
                if(response_length){
                    delete[] response;
                }
                subparams.clear();
            }
            close(clientSocket);
        }
    }
    close(serverSocket);
    //释放资源
    cass->disconnect();
    delete cass;
    delete[] key;
    delete pool;
    free(key_prg_ver);
}

void server_main(LibCass *cass, uint num_parties, uint size, uint batch_size, vector<string> subparams, char* Data, __m128i* key_prg_ver, char* &response, int &response_length, uint8_t *key, uint32_t ecx, ThreadPool* pool, int thread_num, bool malicious) {
    int operation = stoi(subparams[0]);
    if(operation == 1){  // create table
        string sql = subparams[1];
        cass->create_table(sql);
    } else if(operation == 2){  // insert data
        int asize = stoi(subparams[1]);
        string sql = subparams[2];
        cout << sql << endl;
        //cout << asize << endl;

        Lint **a = new Lint *[2];
        for (int i = 0; i < 2; i++) {
            a[i] = new Lint[asize * batch_size];
            memset(a[i], 0, sizeof(Lint) * (asize * batch_size));
        }
        memcpy(a[0], Data, sizeof(Lint) * (asize * batch_size));
        memcpy(a[1], Data + sizeof(Lint) * (asize * batch_size), sizeof(Lint) * (asize * batch_size));

        UploadData(cass, asize, a, sql, thread_num);
        for (int i = 0; i < 2; i++) {
            delete[] a[i];
        }
        delete[] a;
    } else if(operation == 3){  // range query
        //string sql = "SELECT TripSeconds FROM transportation.taxi SECWHERE 200 < TripSeconds < 400";

        vector<string> sql;
        int num_iterations = stoi(subparams[1]);
        for (int k = 0; k < num_iterations; k++){
            sql.emplace_back(subparams[2+k]);
        }
        int value_operation = stoi(subparams[2+num_iterations].c_str());
        string vsql = subparams[3+num_iterations];
        //cout << sql[0] << endl;
        //cout << num_iterations << endl;

        Lint*** b = new Lint **[num_iterations];
        Lint*** DataVer = new Lint **[num_iterations];
        Lint r = 0;
        ServerKeyLt** ltk = new ServerKeyLt*[num_iterations];
        int RetValue_Length = 0;
        if(malicious){
            if(value_operation == 2){
                RetValue_Length = 2;
            } else if(value_operation == 3){
                RetValue_Length = size * 2 + 2;
            } else if(value_operation == 4){
                RetValue_Length = size * 4 + 2;
            }else{
                RetValue_Length = size * 2;
            }
        } else {
            if(value_operation == 2){
                RetValue_Length = 1;
            } else if(value_operation == 3){
                RetValue_Length = size + 1;
            } else if(value_operation == 4){
                RetValue_Length = size * 2 + 1;
            }else{
                RetValue_Length = size;
            }
        }
        Lint * RetValue = new Lint[RetValue_Length];
        memset(RetValue, 0, sizeof(Lint) * RetValue_Length);
        for (int k = 0; k < num_iterations; k++){
            b[k] = new Lint *[2];
            DataVer[k] = new Lint *[2];
            for (int i = 0; i < 2; i++) {
                b[k][i] = new Lint[batch_size];
                //memset(b[k][i], 0, sizeof(Lint) * batch_size);
                DataVer[k][i] = new Lint[batch_size];
                //memset(DataVer[k][i], 0, sizeof(Lint) * batch_size);
            }
            ltk[k] = new ServerKeyLt[4];
        }

        size_t offset = 0;
        Fss fClient;
        deserialize(Data, fClient, offset);
        deserializeKey(Data, fClient.numBits, ltk, num_iterations, 4, offset);
        for(int k=0; k<num_iterations; k++){
            for(int i=0; i < 2; i++){
                memcpy(b[k][i], Data+offset, sizeof(Lint) * batch_size);
                offset += sizeof(Lint) * batch_size;
                memcpy(DataVer[k][i], Data+offset, sizeof(Lint) * batch_size);
                offset += sizeof(Lint) * batch_size;
            }
        }
        memcpy(&r, Data+offset, sizeof(Lint));
        //offset += sizeof(Lint);
        
        benchmark_query(fClient, cass, nNet, size, batch_size, num_iterations, sql, vsql, value_operation, DataVer, b, r, ltk, key_prg_ver, RetValue, key, ecx, pool, thread_num, malicious);

        int ret_size = 0;
        if(value_operation == 2){
            ret_size = 1;
        } else if(value_operation == 3){
            ret_size = size+1;
        } else if(value_operation == 4){
            ret_size = 2*size+1;
        }else{
            ret_size = size;
        }
        response_length = sizeof(Lint) * RetValue_Length+sizeof(ret_size)+sizeof(malicious);
        response = new char[response_length];

        memcpy(response, &ret_size, sizeof(ret_size));
        offset = sizeof(ret_size);
        memcpy(response+offset, &malicious, sizeof(malicious));
        offset += sizeof(malicious);
        memcpy(response+offset, RetValue, sizeof(Lint) * RetValue_Length);

        destroyServerKeyLt(ltk, num_iterations, 4);
        destroyFSS(&fClient);

        for (int k = 0; k < num_iterations; k++) {
            for (size_t i = 0; i < 2; i++) {
                delete[] b[k][i];
                delete[] DataVer[k][i];
            }
            delete[] b[k];
            delete[] ltk[k];
            delete[] DataVer[k];
        }
        delete[] b;
        delete[] ltk;
        delete[] DataVer;
        delete[] RetValue;
    }
}

// ./server 3 config/runtime-config-3 config/server-config
// ./server 2 config/runtime-config-3 config/server-config
// ./server 1 config/runtime-config-3 config/server-config