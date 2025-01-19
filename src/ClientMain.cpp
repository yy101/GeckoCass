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

#include "ClientMain.h"

int main(int argc, char **argv) {
    vector<string> IPs;
    vector<int> Ports;
    loadConfig(argv[1], IPs, Ports);

    std::ifstream configFile(argv[2]);
    if (!configFile.is_open()) {
        throw std::runtime_error("Could not open config file");
    }

    nlohmann::json jsonConfig;
    configFile >> jsonConfig;
    uint operation = jsonConfig.at("operation").get<uint>();
    uint num_ands = jsonConfig.at("num_ands").get<uint>();
    uint batch_size = jsonConfig.at("vector_size").get<uint>();
    uint size = pow(2, jsonConfig.at("data_size (2^x)").get<int>());
    string filename = jsonConfig.at("source_path").get<string>();

    switch (operation)
    {
    case 1:
        cout << "operation: create table" << endl;
        break;

    case 2:
        cout << "operation: upload data" << endl;
        break;

    case 3:
        cout << "operation: range query" << endl;
        break;
    
    default:
        cout << "operation not recognized" << endl;
        return 0;
    }
    cout << "size = " << size << endl;
    cout << "num_ands = " << num_ands << endl;

    struct timeval start, end;
    unsigned long timer;
    gettimeofday(&start, NULL); // start timer here
    client_main(operation, size, batch_size, num_ands, IPs, Ports, filename);
    gettimeofday(&end, NULL); // stop timer here
    timer = 1e6 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
    printf("operation cost: %.6lf ms\n", (double)(timer * 0.001));
    return 0;
}

void client_main(int operation, uint size, uint batch_size, uint num_iterations, vector<string> IPs, vector<int> Ports, string filename) {
    __int128_t xl = 0;
    __int128_t xr = std::numeric_limits<int>::max();
    bool reverse = false;
    string AggOp = "";
    vector<string> cqls;
    vector<string> vcqls;
    vector<boost::unique_future<vector<int>>> threads;
    Lint** fssres = new Lint*[3];
    Lint** fssverres = new Lint*[3];
    
    if(operation == 1){
        // create table
        string sql = "SECCREATE TABLE transportation.taxi (id INT, TripSeconds INT, PRIMARY KEY(id))";
        CQLParser(sql, cqls, vcqls, xl, xr, reverse, AggOp);
        for(int i=0; i<3; i++){
            string request = to_string(1)+"!"+cqls[i];
            cout << request << endl;
            int request_length = request.size();
            int bufferSize = request_length+sizeof(request_length);
            char* reqdata = new char[bufferSize];
            memcpy(reqdata, &request_length, sizeof(request_length));
            memcpy(reqdata+sizeof(request_length), request.c_str(), request_length);
            //sendRequest(IPs[i], Ports[i], request, reqdata, 0);
            threads.emplace_back(boost::async(boost::bind(&sendRequest, IPs[i], Ports[i], reqdata, bufferSize, num_iterations, fssres[i], fssverres[i])));
        }

        for(int count =0; count < 3; count++){
            auto& rthread = threads[count];
            boost::wait_for_any(rthread);
        }
    } else if(operation == 2){
        // insert data
        string sql = "SECINSERT INTO transportation.taxi (id, TripSeconds) VALUES (?, ?)";
        CQLParser(sql, cqls, vcqls, xl, xr, reverse, AggOp);

        std::random_device rd;  // 获取随机数种子
        std::mt19937 gen(rd()); // 以 rd() 初始化 Mersenne Twister 引擎
        std::uniform_int_distribution<unsigned long> distrib(0, std::numeric_limits<unsigned long>::max());
        size_t seed = distrib(gen);
        /*for(int i=0; i< size; i++){
            data[i] = 25;
        }*/
        Lint **Data1 = new Lint *[3];
        for (int i = 0; i < 3; i++) {
            Data1[i] = new Lint[(size * batch_size)];
            memset(Data1[i], 0, sizeof(Lint) * (size * batch_size));
        }
        readCSV(filename.c_str(), Data1, size, batch_size, seed);

        Lint **a = new Lint *[2];
        for (int i = 0; i < 2; i++) {
            a[i] = new Lint[(size * batch_size)];
            memset(a[i], 0, sizeof(Lint) * (size * batch_size));
        }

        for(int id=0; id<3; id++){
            memcpy(a[0], Data1[id], sizeof(Lint) * (size * batch_size));
            for(uint i=0; i < size*batch_size; i++){
                a[1][i] = Data1[(id+1)%3][i]+Data1[id][i];
            }

            /*for(int i=0; i < size*batch_size; i++){
                print128(a[0][i]);
                cout << endl;
                print128(a[1][i]);
                cout << endl;
            }*/
            string request = to_string(2)+"!"+to_string(size)+"!"+cqls[id]+"!";
            cout << request << endl;
            int request_length = request.size();
            int bufferSize = 2 * sizeof(Lint) * (size * batch_size)+request_length+sizeof(request_length);
            char* reqdata = new char[bufferSize];
            memcpy(reqdata, &request_length, sizeof(request_length));
            size_t offset = sizeof(request_length);
            memcpy(reqdata+offset, request.c_str(), request_length);
            offset += request_length;
            memcpy(reqdata+offset, a[0], sizeof(Lint) * (size * batch_size));
            offset += sizeof(Lint) * (size * batch_size);
            memcpy(reqdata+offset, a[1], sizeof(Lint) * (size * batch_size));

            //sendRequest(IPs[id], Ports[id], request, reqdata, bufferSize);
            threads.emplace_back(boost::async(boost::bind(&sendRequest, IPs[id], Ports[id], reqdata, bufferSize, num_iterations, fssres[id], fssverres[id])));
        }

        for(int count =0; count < 3; count++){
            auto& rthread = threads[count];
            boost::wait_for_any(rthread);
        }

        for (int i = 0; i < 3; i++) {
            delete[] Data1[i];
        }
        delete[] Data1;
        
        for (int i = 0; i < 2; i++) {
            delete[] a[i];
        }
        delete[] a;
    } else if(operation == 3){
        omp_set_num_threads(16);

        uint32_t eax, ebx, ecx, edx;
        eax = ebx = ecx = edx = 0;
        __get_cpuid(1, &eax, &ebx, &ecx, &edx);

        struct timeval start_token, end_token;
        unsigned long timer_token;
        gettimeofday(&start_token, NULL); // start timer here
        // range query
        string sql = "SELECT TripSeconds FROM transportation.taxi SECWHERE 200 < TripSeconds < 400";
        //string sql = "SELECT SUM(TripSeconds) FROM transportation.taxi SECWHERE 200 < TripSeconds < 400";
        //string sql = "SELECT TripSeconds FROM transportation.taxi SECWHERE 200 > TripSeconds or TripSeconds > 400";
        CQLParser(sql, cqls, vcqls, xl, xr, reverse, AggOp);

        Fss fClient;
        uint32_t numBits = 128;
        initializeClient(&fClient, numBits, 2, ecx);

        Lint ***b = new Lint **[num_iterations];
        Lint ***br = new Lint **[num_iterations];
        Lint *DataR = new Lint [3];
        Lint ***Data2 = new Lint **[num_iterations];
        Lint ***DataVer = new Lint **[num_iterations];
        ServerKeyLt** ltk = new ServerKeyLt*[num_iterations];
        for (uint k = 0; k < num_iterations; k++){
            b[k] = new Lint *[2];
            br[k] = new Lint *[2];
            for (int i = 0; i < 2; i++) {
                b[k][i] = new Lint[(batch_size)];
                memset(b[k][i], 0, sizeof(Lint) * batch_size);
                br[k][i] = new Lint[(batch_size)];
                memset(br[k][i], 0, sizeof(Lint) * batch_size);
            }
            ltk[k] = new ServerKeyLt[4];
            Data2[k] = new Lint *[3];
            DataVer[k] = new Lint *[3];
            for (int i = 0; i < 3; i++) {
                Data2[k][i] = new Lint[batch_size];
                memset(Data2[k][i], 0, sizeof(Lint) * batch_size);
                DataVer[k][i] = new Lint[batch_size];
                memset(DataVer[k][i], 0, sizeof(Lint) * batch_size);
            }
        }

        ServerKeyLt** lt_k0 = new ServerKeyLt*[num_iterations];
        ServerKeyLt** lt_k1 = new ServerKeyLt*[num_iterations];
        ServerKeyLt** lt_k0_ver = new ServerKeyLt*[num_iterations];
        ServerKeyLt** lt_k1_ver = new ServerKeyLt*[num_iterations];
        for(uint k=0; k<num_iterations; k++){
            lt_k0[k] = new ServerKeyLt[3];
            lt_k1[k] = new ServerKeyLt[3];
            lt_k0_ver[k] = new ServerKeyLt[3];
            lt_k1_ver[k] = new ServerKeyLt[3];
        }
        
        uint64_t sigma = 0;
        TokenGen(fClient, batch_size, num_iterations, xl, xr, reverse, DataVer, Data2, DataR, lt_k0, lt_k1, lt_k0_ver, lt_k1_ver, sigma, ecx);
        
        gettimeofday(&end_token, NULL); // stop timer here
        timer_token = 1e6 * (end_token.tv_sec - start_token.tv_sec) + end_token.tv_usec - start_token.tv_usec;
        printf("token generation cost: %.6lf ms\n", (double)(timer_token * 0.001));
        
        struct timeval start, end;
        unsigned long timer;
        gettimeofday(&start, NULL); // start timer here
        for(int id=0; id<3; id++){
            for(uint k=0; k<num_iterations; k++){
                memcpy(ltk[k], lt_k0[k]+id, sizeof(ServerKeyLt));
                memcpy(ltk[k]+1, lt_k1[k]+(id+2)%3, sizeof(ServerKeyLt));
                //memcpy(ltk[k]+1, lt_k1[k]+id, sizeof(ServerKeyLt));
                memcpy(ltk[k]+2, lt_k0_ver[k]+id, sizeof(ServerKeyLt));
                memcpy(ltk[k]+3, lt_k1_ver[k]+(id+2)%3, sizeof(ServerKeyLt));
                //memcpy(ltk[k]+3, lt_k1_ver[k]+id, sizeof(ServerKeyLt));

                memcpy(b[k][0], Data2[k][id], sizeof(Lint) * batch_size);
                memcpy(br[k][0], DataVer[k][id], sizeof(Lint) * batch_size);
                for(uint i=0; i < batch_size; i++){
                    b[k][1][i] = Data2[k][(id+1)%3][i]+Data2[k][id][i];
                    br[k][1][i] = DataVer[k][(id+1)%3][i]+DataVer[k][id][i];
                }
            }
            Lint r = DataR[id];

            char* Serial;
            size_t Serial_Size;
            serialize(fClient, Serial, Serial_Size);

            char* SerialKey;
            size_t SerialKey_Size;
            serializeKey((const ServerKeyLt**)ltk, num_iterations, 4, fClient.numBits, SerialKey, SerialKey_Size);

            string request = to_string(3)+"!"+to_string(num_iterations);
            for(uint k=0; k<num_iterations; k++){
                request += "!"+cqls[id];
            }
            request += "!"+AggOp+"!"+vcqls[id]+"!";
            int request_length = request.size();
            //cout << request << endl;

            int bufferSize = sizeof(Lint) * batch_size * 4 * num_iterations + sizeof(Lint) + Serial_Size + SerialKey_Size + request_length + sizeof(request_length);
            char* reqdata = new char[bufferSize];
            memcpy(reqdata, &request_length, sizeof(request_length));
            memcpy(reqdata+sizeof(request_length), request.c_str(), request_length);
            size_t offset = request_length + sizeof(request_length);
            memcpy(reqdata+offset, Serial, Serial_Size);
            offset += Serial_Size;
            memcpy(reqdata+offset, SerialKey, SerialKey_Size);
            offset += SerialKey_Size;
            for(uint k=0; k<num_iterations; k++){
                for(int i=0; i < 2; i++){
                    memcpy(reqdata+offset, b[k][i], sizeof(Lint) * batch_size);
                    offset += sizeof(Lint) * batch_size;
                    memcpy(reqdata+offset, br[k][i], sizeof(Lint) * batch_size);
                    offset += sizeof(Lint) * batch_size;
                }
            }
            memcpy(reqdata+offset, &r, sizeof(Lint));
            offset += sizeof(Lint);

            threads.emplace_back(boost::async(boost::bind(&sendRequest, IPs[id], Ports[id], reqdata, bufferSize, num_iterations, std::ref(fssres[id]), std::ref(fssverres[id]))));
            
            delete[] Serial;
            delete[] SerialKey;
        }
        int ret_size = 0;
        bool malicious = true;
        
        for(int count =0; count < 3; count++){
            auto& rthread = threads[count];
            boost::wait_for_any(rthread);
            if(count == 0){
                auto params = rthread.get();
                ret_size = params[0];
                malicious = params[1];
            }
        }
        gettimeofday(&end, NULL); // stop timer here
        timer = 1e6 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
        printf("threads cost: %.6lf ms\n", (double)(timer * 0.001));
        //cout << ret_size << endl;
        //cout << malicious << endl;
        Lint* result = new Lint[ret_size];
        uint64_t verResultSum = 0; 
        uint64_t ResultSum = 0;
        Lint deviation = 3;
        for(uint k=1; k<num_iterations; k++){
            deviation *= 3;
        }
        uint64_t RetCount = 0;
        uint64_t RetSum = 0;
        uint64_t value = 0;
        int offset = 0;
        switch (stoi(AggOp.c_str())){  // 1: SUM; 2: COUNT; 3: AVERAGE; 4: VARIANCE; 5: VALUE;
        case 1:
            for (int i = 0; i < ret_size; i++) {
                value = (fssres[0][i]+fssres[1][i]+fssres[2][i]) & (((Lint)1 << 64) - 1);
                RetSum += ((value>>16) / deviation);
                if(malicious){
                    ResultSum += value;
                    verResultSum += (fssverres[0][i]+fssverres[1][i]+fssverres[2][i]) & (((Lint)1 << 64) - 1);
                }
            }
            result[0] = RetSum;
            break;
        case 2:
            result[0] = (fssres[0][0]+fssres[1][0]+fssres[2][0]) & (((Lint)1 << 64) - 1);
            if(malicious){
                ResultSum = result[0];
                verResultSum = (fssverres[0][0]+fssverres[1][0]+fssverres[2][0]) & (((Lint)1 << 64) - 1);
            }
            result[0] = (result[0]/deviation);
            break;
        case 3:
            for (int i = 1; i < ret_size; i++) {
                value = (fssres[0][i]+fssres[1][i]+fssres[2][i]) & (((Lint)1 << 64) - 1);
                RetSum += ((value>>16) / deviation);
                if(malicious){
                    ResultSum += value;
                    verResultSum += (fssverres[0][i]+fssverres[1][i]+fssverres[2][i]) & (((Lint)1 << 64) - 1);
                }
            }
            RetCount = (fssres[0][0]+fssres[1][0]+fssres[2][0]) & (((Lint)1 << 64) - 1);
            if(malicious){
                ResultSum += RetCount;
                verResultSum += (fssverres[0][0]+fssverres[1][0]+fssverres[2][0]) & (((Lint)1 << 64) - 1);
            }
            result[0] = RetSum*deviation/RetCount;
            break;
        case 4:
            offset = ret_size/2+1;
            for (int i = 1; i < offset; i++) {
                value = (fssres[0][i]+fssres[1][i]+fssres[2][i]) & (((Lint)1 << 64) - 1);
                RetSum += ((value>>16) / deviation);
                if(malicious){
                    ResultSum += value;
                    verResultSum += (fssverres[0][i]+fssverres[1][i]+fssverres[2][i]) & (((Lint)1 << 64) - 1);
                }
            }
            RetCount = (fssres[0][0]+fssres[1][0]+fssres[2][0]) & (((Lint)1 << 64) - 1);
            if(malicious){
                ResultSum += RetCount;
                verResultSum += (fssverres[0][0]+fssverres[1][0]+fssverres[2][0]) & (((Lint)1 << 64) - 1);
            }
            result[1] = RetSum*deviation/RetCount;

            for (int i = offset; i < ret_size; i++) {
                value = (fssres[0][i]+fssres[1][i]+fssres[2][i]) & (((Lint)1 << 64) - 1);
                RetSum += ((value>>32) / deviation);
                if(malicious){
                    ResultSum += value;
                    verResultSum += (fssverres[0][i]+fssverres[1][i]+fssverres[2][i]) & (((Lint)1 << 64) - 1);
                }
            }
            result[2] = RetSum*deviation/RetCount;
            result[0] = result[2] - result[1]*result[1];
            break;
        case 5:
            for (int i = 0; i < ret_size; i++) {
                result[i] = (fssres[0][i]+fssres[1][i]+fssres[2][i]) & (((Lint)1 << 64) - 1);
                if(malicious){
                    ResultSum += result[i];
                    verResultSum += (fssverres[0][i]+fssverres[1][i]+fssverres[2][i]) & (((Lint)1 << 64) - 1);
                }
                result[i] = (result[i]/deviation) >> 16;
            }
            break;
        }
        if(malicious){
            for(uint k=0; k<num_iterations; k++){
                ResultSum *= sigma;
            }
            if(ResultSum != verResultSum){
                cout << "Verification Failed" << endl;
            } else{
                cout << "Verification Successful" << endl;
            }
        }
        if(AggOp == "5"){
            for(uint i=size-16; i < size; i++){
                cout << "result[" << i << "]=";
                print128(result[i]);
                cout << endl;
            }
        } else{
            cout << "result=";
            print128(result[0]);
            cout << endl;
        }

        for (uint k = 0; k < num_iterations; k++) {
            for (size_t i = 0; i < 2; i++) {
                delete[] b[k][i];
                delete[] br[k][i];
            }
            for (int i = 0; i < 3; i++) {
                delete[] DataVer[k][i];
                delete[] Data2[k][i];
            }
            delete[] b[k];
            delete[] br[k];
            delete[] ltk[k];
            delete[] DataVer[k];
            delete[] Data2[k];
            delete[] lt_k0[k];
            delete[] lt_k1[k];
            delete[] lt_k0_ver[k];
            delete[] lt_k1_ver[k];
        }
        for (int i = 0; i < 3; i++) {
            delete[] fssres[i];
            delete[] fssverres[i];
        }
        delete[] DataVer;
        delete[] Data2;
        delete[] DataR;
        delete[] lt_k0;
        delete[] lt_k1;
        delete[] lt_k0_ver;
        delete[] lt_k1_ver;
        delete[] br;
        delete[] b;
        delete[] ltk;
        delete[] result;
    }
    delete[] fssres;
    delete[] fssverres;
}

// 1:create; 2:insert; 3:range query
// ./client config/runtime-config-3 config/client-config