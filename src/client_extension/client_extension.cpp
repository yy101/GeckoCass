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

#include "client_extension.h"
#define Base ((__int128_t)1 << 127)

void loadConfig(std::string configFile, vector<string> &IPs, vector<int> &Ports) {
    std::ifstream configIn(configFile.c_str(), std::ios::in);
    // Make sure the file exists and can be opened
    if (!configIn) {
        std::cout << "File could not be opened";
        std::exit(1);
    }
    std::string line;
    std::vector<std::string> tokens;
    // Read each line of the configuration file
    while (std::getline(configIn, line)) {
        tokens.clear();
        char *s = strdup(line.c_str());
        char *tok = strtok(s, ",");
        std::string str;
        while (tok != NULL) {
            str = tok;
            tokens.emplace_back(str);
            tok = strtok(NULL, ",");
        }
        free(s);

        IPs.emplace_back(tokens[1]);
        Ports.emplace_back(atoi(tokens[2].c_str())+10000);
    }
    configIn.close();
}

vector<int> sendRequest(const std::string serverIP, int serverPort, char* reqData, int DataLength, uint num_iterations, Lint* &fssres, Lint* &fssverres) {
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = inet_addr(serverIP.c_str());
    serverAddr.sin_port = htons(serverPort);
    vector<int> ret;

    if (connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == 0) {
        send(clientSocket, &DataLength, sizeof(DataLength), 0);
        int totalBytesSent = 0;
        while (totalBytesSent < DataLength) {
            int bytesSent = send(clientSocket, reqData + totalBytesSent, DataLength - totalBytesSent, 0);
            if (bytesSent <= 0) break;
            totalBytesSent += bytesSent;
        }

        int length = 0;
        int bytesRead = read(clientSocket, &length, sizeof(length));
        if (bytesRead > 0) {
            //cout << "returned message length: " << length << endl;
            char* receivedData = new char[length];
            //memset(receivedData, 0, length);
            int currentLength = 0;
            char databuffer[4194304];
            while(currentLength < length){
                //memset(databuffer, 0, 4194304);
                bytesRead = read(clientSocket, databuffer, sizeof(databuffer));
                if (bytesRead) {
                    memcpy(receivedData+currentLength, databuffer, bytesRead);
                    currentLength += bytesRead;
                    //cout << currentLength << endl;
                }
            }
            int size = 0;
            bool malicious = 0;
            memcpy(&size, receivedData, sizeof(size));
            size_t offset = sizeof(size);
            memcpy(&malicious, receivedData+offset, sizeof(malicious));
            offset += sizeof(malicious);
            ret.emplace_back(size);
            ret.emplace_back(malicious);

            fssres = new Lint[size];
            //memset(fssres, 0, sizeof(Lint)*size);
            fssverres = new Lint[size];
            //memset(fssverres, 0, sizeof(Lint)*size);
            
            memcpy(fssres, receivedData+offset, sizeof(Lint) * size);
            offset += sizeof(Lint) * (size);
            if(malicious){
                memcpy(fssverres, receivedData+offset, sizeof(Lint) * size);
            }
            close(clientSocket);
            return ret;
        }
    }
    close(clientSocket);
    if(DataLength){
        delete[] reqData;
    }
    return ret;
}

void CQLParser(string CQL, vector<string> &ret, vector<string> &vret, __int128_t &xl, __int128_t &xr, bool &reverse, string &operation){
    if(CQL.find("SECCREATE") != std::string::npos){
        regex pk_regex(R"(PRIMARY KEY\(([^,)]+)\))", std::regex::icase);
        regex table_regex(R"(SECCREATE TABLE\s+(\w+)\.(\w+)\s*\()", std::regex::icase);
        smatch match; 
        string dbName = "";
        string tblName = "";
        string PKey = ""; 
    
        if (std::regex_search(CQL, match, table_regex)) {    
            dbName = match[1];
            tblName = match[2];
        }
        if (std::regex_search(CQL, match, pk_regex)) {  
            // 如果找到匹配项，返回第一个捕获组（即主键名）  
            PKey = match[1];
        }

        regex field_regex(R"((\b\w+\b) \b\w+\b,)");  
      
        std::sregex_iterator iter(CQL.begin(), CQL.end(), field_regex);  
        std::sregex_iterator end;  
        
        // 遍历所有匹配项  
        while (iter != end) {  
            string field = (*iter)[1];
            ++iter;
            if(field != PKey){
                for(int i=1; i<4; i++){
                    string statement = "CREATE TABLE Keyspace"+to_string(i)+"."+dbName+"_"+tblName+"_"+field+" (section tinyint, "+PKey+" int, data blob, PRIMARY KEY (section, id));";
                    ret.emplace_back(statement);
                    //cout << statement << endl;
                }
            }
        }  
    } else if(CQL.find("SECINSERT") != std::string::npos) {
        regex table_regex(R"(SECINSERT INTO\s+(\w+)\.(\w+)\s*\()", std::regex::icase);
        regex bracket_regex("\\(([^)]+)\\)"); // 匹配括号内的内容
        regex fields_regex("\\s*,\\s*");
        smatch match;
        string dbName = "";
        string tblName = "";
        string PKey = "";
        if (std::regex_search(CQL, match, table_regex)) {   
            dbName = match[1];
            tblName = match[2];
        }
        if (std::regex_search(CQL, match, bracket_regex)) {  
            string bracket = match[1].str();
            std::sregex_token_iterator it(bracket.begin(), bracket.end(), fields_regex, -1);
            std::sregex_token_iterator end;

            PKey = *it;
            ++it;
            while (it != end) {
                string field = *it;
                for(int i=1; i<4; i++){
                    string statement = "INSERT INTO Keyspace"+to_string(i)+"."+dbName+"_"+tblName+"_"+field+" (section, "+PKey+", data) VALUES (?,?,?);";
                    ret.emplace_back(statement);
                    //cout << statement << endl;
                }
                ++it;
            }
        }
    } else if(CQL.find("SECWHERE") != std::string::npos) {    // 1: SUM; 2: COUNT; 3: AVERAGE; 4: VARIANCE; 5: VALUE;
        // "select hd11, ld11, hd12, ld12, hd13, ld13, hd21, ld21, hd22, ld22, hd23, ld23 from keyspace"+to_string(pid)+".idx_s where section = ?"
        regex table_regex(R"(FROM\s+(\w+)\.(\w+)\s+SECWHERE)", std::regex::icase);
        regex range_regex(R"((\d+)\s*<\s*(\w+)\s*<\s*(\d+)|(\d+)\s*>\s*(\w+)\s*>\s*(\d+)|(\d+)\s*<\s*(\w+)|(\w+)\s*<\s*(\d+)|(\w+)\s*>\s*(\d+)|(\d+)\s*>\s*(\w+))");
        regex agg_regex(R"(SELECT\s+(SUM|COUNT|AVERAGE|VARIANCE)\s*\(\s*([^\s\(\)]+)\s*\)\s+FROM)", std::regex::icase);
        regex simple_regex(R"(SELECT\s+([^\s]+)\s+FROM)", std::regex::icase);
        std::smatch match;
        string dbName = "";
        string tblName = "";
        string VKey = "";

        if (std::regex_search(CQL, match, table_regex)) {  
            dbName = match[1];
            tblName = match[2];
        }
        if (std::regex_search(CQL, match, agg_regex)) {
            string aggFunc = toUpperCase(match[1].str());
            if(aggFunc == "SUM"){
                operation = "1";
            } else if(aggFunc == "COUNT"){
                operation = "2";
            } else if(aggFunc == "AVERAGE"){
                operation = "3";
            } else {
                operation = "4";
            }
            VKey = match[2];
        } else {
            // 特殊情况处理：没有聚合函数的简单查询
            if (std::regex_search(CQL, match, simple_regex)) {
                VKey = match[1];
                operation = "5";
            } else {
                std::cout << "No match found." << std::endl;
                exit(1);
            }
        }

        auto it = CQL.cbegin();
        string fieldl = "";
        string fieldr = "";
        vector<string> fields;
        while (std::regex_search(it, CQL.cend(), match, range_regex)) {
            if (match[1].matched && match[3].matched) {
                xl = std::stoi(match[1]);
                xr = std::stoi(match[3]);
                fields.emplace_back(match[2]);
            } else if (match[4].matched && match[6].matched) {
                xr = std::stoi(match[4]);
                xl = std::stoi(match[6]);
                fields.emplace_back(match[5]);
            } else{
                if (match[7].matched) {
                    xl = std::max((int)xl, std::stoi(match[7]));
                    fieldl = match[8];
                } else if (match[12].matched) {
                    xl = std::max((int)xl, std::stoi(match[12]));
                    fieldl = match[11];
                } else if (match[10].matched) {
                    xr = std::min((int)xr, std::stoi(match[10]));
                    fieldr = match[9];
                }  else if (match[13].matched) {
                    xr = std::min((int)xr, std::stoi(match[13]));
                    fieldr = match[14];
                }
            }
            if((fieldl == fieldr) & (xl > xr)){
                int temp = xl;
                xl = xr;
                xr = temp;
                reverse = 1;
                fields.emplace_back(fieldl);
            }
            it = match.suffix().first;
        }
        for(string field : fields){
            for(int i=1; i<4; i++){
                string statement = "select data from Keyspace"+to_string(i)+"."+dbName+"_"+tblName+"_"+field+" where section = ?;";
                ret.emplace_back(statement);
                statement = "select data from Keyspace"+to_string(i)+"."+dbName+"_"+tblName+"_"+VKey+" where section = ?;";
                vret.emplace_back(statement);
                //cout << statement << endl;
            }
        }

        std::cout << "xl = " << (int)xl << ", xr = " << (int)xr << ", reverse = " << reverse  << ", Agg operation = " << operation << endl;
    }
}

void readCSV(const char* filename, Lint **Data1, int RecordSize, uint batch_size, size_t seed) {
    std::cout << "filename: " << filename << std::endl;
    ifstream in(filename, ifstream::binary);
    string cur_line;

    int count = 0;
    int* data = new int[RecordSize];
    getline(in, cur_line);
    while (getline(in, cur_line)) {
        //cout << "Parse line: " << cur_line << endl;
        if(cur_line.size()<10){
            continue;
        }

        // A row of CSV format data, with ',' as the separator between columns, parsed row by row
        istringstream iss(cur_line);	// input stream
        string token;			// receive buffer
        char split = ',';
        vector<string> item;
        while (getline(iss, token, split))	// Use split as the separator
        {
            item.emplace_back(token);
        }
        if(item[4].empty() or item[4] == "0"){
            continue;
        }
        data[count] = stoi(item[4]);
        count++;
        if(count%RecordSize==0){
            break;
        }
    }
    in.close();
    std::cout << "File size: " << count << std::endl;

    __m128i *key_prg;
    uint8_t key_raw[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    key_prg = offline_prg_keyschedule(key_raw);
    uint8_t k1[] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    int precision = 16;

    struct shuffle_ctx ctx;
    size_t offset_size = 1 << precision;
	shuffle_init(&ctx, offset_size, seed);

    unordered_map<int, int> countMap;
    for (int i = 0; i < RecordSize; i++) {
        countMap[data[i]-1] += 1;
        size_t offset = shuffle_index(&ctx, countMap[data[i]-1]);
        for(uint j = 0; j < batch_size; j++){
            int index = i*batch_size+j;
            prg_aes_ni(Data1[0] + index, k1, key_prg);
            prg_aes_ni(Data1[1] + index, k1, key_prg);
            //__int128_t value = F2I(pow(data[i], j), precision);
            Data1[2][index] = ipow(data[i], j, precision, offset) - Data1[0][index] - Data1[1][index];
            //cout << pow(data, j) << " : " << range(delta, xl, xr, j) << endl;
        }
    }
    delete[] data;
}

void TokenGen(Fss fClient, uint batch_size, uint num_iterations, __int128_t xl, __int128_t xr, bool reverse, Lint ***DataVer, Lint ***Data2, Lint *DataR, ServerKeyLt** lt_k0, ServerKeyLt** lt_k1, ServerKeyLt** lt_k0_ver, ServerKeyLt** lt_k1_ver, uint64_t &sigma, uint32_t ecx){
    __m128i *key_prg;
    uint8_t key_raw[] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    key_prg = offline_prg_keyschedule(key_raw);
    // setup prg seed(k1, k2, k3)
    uint8_t k2[] = {0xa2, 0x34, 0x6f, 0x67, 0x10, 0x1b, 0x13, 0xa3, 0x56, 0x45, 0x90, 0xb2, 0x13, 0xe3, 0x23, 0x24};

    std::random_device rd;  // 获取随机数种子
    std::mt19937 gen(rd()); // 以 rd() 初始化 Mersenne Twister 引擎
    std::uniform_int_distribution<> distrib(0, std::numeric_limits<int>::max());
    __int128_t delta = distrib(gen);
    __int128_t gamma = distrib(gen);
    int precision = 16;
    long random = distrib(gen);
    sigma = distrib(gen);
    __int128_t xl_p = xl << precision;
    __int128_t xr_p = xr << precision;
    __int128_t threhold = -gamma*delta*(xl_p-xr_p)-gamma*delta*delta;
    __uint128_t thre = threhold+Base;
    std::cout << "delta: ";
    print128(delta);
    cout << endl;
    std::cout << "Threshold: ";
    print128(threhold);
    cout << endl;
    std::cout << "Random: " << random << endl;
    std::cout << "Sigma: " << sigma << endl;
    
    for(uint k=0; k<num_iterations; k++){
        for(int i=0; i<3; i++){
            generateTreeLt(&fClient, &lt_k0[k][i], &lt_k1[k][i], thre, 1, ecx);
            generateTreeLt(&fClient, &lt_k0_ver[k][i], &lt_k1_ver[k][i], thre, sigma, ecx);
        }
    }
    prg_aes_ni(&DataR[0], k2, key_prg);
    prg_aes_ni(&DataR[1], k2, key_prg);
    DataR[2] = random - DataR[0] - DataR[1];
    for(uint j = 0; j < batch_size; j++){
        for(uint k=0; k<num_iterations; k++){
            prg_aes_ni(Data2[k][0] + j, k2, key_prg);
            prg_aes_ni(Data2[k][1] + j, k2, key_prg);
            Data2[k][2][j] = gamma*range(delta, xl_p, xr_p, j, reverse) - Data2[k][0][j] - Data2[k][1][j];
            DataVer[k][0][j] = DataR[0]*Data2[k][0][j] + DataR[1]*Data2[k][0][j] + DataR[0]*Data2[k][1][j];
            DataVer[k][1][j] = DataR[1]*Data2[k][1][j] + DataR[2]*Data2[k][1][j] + DataR[1]*Data2[k][2][j];
            DataVer[k][2][j] = DataR[2]*Data2[k][2][j] + DataR[0]*Data2[k][2][j] + DataR[2]*Data2[k][0][j];
        }
    }
    free(key_prg);
}