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

#ifndef _CLIENT_EXTENSION
#define _CLIENT_EXTENSION
#include <sys/time.h>
#include <random>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <regex>
#include <arpa/inet.h>
#include <unistd.h>
#include "shuffle.h"
#include "fss-common.h"
#include "fss-server.h"
#include "fss-client.h"
#include "mpc_util.h"
extern "C" {
#include "aes_ni.h"
}
using namespace std;

void loadConfig(std::string configFile, vector<string> &IPs, vector<int> &Ports);
vector<int> sendRequest(const std::string serverIP, int serverPort, char* reqData, int Datalength, uint num_iterations, Lint* &fssres, Lint* &fssverres);
void CQLParser(string CQL, vector<string> &ret, vector<string> &vret, __int128_t &xl, __int128_t &xr, bool &reverse, string &operation);
void readCSV(const char* filename, Lint **Data1, int RecordSize, uint batch_size, size_t seed);
void TokenGen(Fss fClient, uint batch_size, uint num_iterations, __int128_t xl, __int128_t xr, bool reverse, Lint ***DataVer, Lint ***Data2, Lint *DataR, ServerKeyLt** lt_k0, ServerKeyLt** lt_k1, ServerKeyLt** lt_k0_ver, ServerKeyLt** lt_k1_ver, uint64_t &sigma, uint32_t ecx);

#endif