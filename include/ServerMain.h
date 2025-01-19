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

#ifndef MAIN_H_
#define MAIN_H_

#include "NodeConfiguration.h"
#include "NodeNetwork.h"
#include "server_extension.h"
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>
//#include <gperftools/profiler.h>

void startServer(string IP, int port, uint num_parties, uint size, uint batch_size, int thread_num, bool malicious, string dc);
void server_main(LibCass *cass, uint numParties, uint size, uint batch_size, vector<string> subparams, char* Data, __m128i* key_prg_ver, char* &response, int &response_length, uint8_t *key, uint32_t ecx, ThreadPool* pool, int thread_num, bool malicious);

#endif