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

#ifndef _SERVER_EXTENSION
#define _SERVER_EXTENSION
#include <sys/time.h>
#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>
#include <omp.h>
#include "shuffle.h"
#include "fss-common.h"
#include "fss-server.h"
#include "fss-client.h"
#include "3pc_all.h"
#include "mpc_util.h"
extern "C" {
#include "aes_ni.h"
}
#include "ThreadPool.h"

using namespace std;

void UploadData(LibCass *cass, uint size, Lint **a, string sql, int thread_num);
void benchmark_query(Fss fServer, LibCass *cass, NodeNetwork *nodeNet, uint size, uint batch_size, uint num_iterations, vector<string> sql, string vsql, int value_operation, Lint ***DataVer, Lint ***b, Lint r, ServerKeyLt** ltk, __m128i* key_prg_ver, Lint * RetValue, uint8_t *key, uint32_t ecx, ThreadPool* pool, int thread_num, bool malicious);
void DBRetrival(LibCass *cass, CassPrepared **SelectPrepared, CassPrepared * SelectValuePrepared, Lint ***a, Lint **value, int ThreadId, uint num_iterations, int thread_num);
void DBRSS(Lint ***a, Lint ***b, Lint ***DataVer, Lint **c, Lint **mac, Lint ***v, int* param);
void DBWorker(LibCass *cass, CassPrepared **SelectPrepared,  
        Lint ***a, Lint ***b, Lint ***DataVer, Lint **c, Lint **mac, Lint ***v, int* param);
void FSSWorker(Fss fServer, ServerKeyLt** ltk, __int128_t **res, uint size, int ThreadId, uint num_iterations, Lint*** fssres, uint32_t ecx, int thread_num, bool malicious);

#endif
