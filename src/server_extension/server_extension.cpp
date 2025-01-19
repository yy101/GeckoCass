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

#include "server_extension.h"
#define Base ((__int128_t)1 << 127)

void UploadData(LibCass *cass, uint size, Lint **a, string sql, int thread_num){
    /*CassPrepared *InsertPrepared = cass->buildInsertStmt(sql.c_str());
    vector<boost::unique_future<bool>> threads;
    for(int i=0; i<thread_num; i++){
        threads.emplace_back(boost::async(boost::bind(&LibCass::upload_index, &(*cass), a, size, InsertPrepared, thread_num, i)));
    }
    for(int count =0; count < thread_num; count++){
        auto& rthread = threads[count];
        boost::wait_for_any(rthread);
    }*/
    cass->upload_index(a, size, sql, thread_num);
}

void benchmark_query(Fss fServer, LibCass *cass, NodeNetwork *nodeNet, uint size, uint batch_size, uint num_iterations, vector<string> sql, string vsql, int value_operation, Lint ***DataVer, Lint ***b, Lint r, ServerKeyLt** ltk, __m128i* key_prg_ver, Lint * RetValue, uint8_t *key, uint32_t ecx, ThreadPool* pool, int thread_num, bool malicious) {   
    struct timeval startr, endr, startRSS, endRSS, startFSS, endFSS;
    unsigned long timerR, timerRSS, timerFSS;

    std::vector<std::future<void>> threadResults;

    int ring_size = nodeNet->RING;

    Lint ***a = new Lint **[num_iterations];
    Lint ***v = new Lint **[num_iterations];
    Lint ***fssres = new Lint **[num_iterations];
    Lint **value = new Lint *[2];
    Lint **c = new Lint *[num_iterations];
    Lint **mac = new Lint *[num_iterations];
    __int128_t **rssres = new __int128_t *[num_iterations];
    uint bytes = (ring_size + 7) >> 3;
    uint8_t *buffer = new uint8_t[bytes];
    string SelectQuery[num_iterations];
    for(size_t k=0; k<num_iterations; k++){
        a[k] = new Lint *[2];
        v[k] = new Lint *[2];
        fssres[k] = new Lint *[2];
        rssres[k] = new __int128_t[size];
        //memset(rssres[k], 0, sizeof(__int128_t) * (size));
        c[k] = new Lint[size];
        //memset(c[k], 0, sizeof(Lint) * size);
        if(malicious){
            mac[k] = new Lint[size];
            //memset(mac[k], 0, sizeof(Lint) * size);
        }

        for (size_t i = 0; i < 2; i++) {
            a[k][i] = new Lint[size * batch_size];
            //memset(a[k][i], 0, sizeof(Lint) * (size * batch_size));
            v[k][i] = new Lint[2];
            for (size_t j = 0; j < 2; j++) {
                //memset(v[k][i]+j, 0, sizeof(unsigned long));
                nodeNet->prg_getrandom(j, bytes, 1, buffer);
                memcpy(v[k][i]+j, buffer, bytes);
            }
            if(malicious){
                fssres[k][i] = new Lint[size*2];
                //memset(fssres[k][i], 0, sizeof(Lint) * (size*2));
            } else{
                fssres[k][i] = new Lint[size];
                //memset(fssres[k][i], 0, sizeof(Lint) * (size));
            }
        }
        SelectQuery[k] = sql[k];
    }
    for (size_t i = 0; i < 2; i++) {
        value[i] = new Lint[size * batch_size];
    }

    gettimeofday(&startr, NULL);   // start timer here
    CassPrepared ** SelectPrepared = cass->buildSelectStmt(SelectQuery, num_iterations);
    CassPrepared * SelectValuePrepared = cass->buildValueSelectStmt(vsql);
    for (int i = 0; i < thread_num; ++i) {
        threadResults.emplace_back(pool->enqueue(DBRetrival, cass, SelectPrepared, SelectValuePrepared, a, value, i, num_iterations, thread_num));
    }
    // Wait for all tasks to complete
    for (auto &&result : threadResults) {
        result.get();
    }
    threadResults.clear();
    gettimeofday(&endr, NULL);     // stop timer here
    timerR = 1e6 * (endr.tv_sec - startr.tv_sec) + endr.tv_usec - startr.tv_usec;

    gettimeofday(&startRSS, NULL); // start timer here
    /*for(int i=0; i<thread_num; i++){
        param[i][0]=i;  //ThreadID
        param[i][1]=num_iterations;
        param[i][2]=size;
        threads.emplace_back(boost::async(boost::bind(&DBRSS, a, b, DataVer, c, mac, v, param[i])));
    }
    for(int count =0; count < thread_num; count++){
        auto& rthread = threads[count];
        boost::wait_for_any(rthread);
    }
    threads.clear();*/
    for(uint k=0; k<num_iterations; k++){
        Rss_Mult_Vec(c[k], a[k], b[k], size, batch_size, 1, 0, v[k][0]);
        if(malicious){
            Rss_Mult_Vec(mac[k], a[k], DataVer[k], size, batch_size, 1, 0, v[k][1]);
        }
    }
    bool ret = true;
    if(malicious){
        ret = Rss_Open_Verification(c, mac, r, size, ring_size, num_iterations, nodeNet, key_prg_ver, key);
    }

    for(uint k=0; k<num_iterations; k++){
        Rss_Open_Signal(rssres[k], c[k], size, ring_size, nodeNet);
    }
    gettimeofday(&endRSS, NULL);   // stop timer here
    timerRSS = 1e6 * (endRSS.tv_sec - startRSS.tv_sec) + endRSS.tv_usec - startRSS.tv_usec;

    gettimeofday(&startFSS, NULL); // start timer here
    // Enqueue tasks
    for (int i = 0; i < thread_num; ++i) {
        threadResults.emplace_back(pool->enqueue(FSSWorker, fServer, ltk, rssres, size, i, num_iterations, fssres, ecx, thread_num, malicious));
    }
    // Wait for all tasks to complete
    for (auto &&result : threadResults) {
        result.get();
    }
    gettimeofday(&endFSS, NULL); // stop timer here
    timerFSS = 1e6 * (endFSS.tv_sec - startFSS.tv_sec) + endFSS.tv_usec - startFSS.tv_usec;

    gettimeofday(&startRSS, NULL); // start timer here
    if(malicious){
        Rss_Reshare(fssres[0], size*2, nodeNet);
    } else{
        Rss_Reshare(fssres[0], size, nodeNet);
    }
    for(uint k=1; k<num_iterations; k++){
        if(malicious){
            Rss_Reshare(fssres[k], size*2, nodeNet);
            Rss_Mult_Reshare(fssres[0], fssres[0], fssres[k], size*2, ring_size, nodeNet);
        } else{
            Rss_Reshare(fssres[k], size, nodeNet);
            Rss_Mult_Reshare(fssres[0], fssres[0], fssres[k], size, ring_size, nodeNet);
        }
    }

    Lint* RetMult;
    //cout << value_operation << endl;
    Lint count = 0;
    Lint count_MAC = 0;
    switch (value_operation){  // 1: SUM; 2: COUNT; 3: AVERAGE; 4: VARIANCE; 5: VALUE;
        case 1:
            Rss_nMult(RetValue, fssres[0], value, size, batch_size, malicious, 1);
            break;
        case 2:
            for(uint i = 0; i < size; i++){
                RetValue[0] += fssres[0][0][i];
                if(malicious){
                    RetValue[1] += fssres[0][0][i+size];
                }
            }
            break;
        case 3:
            RetMult = new Lint[size*(1+malicious)];
            Rss_nMult(RetMult, fssres[0], value, size, batch_size, malicious, 1);
            for(uint i = 0; i < size; i++){
                count += fssres[0][0][i];
                if(malicious){
                    count_MAC += fssres[0][0][i+size];
                }
            }
            RetValue[0] = count;
            memcpy(RetValue+1, RetMult, size*sizeof(Lint));
            if(malicious){
                RetValue[size+1] = count_MAC;
                memcpy(RetValue+size+2, RetMult+size, size*sizeof(Lint));
            }            
            delete RetMult;
            break;
        case 4:
            RetMult = new Lint[size*(1+malicious)];
            Rss_nMult(RetMult, fssres[0], value, size, batch_size, malicious, 1);
            for(uint i = 0; i < size; i++){
                count += fssres[0][0][i];
                if(malicious){
                    count_MAC += fssres[0][0][i+size];
                }
            }
            RetValue[0] = count;
            memcpy(RetValue+1, RetMult, size*sizeof(Lint));
            if(malicious){
                RetValue[2*size+1] = count_MAC;
                memcpy(RetValue+2*size+2, RetMult+size, size*sizeof(Lint));
            }

            Rss_nMult(RetMult, fssres[0], value, size, batch_size, malicious, 2);
            for(uint i = 0; i < size; i++){
                count += fssres[0][0][i];
                if(malicious){
                    count_MAC += fssres[0][0][i+size];
                }
            }
            memcpy(RetValue+1+size, RetMult, size*sizeof(Lint));
            if(malicious){
                memcpy(RetValue+3*size+2, RetMult+size, size*sizeof(Lint));
            }
            delete RetMult;
            break;
        case 5:
            Rss_nMult(RetValue, fssres[0], value, size, batch_size, malicious, 1);
            break;
    }
    gettimeofday(&endRSS, NULL); // stop timer here
    timerRSS += 1e6 * (endRSS.tv_sec - startRSS.tv_sec) + endRSS.tv_usec - startRSS.tv_usec;

    /*for(int i=0; i<6; i++){
        std::cout << "RetValue[" << i << "]=";
        print128(RetValue[i]);
        cout << endl;
        std::cout << "RetValue[" << i+size << "]=";
        print128(RetValue[i+size]);
        cout << endl;
    }

    for(int i=0; i<6; i++){
        uint64_t lt_ans0, lt_ans1, lt_fin;
        Lint result;
        std::cout << "res[i]=";
        print128(rssres[0][i]);
        cout << endl;
        result = rssres[0][i]+Base;
        //cout << int128ToBinary(result) << endl;
        lt_ans0 = evaluateLt(&fServer, &ltk[0][2], result, ecx);
        lt_ans1 = evaluateLt(&fServer, &ltk[0][3], result, ecx);
        lt_fin = lt_ans0 - lt_ans1;
        std::cout << "Cmp: " << lt_fin << std::endl;
    }*/

    printf("Retrieval cost: %.6lf ms\n", (double)(timerR * 0.001));
    printf("RSS cost: %.6lf ms\n", (double)(timerRSS * 0.001));
    printf("FSS cost: %.6lf ms\n", (double)(timerFSS * 0.001));

    std::cout << "Verification Pass : " << ret << ", num_iterations : " << num_iterations << endl;
    //timer = 1e6 * (end.tv_sec - start.tv_sec) + end.tv_usec - start.tv_usec;
    //printf("[%u, %i, %u, %u] [%.6lf ms,  %.6lf ms/size,  %lu bytes] \n", ring_size, size, batch_size, num_iterations, (double)(timer * 0.001), (double)(timer * 0.001 / size) / num_iterations, nodeNet->getCommunicationInBytes() / num_iterations);

    for (uint k = 0; k < num_iterations; k++) {
        for (size_t i = 0; i < 2; i++) {
            delete[] a[k][i];
            delete[] v[k][i];
            delete[] fssres[k][i];
        }
        delete[] a[k];
        delete[] c[k];
        delete[] v[k];
        delete[] rssres[k];
        delete[] fssres[k];
        if(malicious){
            delete[] mac[k];
        }
    }
    delete[] a;
    delete[] c;
    delete[] mac;
    delete[] rssres;
    delete[] fssres;
    delete[] v;
    delete[] buffer;
}

void DBRetrival(LibCass *cass, CassPrepared **SelectPrepared, CassPrepared * SelectValuePrepared, Lint ***a, Lint **value, int ThreadId, uint num_iterations, int thread_num){
    uint batch_size = 3;
    for(uint k=0; k<num_iterations; k++){
        cass->Load_Index(SelectPrepared[k], thread_num, ThreadId, batch_size, a[k]); 
    }
    cass->Load_Index(SelectValuePrepared, thread_num, ThreadId, batch_size, value);
}

void DBRSS(Lint ***a, Lint ***b, Lint ***DataVer, Lint **c, Lint **mac, Lint ***v, int* param){
    uint batch_size = 3;
    int thread_num = param[3];
    int malicious = param[4];
    uint size = param[2]/thread_num;
    int ThreadId = param[0];
    int num_iterations = param[1];
    for(int k=0; k<num_iterations; k++){
        Rss_Mult_Vec(c[k], a[k], b[k], size, batch_size, thread_num, ThreadId, v[k][0]);
        if(malicious){
            Rss_Mult_Vec(mac[k], a[k], DataVer[k], size, batch_size, thread_num, ThreadId, v[k][1]);
        }
    }
}

void DBWorker(LibCass *cass, CassPrepared **SelectPrepared, Lint ***a, Lint ***b, Lint ***DataVer, Lint **c, Lint **mac, Lint ***v, int* param){
    uint batch_size = 3;
    int ThreadId = param[0];
    int num_iterations = param[1];
    int thread_num = param[3];
    int malicious = param[4];
    int size = 0;
    for(int k=0; k<num_iterations; k++){
        size = cass->Load_Index(SelectPrepared[k], thread_num, ThreadId, batch_size, a[k]);
        Rss_Mult_Vec(c[k], a[k], b[k], size, batch_size, thread_num, ThreadId, v[k][0]);
        if(malicious){
            Rss_Mult_Vec(mac[k], a[k], DataVer[k], size, batch_size, thread_num, ThreadId, v[k][1]);
        }
    }
}

void FSSWorker(Fss fServer, ServerKeyLt** ltk, __int128_t **res, uint size, int ThreadId, uint num_iterations, Lint*** fssres, uint32_t ecx, int thread_num, bool malicious){
    uint64_t lt_ans0, lt_ans1;
    Lint result;
    uint begin = ThreadId*size/thread_num;
    uint end = (ThreadId+1)*size/thread_num;
    uint i,k;
    for(k=0; k<num_iterations; k++){
        ServerKeyLt lt_k0 = ltk[k][0];
        ServerKeyLt lt_k1 = ltk[k][1];
        ServerKeyLt lt_k0_ver = ltk[k][2];
        ServerKeyLt lt_k1_ver = ltk[k][3];
        for(i = begin; i < end; i ++){
            //std::cout << "res[i]=" << res[i] << std::endl;
            result = res[k][i]+Base;
            lt_ans0 = evaluateLt(&fServer, &lt_k0, result, ecx);
            lt_ans1 = evaluateLt(&fServer, &lt_k1, result, ecx);
            fssres[k][0][i] = lt_ans0-lt_ans1;

            if(malicious){
                lt_ans0 = evaluateLt(&fServer, &lt_k0_ver, result, ecx);
                lt_ans1 = evaluateLt(&fServer, &lt_k1_ver, result, ecx);
                fssres[k][0][size+i] = lt_ans0-lt_ans1;
            }
        }
    }
}