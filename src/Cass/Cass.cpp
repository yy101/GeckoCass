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

#include "Cass.h"

    //连接Cassandra
    bool LibCass::connect(int pid, string IP, string dc)
    {
        if (m_bConnect) return true;

        m_pCluster = cass_cluster_new();
        m_pSession = cass_session_new();
        cass_cluster_set_contact_points(m_pCluster, IP.c_str());
        cass_cluster_set_protocol_version(m_pCluster, CASS_PROTOCOL_VERSION_V4);
        cass_cluster_set_port(m_pCluster, 9042);
        m_pConnFuture = cass_session_connect(m_pSession, m_pCluster);
        if (cass_future_error_code(m_pConnFuture)!=CASS_OK)  //错误处理
        {
            const char* message;
            size_t message_length;
            cass_future_error_message(m_pConnFuture, &message, &message_length);
            fprintf(stderr, "Unable to connect: '%.*s'\n", (int)message_length, message);
            return false;
        }
        printf("Cassandra Connect Success!\n");
        m_bConnect = true;

        string CQL = "CREATE KEYSPACE IF NOT EXISTS Keyspace"+to_string(pid)+" WITH REPLICATION = {'class': 'NetworkTopologyStrategy','"+ dc +"':1};";
        CassStatement* DBStatement = cass_statement_new(CQL.c_str(), 0);
        CassFuture* result_future = cass_session_execute(m_pSession, DBStatement);

        cass_statement_free(DBStatement);
        cass_future_free(result_future);
        return m_bConnect;
    }

    //断开Cassandra
    void LibCass::disconnect()
    {
        if (!m_bConnect) return;
        //关闭session并释放局部变量
        CassFuture *pCloseFuture = cass_session_close(m_pSession);
        cass_future_wait(pCloseFuture);
        cass_future_free(pCloseFuture);
        //释放所有成员变量
        if (m_pInsertStmt) cass_prepared_free(m_pInsertStmt);
        if(m_pSelectStmt_size){
            for(int i=0; i<m_pSelectStmt_size; i++){
                cass_prepared_free(m_pSelectStmt[i]);
            }
            free(m_pSelectStmt);
        }
        if (m_pValueSelectStmt) cass_prepared_free(m_pValueSelectStmt);
        cass_future_free(m_pConnFuture);
        cass_cluster_free(m_pCluster);
        cass_session_free(m_pSession);
        m_bConnect = false;
        printf("Disonnect Successful!\n");
    }

    CassPrepared * LibCass::buildInsertStmt(string query){
        if(m_pInsertStmt){
            cass_prepared_free(m_pInsertStmt);
        }
        CassFuture *pPrepareFuture = cass_session_prepare(m_pSession, query.c_str());
        m_pInsertStmt = (CassPrepared*)cass_future_get_prepared(pPrepareFuture);
        cass_future_free(pPrepareFuture);
        return m_pInsertStmt;
    }

    CassPrepared ** LibCass::buildSelectStmt(string* query, int num_iterations){
        if(m_pSelectStmt_size){
            for(int i=0; i<m_pSelectStmt_size; i++){
                cass_prepared_free(m_pSelectStmt[i]);
            }
            delete[] m_pSelectStmt;
        }
        m_pSelectStmt = new CassPrepared* [num_iterations];
        m_pSelectStmt_size = num_iterations;
        for(int i=0; i<m_pSelectStmt_size; i++){
            CassFuture *pPrepareFuture = cass_session_prepare(m_pSession, query[i].c_str());
            m_pSelectStmt[i] = (CassPrepared*)cass_future_get_prepared(pPrepareFuture);
            cass_future_free(pPrepareFuture);
        }
        return m_pSelectStmt;
    }

    CassPrepared * LibCass::buildValueSelectStmt(string query){
        if(m_pValueSelectStmt){
            cass_prepared_free(m_pValueSelectStmt);
        }
        CassFuture *pPrepareFuture = cass_session_prepare(m_pSession, query.c_str());
        m_pValueSelectStmt = (CassPrepared*)cass_future_get_prepared(pPrepareFuture);
        cass_future_free(pPrepareFuture);
        return m_pValueSelectStmt;
    }

    bool LibCass::create_table(string CQL){
        CassStatement* KeyspaceStatement = cass_statement_new(CQL.c_str(), 0);
        CassFuture* result_future = cass_session_execute(m_pSession, KeyspaceStatement);
        cass_statement_free(KeyspaceStatement);
        cass_future_free(result_future);
        return true;
    }

    bool LibCass::upload_index(Lint** data, int size, string InsertQuery, int ThreadNum){
        //string InsertQuery = "INSERT INTO keyspace"+to_string(pid)+".idx_s (section, id, hd11, ld11, hd12, ld12, hd13, ld13, hd21, ld21, hd22, ld22, hd23, ld23) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
        CassPrepared *InsertPrepared = buildInsertStmt(InsertQuery.c_str());
        CassBatch *batch = cass_batch_new(CASS_BATCH_TYPE_LOGGED); 
        cass_batch_set_consistency(batch, CASS_CONSISTENCY_QUORUM);
        //int id = ThreadId*size/ThreadNum;
        //for(; id<(ThreadId+1)*size/ThreadNum; id++){
        unsigned char temp[96];
        int j, offset;
        for(int id = 0; id<size; id++){
            CassStatement* InsertStatement = cass_prepared_bind(InsertPrepared);
            cass_statement_bind_int8(InsertStatement, 0, id%ThreadNum);
            cass_statement_bind_int32(InsertStatement, 1, id);
            offset = 0;
            for(j=0; j<3; j++){
                memcpy(temp+offset, data[0]+id*3+j, 16);
                offset += 16;
                memcpy(temp+offset, data[1]+id*3+j, 16);
                offset += 16;
            }
            cass_statement_bind_bytes(InsertStatement, 2, (cass_byte_t*)temp, offset);
            cass_batch_add_statement(batch, InsertStatement);
            cass_statement_free(InsertStatement);
            if(id % 16384 == 16383){
                //cout << count << " : " << iid << " : " << idot << endl;
                CassFuture *batchFuture = cass_session_execute_batch(m_pSession, batch);
                cass_future_free(batchFuture);
                cass_batch_free(batch);
                batch = cass_batch_new(CASS_BATCH_TYPE_LOGGED);
                cass_batch_set_consistency(batch, CASS_CONSISTENCY_QUORUM);
                usleep(100000);
            }
        }
        CassFuture *batchFuture = cass_session_execute_batch(m_pSession, batch);
        cass_future_free(batchFuture);
        cass_batch_free(batch);
        return true;
    }

    int LibCass::Load_Index(CassPrepared *SelectPrepared, int ThreadNum, int ThreadId, uint batch_size, Lint** data){
        CassStatement* SelectStatement = cass_prepared_bind(SelectPrepared);
        cass_statement_set_consistency(SelectStatement, CASS_CONSISTENCY_QUORUM);
        cass_statement_bind_int8(SelectStatement, 0, ThreadId);
        //cass_statement_set_paging_size(SelectStatement, 64);
            
        CassFuture* result_future = cass_session_execute(m_pSession, SelectStatement);
        //获取查询结果
        const CassResult* result = cass_future_get_result(result_future);
        CassIterator* rows = cass_iterator_from_result(result);

        int count = 0;
        int index = ThreadId*batch_size;   //(count*ThreadNum+ThreadId)*batch_size;
        char column_name[] = "data";
        int j, offset;
        const cass_byte_t* bytes;
        size_t bytes_size;
        while(cass_iterator_next(rows)) {
            const CassRow* row = cass_iterator_get_row(rows);
            const CassValue* value = cass_row_get_column_by_name(row, column_name);
            cass_value_get_bytes(value, &bytes, &bytes_size);
            offset = 0;
            for(j=0; j<3; j++){
                memcpy(data[0]+index+j, bytes+offset, 16);
                offset += 16;
                memcpy(data[1]+index+j, bytes+offset, 16);
                offset += 16;
            }
            count++;
            index += ThreadNum*batch_size;
        }
        cass_statement_free(SelectStatement);

        cass_result_free(result);
        cass_future_free(result_future);
        cass_iterator_free(rows);

        return count;
    }