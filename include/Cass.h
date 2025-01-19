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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cassandra.h>
#include <iostream> 
#include <chrono>
#include <vector>
#include <unistd.h>
#include <immintrin.h>
#include "setringsize.h"
using namespace std;

class LibCass
{
private:
    CassFuture     *m_pConnFuture;
    CassCluster    *m_pCluster;
    CassPrepared   *m_pInsertStmt = NULL;
    CassPrepared   **m_pSelectStmt = NULL;
    CassPrepared   *m_pValueSelectStmt = NULL;
    int m_pSelectStmt_size = 0;
    bool m_bConnect = false;
public:
    CassSession    *m_pSession;  //其实该成员变量也应是私有的，为偷懒改成公共的了

public:
    LibCass() {}
    ~LibCass()
    {
        disconnect();
    }

    //连接Cassandra
    bool connect(int pid, string IP, string dc);

    //断开Cassandra
    void disconnect();

    bool create_table(string CQL);

    CassPrepared * buildInsertStmt(string query);

    CassPrepared ** buildSelectStmt(string* query, int num_iterations);
    CassPrepared * buildValueSelectStmt(string query);

    bool upload_index(Lint** data, int size, string InsertQuery, int ThreadNum);

    int Load_Index(CassPrepared *SelectPrepared, int ThreadNum, int ThreadId, uint batch_size, Lint** data);
};