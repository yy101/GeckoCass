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

#ifndef MULT_H_
#define MULT_H_

#include "NodeNetwork.h"
#include "mpc_util.h"
#include <cmath>
#include <stdio.h>
#include <sys/time.h>
#include <immintrin.h>
#include <omp.h>
#include "Cass.h"

void Rss_Mult_Bitwise(Lint **c, Lint **a, Lint **b, uint size, uint ring_size, NodeNetwork *nodeNet);
void Rss_Mult(Lint **c, Lint **a, Lint **b, uint size, uint ring_size, NodeNetwork *nodeNet);
void Rss_nMult(Lint *c, Lint **a, Lint **b, uint size, uint batch_size, bool malicious, uint offset);
void Rss_Reshare(Lint **a, uint size, NodeNetwork *nodeNet);
void Rss_Mult_Reshare(Lint **c, Lint **a, Lint **b, uint size, uint ring_size, NodeNetwork *nodeNet);
void Rss_Mult_Vec(Lint *c, Lint **a, Lint **b, uint size, uint batch_size, int ThreadNum, int ThreadId, Lint *v);
void Rss_Mult_Random(Lint **c, uint size, uint batch_size, uint ring_size, NodeNetwork *nodeNet);
void Rss_MultPub(Lint *c, Lint **a, Lint **b, uint size, uint ring_size, NodeNetwork *nodeNet);

#endif
