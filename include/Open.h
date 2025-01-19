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

#ifndef OPEN_H_
#define OPEN_H_

#include "NodeNetwork.h"
#include "3pc_all.h"
#include "fss-common.h"
#include "mpc_util.h"
#include <cmath>
#include <stdio.h>
#include <sys/time.h>
extern "C" {
#include "aes_ni.h"
}

void Rss_Open(Lint *res, Lint **a, uint size, uint ring_size, NodeNetwork *nodeNet);
void Rss_Open_Signal(__int128_t *res, Lint *a, uint size, uint ring_size, NodeNetwork *nodeNet);
bool Rss_Open_Verification(Lint **a, Lint **b, Lint r, uint size, uint ring_size, uint num_iterations, NodeNetwork *nodeNet, __m128i * key_prg_ver, uint8_t *key);
void generateCommonKey(uint8_t *key, uint ring_size, NodeNetwork *nodeNet);
void Rss_Open_Byte(uint8_t *res, uint8_t **a, uint size);
void Rss_Open_Bitwise(Lint *res, Lint **a, uint size, uint ring_size, NodeNetwork *nodeNet);

#endif
