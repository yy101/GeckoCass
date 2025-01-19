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

#ifndef FSS_SERVER_H
#define FSS_SERVER_H

#include "fss-common.h"
#include <cmath>

// Initializes server with information from the client, namely aes_keys for PRF and numBits in input domain
void initializeServer(Fss* fServer, Fss* fClient);

// Runs interval(step) FSS given key on input x for 2 parties/providers
uint64_t evaluateLt(Fss* f, ServerKeyLt *k, __uint128_t x, uint32_t ecx);

#endif
