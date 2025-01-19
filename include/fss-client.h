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

#ifndef FSS_CLIENT_H
#define FSS_CLIENT_H

#include "fss-common.h"
#include <cmath>
#include <gmp.h>
#include <gmpxx.h>

// Initializes client. numBits is number of bits in input domain
void initializeClient(Fss* f, uint32_t numBits, uint32_t numParties, uint32_t ecx);

// Creates keys for a function that evaluates to b when input x < a.
void generateTreeLt(Fss* f, ServerKeyLt* k0, ServerKeyLt* k1, __uint128_t a_i, uint64_t b_i, uint32_t ecx);

#endif
