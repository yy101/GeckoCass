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

#ifndef SHUFFLE_H
#define SHUFFLE_H

#include <stdint.h>
#include <limits.h>
#include <stdio.h>

struct shuffle_ctx {
	size_t key;
	size_t nitems;
	/* Half block size in bits */
	size_t hbsz;
};

void shuffle_init(struct shuffle_ctx *ctx, size_t nitems, size_t seed);

size_t shuffle_index(struct shuffle_ctx *ctx, size_t index);

size_t shuffle_index_invert(struct shuffle_ctx *ctx, size_t index);

void shuffle_reseed(struct shuffle_ctx *ctx, size_t seed);

#endif