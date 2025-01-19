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

#include "mpc_util.h"

void print_binary(Lint n, uint size){
    uint temp = size-1;
    int i = size-1;
    uint b;
    while(i !=-1) {
        b = GET_BIT(n, temp);
        printf("%u", b);
        temp--;
        i -= 1;
    }
    printf("\n");
}

void print128(__int128_t x) {
    if (x < 0) {
        putchar('-');
        x = -x;
    }
    if (x > 9) print128(x / 10);
    putchar(x % 10 + '0');
}

// Function to convert string to __uint128_t
__uint128_t stringToUint128(const std::string& str) {
    __uint128_t result = 0;
    for (char c : str) {
        result = result * 10 + (c - '0');
    }
    return result;
}

// Function to convert __uint128_t to string
std::string uint128ToString(__uint128_t value) {
    std::string result;
    while (value > 0) {
        result = char('0' + value % 10) + result;
        value /= 10;
    }
    return result.empty() ? "0" : result;
}

__int128_t range(__int128_t delta, __int128_t xl, __int128_t xr, int batch, bool reverse){
    if(batch == 2){
        if(reverse){
            return -1;
        } else{
            return 1;
        }
    } else if(batch == 1){
        if(reverse){
            return xl+xr;
        } else{
            return -xl-xr;
        }
    } else{
        if(reverse){
            return (xl+delta)*(xr-delta)-2*xl*xr;
        } else{
            return (xl+delta)*(xr-delta);
        }
    }
}

__int128_t ipow(__int128_t data, int exp, int precision, __int128_t offset){
    if(exp == 2){
        return ((data << precision)+offset)*((data << precision)+offset);
    } else if(exp == 1){
        return (data << precision) + offset;
    } else{
        return 1;
    }
}

/*double I2F(int value, int precision, int length){
    double ret = value >> precision;
    float decimal = (value << (length-precision-1)) >> (length-precision-1);
    ret += decimal / pow(2, precision);
    return ret;
}

__int128_t F2I(double value, int precision){
    __int128_t ret = value;
    ret = (ret << precision) + (value-ret) * pow(2, precision);
    return ret;
}*/

double absMax(double *input, uint size){
    double max = abs(input[0]);
    for (size_t i = 1; i < size; i++) {
        if (abs(input[i]) > max) {
            max = abs(input[i]);
        }
    }
    return max;
}

double absMax(std::vector<double> input){
    double max = abs(input[0]);
    for (size_t i = 1; i < input.size(); i++) {
        if (abs(input[i]) > max) {
            max = abs(input[i]);
        }
    }
    return max;
}


double getScale(uint bound, double *input, uint size){
    double abs_max = absMax(input, size);
    return ((double) bound / abs_max);
}

double getScale(uint bound, std::vector<double> x){

    double abs_max = absMax(x);
    return ((double) bound / abs_max);
}

void q_applyScale(sLint *output, double *input, double scale, uint size){
    for (size_t i = 0; i < size ; i++) {
        // y.at(i) = scale * x.at(i);
        output[i] = input[i] * scale;
    }
}
