# GeckoCass: Lightweight and Scalable Secure Range Search on Cassandra

This is the implementation for USENIX SECURITY'25 Cycle 2 paper #211.

**WARNING**: This is an academic proof-of-concept prototype. This implementation is NOT ready for production use.

This prototype is released under the GNU General Public v3 License (see [License](http://www.gnu.org/licenses/)).

## Environment

We test our scheme on the Ubuntu 22.04.5 LTS operating system. Some of our optimizations may not be applicable to other operating systems. 

## Setup

Install the dependency libraries with 
`
apt-get install libssl-dev build-essential cmake git zlib1g-dev libkrb5-dev libuv1-dev nlohmann-json3-dev libcrypto++-dev libgmp-dev libboost-all-dev libunwind8-dev libgoogle-perftools-dev
`.

Install Cassandra's C/C++ Driver (tested on v2.17.1) using the instructions [here](https://docs.datastax.com/en/developer/cpp-driver/2.17/topics/building/index.html). Download Cassandra database (tested on v5.0.0) from [here](https://archive.apache.org/dist/cassandra/5.0.0/), unpack it on the server.

## Building

Build GeckoCass
```
mkdir build
cd build
cmake ..
make
cd ..
```

## Key generation
In order to run the code, you first need to generate ssh key pairs for each party; the public keys must be accessible by each computing party. To generate the key pairs, run the script:

```
./ssh_keygen.sh 3
```

## Parameter configuration
Cassandra's configuration files can be found in the `apache-cassandra-x.x.x/conf`. Open `cassandra-rackdc.properties` and rename data center $DC_X$'s dc and rack as `dc=dcX` and `rack=rackX` (`X`∈{1,2,3}).

The configuration files can be found in the `config` directory. Please update `runtime-config-3`and `server-config` with the data center's IP address and dc.

`server-config`:  
`data_size` is the record number of the queried table in the `KeySpace_X`. We use it to simulate caching the number of records in the tables within `KeySpace_X` on the data center $DC_X$.
`thread_num` is the number of threads in parallel computing. Ensure that `thread_num` does not exceed the number of physical cores. Exceeding this limit may lead to thread contention, resulting in increased context switching and decreased performance.

`client-config`:  
`data_size` is the number of records to be inserted. 
`operation` specifies the operation to be executed: `1` for `SECCREATE`, `2` for `SECINSERT`, and `3` for `SECWHERE`.
`num_ands` is the number of range filter.
`source_path` is the absolute path of data file.

## Testing locally
Start Cassandra with `apache-cassandra-x.x.x/bin/cassandra -f`.

To run the entire system locally, start data center $DC_X$ as `./server X config/runtime-config-3 config/server-config`. Make sure to start the data center in order from 3 to 1. Then, start the client with `./client config/runtime-config-3 config/client-config`. 

When querying data, please keep the `thread_num` of the data center consistent with when inserting those data.
