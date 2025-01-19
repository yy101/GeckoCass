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

#ifndef NODECONFIGURATION_H_
#define NODECONFIGURATION_H_

#include <cstdlib>
#include <fstream>
#include <iostream>
#include "setringsize.h"
#include <string.h>
#include <string>
#include <vector>

class NodeConfiguration {

public:
    NodeConfiguration();
    NodeConfiguration(int nodeID, std::string configFile, int bits);
    int getID();
    void setBits(int); // add for 3p
    std::string getIP();
    int getPort();
    int getBits();
    int getPeerCount();
    int getPeerIndex(int id);
    std::string getPeerIP(int id);
    int getPeerPort(int id);
    virtual ~NodeConfiguration();
    std::string getPubKey();
    std::string getPeerPubKey(int id);

private:
    int id;
    int bits;
    std::string ip;
    int port;
    std::vector<std::string> peerIP;
    std::vector<int> peerPort;
    std::vector<int> peerID;
    void loadConfig(std::string configFile);
    std::string pubKey;
    std::vector<std::string> peerPubKey;
};

inline int NodeConfiguration::getBits() {
    return 128;
}

inline void NodeConfiguration::setBits(int imputbits) {
    bits = imputbits;
}

inline int NodeConfiguration::getID() {
    return id;
}

inline std::string NodeConfiguration::getIP() {
    return ip;
}

inline int NodeConfiguration::getPort() {
    return port;
}

inline int NodeConfiguration::getPeerCount() {
    return peerIP.size();
}

inline std::string NodeConfiguration::getPubKey() {
    return pubKey;
}

#endif
