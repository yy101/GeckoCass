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

#include "NodeConfiguration.h"

NodeConfiguration::NodeConfiguration() {}

NodeConfiguration::NodeConfiguration(int nodeID, std::string configFile, int sizeOfModulus) {
    bits = sizeOfModulus;
    id = nodeID;
    loadConfig(configFile);
}

std::string NodeConfiguration::getPeerIP(int id) {
    // Get the index of the id;
    int index = -1;
    for (int i = 0; i < peerID.size(); ++i) {
        if (peerID[i] == id) {
            index = i;
            break;
        }
    }
    return peerIP[index];
}

int NodeConfiguration::getPeerPort(int id) {
    // Get the index of the id;
    int index = -1;
    for (int i = 0; i < peerID.size(); ++i) {
        if (peerID[i] == id) {
            index = i;
            break;
        }
    }
    return peerPort[index];
}

int NodeConfiguration::getPeerIndex(int id) {
    // Get the index of the id
    for (int i = 0; i < peerID.size(); ++i) {
        if (peerID[i] == id)
            return i;
    }
    return -1;
}

std::string NodeConfiguration::getPeerPubKey(int id) {
    // Get the index of the id;
    int index = -1;
    for (int i = 0; i < peerID.size(); ++i) {
        if (peerID[i] == id) {
            index = i;
            break;
        }
    }
    return peerPubKey[index];
}

/*
 * Loads the network configuration from the file.
 * Assumes that the config file is sorted
 */
void NodeConfiguration::loadConfig(std::string configFile) {
    std::ifstream configIn(configFile.c_str(), std::ios::in);
    // Make sure the file exists and can be opened
    if (!configIn) {
        std::cout << "File could not be opened";
        std::exit(1);
    }
    std::string line;
    std::vector<std::string> tokens;
    // Read each line of the configuration file
    while (std::getline(configIn, line)) {
        tokens.clear();
        char *s = strdup(line.c_str());
        char *tok = strtok(s, ",");
        std::string str;
        while (tok != NULL) {
            str = tok;
            tokens.emplace_back(str);
            tok = strtok(NULL, ",");
        }
        // free(original_copy);
        free(s);
        // delete tok;
        // free((char *) tok);
        if (id == atoi(tokens[0].c_str())) {
            ip = tokens[1];
            port = atoi(tokens[2].c_str());
            pubKey = tokens[3];
        } else {
            peerID.emplace_back(atoi(tokens[0].c_str()));
            peerIP.emplace_back(tokens[1]);
            peerPort.emplace_back(atoi(tokens[2].c_str()));
            peerPubKey.emplace_back(tokens[3]);
        }
    }
    configIn.close();
}

NodeConfiguration::~NodeConfiguration() {
}
