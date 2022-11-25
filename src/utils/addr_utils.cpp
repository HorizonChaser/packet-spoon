#include "utils.h"
#include "packet-spoon.h"
using namespace std;
const AddressItem& get_addr_from_type(const vector<AddressItem>& addrs, const string& type){
    if(type == "AF_INET"){
        for(auto &addr : addrs){
            if(addr.type == type){
                return addr;
            }
        }
        return AddressItem::UNKNOWN_ADDR_IPV4;
    }
    if(type == "AF_INET6"){
        for(auto &addr : addrs){
            if(addr.type == type){
                return addr;
            }
        }
        return AddressItem::UNKNOWN_ADDR_IPV6;
    }
    return AddressItem::DEFAULT_ADDR;
    
}