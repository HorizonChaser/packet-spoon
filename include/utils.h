#ifndef PACKET_SPOON_GUI_UTILS_H
#define PACKET_SPOON_GUI_UTILS_H

#include "packet-spoon.h"
#include <string>
#include <vector>



const AddressItem& get_addr_from_type(const std::vector<AddressItem>& addrs, const std::string& type);

#endif // PACKET_SPOON_GUI_UTILS_H