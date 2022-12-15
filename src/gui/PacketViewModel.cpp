//
// Created by GoldenPigeon on 2022/12/15.
//

#include "gui/PacketViewModel.h"
#include <QStandardItem>
#include <string>
#include <sstream>
#include <ctime>
#include <iomanip>

#define CLR_OSS(oss)  do{(oss).clear();oss.str("");}while(0)
#define OSS2Item new_item(oss.str())

using namespace std;
static QStandardItem* new_item(const string& str){
    return new QStandardItem(str.c_str());
}

static _Put_time<char> get_datetime(int64_t timestamp){
    time_t tmp = timestamp;
    tm* t = gmtime(&tmp);
    return put_time(t, "%Y-%m-%d %H:%M:%S");
}

//static string double2str(double d){
//
//}

PacketViewModel::PacketViewModel(const PacketViewItem &packet, QObject *parent) : QStandardItemModel(parent) {
//    auto *brief = new_item("Protocol: " + packet.protocol);
//    auto *description = new_item(packet.description);
//    brief->appendRow(description);
//    auto *src = new_item(packet.source.addr);
    ostringstream oss;
    oss << "Frame " << packet.id << ": " << packet.cap_len << " bytes on wire " << packet.len << " bytes captured "
    << " on interface " << packet.nic_name;
    auto *frame = OSS2Item;
    CLR_OSS(oss);
    oss << "Interface: " << packet.nic_name;
    auto *nic = OSS2Item;
    CLR_OSS(oss);
    oss << "Interface name: " << packet.nic_name;
    auto *nic_name = OSS2Item;
    CLR_OSS(oss);
    oss << "Interface description" << packet.nic_friendly;
    auto *nic_friendly = OSS2Item;
    CLR_OSS(oss);
    // TODO: set time zone.
    oss << "Arrival Time: " << get_datetime(static_cast<int64_t>(packet.cap_time)) << "." << to_string(packet.cap_time - floor(packet.cap_time)).substr(2);
    auto *cap_time = OSS2Item;
    CLR_OSS(oss);
    oss << "Epoch Time: " << to_string(packet.cap_time);
    auto *epoch_time = OSS2Item;
    CLR_OSS(oss);
    oss << "Frame length: " << packet.len;
    auto *len = OSS2Item;
    CLR_OSS(oss);
    oss << "Capture length: " << packet.cap_time;
    auto *cap_len = OSS2Item;
    CLR_OSS(oss);
    auto *addresses = new_item("Addresses");
    oss << "Source: " << packet.source.addr;
    auto *src = OSS2Item;
    CLR_OSS(oss);
    oss << "Target: " << packet.target.addr;
    auto *dst = OSS2Item;
    CLR_OSS(oss);
    nic->appendRow(nic_name);
    nic->appendRow(nic_friendly);
    frame->appendRow(nic);
    frame->appendRow(cap_time);
    frame->appendRow(epoch_time);
    frame->appendRow(cap_len);
    frame->appendRow(len);
    addresses->appendRow(src);
    addresses->appendRow(dst);
    appendRow(frame);
    appendRow(addresses);

    for(auto &field : packet.detail){
        auto *fieldItem = new_item(field.name);
        for(auto &term : field.frame){
            fieldItem->appendRow(new_item(get<0>(term) + get<1>(term)));
        }
        appendRow(fieldItem);
    }

}
