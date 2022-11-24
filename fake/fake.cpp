#include "packet-spoon.h"
#include <istream>
#include <ctime>
#include <windows.h>
using namespace std;


AddressItem addrItems[] = {
    AddressItem{"AF_INET", "1.1.1.1", "255.255.255.0", "1.1.1.255"},
    AddressItem{"AF_INET6", "aaaa:aaaa:aaaa:aaaa:aaaa:aaaa"}
};

AddressItem src = {"AF_INET", "1.1.1.1", "255.255.255.0", "1.1.1.255"};
AddressItem dst = {"AF_INET", "1.1.1.2", "255.255.255.0", "1.1.1.255"};
vector<PacketItem> packetItems = {
    {1, 1, 10, 10, "aaaaaaaaaa"},
    {2, 2, 10, 10, "bbbbbbbbbb"},
    {3, 3, 10, 10, "cccccccccc"},
    {4, 4, 10, 10, "dddddddddd"},
    {5, 5, 10, 10, "eeeeeeeeee"},
    {6, 6, 10, 10, "ffffffffff"},
    {7, 7, 10, 10, "gggggggggg"},
    {8, 8, 10, 10, "hhhhhhhhhh"},
    {9, 9, 10, 10, "iiiiiiiiii"},
    {10, 10, 10, 10, "jjjjjjjjjj"},
};


vector<PacketViewItem> packetViewItems = {
    {
        1,
        1,
        src,
        dst,
        "TCP",
        "ACK",
        {
            {"Header", {{"src", src.addr}, {"dst", dst.addr}}},
            {"Action", {{"atc", "ACK"}}},
            {"Payload", {{"data", "aaa"}}},
        }
    },
    {
        2,
        2,
        src,
        dst,
        "TCP",
        "ACK",
        {
            {"Header", {{"src", src.addr}, {"dst", dst.addr}}},
            {"Action", {{"atc", "ACK"}}},
            {"Payload", {{"data", "bbb"}}},
        }
    },
    {
        3,
        3,
        src,
        dst,
        "TCP",
        "ACK",
        {
            {"Header", {{"src", src.addr}, {"dst", dst.addr}}},
            {"Action", {{"atc", "ACK"}}},
            {"Payload", {{"data", "ccc"}}},
        }
    },
    {
        4,
        4,
        src,
        dst,
        "TCP",
        "ACK",
        {
            {"Header", {{"src", src.addr}, {"dst", dst.addr}}},
            {"Action", {{"atc", "ACK"}}},
            {"Payload", {{"data", "ddd"}}},
        }
    },
    {
        5,
        5,
        src,
        dst,
        "TCP",
        "ACK",
        {
            {"Header", {{"src", src.addr}, {"dst", dst.addr}}},
            {"Action", {{"atc", "ACK"}}},
            {"Payload", {{"data", "eee"}}},
        }
    },
    {
        6,
        6,
        src,
        dst,
        "TCP",
        "ACK",
        {
            {"Header", {{"src", src.addr}, {"dst", dst.addr}}},
            {"Action", {{"atc", "ACK"}}},
            {"Payload", {{"data", "fff"}}},
        }
    },
    {
        7,
        7,
        src,
        dst,
        "TCP",
        "ACK",
        {
            {"Header", {{"src", src.addr}, {"dst", dst.addr}}},
            {"Action", {{"atc", "ACK"}}},
            {"Payload", {{"data", "ggg"}}},
        }
    },
    {
        8,
        8,
        src,
        dst,
        "TCP",
        "ACK",
        {
            {"Header", {{"src", src.addr}, {"dst", dst.addr}}},
            {"Action", {{"atc", "ACK"}}},
            {"Payload", {{"data", "hhh"}}},
        }
    },
    {
        9,
        9,
        src,
        dst,
        "TCP",
        "ACK",
        {
            {"Header", {{"src", src.addr}, {"dst", dst.addr}}},
            {"Action", {{"atc", "ACK"}}},
            {"Payload", {{"data", "iii"}}},
        }
    },
    {
        10,
        10,
        src,
        dst,
        "TCP",
        "ACK",
        {
            {"Header", {{"src", src.addr}, {"dst", dst.addr}}},
            {"Action", {{"atc", "ACK"}}},
            {"Payload", {{"data", "jjj"}}},
        }
    }
};
vector<NetworkInterface> nis;
const int ni_count = 5;
static NetworkInterface& get_ni_by_name(const string& name){
    int i = 0;
    for(; i < ni_count; i++){
        if(nis[i].name == name){
            break;
        }
    }
    return nis[i];
}

int ni_id = 0;

vector<NetworkInterface> NetworkInterface::get_all_network_interfaces(){
    if(nis.size() == 0){
        
        string names[] = {"a", "b", "c", "d", "e"};
        string friendly_names[] = {"aaa", "bbb", "ccc", "ddd", "eee"};
        bool is_loop_back = false;
        for(int i = 0; i < 5; i++){
            nis.push_back(NetworkInterface{names[i], friendly_names[i], is_loop_back, addrItems});
        }
        nis.push_back(NetworkInterface{"Default", "Default", "Default", addrItems});
    }
    return nis;
}

void f(istream& is){
    vector<NetworkInterface> nis = NetworkInterface::get_all_network_interfaces();
    NetworkInterface& ni = nis[0];
    CaptureSession a(ni);
}


CaptureSession::CaptureSession(const NetworkInterface &selected_nic) : curr_interface(selected_nic){
    cap_count = ni_id++;
    cap_started_at = clock() / 1000.0;
    cap_ended_at = 0;
    status = 1;
}

CaptureSession::CaptureSession(const string& name) : curr_interface(get_ni_by_name(name)){
    cap_count = ni_id++;
    cap_started_at = clock() / 1000.0;
    cap_ended_at = 0;
    status = 1;
}

bool CaptureSession::start_capture(){
    for(size_t i = 0; i < packetItems.size() && status == 1; i++){
        cap_packets.push_back(packetItems[i]);
        // _sleep(1000UL);
        Sleep(1000);
    }
    return true;
}

bool CaptureSession::start_capture(int target_count){
    for(size_t i = 0; i < packetItems.size() && i < target_count && status == 1; i++){
        cap_packets.push_back(packetItems[i]);
        // _sleep(1000UL);
        Sleep(1000);
    }
    return true;
}

bool CaptureSession::stop_capture(){
    status = 0;
    return true;
}

bool CaptureSession::start_analysis(){
    for(size_t i = 0; i < cap_packets.size(); i++){
        if(cap_packets_view.count(i) == 0){
            cap_packets_view[i] = packetViewItems[i];
        }
    }
    return true;
}

const vector<PacketItem>& CaptureSession::get_packets() const {
    return cap_packets;
}

const PacketViewItem& CaptureSession::get_packet_view(int id){
    if(cap_packets_view.count(id) == 0){
        cap_packets_view[id] = packetViewItems[id];
    }
    return cap_packets_view[id];
}

bool CaptureSession::dump_to_file_all(const string &path){
    return true;
}

bool CaptureSession::dump_selected_frame(const string& frame_name, const string& path){
    return true;
}

bool CaptureSession::close(){
    return true;
}

