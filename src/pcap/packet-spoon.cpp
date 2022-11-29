
#include <packet-spoon.h>
#include <pcap.h>
#include <tchar.h>
#include <winsock.h>
#include <ws2tcpip.h>

#include <map>
#include <string>
#include <vector>
#include "iostream"
#include "fstream"

#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A00000A
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#ifndef _WIN32
#define _WIN32
#endif

const AddressItem AddressItem::UNKNOWN_ADDR_IPV4 = {
        "AF_INET",
        UNKNOWN_ADDR_STR,
        UNKNOWN_ADDR_STR,
        UNKNOWN_ADDR_STR};

const AddressItem AddressItem::UNKNOWN_ADDR_IPV6 = {
        "AF_INET6",
        UNKNOWN_ADDR_STR,
        "",
        ""};

const AddressItem AddressItem::DEFAULT_ADDR = {
        UNKNOWN_ADDR_TYPE,
        "",
        "",
        ""};

std::vector<NetworkInterface> NetworkInterface::get_all_network_interfaces() {
    std::vector<NetworkInterface> ret;
    pcap_if_t *alldevs;
    char errBuf[256];

    if (pcap_findalldevs(&alldevs, errBuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errBuf);
        return ret;
    }

    for (auto b = alldevs; b; b = b->next) {
        std::vector<AddressItem> *currAddrList = (new std::vector<AddressItem>());
        NetworkInterface *nic = (new NetworkInterface(*currAddrList));
        nic->name = *(new std::string(b->name));
        nic->friendly_name = *(new std::string(b->description));
        nic->is_loop_back = (b->flags & PCAP_IF_LOOPBACK);

        char buf[100];
        memset(buf, 0, sizeof(buf));
        for (auto a = b->addresses; a; a = a->next) {
            AddressItem *currAddr = (new AddressItem());
            switch (a->addr->sa_family) {
                case AF_INET:
                    currAddr->type = "AF_INET";
                    if (a->addr) {
                        auto res = inet_ntoa(((struct sockaddr_in *) a->addr)->sin_addr);
                        memcpy(buf, res, strlen(res));
                        currAddr->addr = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    if (a->netmask) {
                        // inet_ntop(AF_INET, &((struct sockaddr_in *)a->addr)->sin_addr.s_addr, buf, 100);
                        auto res = inet_ntoa(((struct sockaddr_in *) a->addr)->sin_addr);
                        memcpy(buf, res, strlen(res));
                        currAddr->mask = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    if (a->broadaddr) {
                        // inet_ntop(AF_INET, &((struct sockaddr_in *)a->addr)->sin_addr.s_addr, buf, 100);
                        auto res = inet_ntoa(((struct sockaddr_in *) a->addr)->sin_addr);
                        memcpy(buf, res, strlen(res));
                        currAddr->broadcast_addr = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    break;

                case AF_INET6:
                    currAddr->type = "AF_INET6";
                    if (a->addr) {
                        // inet_ntop(AF_INET6, &((struct sockaddr_in *)a->addr)->sin_addr.s_addr, buf, 100);
                        // currAddr->addr = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    break;
                default:
                    currAddr->type = UNKNOWN_ADDR_TYPE;
                    break;
            }
            currAddrList->push_back(*currAddr);
        }
        ret.push_back(*nic);
    }
    return ret;
}

NetworkInterface::NetworkInterface(const std::string &name) : addrs(*(new std::vector<AddressItem>())) {
    this->name = *(new std::string(name));
    auto all_nic_list = NetworkInterface::get_all_network_interfaces();
    for (const auto &c: all_nic_list) {
        if (c.name.compare(name) == 0) {
            this->friendly_name = c.friendly_name;
            this->is_loop_back = c.is_loop_back;
            this->addrs = *new std::vector<AddressItem>();
            for (const auto &c_addr: c.addrs) {
                addrs.push_back(c_addr);
            }
            break;
        }
    }
    throw "Requested NIC not found";
}

CaptureSession::CaptureSession(const NetworkInterface &nic) : curr_interface(nic) {
    this->cap_count = 0;
}

CaptureSession::CaptureSession(const std::string &nic_name) : curr_interface(*(new NetworkInterface(nic_name))) {
    this->cap_count = 0;
}

void
CaptureSession::pcap_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content) {
    auto *content = new std::vector<unsigned char>();

    auto *curr = (new PacketItem(*content));
    auto thisPointer = (CaptureSession *) argument;
    curr->id = thisPointer->cap_count++;
    curr->cap_time = packet_header->ts.tv_sec + packet_header->ts.tv_usec * 0.000001;
    curr->cap_len = packet_header->caplen;
    curr->len = packet_header->len;

    for (size_t i = 0; i < packet_header->caplen; i++) {
        content->push_back(packet_content[i]);
    }
    thisPointer->cap_packets.push_back(*curr);

    //判断是否该终止
    if (thisPointer->status < 0) {
        pcap_breakloop(thisPointer->cap_handle);
    }
}

bool CaptureSession::start_capture() {
    pcap_t *capHandle;
    char errBuf[256];

    if ((capHandle = pcap_open_live(this->curr_interface.name.c_str(), 65536, 1, 1000, errBuf)) == NULL) {
        this->error_msg = *(new std::string(errBuf));
        return false;
    }

    this->loop_ret = pcap_loop(capHandle, -1, pcap_callback, (u_char *) this);
    return true;
}

bool CaptureSession::start_capture(int cnt) {
    pcap_t *curr_handle;
    char errBuf[256];

    if ((curr_handle = pcap_open_live(this->curr_interface.name.c_str(), 65536, 1, 1000, errBuf)) == NULL) {
        this->error_msg = *(new std::string(errBuf));
        return false;
    }
    this->cap_handle = curr_handle;

    this->loop_ret = pcap_loop(curr_handle, cnt, pcap_callback, (u_char *) this);
    return true;
}

bool CaptureSession::stop_capture() {
    // FIXED: 多线程下可能不能正确结束
    //如果如此, 则使用pacp_next_ex()配合轮询停止位进行判断终止
    // UPDATE: 已确认, 可以正常使用
    status = -1;
    if (this->loop_ret == PCAP_ERROR_BREAK) {
        return false;
    }
    return true;
}

const std::vector<PacketItem> &CaptureSession::get_packets() const {
    return this->cap_packets;
}

const PacketItem &CaptureSession::get_packet(int id) const {
    return this->cap_packets[id];
}

bool CaptureSession::dump_to_file_all(const std::string &path) const {
    std::ofstream outFileStream(path, std::ios::out | std::ios::binary);

    struct PCAP_HEADER {
        uint32_t MAGIC_NUM = 0xA1B2C3D4;
        uint16_t MAJOR_VER = 2;
        uint16_t MINOR_VER = 4;
        uint32_t RESERVED_1 = 0;
        uint32_t RESERVED_2 = 0;
        uint32_t SNAP_LEN = 0xFFFF0000;
        uint32_t LINK_TYPE = 0x1;
    };

    PCAP_HEADER header;

    //TODO 大小写匹配
    if (this->curr_interface.friendly_name.length() &&
        this->curr_interface.friendly_name.find("WiFi") != std::string::npos) {
        header.LINK_TYPE = 0x105;//802.11 WiFi protocol
    }

    outFileStream.write((char *) &header, sizeof(header));

    struct PCAP_PACKET_HEADER {
        uint32_t TIME_HIGH;
        uint32_t TIME_LOW;
        uint32_t CAP_LEN;
        uint32_t ORI_LEN;
    };

    for (const auto &pac: this->cap_packets) {
        PCAP_PACKET_HEADER packetHeader{};
        packetHeader.TIME_HIGH = (uint32_t) pac.cap_time;
        packetHeader.TIME_LOW = (uint32_t) ((pac.cap_time - (uint32_t) pac.cap_time) * 1000000);
        packetHeader.CAP_LEN = pac.cap_len;
        packetHeader.ORI_LEN = pac.len;

        outFileStream.write((char *) &packetHeader, sizeof(packetHeader));

        for (const auto &data: pac.content) {
            outFileStream << data;
        }
    }

    return true;
}


