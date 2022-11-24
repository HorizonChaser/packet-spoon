
#include <packet-spoon.h>
#include <pcap.h>
#include <tchar.h>
#include <winsock.h>
#include <ws2tcpip.h>

#include <map>
#include <string>
#include <vector>
//#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A00000A
//#endif

//#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
//#endif

#define _WIN32

std::vector<NetworkInterface> NetworkInterface::get_all_network_interfaces() {
    std::vector<NetworkInterface> ret;
    pcap_if_t *alldevs;
    char errBuf[256];

    if (pcap_findalldevs(&alldevs, errBuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errBuf);
        return ret;
    }

    for (auto b = alldevs; b; b = b->next) {
        std::vector<AddressItem> currAddrList = *(new std::vector<AddressItem>());
        NetworkInterface nic = *(new NetworkInterface(currAddrList));
        nic.name = *(new std::string(b->name));
        nic.friendly_name = *(new std::string(b->description));
        nic.is_loop_back = (b->flags & PCAP_IF_LOOPBACK);

        char buf[64];
        memset(buf, 0, sizeof(buf));
        for (auto a = b->addresses; a; a = a->next) {
            AddressItem currAddr = *(new AddressItem());
            switch (a->addr->sa_family) {
                case AF_INET:
                    currAddr.type = "AF_INET";
                    if (a->addr) {
                        inet_ntop(AF_INET, &((struct sockaddr_in *)a->addr)->sin_addr.s_addr, buf, 100);
                        currAddr.addr = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    if (a->netmask) {
                        inet_ntop(AF_INET, &((struct sockaddr_in *)a->addr)->sin_addr.s_addr, buf, 100);
                        currAddr.mask = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    if (a->broadaddr) {
                        inet_ntop(AF_INET, &((struct sockaddr_in *)a->addr)->sin_addr.s_addr, buf, 100);
                        currAddr.broadcast_addr = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    break;

                case AF_INET6:
                    if (a->addr) {
                        inet_ntop(AF_INET6, &((struct sockaddr_in *)a->addr)->sin_addr.s_addr, buf, 100);
                        currAddr.addr = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    break;
                default:
                    currAddr.type = "Unknown Address Type";
                    break;
            }
            currAddrList.push_back(currAddr);
        }
        ret.push_back(nic);
    }
    return ret;
}

CaptureSession::CaptureSession(const NetworkInterface &nic) : curr_interface(nic) {
}

CaptureSession::CaptureSession(const std::string &nic_name) : curr_interface(*(new NetworkInterface(nic_name))) {
}

void CaptureSession::pcap_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content) {
}

void CaptureSession::pcap_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content) {
    std::vector<unsigned char> *content = new std::vector<unsigned char>(packet_header->caplen);

    PacketItem curr = *(new PacketItem(*content));
    auto thisPointer = (CaptureSession *)argument;
    curr.id = thisPointer->cap_count++;
    curr.cap_time = packet_header->ts.tv_sec + packet_header->ts.tv_usec * 0.000001;
    curr.cap_len = packet_header->caplen;
    curr.len = packet_header->len;

    for (size_t i = 0; i < packet_header->caplen; i++) {
        content->push_back(packet_content[i]);
    }

    thisPointer->cap_packets.push_back(curr);
}

bool CaptureSession::start_capture() {
    pcap_t *capHandle;
    char errBuf[256];

    if ((capHandle = pcap_open_live(this->curr_interface.name.c_str(), 65536, 1, 1000, errBuf)) == NULL) {
        this->error_msg = *(new std::string(errBuf));
        return false;
    }

    pcap_loop(capHandle, -1, pcap_callback, (u_char *)this);
}

bool CaptureSession::start_capture(int cnt) {
    pcap_t *curr_handle;
    char errBuf[256];

    if ((curr_handle = pcap_open_live(this->curr_interface.name.c_str(), 65536, 1, 1000, errBuf)) == NULL) {
        this->error_msg = *(new std::string(errBuf));
        return false;
    }
    this->cap_handle = curr_handle;

    this->loop_ret = pcap_loop(curr_handle, cnt, pcap_callback, (u_char *)this);
    return true;
}

bool CaptureSession::stop_capture() {
    // FIXME: 多线程下可能不能正确结束
    //如果如此, 则使用pacp_next_ex()配合轮询停止位进行判断终止
    pcap_breakloop(this->cap_handle);
    if (this->loop_ret == PCAP_ERROR_BREAK) {
        return false;
    }
    return true;
}