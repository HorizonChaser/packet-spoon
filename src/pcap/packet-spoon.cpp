#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A00000A
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif

#ifndef _WIN32
#define _WIN32
#endif


#include "packet-spoon.h"

#include <winsock2.h>
#include <WS2tcpip.h>
#include <pcap.h>
#include <tchar.h>

#include "iostream"
#include "fstream"

#include <map>
#include <string>
#include <vector>

#define WPCAP

std::map<std::string, decltype(&Parsers::ipv4Parser)> Parsers::internalParsers;
std::map<std::string, std::string> Parsers::externalParsers;
std::string Parsers::nextSuggestedParser = "null";


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

    for (auto b = alldevs; b; (b = b->next) != NULL) {
        auto *currAddrList = (new std::vector<AddressItem>());
        auto *nic = (new NetworkInterface(*currAddrList));
        nic->name = *(new std::string(b->name));
        nic->friendly_name = *(new std::string(b->description));
        nic->is_loop_back = (b->flags & PCAP_IF_LOOPBACK);

        char buf[100];
        memset(buf, 0, sizeof(buf));
        for (auto a = b->addresses; a; a = a->next) {
            auto *currAddr = (new AddressItem());
            switch (a->addr->sa_family) {
                case AF_INET:
                    currAddr->type = "AF_INET";
                    if (a->addr) {
                        inet_ntop(AF_INET, &((struct sockaddr_in *) a->addr)->sin_addr.s_addr, buf, 100);
                        //auto res = inet_ntoa(((struct sockaddr_in *) a->addr)->sin_addr);
                        //memcpy(buf, res, strlen(res));
                        currAddr->addr = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    if (a->netmask) {
                        inet_ntop(AF_INET, &((struct sockaddr_in *) a->addr)->sin_addr.s_addr, buf, 100);
                        //auto res = inet_ntoa(((struct sockaddr_in *) a->addr)->sin_addr);
                        //memcpy(buf, res, strlen(res));
                        currAddr->mask = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    if (a->broadaddr) {
                        inet_ntop(AF_INET, &((struct sockaddr_in *) a->addr)->sin_addr.s_addr, buf, 100);
                        //auto res = inet_ntoa(((struct sockaddr_in *) a->addr)->sin_addr);
                        //memcpy(buf, res, strlen(res));
                        currAddr->broadcast_addr = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    break;

                case AF_INET6:
                    currAddr->type = "AF_INET6";
                    if (a->addr) {
                        inet_ntop(AF_INET6, &((struct sockaddr_in *) a->addr)->sin_addr.s_addr, buf, 100);
                        currAddr->addr = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    break;
                default:
                    currAddr->type = UNKNOWN_ADDR_TYPE;
                    memset(buf, 0, 100);
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
    this->is_loop_back = false;
}

NetworkInterface::~NetworkInterface() {
    delete &(this->addrs);
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
    this->cap_handle = capHandle;
    status = 1;
    this->cap_started_at = get_time_double();
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
    this->cap_started_at = get_time_double();
    this->loop_ret = pcap_loop(curr_handle, cnt, pcap_callback, (u_char *) this);
    return true;
}

bool CaptureSession::stop_capture() {
    // FIXED: 多线程下可能不能正确结束
    //如果如此, 则使用pacp_next_ex()配合轮询停止位进行判断终止
    // UPDATE: 已确认, 可以正常使用
    status = -1;
    this->cap_ended_at = get_time_double();
    if (this->loop_ret == PCAP_ERROR_BREAK) {
        return true;
    }
    return false;
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

bool CaptureSession::close() {
    pcap_close(this->cap_handle);
    this->status = -2;

    return true;
}

const PacketViewItem &CaptureSession::get_packet_view(int id) {
    //如果已经有解析了的内容
    if (this->cap_packets_view.find(id) != this->cap_packets_view.end()) {
        return this->cap_packets_view.find(id)->second;
    }

    auto packetViewItem = new PacketViewItem();
    const auto &vec = this->cap_packets[id].content;
    std::pair<ParsedFrame, uint32_t> ret;
    ret = Parsers::ethernetParser(vec, 0, *packetViewItem);

    while(Parsers::nextSuggestedParser != ("null")) {
        auto nextInternalParser = Parsers::internalParsers.find(Parsers::nextSuggestedParser);
        if (nextInternalParser != Parsers::internalParsers.end()) {
            ret = nextInternalParser->second(vec, ret.second, *packetViewItem);
            continue;
        }
        auto nextExteralParser = Parsers::externalParsers.find(Parsers::nextSuggestedParser);
        if (nextExteralParser != Parsers::externalParsers.end()) {
            //TODO use external parsers
            continue;
        }
    }
    typedef std::pair<int, PacketViewItem> PacketViewMapKV;

    this->cap_packets_view.insert(PacketViewMapKV(id, *packetViewItem));

    return *packetViewItem;
}

bool CaptureSession::dump_selected_frame(const std::string &frame_name, const std::string &path) {
    return false;
}

std::pair<ParsedFrame, uint32_t>
Parsers::ipv4Parser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem) {
    typedef std::tuple<std::string, std::string, int, int> FrameTuple;

    auto frame = new ParsedFrame();
    if ((vec[pos] & 0xF0) == 0x40) {
        frame->name = "Internet Protocol Version 4";
    } else {
        return Parsers::dummyParser(vec, pos, packetViewItem);
    }
    uint32_t headerLen = (vec[pos] & 0x0F) * 4;
    frame->frame.push_back(*(new FrameTuple("Protocol Version: ", "4", pos, pos)));
    frame->frame.push_back(*(new FrameTuple("Header Length: ", std::to_string(headerLen), pos, pos)));
    frame->frame.push_back(
            *(new FrameTuple("Diff Service: ", ((new std::string())->append(Tools::hexBytesToString(vec, pos + 1, 1))),
                             pos + 1, pos + 1)));

    uint32_t totalLen = vec[pos + 2] * 16 + vec[pos + 3];
    frame->frame.push_back(*(new FrameTuple("Total Length: ", std::to_string(totalLen), pos + 2, pos + 3)));
    frame->frame.push_back(
            *(new FrameTuple("Identification: ", Tools::hexBytesToString(vec, pos + 4, 2), pos + 4, pos + 5)));

    bool isDF = vec[pos + 6] & 0x4;
    bool isMF = vec[pos + 6] & 0x2;
    std::string flagDesc;
    if (isDF) {
        flagDesc.append("Don't Fragment");
    }
    if (isMF) {
        flagDesc.append(" More Fragment");
    }
    if (flagDesc.empty()) {
        flagDesc.append("No flags set");
    }
    frame->frame.push_back(*(new FrameTuple("Flags: ", flagDesc, pos + 6, pos + 6)));

    uint32_t fragmentOffset = ((vec[pos + 6] & 0x1F) << 8) + vec[pos + 7];
    frame->frame.push_back(*(new FrameTuple("Fragment Offset: ", std::to_string(fragmentOffset), pos + 6, pos + 7)));

    uint32_t ttl = vec[pos + 8];
    frame->frame.push_back(*(new FrameTuple("Time To Live (TTL): ", std::to_string(ttl), pos + 8, pos + 8)));

    if (vec[pos + 9] == 0x06) {
        frame->frame.push_back(*(new FrameTuple("Protocol: ", "IPv4", pos + 9, pos + 9)));
    } else {
        frame->frame.push_back(*(new FrameTuple("Protocol: ", "UNKNOWN", pos + 9, pos + 9)));
        return *(new std::pair<ParsedFrame, uint32_t>(*frame, pos + headerLen));
    }
    frame->frame.push_back(
            *(new FrameTuple("Checksum [Unverified] : ", Tools::hexBytesToString(vec, pos + 10, 2), pos + 10,
                             pos + 11)));

    frame->frame.push_back(*(new FrameTuple("Source: ", Tools::ipv4BytesToString(vec, pos + 12), pos + 12, pos + 15)));
    frame->frame.push_back(
            *(new FrameTuple("Destination: ", Tools::ipv4BytesToString(vec, pos + 16), pos + 16, pos + 20)));

    //如果还有选项, 即IP头总长度大于20字节
    if (headerLen > 20) {
        frame->frame.push_back(
                *(new FrameTuple("Options: ", Tools::hexBytesToString(vec, pos + 20, headerLen - 20), pos + 20,
                                 pos + headerLen)));
    }

    //TODO add proto switch for transport layer
    Parsers::nextSuggestedParser = "dummyParser";

    packetViewItem.protocol = "IPV4";
    packetViewItem.source.addr = Tools::ipv4BytesToString(vec, pos + 12);
    packetViewItem.target.addr = Tools::ipv4BytesToString(vec, pos + 16);

    packetViewItem.detail.push_back(*frame);

    return std::pair<ParsedFrame, uint32_t>(*frame, pos + headerLen);
}

std::pair<ParsedFrame, uint32_t>
Parsers::ipv6Parser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem) {

    return Parsers::dummyParser(vec, pos, packetViewItem);
}

std::pair<ParsedFrame, uint32_t>
Parsers::arpParser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem) {
    return Parsers::dummyParser(vec, pos, packetViewItem);
}

std::pair<ParsedFrame, uint32_t>
Parsers::wolParser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem) {
    return Parsers::dummyParser(vec, pos, packetViewItem);
}

std::pair<ParsedFrame, uint32_t>
Parsers::tcpParser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem) {

    return {};
}

void Parsers::initParsers() {
    typedef std::pair<std::string, decltype(&ipv4Parser)> MapPair;
    Parsers::internalParsers.insert(MapPair("ipv4Parser", &(Parsers::ipv4Parser)));
    Parsers::internalParsers.insert(MapPair("ipv6Parser", &Parsers::ipv6Parser));
    Parsers::internalParsers.insert(MapPair("wolParser", &Parsers::wolParser));
    Parsers::internalParsers.insert(MapPair("dummyParser", &Parsers::dummyParser));
}

/**
 * 添加新的 External Parser
 * @param path
 * @return
 */
bool Parsers::addExternalParser(const std::string &path) {
    //TODO
    return false;
}

std::pair<ParsedFrame, uint32_t>
Parsers::ethernetParser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem) {
    typedef std::tuple<std::string, std::string, int, int> FrameTuple;

    auto ethernetFrame = new ParsedFrame();
    ethernetFrame->name.append("Ethernet Src: ");
    auto macSrc = Tools::macBytesToString(vec, 0);
    auto macDest = Tools::macBytesToString(vec, 6);
    ethernetFrame->name.append(macSrc);
    ethernetFrame->name.append(" Dst: ");
    ethernetFrame->name.append(macDest);

    enum L3_PROTO {
        IPv4, //0x0800
        IPv6, //0x86DD
        ARP, //0x0806
        WoL,//0x0842
        //其他协议以后再说
    };
    L3_PROTO l3Proto;
    if (vec[12] == 0x08 && vec[13] == 0x00) {
        l3Proto = IPv4;
        Parsers::nextSuggestedParser = "ipv4Parser";
    } else if (vec[12] == 0x86 && vec[13] == 0xDD) {
        l3Proto = IPv6;
    } else if (vec[12] == 0x08 && vec[13] == 0x06) {
        l3Proto = ARP;
    } else if (vec[12] == 0x08 && vec[13] == 0x42) {
        l3Proto = WoL;
    }

    auto l2Src = new FrameTuple("Source MAC Address", macSrc, 0, 5);
    auto l2Dest = new FrameTuple("Destination MAC Address", macDest, 6, 11);
    auto l2Type = new FrameTuple();
    switch (l3Proto) {
        case IPv4:
            l2Type = new FrameTuple("Type: ", "IPv4", 12, 13);
            break;
        case IPv6:
            l2Type = new FrameTuple("Type: ", "IPv6", 12, 13);
            break;
        case ARP:
            l2Type = new FrameTuple("Type: ", "ARP", 12, 13);
            break;
        case WoL:
            l2Type = new FrameTuple("Type: ", "WoL", 12, 13);
            break;
    }
    ethernetFrame->frame.push_back(*l2Dest);
    ethernetFrame->frame.push_back(*l2Src);
    ethernetFrame->frame.push_back(*l2Type);

    Parsers::nextSuggestedParser = "ipv4Parser";

    packetViewItem.detail.push_back(*ethernetFrame);
    return std::pair<ParsedFrame, uint32_t>(*ethernetFrame, (uint32_t) 14);
}
