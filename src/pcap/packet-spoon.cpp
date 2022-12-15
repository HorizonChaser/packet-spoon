#pragma clang diagnostic push
#pragma ide diagnostic ignored "OCInconsistentNamingInspection"
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
#include "py/python.h"
#include "rapidjson/document.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/reader.h"

#define WPCAP

std::map<std::string, decltype(&Parsers::ipv4Parser)> Parsers::internalParsers;
std::map<std::string, std::string> Parsers::externalParsers;
std::string Parsers::nextSuggestedParser = "null";
bool Parsers::isInitialized = false;
uint32_t Parsers::externalParserPos = 0;


const AddressItem AddressItem::UNKNOWN_ADDR_IPV4 = {"AF_INET", UNKNOWN_ADDR_STR, UNKNOWN_ADDR_STR, UNKNOWN_ADDR_STR};

const AddressItem AddressItem::UNKNOWN_ADDR_IPV6 = {"AF_INET6", UNKNOWN_ADDR_STR, "", ""};

const AddressItem AddressItem::DEFAULT_ADDR = {UNKNOWN_ADDR_TYPE, "", "", ""};

std::vector<NetworkInterface> NetworkInterface::get_all_network_interfaces() {
    std::vector<NetworkInterface> ret;
    pcap_if_t *alldevs;
    char errBuf[256];

    if (pcap_findalldevs(&alldevs, errBuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errBuf);
        return ret;
    }
    if (alldevs == nullptr) {
        return ret;
    }

    for (auto b = alldevs; b; b = b->next) {
        auto *nic = new NetworkInterface();
        auto &currAddrList = nic->addrs;
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
//                        auto res = inet_ntoa(((struct sockaddr_in *) a->addr)->sin_addr);
//                        memcpy(buf, res, strlen(res));
                        currAddr->addr = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    if (a->netmask) {
                        inet_ntop(AF_INET, &((struct sockaddr_in *) a->addr)->sin_addr.s_addr, buf, 100);
//                        auto res = inet_ntoa(((struct sockaddr_in *) a->addr)->sin_addr);
//                        memcpy(buf, res, strlen(res));
                        currAddr->mask = *(new std::string(buf));
                        memset(buf, 0, 100);
                    }
                    if (a->broadaddr) {
                        inet_ntop(AF_INET, &((struct sockaddr_in *) a->addr)->sin_addr.s_addr, buf, 100);
//                        auto res = inet_ntoa(((struct sockaddr_in *) a->addr)->sin_addr);
//                        memcpy(buf, res, strlen(res));
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
            currAddrList.push_back(*currAddr);
        }
        ret.push_back(*nic);
    }
    pcap_freealldevs(alldevs);
    return ret;
}

NetworkInterface::NetworkInterface(const std::string &name) : addrs(*(new std::vector<AddressItem>())) {
    this->name = *(new std::string(name));
    this->is_loop_back = false;
}

NetworkInterface::~NetworkInterface() = default;

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

    //TODO 预分配空间
    for (size_t i = 0; i < packet_header->caplen; i++) {
        content->push_back(packet_content[i]);
    }
    thisPointer->cap_packets.push_back(*curr);

    //如果被中断, 或在已设定目标数量的前提下抓到了足够的包, 则可退出
    if (thisPointer->status < 0 ||
        ((thisPointer->cap_target > 0) && (thisPointer->cap_count >= thisPointer->cap_target))) {
        pcap_breakloop(thisPointer->cap_handle);
    }
}

bool CaptureSession::start_capture() {
    pcap_t *capHandle;
    char errBuf[256];
    this->cap_count = 0;
    this->cap_target = 0;

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
    this->cap_count = 0;
    this->cap_target = cnt;

    if ((curr_handle = pcap_open_live(this->curr_interface.name.c_str(), 65536, 1, 1000, errBuf)) == NULL) {
        this->error_msg = *(new std::string(errBuf));
        return false;
    }
    status = 1;
    this->cap_handle = curr_handle;
    this->cap_started_at = get_time_double();
    this->loop_ret = pcap_loop(curr_handle, cnt, pcap_callback, (u_char *) this);
    return true;
}

bool CaptureSession::stop_capture() {
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
        header.LINK_TYPE = 0x105; //802.11 WiFi protocol
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
    //如果已经有当前数据包的解析结果
    if (this->cap_packets_view.find(id) != this->cap_packets_view.end()) {
        return this->cap_packets_view.find(id)->second;
    }

    auto packetViewItem = new PacketViewItem();
    packetViewItem->id = id;
    packetViewItem->len = this->get_packet(id).len;
    packetViewItem->cap_len = this->get_packet(id).cap_len;
    packetViewItem->nic_name = curr_interface.name;
    packetViewItem->nic_friendly = curr_interface.friendly_name;
    packetViewItem->cap_time = this->get_packet(id).cap_time;

    const auto &vec = this->cap_packets[id].content;
    std::pair<ParsedFrame, uint32_t> ret;
    ret = Parsers::ethernetParser(vec, 0, *packetViewItem);
    Parsers::externalParserPos = ret.second;

    while (Parsers::nextSuggestedParser != ("null")) {
        auto nextInternalParser = Parsers::internalParsers.find(Parsers::nextSuggestedParser);
        if (nextInternalParser != Parsers::internalParsers.end()) {
            ret = nextInternalParser->second(vec, ret.second, *packetViewItem);
            Parsers::externalParserPos = ret.second;
            continue;
        }
        auto nextExternalParser = Parsers::externalParsers.find(Parsers::nextSuggestedParser);
        if (nextExternalParser != Parsers::externalParsers.end()) {
            auto xxx = nextInternalParser->second;
            auto exRet = Parsers::externalParserWrapper(nextExternalParser->second, nextExternalParser->first, vec,
                                                        Parsers::externalParserPos, *packetViewItem);
            continue;
        }
    }
    typedef std::pair<int, PacketViewItem> PacketViewMapKV;

    this->cap_packets_view.insert(PacketViewMapKV(id, *packetViewItem));
    return *packetViewItem;
}

bool CaptureSession::dump_selected_frame(int id, const std::string &frame_name, const std::string &path) {
    const auto &view = get_packet_view(id).detail;
    for (const auto &cFrame: view) {
        if (cFrame.name == frame_name) {
            std::ofstream outFileStream(path, std::ios::out | std::ios::binary);
            if (cFrame.frame.empty()) {
                return false;
            }
            uint32_t beginPos = std::get<2>(cFrame.frame[0]);
            uint32_t endPos = std::get<3>(cFrame.frame.back());
            for (uint32_t i = beginPos; i <= endPos; ++i) {
                outFileStream << get_packet(id).content[i];
            }
            return true;
        }
    }
    return false;
}

bool CaptureSession::dump_range_to_file(int id, const std::string &path, uint32_t beginPos, uint32_t endPos) {
    const auto &view = get_packet_view(id).detail;

    std::ofstream outFileStream(path, std::ios::out | std::ios::binary);
    if (endPos >= get_packet(id).content.size()) {
        return false;
    }

    for (uint32_t i = beginPos; i <= endPos; ++i) {
        outFileStream << get_packet(id).content[i];
    }
    return true;
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

    //如果还有选项, 即 IP 头总长度大于 20 字节
    if (headerLen > 20) {
        frame->frame.push_back(
                *(new FrameTuple("Options: ", Tools::hexBytesToString(vec, pos + 20, headerLen - 20), pos + 20,
                                 pos + headerLen)));
    }

    //TODO add proto switch for transport layer
    Parsers::nextSuggestedParser = "tcpParser";

    packetViewItem.protocol = "IPv4";
    packetViewItem.source.addr = Tools::ipv4BytesToString(vec, pos + 12);
    packetViewItem.target.addr = Tools::ipv4BytesToString(vec, pos + 16);

    //TODO set packetViewItem.desc
    packetViewItem.detail.push_back(*frame);

    return std::make_pair(*frame, pos + headerLen);
}

std::pair<ParsedFrame, uint32_t>
Parsers::ipv6Parser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem) {
    //TODO
    return Parsers::dummyParser(vec, pos, packetViewItem);
}

std::pair<ParsedFrame, uint32_t>
Parsers::arpParser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem) {
    //TODO
    return Parsers::dummyParser(vec, pos, packetViewItem);
}

std::pair<ParsedFrame, uint32_t>
Parsers::wolParser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem) {
    //TODO
    return Parsers::dummyParser(vec, pos, packetViewItem);
}

/**
 * 初始化 Parsers, 添加 Internal Parsers
 */
void Parsers::initParsers() {
    typedef std::pair<std::string, decltype(&ipv4Parser)> MapPair;
    if (!isInitialized) {
        Parsers::internalParsers.insert(MapPair("ipv4Parser", Parsers::ipv4Parser));
        Parsers::internalParsers.insert(MapPair("ipv6Parser", Parsers::ipv6Parser));
        Parsers::internalParsers.insert(MapPair("wolParser", Parsers::wolParser));
        Parsers::internalParsers.insert(MapPair("dummyParser", Parsers::dummyParser));
        isInitialized = true;
    }
}

bool Parsers::addExternalParser(const std::string &path, const std::string &name) {
    if (checkParserPresent(name)) {
        return false;
    }
    externalParsers.insert(std::pair<std::string, std::string>(path, name));
    return true;
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
        Parsers::nextSuggestedParser = "dummyParser";
    } else if (vec[12] == 0x08 && vec[13] == 0x06) {
        l3Proto = ARP;
        Parsers::nextSuggestedParser = "dummyParser";
    } else if (vec[12] == 0x08 && vec[13] == 0x42) {
        l3Proto = WoL;
        Parsers::nextSuggestedParser = "dummyParser";
    }

    auto l2Src = new FrameTuple("Source MAC Address: ", macSrc, 0, 5);
    auto l2Dest = new FrameTuple("Destination MAC Address: ", macDest, 6, 11);
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

    //TODO set packetViewItem.desc
    packetViewItem.detail.push_back(*ethernetFrame);
    return std::make_pair(*ethernetFrame, (uint32_t) 14);
}

void Parsers::initParsers(const std::vector<std::pair<std::string, std::string>> &paths) {
    if (!isInitialized) {
        initParsers();
        for (auto p: paths) {

        }
    }
}

std::pair<bool, std::string>
Parsers::externalParserWrapper(const std::string& parserModule, const std::string& parserFunc, const std::vector<unsigned char> &vec,
                               uint32_t pos, PacketViewItem &packetViewItem) {
    Py_Initialize();
    PyRun_SimpleString("import sys");
    PyRun_SimpleString("sys.path.append('./')");
    PyRun_SimpleString("sys.path.append('./pyParsers')");
    auto pName = PyUnicode_FromString(parserModule.c_str());
    auto pModule = PyImport_Import(pName);

    if (!pModule) {
        Py_Finalize();
        return std::pair<bool, std::string>{false, "Parser not found"};
    }

    char *mem = (char *) ::malloc(vec.size());
    for (int i = 0; i < vec.size(); ++i) {
        mem[i] = vec[i];
    }
    PyObject * byteArr = PyBytes_FromStringAndSize(mem, vec.size());
    PyObject * pFunc = PyObject_GetAttrString(pModule, parserFunc.c_str());
    PyObject * pArgs = PyTuple_New(2);
    PyTuple_SetItem(pArgs, 1, Py_BuildValue("i", pos));
    PyTuple_SetItem(pArgs, 0, byteArr);

    if (!PyCallable_Check(pFunc)) {
        Py_Finalize();
        return std::pair<bool, std::string>{false, "Parser not callable"};
    }

    auto ret = PyObject_CallObject(pFunc, pArgs);
    PyObject * ptype, *pvalue, *ptraceback;
    char *pStrErrorMessage;
    if (PyErr_Occurred()) {
        PyErr_Fetch(&ptype, &pvalue, &ptraceback);
        PyErr_Clear();
        Py_Finalize();
        return std::pair<bool, std::string>{false,
                                            "Python Exception Occurred:" + std::string(PyBytes_AS_STRING(pvalue))};
    }
    if (ret == nullptr) {
        Py_Finalize();
        return std::pair<bool, std::string>{false, "Parser Returned Null"};
    }

    rapidjson::Document document;
    document.Parse(PyBytes_AS_STRING(ret));
    Py_Finalize();

    auto newFrame = new ParsedFrame();
    auto memberFinder = document.FindMember("name");
    if (memberFinder == document.MemberEnd()) {
        delete newFrame;
        return std::pair<bool, std::string>{false, "Parser result missing following field: name"};
    }
    newFrame->name = std::string(memberFinder->value.GetString());

    memberFinder = document.FindMember("nextSuggestedParser");
    if (memberFinder == document.MemberEnd()) {
        delete newFrame;
        return std::pair<bool, std::string>{false, "Parser result missing following field: nextSuggestedParser"};
    }
    if (!checkParserPresent(memberFinder->value.GetString())) {
        delete newFrame;
        return std::pair<bool, std::string>{false, "Parser result points to a non-existing parser: " +
                                                   std::string(memberFinder->value.GetString())};
    }
    Parsers::nextSuggestedParser = memberFinder->value.GetString();

    memberFinder = document.FindMember("pos");
    if (memberFinder == document.MemberEnd()) {
        delete newFrame;
        return std::pair<bool, std::string>{false, "Parser result missing following field: pos"};
    }
    uint32_t retPos = memberFinder->value.GetUint();

    memberFinder = document.FindMember("frameCount");
    if (memberFinder == document.MemberEnd()) {
        delete newFrame;
        return std::pair<bool, std::string>{false, "Parser result missing following field: frameCount"};
    }
    int frameCount = memberFinder->value.GetInt();

    memberFinder = document.FindMember("frames");
    if (memberFinder == document.MemberEnd()) {
        delete newFrame;
        return std::pair<bool, std::string>{false, "Parser result missing following field: frames"};
    }

    memberFinder = document.FindMember("desc");
    if (memberFinder == document.MemberEnd()) {
        delete newFrame;
        return std::pair<bool, std::string>{false, "Parser result missing following field: desc"};
    }
    packetViewItem.description = memberFinder->value.GetString();

    memberFinder = document.FindMember("source");
    if (memberFinder != document.MemberEnd()) {
        packetViewItem.source = AddressItem();
        packetViewItem.source.addr = memberFinder->value.GetString();
    }

    memberFinder = document.FindMember("destination");
    if (memberFinder != document.MemberEnd()) {
        packetViewItem.target = AddressItem();
        packetViewItem.target.addr = memberFinder->value.GetString();
    }

    memberFinder = document.FindMember("protocol");
    if (memberFinder != document.MemberEnd()) {
        packetViewItem.protocol = memberFinder->value.GetString();
    }

    const auto &frames = document["frames"];
    for (int i = 0; i < frameCount; ++i) {
        newFrame->frame.emplace_back(frames[i]["key"].GetString(), frames[i]["val"].GetString(),
                                     frames[i]["posBegin"].GetInt(), frames[i]["posEnd"].GetInt());
    }

    packetViewItem.detail.push_back(*newFrame);
    Parsers::externalParserPos = retPos;
    return std::pair<bool, std::string>{true, ""};
}

bool Parsers::checkParserPresent(const std::string &name) {
    return internalParsers.find(name) != internalParsers.end() || externalParsers.find(name) != externalParsers.end();
}

#pragma clang diagnostic pop