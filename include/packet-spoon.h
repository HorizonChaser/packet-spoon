#ifndef DEMO_PACKET_SPOON_H
#define DEMO_PACKET_SPOON_H

#include <chrono>
#include "sstream"
#include <ctime>
#include <map>
#include <string>
#include <tuple>
#include <vector>
#include "pcap.h"
/*

网卡信息的样例

\Device\NPF_{30992269-20EC-4F8B-938A-7842D5458AFA}
        Description: Realtek Gaming GbE Family Controller
        Loopback: no
        Address Family: #2
        Address Family Name: AF_INET
        Address: 192.168.31.239
        Netmask: 255.255.255.0
        Broadcast Address: 192.168.31.255
        Address Family: #23
        Address Family Name: AF_INET6
        Address: 0:0:fe80::93a:36e8
*/

/**
 * 地址
 */

const std::string DEFAULT_NIC_NAME = "Default";
const std::string UNKNOWN_ADDR_TYPE = "Unknown Address Type";
const std::string UNKNOWN_ADDR_STR = "Unknown Address";

class AddressItem {
public:
    // friend class std::vector;
    std::string type;  // AF_INET for IPv4, AF_INET6 for IPv6
    std::string addr;  //地址

    // 下面两项在 IPv6 下不一定可用, 可能是空串
    std::string mask;            //掩码
    std::string broadcast_addr;  //广播地址
    static const AddressItem UNKNOWN_ADDR_IPV4;
    static const AddressItem UNKNOWN_ADDR_IPV6;
    static const AddressItem DEFAULT_ADDR;

    // private:

};


/**
 * 网卡信息
 */
class NetworkInterface {
public:
    // friend class std::vector;
    std::string name;                 //类似第一行的设备路径
    std::string friendly_name;        //人类可读的名字
    bool is_loop_back;                //是否环回设备
    std::vector<AddressItem> &addrs;  //地址列表, 一个网卡可能有多个地址

    explicit NetworkInterface(const std::string &);

    NetworkInterface(const NetworkInterface &ni) = default;

    NetworkInterface(NetworkInterface &&ni) = default;

    NetworkInterface &operator=(const NetworkInterface &another) = delete;

    /**
     * 获得所有的网络接口
     */
    static std::vector<NetworkInterface> get_all_network_interfaces();

    ~NetworkInterface();

    NetworkInterface(std::vector<AddressItem> &in) : addrs(in) {}

    NetworkInterface(const std::string &name, const std::string &friendly_name, bool is_loop_back,
                     std::vector<AddressItem> &addrs) : name(name), friendly_name(friendly_name),
                                                        is_loop_back(is_loop_back), addrs(addrs) {}

};


/**
 * 原始数据包
 */
struct PacketItem {
public:
    // friend class std::vector;
    uint32_t id;                                     //序号, 保证和 PacketViewItem 的一一对应
    double cap_time;                            //捕获到的时刻, 相对开始捕获的时刻来说
    uint32_t cap_len;                                //捕获到的长度, 可能小于 Len, 即没能完全捕获
    uint32_t len;                                    //真实长度
    const std::vector<unsigned char> &content;  //原始内容

    PacketItem(const std::vector<unsigned char> &c) : content(c) {}

//    private:
    ~PacketItem() = default;
};

/**
 * 每一层的解析结果
 */
class ParsedFrame {
public:
    std::string name;                                                   //当前层的解析名称
    std::vector<std::tuple<std::string, std::string, int, int>> frame;  //当前层的解析结果, 0 到多个键值对
};

/**
 * 每个数据包的解析结果, 可能由多层构成
 */
class PacketViewItem {
public:
    uint32_t id;           //序号, 保证和 PacketItem 的一一对应
    double cap_time;  //捕获到的时刻, 相对开始捕获的时刻来说
    AddressItem source;
    AddressItem target;
    std::string protocol;             //最细化的协议, 如果完全不能解析则以 0x 开头
    std::string description;          //行为描述, 如果不能解析长度可能为 0
    std::vector<ParsedFrame> detail;  //解析结果, 由 0 到多个 ParsedFrame 组成
};

/**
 * 捕获过程的控制类, 每一次捕获应当都是一个新的 CaptureSession 对象
 * 成员函数返回 false 说明存在错误, 详细信息在 this.error_msg 中给出
 * 此时不会主动关闭 Session (例如可能是抓包过程中存在错误, 但我们还需要之前正确捕获的数据), 仍需要在合适的时候关闭
 * 该类不允许对 public 字段并发修改
 */
class CaptureSession {
public:
    volatile uint32_t cap_count;                  //当前已经捕获多少个包, 允许并发读取
    uint32_t cap_target;                          //目标捕获的包数, <0 则无限制
    const NetworkInterface &curr_interface;  //当前被选中的网卡
    double cap_started_at;                   //捕获开始时间
    double cap_ended_at;                     //捕获结束时间
    std::string error_msg;                   //错误原因

    std::map<int, PacketViewItem> cap_packets_view;  //解析结果
    std::vector<PacketItem> cap_packets;             //原始数据包

    volatile int status;  //状态, 仅供内部分析等同步用
    pcap_t *cap_handle;   //捕获的句柄
    int loop_ret;         // pcap_loop() 返回的状态

public:
    CaptureSession() = delete;

    explicit CaptureSession(const NetworkInterface &selected_nic) : curr_interface(selected_nic) {}

    CaptureSession(const std::string &selected_nic_name);

    /**
     * 开始捕获, 需要手动调用 stop_capture() 结束
     * 同步阻塞
     */
    bool start_capture();

    /**
     * 捕获到目标数量的包之后自动停止, 或手动调用 stop_capture() 结束
     * 同步阻塞
     */
    bool start_capture(int target_count);

    /**
     * 停止捕获
     */
    bool stop_capture();

    /**
     * 开始解析所有数据包
     * DELETED
     */
    // bool start_analysis();

    /**
     * 获得所有原始数据包内容, 供 16 进制查看
     */
    const std::vector<PacketItem> &get_packets() const;

    /**
     * 获得某个编号的原始数据包内容
     */
    const PacketItem &get_packet(int id) const;

    /**
     * 获得指定 id 的数据包的解析结果
     */
    const PacketViewItem &get_packet_view(int id);

    // TODO: 路径类型不一定必须是 string, 可以按照方便改, 比如 FILE 也可以
    // TODO: 保存失败的返回细节 - 不一定必须是 bool, 可再议

    /**
     * 保存到 pcap 文件
     */
    bool dump_to_file_all(const std::string &path) const;

    /**
     * 保存某一层的原始内容到文件
     */
    bool dump_selected_frame(const std::string &frame_name, const std::string &path);

    /**
     * 关闭当前 Session
     * 注意, 关闭 Session 后该 Session 所有的资源将不保证可用, 因此请确定是否真正需要关闭
     */
    bool close();

    static double get_time_double() {
        auto time = std::chrono::system_clock::now().time_since_epoch();
        std::chrono::seconds seconds = std::chrono::duration_cast<std::chrono::seconds>(time);
        std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(time);
        return (double) seconds.count() + ((double) (ms.count() % 1000) / 1000.0);
    }

private:
    static void pcap_callback(u_char *argument, const struct pcap_pkthdr *packet_header, const u_char *packet_content);
};

class Tools {

public:

    static inline std::pair<char, char> hexBytesToCharPair(unsigned char in) {
        char hi, lo;
        int val = in;
        int H = val / 16, L = val % 16;
        if (H >= 0 && H <= 9) {
            hi = (char) (48 + H);
        } else {
            hi = (char) (55 + H);
        }

        if (L >= 0 && L <= 9) {
            lo = (char) (48 + L);
        } else {
            lo = (char) (55 + L);
        }

        std::pair<char, char> ret;
        ret.first = hi;
        ret.second = lo;

        return ret;
    }

    static std::string macBytesToString(const std::vector<unsigned char> &vec, int pos) {
        std::string ret;
        for (int i = 0; i < 6; ++i) {
            auto c = hexBytesToCharPair(vec[pos + i]);
            ret.push_back(c.first);
            ret.push_back(c.second);
            if (i != 5) {
                ret.push_back(':');
            }
        }

        return ret;
    }

    static std::string ipv4BytesToString(const std::vector<unsigned char> &vec, int pos) {
        std::string ret;
        for (int i = 0; i < 4; ++i) {
            ret.append(std::to_string(vec[pos + i]));
            if (i != 3) {
                ret.push_back('.');
            }
        }

        return ret;
    }

    static std::string ipv6BytesToString(const std::vector<unsigned char> &vec, int pos) {
        //16字节
        std::string ret;
        for (int i = 0; i < 8; ++i) {
            auto c = hexBytesToCharPair(vec[pos + i * 2]);
            ret.push_back(c.first);
            ret.push_back(c.second);

            c = hexBytesToCharPair(vec[pos + i * 2 + 1]);
            ret.push_back(c.first);
            ret.push_back(c.second);

            if (i != 7) {
                ret.push_back(':');
            }
        }

        return ret;
    }

    static std::string hexBytesToString(const std::vector<unsigned char> &vec, int pos, int len) {
        std::string ret;
        for (int i = pos; i < pos + 1; ++i) {
            auto p = hexBytesToCharPair(vec[i]);
            ret.push_back(p.first);
            ret.push_back(p.second);
        }

        return ret;
    }


};

class Parsers {
public:
    friend class CaptureSession;

private:
    static std::string nextSuggestedParser;

    static std::pair<ParsedFrame, uint32_t>
    ethernetParser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem);


    static std::pair<ParsedFrame, uint32_t>
    ipv4Parser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem);

    static std::pair<ParsedFrame, uint32_t>
    ipv6Parser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem);

    static std::pair<ParsedFrame, uint32_t>
    arpParser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem);

    static std::pair<ParsedFrame, uint32_t>
    wolParser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem);

    static std::pair<ParsedFrame, uint32_t>
    tcpParser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem);

    static std::pair<ParsedFrame, uint32_t>
    dummyParser(const std::vector<unsigned char> &vec, uint32_t pos, PacketViewItem &packetViewItem) {
        //没有下一层
        Parsers::nextSuggestedParser = "null";
        auto retFrame = new ParsedFrame();
        retFrame->name = "Dummy Frame, contains nothing but peace and love";
        retFrame->frame.emplace_back("Dummy Key: ", "with Dummy Value", pos, pos);

        packetViewItem.detail.push_back(*retFrame);
        return std::pair<ParsedFrame, uint32_t>(*retFrame, pos);
    }

    Parsers() = default;

    //explicit Parsers(const std::vector<std::pair<std::string, std::string>> &paths);

public:
    static std::map<std::string, decltype(&ipv4Parser)> internalParsers;
    static std::map<std::string, std::string> externalParsers;

    static void initParsers();
    bool addExternalParser(const std::string &path);
};

#endif  // DEMO_PACKET_SPOON_H
