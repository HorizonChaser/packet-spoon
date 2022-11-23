#ifndef DEMO_PACKET_SPOON_H
#define DEMO_PACKET_SPOON_H

#include <vector>
#include <string>

typedef uint32_t ipv4_t;

// 网卡
struct NetCard{
    // 网卡名称 如 WLAN
    std::string name;
    // 网卡描述 如 Qualcomm QCA9377 802.11ac Wireless Adapter
    std::string description;
    // 物理地址 如 0xEC5C68257AF5 代表 EC-5C-68-25-7A-F5
    uint64_t physics;
    // ipv6高48位
    uint64_t ipv6_high = 0;
    // ipv6低48位
    uint64_t ipv6_low = 0;
    ipv4_t ipv4 = 0;
    // 掩码位数 如 24
    uint8_t mask_bits = 0;
    // 网关
    ipv4_t gateway = 0;
    ipv4_t dns = 0;

    NetCard();
    NetCard(const std::string &name, const std::string &description, uint64_t physics, uint64_t ipv6_high, uint64_t ipv6_low, ipv4_t ipv4, uint8_t mask_bits, ipv4_t gateway, ipv4_t dns) : name(name), description(description), physics(physics), ipv6_high(ipv6_high), ipv6_low(ipv6_low), ipv4(ipv4), mask_bits(mask_bits), gateway(gateway), dns(dns) {}
};
// 返回值DTO
template <typename T>
struct RetMsg{
    T* retVal;
    bool success = true;
    std::string msg = "";
    RetMsg();
    RetMsg(T* retVal, bool success, std::string msg) : retVal(retVal), success(success), msg(msg) {}
};

// 数据包字段
struct PacketItemTreeNode{
    std::string name = "";
    std::string content = "";
    int start_pos = -1;
    int end_pos = -1;
    int len = 0;
    // 子节点
    PacketItemTreeNode* child = nullptr;
    // 兄弟节点
    PacketItemTreeNode* next = nullptr;
    PacketItemTreeNode(const std::string &name, const std::string &content, int start_pos = -1, int end_pos = -1) : name(name), content(content), start_pos(start_pos), end_pos(end_pos) {}
};

struct PacketItemTree{
    PacketItemTreeNode* root;
    PacketItemTree(PacketItemTreeNode* root) : root(root) {}
    ~PacketItemTree() {
        if(root)
            delete root;
    }
};

// 数据包
struct Packet{
    int id;
    // 自开始捕获起的时间
    double time;
    // 源地址
    ipv4_t sourse;
    // 目标地址
    ipv4_t target;
    // 协议编号 如果未知协议名，则显示编号
    int protocol;
    int len;
    std::string protocol_name;
    // 数据包行为描述430443	如 443 → 9319 [ACK] Seq=4555 Ack=4528 Win=525568 Len=0
    std::string info;
};


// 网卡句柄
typedef int nc_handler_t;
// 初始化系统
void init_capture_system();
// 程序结束前调用
void free_all();

//获取所有网卡信息
RetMsg<std::vector<NetCard>> get_all_net_cards();


//根据网卡名获取网卡句柄，句柄类型为int，可以将实际的pcap_t存于数组中，然后返回数组的索引
RetMsg<nc_handler_t> get_net_card(std::string name);

// 开启一个线程，捕获包，并缓存
void start_capture(nc_handler_t ncHandler);

// 如果缓存区中有包，获取下一个包。如果没有，阻塞
RetMsg<Packet> get_next_packet(nc_handler_t ncHandler);
// 停止捕获，并关闭网卡
void close_net_card(nc_handler_t ncHandler);
// 解析数据包
RetMsg<PacketItemTree> parse_packet(nc_handler_t ncHandler, int id);
// 保存网卡捕获结果
RetMsg<bool> save_net_card_capture_result(nc_handler_t ncHandler, std::vector<int> saving_ids, std::string path);
// 自定义扩展信息
struct Extension{
    std::string name;
    std::string description;
    std::string path;
    Extension();
    Extension(std::string name, std::string description, std::string path) : name(name), description(description), path(path) {}
};

RetMsg<bool> add_extension(const Extension& ext);

RetMsg<bool> remove_extension(std::string name);

RetMsg<std::vector<Extension>> get_all_extensions();




#endif // DEMO_PACKET_SPOON_H