#ifndef DEMO_PACKET_SPOON_H
#define DEMO_PACKET_SPOON_H

#include <string>
#include <vector>

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
class AddressItem {
   public:
    std::string type;  // AF_INET for IPv4, AF_INET6 for IPv6
    std::string addr;  //地址

    // 下面两项在 IPv6 下不一定可用, 可能是空串
    std::string mask;            //掩码
    std::string broadcast_addr;  //广播地址
};

/**
 * 网卡信息
 */
class NetworkInterface {
   public:
    std::string name;           //类似第一行的设备路径
    std::string friendly_name;  //人类可读的名字
    bool is_loop_back;          //是否环回设备
    AddressItem* addrs;         //地址列表, 一个网卡可能有多个地址

    NetworkInterface() = delete;

    /**
     * 获得所有的网络接口
     */
    static std::vector<NetworkInterface> get_all_network_interfaces();
};

/**
 * 原始数据包
 */
struct PacketItem {
    int id;           //序号, 保证和 PacketViewItem 的一一对应
    double cap_time;  //捕获到的时刻, 相对开始捕获的时刻来说
    int cap_len;      //捕获到的长度, 可能小于 Len, 即没能完全捕获
    int len;          //真实长度
    char* content;    //原始内容
};

/**
 * 每一层的解析结果
 */
class ParsedFrame {
   public:
    std::string name;                                        //当前层的解析名称
    std::vector<std::pair<std::string, std::string>> frame;  //当前层的解析结果, 0 到多个键值对
};

/**
 * 每个数据包的解析结果, 可能由多层构成
 */
class PacketViewItem {
   public:
    int id;           //序号, 保证和 PacketItem 的一一对应
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
    volatile int cap_count;           //当前已经捕获多少个包, 允许并发读取
    NetworkInterface curr_interface;  //当前被选中的网卡
    double cap_started_at;            //捕获开始时间
    double cap_ended_at;              //捕获结束时间
    std::string error_msg;            //错误原因

    std::vector<PacketViewItem> cap_packets_view;  //解析结果
    std::vector<PacketItem> cap_packets;           //原始数据包

   private:
    volatile int status;  //状态, 仅供内部分析等同步用

   public:
    CaptureSession() = delete;
    CaptureSession(NetworkInterface selected_nic);
    CaptureSession(std::string selected_nic_name);

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
     */
    bool start_analysis();

    /**
     * 获得原始数据包内容, 供 16 进制查看
     */
    const std::vector<PacketItem>& get_packets();

    /**
     * 获得解析结果
     */
    const std::vector<PacketViewItem>& get_packet_views();

    // TODO: 路径类型不一定必须是 string, 可以按照方便改, 比如 FILE 也可以
    // TODO: 保存失败的返回细节 - 不一定必须是 bool, 可再议

    /**
     * 保存到 pcap 文件
     */
    bool dump_to_file_all(std::string path);

    /**
     * 保存某一层的原始内容到文件
     */
    bool dump_selected_frame(std::string frame_name, std::string path);

    /**
     * 关闭当前 Session
     * 注意, 关闭 Session 后该 Session 所有的资源将不保证可用, 因此请确定是否真正需要关闭
     */
    bool close();
};

#endif  // DEMO_PACKET_SPOON_H
