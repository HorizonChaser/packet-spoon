#include <QString>


#include "gui/netcarditemmodel.h"

#include "packet-spoon.h"
#include "utils.h"
using namespace std;

NetCardItemModel::NetCardItemModel(QObject *parent)
    : QStandardItemModel(parent)
{
    vector<NetworkInterface> nis = NetworkInterface::get_all_network_interfaces();
    for(auto &ni : nis){
        const AddressItem& addrIPv4 = get_addr_from_type(ni.addrs, "AF_INET");
        const AddressItem& addrIPv6 = get_addr_from_type(ni.addrs, "AF_INET6");
        QStandardItem *name = new QStandardItem(QString(ni.name.c_str()));
        QStandardItem *friendly = new QStandardItem(QString(("Description : " + ni.friendly_name).c_str()));
        QStandardItem *loop = new QStandardItem(QString((ni.is_loop_back ? "LOOP : True" : "LOOP : False")));
        QStandardItem *ipv4 = new QStandardItem(QString(("IPv4 : " + addrIPv4.addr).c_str()));
        QStandardItem *mask = new QStandardItem(QString(("MASK : " + addrIPv4.mask).c_str()));
        QStandardItem *broadcast = new QStandardItem(QString(("BroadCast : " + addrIPv4.broadcast_addr).c_str()));
        QStandardItem *ipv6 = new QStandardItem(QString(("IPv6 : " + addrIPv6.addr).c_str()));
        name->appendRow(friendly);
        name->appendRow(loop);
        name->appendRow(ipv4);
        name->appendRow(mask);
        name->appendRow(broadcast);
        appendRow(name);
    }
    setHorizontalHeaderLabels(QStringList()<<QStringLiteral("网卡列表"));
}
