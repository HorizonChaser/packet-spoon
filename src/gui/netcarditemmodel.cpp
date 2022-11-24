#include <QString>


#include "gui/netcarditemmodel.h"

#include "packet-spoon.h"

using namespace std;

NetCardItemModel::NetCardItemModel(QObject *parent)
    : QStandardItemModel(parent)
{
    vector<NetworkInterface> nis = NetworkInterface::get_all_network_interfaces();
    for(auto &ni : nis){
        QStandardItem *name = new QStandardItem(QString(ni.name.c_str()));
        QStandardItem *friendly = new QStandardItem(QString(("Description : " + ni.friendly_name).c_str()));
        QStandardItem *loop = new QStandardItem(QString((ni.is_loop_back ? "LOOP : True" : "LOOP : False")));
        QStandardItem *ipv4 = new QStandardItem(QString(("IPv4 : " + ni.addrs->addr).c_str()));
        QStandardItem *mask = new QStandardItem(QString(("MASK : " + ni.addrs->mask).c_str()));
        QStandardItem *broadcast = new QStandardItem(QString(("BroadCast : " + ni.addrs->broadcast_addr).c_str()));
        name->appendRow(friendly);
        name->appendRow(loop);
        name->appendRow(ipv4);
        name->appendRow(mask);
        name->appendRow(broadcast);
        appendRow(name);
    }
    setHorizontalHeaderLabels(QStringList()<<QStringLiteral("网卡列表"));
}
