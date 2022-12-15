//
// Created by GoldenPigeon on 2022/12/15.
//

#ifndef DEMO_PACKETVIEWMODEL_H
#define DEMO_PACKETVIEWMODEL_H

#include <QStandardItemModel>
#include "packet-spoon.h"
class PacketViewModel : public QStandardItemModel{

public:
    explicit PacketViewModel(const PacketViewItem& packet, QObject *parent = nullptr);

};


#endif //DEMO_PACKETVIEWMODEL_H
