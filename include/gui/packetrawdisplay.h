#ifndef PACKETRAWDISPLAY_H
#define PACKETRAWDISPLAY_H

#include <QWidget>
#include "packet-spoon.h"
namespace Ui {
class PacketRawDisplay;
}

class PacketRawDisplay : public QWidget
{
    Q_OBJECT

public:
    explicit PacketRawDisplay(QWidget *parent = nullptr);
    ~PacketRawDisplay() override;

    void showPacket(const PacketItem& packet, const PacketViewItem& view);
    void highlight(int start, int end);


public slots:
//    void onFieldSelected(int begin, int end);
    void onBitSelected(int pos);

private:
    Ui::PacketRawDisplay *ui;
    std::vector<std::pair<int, int>> groups;
};

#endif // PACKETRAWDISPLAY_H
