#include "gui/packetrawdisplay.h"
#include "ui_packetrawdisplay.h"

PacketRawDisplay::PacketRawDisplay(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::PacketRawDisplay)
{
    ui->setupUi(this);
    ui->charDisplay->setContentType(TextContent::ASCII);
    connect(ui->charDisplay, &CodeHighlightableTextEdit::mouseOverPos, this, &PacketRawDisplay::onBitSelected);
    connect(ui->hexDisplay, &CodeHighlightableTextEdit::mouseOverPos, this, &PacketRawDisplay::onBitSelected);
}

PacketRawDisplay::~PacketRawDisplay()
{
    delete ui;
}

void PacketRawDisplay::showPacket(const PacketItem &packet, const PacketViewItem &view) {
    ui->charDisplay->setRaw(packet.content);
    ui->hexDisplay->setRaw(packet.content);
    groups.clear();
    for(auto &frame : view.detail){
        for(auto &item : frame.frame){
            int start = get<2>(item);
            int end = get<3>(item);
            groups.emplace_back(start, end + 1);
        }
    }
}

void PacketRawDisplay::onBitSelected(int pos) {
    qDebug() << "onBitSelected(pos): " << pos;
    for(auto &group : groups) {
        if(group.first <= pos && group.second > pos){
            highlight(group.first, group.second);
            return;
        }
    }
    highlight(pos, pos + 1);
}

void PacketRawDisplay::highlight(int start, int end) {
    ui->charDisplay->highlight(start, end);
    ui->hexDisplay->highlight(start, end);
}
