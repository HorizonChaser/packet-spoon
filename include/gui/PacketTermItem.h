//
// Created by GoldenPigeon on 2023/1/5.
//

#ifndef DEMO_PACKETTERMITEM_H
#define DEMO_PACKETTERMITEM_H

#include <QStandardItem>

class PacketTermItem : public QStandardItem {
public:
    PacketTermItem() : QStandardItem() {

    }

    explicit PacketTermItem(const QString &text) : QStandardItem(text), start(-1), end(-1) {

    }

    PacketTermItem(const QString &text, int start, int end) : QStandardItem(text), start(start), end(end) {

    }

    PacketTermItem(const QIcon &icon, const QString &text) : QStandardItem(icon, text) {

    }

    explicit PacketTermItem(int rows, int columns) : QStandardItem(rows, columns) {

    }

    bool hasHighlight() const {
        return !(start == -1 && end == -1);
    }

    int getStart() const {
        return start;
    }

    int getEnd() const{
        return end;
    }

    void setStart(int Start) {
        start = Start;
    }

    void setEnd(int End) {
        end = End;
    }

private:
    int start{};
    int end{};
};


#endif //DEMO_PACKETTERMITEM_H
