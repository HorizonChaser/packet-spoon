//
// Created by GoldenPigeon on 2023/1/6.
//

#include "include/gui/StatusBarUpdater.h"

StatusBarUpdater *statusBarUpdater() {
    static StatusBarUpdater instance;
    return &instance;
}

void StatusBarUpdater::show(const QString &str) {
    emit statusBarSend(str);
}
