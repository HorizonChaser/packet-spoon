//
// Created by GoldenPigeon on 2023/1/6.
//

#ifndef DEMO_STATUSBARUPDATER_H
#define DEMO_STATUSBARUPDATER_H

#include <QObject>

class StatusBarUpdater : public QObject{
Q_OBJECT
public:
    friend StatusBarUpdater *statusBarUpdater();
    void show(const QString &str);

signals:
    void statusBarSend(const QString &str);
private:
    StatusBarUpdater() = default;

};


StatusBarUpdater *statusBarUpdater();


#endif //DEMO_STATUSBARUPDATER_H
