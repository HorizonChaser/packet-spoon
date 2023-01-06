#ifndef CAPPAGE_H
#define CAPPAGE_H

#include <QWidget>
#include <QString>
#include <QThread>
#include <QTimer>
#include "packet-spoon.h"


class CapThread : public QThread{
Q_OBJECT
public:
    explicit CapThread(CaptureSession* session, int cap_cnt=0) : session(session), cap_cnt(cap_cnt) {}
    void run() override;
signals:
    void error(const QString &msg);
private:
    CaptureSession *session;
    int cap_cnt;
};

namespace Ui {
class CapPage;
}

class CapPage : public QWidget
{
    Q_OBJECT

public:
    explicit CapPage(QWidget *parent = nullptr);
    ~CapPage();
    void open_session(const QString &name);
    void start_capture();
    void stop_capture();

public slots:
    void onCapThreadError(const QString &msg);
    void updatePacketsTable();
    void slotIfTableCurrentRowChanged(const QModelIndex &current, const QModelIndex &previous);

private slots:
    void on_startButton_clicked();

    void on_stopButton_clicked();

    void on_backButton_clicked();

    void on_packetsBriefTableView_clicked(const QModelIndex &index);

signals:
    void goBackSignal();

private:
    Ui::CapPage *ui;
    CaptureSession *session;
    void free_session();
    void free_cthread();
    CapThread* cThread;
    QTimer *timer;
};

#endif // CAPPAGE_H
