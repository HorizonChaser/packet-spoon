#include <QThread>
#include <QMessageBox>
#include <QTimer>
#include <QStandardItemModel>
#include <QList>
#include <QStandardItem>
#include <QByteArray>
#include <QStringList>
#include <QChar>
#include <cctype>
#include <vector>
#include <QHeaderView>
#include "utils.h"
#include "gui/cappage.h"
#include "ui_cappage.h"

using namespace std;

static QString hex2QChar(int h){
    Q_ASSERT(h >= 0 && h < 16);
    if(h < 10){
        return QChar('0' + h);
    } else {
        return QChar('A' + h);
    }
}

static QString unprintable2QString(char unprintable){
    Q_ASSERT(!isprint(unprintable));
    QString str = "\\x";
    str.append(hex2QChar((static_cast<unsigned char>(unprintable) & 0xF0) >> 4));
    str.append(hex2QChar(static_cast<unsigned char>(unprintable) & 0x0F));
    return str;
}

static QString byteVec2QString(const vector<unsigned char> &byteVec, size_t maxLen=0){
    if(maxLen == 0)
        maxLen = byteVec.size();
    QString str;
    for(int i = 0; i < maxLen; i++){
        char c = static_cast<char>(byteVec[i]);
        if(isprint(c))
            str.append(c);
        else
            str.append(unprintable2QString(c));
    }
    return str;
}


void CapThread::run() {
    if(session == nullptr){
        emit error("程序逻辑错误，请联系开发者。");
    }
//    qDebug()<<"Thread "<<QThread::currentThreadId() << " starting capturing...\n";
    if(cap_cnt <= 0){
        session->start_capture();
    } else {
        session->start_capture(cap_cnt);
    }
//    qDebug()<<"Thread "<<QThread::currentThreadId() << " capturing stopped.\n";
    printf("cThread stopped.");
    fflush(stdout);
}


CapPage::CapPage(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::CapPage)
{
    ui->setupUi(this);
    ui->packetsBriefTableView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->packetsBriefTableView->verticalHeader()->hide();
    ui->packetsBriefTableView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->packetsBriefTableView->horizontalHeader()->setMinimumSectionSize(80);
    ui->packetsBriefTableView->horizontalHeader()->setMaximumSectionSize(200);

    session = nullptr;
    cThread = nullptr;
    timer = new QTimer();
    connect(timer, &QTimer::timeout, this, &CapPage::updatePacketsTable);
    timer->start(500);
}

CapPage::~CapPage()
{
    delete ui;
    delete timer;
    free_session();
    free_cthread();
}

void CapPage::free_session() {
    Q_ASSERT(cThread == nullptr);
    if(session != nullptr) {
        session->close();
        delete session;
        session = nullptr;
    }
}

void CapPage::open_session(const QString &name) {
    free_cthread();
    free_session();
    session = new CaptureSession(name.toStdString());
    auto* model = new QStandardItemModel;
    model->setHorizontalHeaderLabels(QStringList()
                                          << "id"
                                          << "time"
                                          << "len"
                                          << "brief content"
                                          );
    replace_model(ui->packetsBriefTableView, model);
    // TODO: SETTING CAP COUNT MANUALLY
    cThread = new CapThread(session, 1000);
    connect(cThread, &CapThread::error, this, &CapPage::onCapThreadError);
}

void CapPage::start_capture() {
    Q_ASSERT(cThread != nullptr);
    cThread->start();
    printf("cThread started.");
    fflush(stdout);
}

void CapPage::stop_capture() {
    session->stop_capture();
    QThread::msleep(500);
    //TODO: test whether it is appropriate to quit the thread.
    if(cThread->isRunning())
        cThread->quit();
}

void CapPage::free_cthread() {
    if(cThread != nullptr) {
        delete cThread;
        cThread = nullptr;
    }
}

void CapPage::onCapThreadError(const QString &msg) {
    QMessageBox::critical(this, "严重错误", msg);
}

void CapPage::updatePacketsTable() {
    if(session == nullptr)
        return;
    auto *model = reinterpret_cast<QStandardItemModel*>(ui->packetsBriefTableView->model());
    auto rows = model->rowCount();
    size_t captured_cnt = session->get_packets().size();
    for(size_t i = rows; i < captured_cnt; i++){
        const PacketItem &packet = session->get_packet(static_cast<int>(i));
        model->appendRow(QList<QStandardItem *>()
                    << new QStandardItem(QString::number(packet.id))
                    << new QStandardItem(QString::number(packet.cap_time))
                    << new QStandardItem(QString::number(packet.cap_len))
                    << new QStandardItem(byteVec2QString(packet.content, 10))
                    );
    }

//
//    auto *model = new QStandardItemModel;
//    auto packets = session->cap_packets;
//    int index = 0;
//    for(auto &packet : packets){
//        model->appendRow(QList<QStandardItem *>()
//                            << new QStandardItem(QString::number(packet.id))
//                            << new QStandardItem(QString::number(packet.cap_time))
//                            << new QStandardItem(QString::number(packet.cap_len))
//                            << new QStandardItem(byteVec2QString(packet.content, 10))
//                            );
//        index++;
//    }
//    model->setHorizontalHeaderLabels(QStringList()
//                                              << "id"
//                                              << "time"
//                                              << "len"
//                                              << "brief content"
//                                              );
//    replace_model(ui->packetsBriefTableView, model);
}

void CapPage::on_startButton_clicked()
{
    start_capture();
}

void CapPage::on_stopButton_clicked()
{
    stop_capture();
//    updatePacketsTable();
}

void CapPage::on_backButton_clicked()
{
    stop_capture();
    QThread::msleep(1000);
    free_cthread();
    free_session();
    emit goBackSignal();
}
