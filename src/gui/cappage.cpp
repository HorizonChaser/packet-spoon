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
#include <QFileDialog>
#include "utils.h"
#include "gui/cappage.h"
#include "ui_cappage.h"
#include "gui/PacketViewModel.h"
#include "gui/PacketTermItem.h"
#include "gui/StatusBarUpdater.h"
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
    qDebug()<<"Thread "<<QThread::currentThreadId() << " starting capturing...\n";
    if(cap_cnt <= 0){
        session->start_capture();
    } else {
        session->start_capture(cap_cnt);
    }
    qDebug()<<"Thread "<<QThread::currentThreadId() << " capturing stopped.\n";
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
    ui->packetDetailTreeView_4->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->packetDetailTreeView_4->header()->hide();
//    ui->packetDetailTreeView_4->header()->setStretchLastSection(false);
    ui->packetDetailTreeView_4->header()->setSectionResizeMode(QHeaderView::ResizeToContents);
//    ui->packetDetailTreeView_4->header()->setMinimumSectionSize(10000);
    ui->packetDetailTreeView_4->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOn);

    session = nullptr;
    cThread = nullptr;
    timer = new QTimer();
    connect(timer, &QTimer::timeout, this, &CapPage::updatePacketsTable);


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
        if(started)
            session->close();
        delete session;
        session = nullptr;
    }
}

void CapPage::open_session(const QString &name) {
    started = false;
    stopped = false;
    ui->stopButton->setEnabled(false);
    ui->startButton->setEnabled(true);
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
    replace_model(ui->packetDetailTreeView_4, nullptr);
    // TODO: SETTING CAP COUNT MANUALLY
    cThread = new CapThread(session, 1000);
    connect(cThread, &CapThread::error, this, &CapPage::onCapThreadError);
}

void CapPage::start_capture() {
    Q_ASSERT(cThread != nullptr);
    cThread->start();
    qDebug() << "cThread started.";
    started = true;
    ui->stopButton->setEnabled(true);
    ui->startButton->setEnabled(false);
    timer->start(500);
}

void CapPage::stop_capture() {
    if(!started){
        return;
    }

    session->stop_capture();
//    QThread::msleep(500);
    //TODO: test whether it is appropriate to quit the thread.
    if(cThread->isRunning())
        cThread->quit();
    timer->stop();
    stopped = true;
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
    if (session == nullptr)
        return;
    auto *model = dynamic_cast<QStandardItemModel *>(ui->packetsBriefTableView->model());
    auto rows = model->rowCount();
    size_t captured_cnt = session->get_packets().size();
    for (size_t i = rows; i < captured_cnt; i++) {
        const PacketItem &packet = session->get_packet(static_cast<int>(i));
        model->appendRow(QList<QStandardItem *>()
                                 << new QStandardItem(QString::number(packet.id))
                                 << new QStandardItem(to_string(packet.cap_time).c_str())
                                 << new QStandardItem(QString::number(packet.cap_len))
                                 << new QStandardItem(byteVec2QString(packet.content, 10))
        );
    }
}
void CapPage::on_startButton_clicked()
{

    start_capture();
}

void CapPage::on_stopButton_clicked()
{
    stop_capture();

    ui->stopButton->setEnabled(false);
}

void CapPage::on_backButton_clicked()
{
    stop_capture();
//    QThread::msleep(500);
    free_cthread();
    free_session();
    emit goBackSignal();
}

void CapPage::on_packetsBriefTableView_clicked(const QModelIndex &index)
{
    int idx = index.row();
    auto packetView = session->get_packet_view(idx);
    auto *model = new PacketViewModel(packetView);
    replace_model(ui->packetDetailTreeView_4, model);
    auto *selectionModel = ui->packetDetailTreeView_4->selectionModel();
    qDebug() << "on_packetsBriefTableView_clicked: " << selectionModel->model()->rowCount();
    connect(selectionModel,&QItemSelectionModel::currentRowChanged,this,&CapPage::slotPacketDetailCurrentRowChanged);
    ui->packetRawDisplay->showPacket(session->get_packet(idx), session->get_packet_view(idx));
}

void CapPage::slotPacketDetailCurrentRowChanged(const QModelIndex &current, const QModelIndex &previous) {
//    QMessageBox::information(this, "提示", "treeview clicked");
    QModelIndex index = current.sibling(current.row(),0);
    auto* item = dynamic_cast<PacketTermItem *>(dynamic_cast<PacketViewModel *>(ui->packetDetailTreeView_4->model())->itemFromIndex(
            index));
    QStringList qsl;
    qsl.append("selected range:");
    qsl.append(QString::number(item->getStart()));
    qsl.append(QString::number(item->getEnd()));
    statusBarUpdater()->statusBarSend(qsl.join(" "));
    if(item->hasHighlight()){
        ui->packetRawDisplay->highlight(item->getStart(), item->getEnd());
    }
}

void CapPage::savePcap() {
    if(!stopped){
        QMessageBox::information(this, "提示", "抓包完成，请完成抓包后再保存");
    }
    QString fileName = QFileDialog::getSaveFileName(this, "保存抓包结果", "./", "pcap files (*.pcap)");
    session->dump_to_file_all(fileName.toStdString());
}
