#include <QStandardItemModel>
#include "gui/mainwindow.h"
#include "ui_mainwindow.h"
#include "gui/netcarditemmodel.h"


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    NetCardItemModel *ncModel = new NetCardItemModel(ui->if_table);
    ui->if_table->setModel(ncModel);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
    ui->stackedWidget->setCurrentIndex(1);
}
