#include <QStandardItemModel>
#include <QItemSelectionModel>
#include <QAbstractItemView>
#include <QMessageBox>
#include "gui/mainwindow.h"
#include "ui_mainwindow.h"
#include "gui/netcarditemmodel.h"


MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ncModel = new NetCardItemModel(ui->if_table);
    ui->if_table->setModel(ncModel);
    ui->if_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    connect(ui->if_table->selectionModel(),&QItemSelectionModel::selectionChanged,this,&MainWindow::slotIfTableSelectionChanged);
    connect(ui->if_table->selectionModel(),&QItemSelectionModel::currentChanged,this,&MainWindow::slotIfTableCurrentChanged);
    connect(ui->if_table->selectionModel(),&QItemSelectionModel::currentRowChanged,this,&MainWindow::slotIfTableCurrentRowChanged);
    connect(this, &MainWindow::signalSelectNIC, this, &MainWindow::slotSelectNIC);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_pushButton_clicked()
{
    ui->stackedWidget->setCurrentIndex(1);
    emit signalSelectNIC(current_selected_nic);
}



void MainWindow::slotSelectNIC(const QString &nic_name){

    printf("using nic %s\n", nic_name.toStdString().c_str());
    fflush(stdout);
    QMessageBox::information(this, "提示", "using nic " + nic_name);
}

void MainWindow::slotIfTableSelectionChanged(const QItemSelection &selected, const QItemSelection &deselected)
{

}

//当前选中index变化，单个
void MainWindow::slotIfTableCurrentChanged(const QModelIndex &current, const QModelIndex &previous)
{

}

//当前选中行变化，单行
void MainWindow::slotIfTableCurrentRowChanged(const QModelIndex &current, const QModelIndex &previous)
{
//    printf("slotIfTableCurrentRowChanged\n");

    //取选中的这行的第一个元素的index
    QModelIndex index = current.sibling(current.row(),0);
    QStandardItem* item = ncModel->itemFromIndex(index);
    if(item){
        for(int i = 0; i < ncModel->rowCount(); i++){
            auto *nic = ncModel->item(i);
            if((QStandardItem*)nic == item){
                current_selected_nic = ((QStandardItem*)nic)->text();
                printf("%s\n", ("selected nic " + current_selected_nic).toStdString().c_str());
                ui->statusbar->showMessage("selected nic " + current_selected_nic, 3000);
                fflush(stdout);
                return;
            }
            for(int j = 0; j < nic->rowCount(); j++){
                auto *it = ((QStandardItem*)nic)->child(j);
                if((QStandardItem*)it == item){
                    current_selected_nic = ((QStandardItem*)nic)->text();
                    printf("%s\n", ("selected nic " + current_selected_nic).toStdString().c_str());
                    ui->statusbar->showMessage("selected nic " + current_selected_nic, 3000);
                    fflush(stdout);
                    return;
                }
            }
        }
    }
}
