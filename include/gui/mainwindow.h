#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QItemSelection>
#include "gui/netcarditemmodel.h"
#include "packet-spoon.h"
namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

signals:
    void signalSelectNIC(const QString &nic_name);

public slots:
    void onCapPageBack();

private slots:
    void slotSelectNIC(const QString &nic_name);
    void on_pushButton_clicked();
    void slotIfTableSelectionChanged(const QItemSelection &selected, const QItemSelection &deselected);
    void slotIfTableCurrentChanged(const QModelIndex &current, const QModelIndex &previous);
    void slotIfTableCurrentRowChanged(const QModelIndex &current, const QModelIndex &previous);

private:
    Ui::MainWindow *ui;
    QString current_selected_nic = DEFAULT_NIC_NAME.c_str();
    NetCardItemModel *ncModel;
};

#endif // MAINWINDOW_H
