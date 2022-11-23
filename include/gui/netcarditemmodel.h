#ifndef NETCARDITEMMODEL_H
#define NETCARDITEMMODEL_H

#include <QStandardItemModel>

class NetCardItemModel : public QStandardItemModel
{
    Q_OBJECT

public:
    explicit NetCardItemModel(QObject *parent = nullptr);

private:
};

#endif // NETCARDITEMMODEL_H
