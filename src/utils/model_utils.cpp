//
// Created by GoldenPigeon on 2022/12/5.
//

#include "utils.h"
#include <QItemSelectionModel>


void replace_model(QAbstractItemView *view, QAbstractItemModel *model){
    Q_ASSERT(view != nullptr);
    QItemSelectionModel *m = view->selectionModel();
    view->setModel(model);
    if(m != nullptr){
        delete m;
    }
}