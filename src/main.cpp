#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "gui/mainwindow.h"
#include "include/pcap.h"
#include <cstdio>
#include <tchar.h>
#include <ctime>

#include <QApplication>
#include <QStyleFactory>
#include "packet-spoon.h"

static void init_program(){
    Parsers::initParsers();
    Parsers::addExternalParser("tcpParser", "tcpParser");
    Parsers::addExternalParser("httpParserAppLayer", "httpParserAppLayer");
}

#undef main
int main(int argc, char** argv) {
    init_program();
    QApplication a(argc, argv);
    QApplication::setStyle(QStyleFactory::create("Fusion"));
    MainWindow w;
    w.setWindowTitle("Packet Spoon");
    w.show();

    return a.exec();
}
