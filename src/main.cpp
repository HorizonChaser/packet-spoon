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
#include "packet-spoon.h"

static void init_program(){
    Parsers::initParsers();
    Parsers::addExternalParser("tcpParser", "tcpParser");
    Parsers::addExternalParser("httpParserAppLayer", "httpParserAppLayer");
    rmdir("logs");
    mkdir("logs");
}

#undef main
int main(int argc, char** argv) {
    init_program();
    QApplication a(argc, argv);
    MainWindow w;
    w.show();

    return a.exec();
}
