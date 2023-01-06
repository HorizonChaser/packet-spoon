#include "gui/codehighlightabletextedit.h"
#include <QTextCursor>
#include <QMouseEvent>
#include <cctype>
static QString uchar2hex(unsigned char uc){
    return QString::asprintf("%02x", static_cast<uint8_t>(uc));
}

static QString uchar2printable(unsigned char uc){
    if(isprint(uc)){
        return {QChar(uc)};
    } else {
        return {"."};
    }
}

CodeHighlightableTextEdit::CodeHighlightableTextEdit() : QTextEdit()
{

}

CodeHighlightableTextEdit::CodeHighlightableTextEdit(QWidget *parent) : QTextEdit(parent) {
}

CodeHighlightableTextEdit::CodeHighlightableTextEdit(const QString &text, QWidget *parent) : QTextEdit(text, parent) {}

CodeHighlightableTextEdit::CodeHighlightableTextEdit(QTextEditPrivate &dd, QWidget *parent) : QTextEdit(dd, parent) {}

void CodeHighlightableTextEdit::mouseMoveEvent(QMouseEvent *e) {
    auto tc = cursorForPosition(e->pos());
    tc.select(QTextCursor::WordUnderCursor);
    int start = tc.selectionStart();
    int end = tc.selectionEnd();
    QString text = tc.selectedText();
    if(content == TextContent::HEX)
        emit mouseOverPos(start / 3);
    else
        emit mouseOverPos(start / 2);
//    printf("%d %d %s\n", start, end, text.toStdString().c_str());
//    fflush(stdout);
    qDebug() << "MouseOverPos(start, end, text): " << start << " " << end << " " << text;
}

void CodeHighlightableTextEdit::setRaw(const vector<unsigned char> &bArr) {
    clear();
    vector<QString> vec;
    if(content == TextContent::HEX){
        std::transform(bArr.begin(), bArr.end(), back_inserter(vec), [](auto& uc){
           return uchar2hex(uc);
        });
        vec.emplace_back("XX");
    } else {
        std::transform(bArr.begin(), bArr.end(), back_inserter(vec), [](auto& uc){
            return uchar2printable(uc);
        });
        vec.emplace_back("X");
    }
    for(int i = 0; i * 8 < vec.size(); i++){
        QStringList qsl;
        for(int j = 0; j < 8 && i * 8 + j < vec.size(); j++){
            qsl.append(vec[i * 8 + j]);
        }
        setAlignment(Qt::AlignCenter);
        append(qsl.join(" "));
    }

}

void CodeHighlightableTextEdit::highlight(int start, int end) {
    if(content == HEX){
        start *= 3;
        end *= 3;
    } else {
        start *= 2;
        end *= 2;
    }
    clearHighlight();
    QTextCharFormat fmt;
    fmt.setBackground(Qt::blue);
    fmt.setForeground(Qt::white);
    QTextCursor cursor(this->document());
    cursor.setPosition(start, QTextCursor::MoveAnchor);
    cursor.setPosition(end, QTextCursor::KeepAnchor);
    cursor.setCharFormat(fmt);
}

void CodeHighlightableTextEdit::clearHighlight() {
    QTextCharFormat fmt;
    fmt.setBackground(Qt::white);
    fmt.setForeground(Qt::black);
    QTextCursor cursor(this->document());
    cursor.setPosition(0, QTextCursor::MoveAnchor);
    cursor.setPosition(this->document()->toPlainText().size(), QTextCursor::KeepAnchor);
    cursor.setCharFormat(fmt);
}


