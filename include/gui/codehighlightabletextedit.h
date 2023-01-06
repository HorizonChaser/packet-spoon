#ifndef CODEHIGHLITABLETEXTEDIT_H
#define CODEHIGHLITABLETEXTEDIT_H

#include <QTextEdit>
#include <vector>
using namespace std;
enum TextContent {HEX, ASCII};

class CodeHighlightableTextEdit : public QTextEdit
{
    Q_OBJECT
public:
    CodeHighlightableTextEdit();

    CodeHighlightableTextEdit(QTextEditPrivate &dd, QWidget *parent);

    CodeHighlightableTextEdit(const QString &text, QWidget *parent);

    explicit CodeHighlightableTextEdit(QWidget *parent);

    void highlight(int start, int end);

    void setContentType(TextContent contentType){
        this->content = contentType;
    }

    void setRaw(const vector<unsigned char> &bArr);

signals:
    void mouseOverPos(int pos);

protected:
    void mouseMoveEvent(QMouseEvent *e) override;

private:
    void clearHighlight();

    TextContent content = HEX;
};

#endif // CODEHIGHLITABLETEXTEDIT_H
