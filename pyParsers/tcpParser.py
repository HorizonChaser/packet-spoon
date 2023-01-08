import json
from common_def import *


def tcpParser(in_arr: bytearray, pos: int):

    retFrame = RetFrame()
    retFrame.name = "Transmission Control Protocol (TCP)"
    retFrame.frames = []

    srcFrame = Frame()
    srcFrame.key = "Source Port: "
    srcFrame.val = (b2istr(in_arr[pos:pos + 2]))
    srcFrame.posBegin = pos
    srcFrame.posEnd = pos + 1

    dstFrame = Frame()
    dstFrame.key = "Destination Port: "
    dstFrame.val = (b2istr(in_arr[pos + 2:pos + 4]))
    dstFrame.posBegin = pos + 2
    dstFrame.posEnd = pos + 3

    seqFrame = Frame()
    seqFrame.key = "Sequence Number: "
    seqFrame.val = (b2istr(in_arr[pos + 4:pos + 8]))
    seqFrame.posBegin = pos + 4
    seqFrame.posEnd = pos + 7

    ackFrame = Frame()
    ackFrame.key = "Acknowledge Number: "
    ackFrame.val = b2istr(in_arr[pos + 8:pos + 12])
    ackFrame.posBegin = pos + 8
    ackFrame.posEnd = pos + 11

    hlenFrame = Frame()
    hlenFrame.key = "Header Length: "
    hlen = in_arr[pos + 12] >> 4 * 4
    hlenFrame.val = str(hlen)
    hlenFrame.posBegin = pos + 12
    hlenFrame.posEnd = pos + 12

    flags = in_arr[pos + 13]
    flagStr = ''
    if flags & 0x80:
        flagStr += 'CWR'
    if flags & 0x40:
        if len(flagStr) > 0:
            flagStr += ' ECE'
        else:
            flagStr += 'ECE'
    if flags & 0x20:
        flagStr += ' URG'
    if flags & 0x10:
        flagStr += ' ACK'
    if flags & 0x08:
        flagStr += ' PSH'
    if flags & 0x04:
        flagStr += ' RST'
    if flags & 0x02:
        flagStr += ' SYN'
    if flags & 0x01:
        flagStr += ' FIN'

    if len(flagStr) == 0:
        flagStr = 'No Flag Set'
    flagFrame = Frame()
    flagFrame.key = "Flags: "
    flagFrame.val = flagStr
    flagFrame.posBegin = pos + 13
    flagFrame.posEnd = pos + 13

    winSizeFrame = Frame()
    winSizeFrame.key = 'Window Size: '
    winSizeFrame.val = b2istr(in_arr[pos + 14:pos + 16])
    winSizeFrame.posBegin = pos + 14
    winSizeFrame.posEnd = pos + 15

    checksumFrame = Frame()
    checksumFrame.key = 'Checksum: '
    checksumFrame.val = ''.join(
        ['%02X' % b for b in in_arr[pos + 16:pos + 18]])
    checksumFrame.posBegin = pos + 16
    checksumFrame.posEnd = pos + 17

    urgFrame = Frame()
    urgFrame.key = "Urgent Pointer: "
    if flags & 0x20:
        urgFrame.key = ''.join(['%02X' % b for b in in_arr[pos + 18:pos + 20]])
    else:
        urgFrame.val = 'null (URG flag not set)'
    urgFrame.posBegin = pos + 18
    urgFrame.posEnd = pos + 19

    optionsFrame = Frame()
    optionsFrame.key = 'Options: '
    if hlen > 20:
        optionsFrame.val = ''.join(
            ['%02X' % b for b in in_arr[pos + 20:pos + hlen + 1]])
        optionsFrame.posBegin = pos + 20
        optionsFrame.posEnd = pos + hlen
        retFrame.pos = pos + hlen + 1
    else:
        optionsFrame.val = 'Not Set '
        optionsFrame.posBegin = pos + 12
        optionsFrame.posEnd = pos + 12
        retFrame.pos = pos + hlen

    # TODO set nextParser according to port?
    retFrame.nextSuggestedParser = "dummyParser"

    if b2istr(in_arr[pos:pos + 2]) == '80' or b2istr(in_arr[pos + 2:pos + 4]) == '80'\
            or b2istr(in_arr[pos:pos + 2]) == '8080' or b2istr(in_arr[pos + 2:pos + 4]) == '8080'\
            or b2istr(in_arr[pos:pos + 2]) == '8088' or b2istr(in_arr[pos + 2:pos + 4]) == '8088':
        retFrame.nextSuggestedParser = "httpParserAppLayer"

    retFrame.frames.append(srcFrame)
    retFrame.frames.append(dstFrame)
    retFrame.frames.append(seqFrame)
    retFrame.frames.append(ackFrame)
    retFrame.frames.append(hlenFrame)
    retFrame.frames.append(flagFrame)
    retFrame.frames.append(winSizeFrame)
    retFrame.frames.append(checksumFrame)
    retFrame.frames.append(urgFrame)
    retFrame.frames.append(optionsFrame)
    retFrame.frameCount = len(retFrame.frames)

    retFrame.desc = "{src} -> {dst} [{flags}] Seq={seq} Ack={ack}".format(src=srcFrame.val, dst=dstFrame.val,
                                                                          flags=flagStr,
                                                                          seq=seqFrame.val, ack=ackFrame.val)
    retFrame.protocol = "TCP"
    return json.dumps(retFrame, default=lambda obj: obj.__dict__, sort_keys=True, indent=4).encode('utf-8')


if __name__ == '__main__':
    inx = [0x00, 0x0c, 0x29, 0xe7, 0x0a, 0x71, 0xf0, 0xb6,
           0x1e, 0x60, 0x7f, 0x2a, 0x08, 0x00, 0x45, 0x00,
           0x00, 0x28, 0xe2, 0xdb, 0x40, 0x00, 0x80, 0x06,
           0x7e, 0x7a, 0x0a, 0x00, 0x42, 0xc2, 0x0a, 0x00,
           0x42, 0xb8, 0x0a, 0x43, 0x00, 0x16, 0xc1, 0xd8,
           0xc4, 0x6d, 0x24, 0x88, 0xb3, 0x37, 0x50, 0x10,
           0x10, 0x06, 0x9d, 0xf5, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00]
    inArr = bytearray(inx)
    print(len(inArr))
    print(tcpParser(inArr, 34).decode('utf-8'))
