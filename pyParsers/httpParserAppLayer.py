import json
from common_def import *


def httpParserAppLayer(in_arr: bytearray, pos: int):
    in_str_arr = in_arr[pos:].split(b'\r\n')
    retFrame = RetFrame()

    if in_str_arr[0].count(b'HTTP') == 0:
        retFrame.name = 'Unrecongized Application Layer Protocol'
        retFrame.frames = []
        retFrame.frameCount = 0
        retFrame.nextSuggestedParser = 'null'
        retFrame.desc = 'Unrecongized Application Layer Protocol'
        retFrame.pos = pos
        return json.dumps(retFrame, default=lambda obj: obj.__dict__, sort_keys=True, indent=4).encode('utf-8')

    retFrame.nextSuggestedParser = 'dummyParser'
    retFrame.desc = 'Hyper Text Transfer Protocol'
    in_str_arr[0].split(b' ')
    retFrame.name = 'Hyper Text Transfer Protocol'
    retFrame.frames = []
    retFrame.pos = pos + len(in_arr)

    for cindex, currLine in enumerate(in_str_arr):
        if len(currLine) == 0:
            contentFrame = Frame()
            contentFrame.key = 'Content: '
            contentFrame.val = '[raw bytes]'
            retFrame.frames.append(contentFrame)
            break

        newFrame = Frame()
        newFrame.key = ''
        try:
            newFrame.val = currLine.decode('ASCII')
        except UnicodeDecodeError:
            print("Failed to decode: " + str(currLine))
            newFrame.val = ' '

        # TODO add precise pos for header options
        newFrame.posBegin = pos
        newFrame.posEnd = pos
        retFrame.frames.append(newFrame)
        pass

    retFrame.frameCount = len(retFrame.frames)
    return json.dumps(retFrame, default=lambda obj: obj.__dict__, sort_keys=True, indent=4).encode('utf-8')


if __name__ == '__main__':
    in_str = 'HTTP/1.1 200 OK\r\nAAA\r\n\r\nCCC'
    print(httpParserAppLayer(bytearray(in_str.encode('UTF-8')), 0).decode('UTF-8'))
