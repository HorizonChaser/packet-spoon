class Frame:
    key: str
    val: str
    posBegin: int
    posEnd: int

    def __init__(self):
        pass


class RetFrame:
    name: str
    frameCount: int
    nextSuggestedParser: str
    pos: int
    frames: list
    desc: str

    def __init__(self):
        pass


def b2istr(inArrB: bytearray):
    return str(int.from_bytes(inArrB, byteorder='big'))
