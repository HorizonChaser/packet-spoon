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

    def check(self):
        return self.name is not None and self.frameCount is not None\
            and self.nextSuggestedParser is not None and self.pos is not None \
            and self.frames is not None and self.desc is not None


def b2istr(inArrB: bytearray):
    return str(int.from_bytes(inArrB, byteorder='big'))
