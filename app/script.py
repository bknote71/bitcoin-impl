import io


class Script:
    def __init__(self) -> None:
        pass

    @classmethod
    def parse(cls, s: io.BytesIO) -> "Script":
        return cls()

    def serialize(self) -> bytes:
        return bytes()
