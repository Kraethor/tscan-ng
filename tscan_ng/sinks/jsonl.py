import os, orjson as json

class JSONLSink:
    def __init__(self, path: str|None):
        self._fd = None
        if path:
            self._fd = open(path, "ab", buffering=0)

    def write(self, obj: dict):
        line = json.dumps(obj) + b"\n"
        if self._fd:
            self._fd.write(line)
        else:
            try:
                os.write(1, line)
            except OSError:
                pass
