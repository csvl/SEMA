from .CreateFileA import CreateFileA


class CreateFileW(CreateFileA):
    def decodeString(self, ptr):
        filename = self.state.mem[ptr].wstring.concrete
        # if hasattr(filename, "decode"):
        #     filename = filename.decode("utf-8","ignore")
        return filename
