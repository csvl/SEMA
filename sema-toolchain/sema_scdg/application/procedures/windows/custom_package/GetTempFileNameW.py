from .GetTempFileNameA import GetTempFileNameA


class GetTempFileNameW(GetTempFileNameA):
    def decodeString(self, ptr):
        fileName = self.state.mem[ptr].wstring.concrete
        return fileName
