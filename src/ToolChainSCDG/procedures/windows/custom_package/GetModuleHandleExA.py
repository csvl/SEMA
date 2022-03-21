from .GetModuleHandleExW import GetModuleHandleExW


class GetModuleHandleExA(GetModuleHandleExW):
    def decodeString(self, ptr):
        try:
            lib = self.state.mem[ptr].string.concrete.decode("utf-8")
        except:
            lib = self.state.mem[ptr].string.concrete.decode("utf-8",errors="ignore")
        return lib
