from .GetModuleHandleW import GetModuleHandleW


class GetModuleHandleA(GetModuleHandleW):
    def decodeString(self, ptr):
        lib = self.state.mem[ptr].string.concrete
        if hasattr(lib, "decode"):
            try:
                lib = lib.decode("utf-8")
            except:
                lib = lib.decode("utf-8", errors="ignore")
        return lib
