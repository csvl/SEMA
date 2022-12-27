from .GetModuleHandleW import GetModuleHandleW


class GetModuleHandleA(GetModuleHandleW):
    def decodeString(self, ptr):
        lib = self.state.mem[ptr].string.concrete
        if hasattr(lib, "decode"):
            lib = lib.decode("utf-8")
        return lib
