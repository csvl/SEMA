from .GetModuleHandleExW import GetModuleHandleExW


class GetModuleHandleExA(GetModuleHandleExW):
    def decodeString(self, ptr):
        lib = self.state.mem[ptr].string.concrete.decode("utf-8")
        return lib
