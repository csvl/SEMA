from .GetModuleFileNameA import GetModuleFileNameA


class GetModuleFileNameW(GetModuleFileNameA):
    def getFakeName(self, size):
        name = self.state.project.filename.split("/")[-1]
        path = (name[: size - 1] + "\0").encode("utf-16-le")  # truncate if too long
        return path

    def decodeString(self, ptr):
        lib = self.state.mem[ptr].wstring.concrete
        return lib
