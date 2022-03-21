from .GetComputerNameA import GetComputerNameA


class GetComputerNameW(GetComputerNameA):
    def get_username(self, size):
        return ("CharlyBVO_PC"[: size - 1] + "\0").encode("utf-16-le")
