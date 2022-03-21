from .GetUserNameA import GetUserNameA


class GetUserNameW(GetUserNameA):
    def get_username(self, size):
        return ("CharlyBVO"[: size - 1] + "\0").encode("utf-16-le")
