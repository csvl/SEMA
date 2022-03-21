from .WNetGetConnectionW import WNetGetConnectionW


class WNetGetConnectionA(WNetGetConnectionW):
    def get_netRessource(self, size, buf_src):
        localName = self.state.mem[buf_src].string.concrete
        try:
            return (("net_" + localName.decode("utf-8"))[: size - 1] + "\0").encode("utf-8")
        except:
            return (("net_" + localName.decode("utf-8",errors="ignore"))[: size - 1] + "\0").encode("utf-8")
