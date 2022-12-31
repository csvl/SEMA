import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class WNetGetConnectionW(angr.SimProcedure):
    def get_netRessource(self, size, buf_src):
        localName = self.state.mem[buf_src].wstring.concrete
        try:
            return (("net_" + localName.decode("utf-8"))[: size - 1] + "\0").encode(
                "utf-16-le"
            )
        except:
            return (("net_" + localName.decode("utf-8",errors="ignore"))[: size - 1] + "\0").encode(
                "utf-16-le"
            )

    def run(self, lpLocalName, lpRemoteName, lpnLength):
        if lpLocalName.symbolic or lpRemoteName.symbolic or lpnLength.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        buf = self.state.solver.eval(lpRemoteName)
        buf_src = self.state.solver.eval(lpLocalName)

        if buf != 0:
            size = self.state.mem[lpnLength].int.concrete
            res_str = self.get_netRessource(size, buf_src)
            res_bvv = self.state.solver.BVV(res_str)

            self.state.memory.store(
                lpRemoteName, res_bvv
            )  # ,endness=self.arch.memory_endness)
            self.state.memory.store(
                size, self.state.solver.BVV(len(res_bvv), self.arch.bits)
            )  # ,endness=self.arch.memory_endness)
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
