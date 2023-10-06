import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class CryptAcquireContextW(angr.SimProcedure):
    def run(
        self,
        phProv,
        szContainer,
        szProvider,
        dwProvType,
        dwFlags
    ):
        return 0x1
