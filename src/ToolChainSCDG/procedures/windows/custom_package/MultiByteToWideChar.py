import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class MultiByteToWideChar(angr.SimProcedure):

    def run(
        self,
        CodePage,
        dwFlags,
        lpMultiByteStr,
        cbMultiByte,
        lpWideCharStr,
        cchWideChar
    ):
        return 0x10
