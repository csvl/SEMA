import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class WideCharToMultiByte(angr.SimProcedure):

    def run(
        self,
        CodePage,
        dwFlags,
        lpWideCharStr,
        cchWideChar,
        lpMultiByteStr,
        cbMultiByte,
        lpDefaultChar,
        lpUsedDefaultChar
    ):
    
        return 0x10
