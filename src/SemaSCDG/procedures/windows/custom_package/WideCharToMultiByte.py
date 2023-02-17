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
        # First, convert the wide character string to a Python string
        wide_char_str = self.state.mem[lpWideCharStr].wstring.concrete # self.state.solver.eval(lpWideCharStr, cast_to=bytes) + b"\x00\x00"
        
        lw.info(wide_char_str)
        
        # multi_byte_str = wide_char_str.decode("utf-8", "ignore")
        
        # lw.info(multi_byte_str)
        
        self.state.plugin_widechar.widechar_address.append(self.state.solver.eval(lpMultiByteStr))

        # Then, store the resulting string in the output buffer
        self.state.memory.store(lpMultiByteStr, wide_char_str.encode("utf-16-le") + b"\x00")

        # Finally, return the length of the resulting string
        return len(wide_char_str)
