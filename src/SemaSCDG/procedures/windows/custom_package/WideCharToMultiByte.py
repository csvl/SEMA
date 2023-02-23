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
        real_codepage = self.state.solver.eval(CodePage)
        if real_codepage == 0: # CP_ACP -> UTF8 https://stackoverflow.com/questions/9033825/how-to-change-the-cp-acp0-of-windows-ansi-apis-in-an-application
            encoding = "utf-8"
        else:
            encoding = "utf-16-le"
        
        cbMultiByte_true = self.state.solver.eval(cbMultiByte)
        lw.info(cbMultiByte_true)
        if cbMultiByte_true > 0:
            lw.info("P1 - WideCharToMultiByte")
            data = wide_char_str.encode(encoding) + b"\x00"
            lw.info(data)
            length_used = cbMultiByte_true if len(data) > cbMultiByte_true else len(data)
            self.state.memory.store(lpMultiByteStr, data, size=length_used)
            return length_used
        else:
            lw.info("P2 - WideCharToMultiByte")
            lw.info(encoding)
            data = wide_char_str.encode(encoding) + b"\x00"
            lw.info(data)
            self.state.memory.store(lpMultiByteStr, data , size=len(data))
            # Finally, return the length of the resulting string
            return len(data)
