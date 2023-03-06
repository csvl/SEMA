import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")

class MultiByteToWideChar(angr.SimProcedure):
    def run(self, code_page, dw_flags, lp_multi_byte_str, cb_multi_byte, lp_wide_char_str, cch_wide_char):
        # This simprocedure can be simplified for the purpose of demonstration. 
        # In reality, it would need to properly handle the various flags and code pages.
        length = self.state.solver.eval(cb_multi_byte)
        lw.info(length)
        loaded_byte = self.state.memory.load(lp_multi_byte_str, size=length)
        lw.info(loaded_byte)
        # multi_byte_str = self.state.solver.eval(loaded_byte, cast_to=bytes) + b"\x00\x00"
        # wide_char_str = multi_byte_str.decode("utf-16le")
        wide_char_str = self.state.mem[lp_multi_byte_str].wstring.concrete
        lw.info(wide_char_str)
        self.state.memory.store(lp_wide_char_str, wide_char_str)
        return len(wide_char_str) // 2
