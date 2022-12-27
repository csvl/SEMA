import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class InitializeCriticalSectionEx(angr.SimProcedure):
    def run(
        self,
        lpCriticalSection,
        dwSpinCount,
        Flags
    ):
        x = self.state.stack_pop()
        self.state.stack_pop()
        self.state.stack_pop()
        self.state.stack_pop()
        self.state.stack_push(x)
        return 0x1
