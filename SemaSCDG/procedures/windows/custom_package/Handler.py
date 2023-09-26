import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")


class Handler(angr.SimProcedure):
    IS_FUNCTION = True

    def run(self):
        self.call(self.state.globals['handler'], (self.state.posix.argc, self.state.posix.argv, self.state.posix.environ), 'run_initializer')

    def run_initializer(self):
            self.jump(self.state.globals['jump'])
            
