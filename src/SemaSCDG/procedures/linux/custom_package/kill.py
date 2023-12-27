import angr


class kill(angr.SimProcedure):
    def run(self, pid, sig):
        return 0