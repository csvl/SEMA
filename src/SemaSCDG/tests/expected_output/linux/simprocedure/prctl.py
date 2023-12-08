import angr


class prctl(angr.SimProcedure):
    def run(self, arg1, arg2, arg3, arg4, arg5):
        # TODO : Return value depending on option choosen
        return 0
