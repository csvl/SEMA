import angr


class nanosleep(angr.SimProcedure):
    # pylint:disable=arguments-differ

    def run(self, struct1, struct2):
        return 0
