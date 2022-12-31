import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class NtQuerySystemInformation(angr.SimProcedure):
    def run(
        self,
        system_information_class,
        system_information,
        system_information_length,
        return_length,
    ):
        if system_information_class.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        class_type = self.state.solver.eval(system_information_class)

        # Get SystemBasicInformation
        if class_type == 1:
            sysinfo = self.state.solver.BVS(
                "System_basic_info_{}".format(self.display_name), 41 * 8
            )
            self.state.memory.store(system_information, sysinfo)
            dwNumberOfProcessors = self.state.solver.BVS(
                "Number_of_processors_{}".format(self.display_name), 8
            )
            self.state.memory.store(lpSystemInfo + 40, dwNumberOfProcessors)
        return self.state.solver.BVS(
            "retval_{}".format(self.display_name), self.arch.bits
        )
