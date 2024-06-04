import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import angr
import archinfo

import os

try:
    lw = logging.getLogger("CustomSimProcedureWindows")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)


class NtQuerySystemInformation(angr.SimProcedure):
    def run(
        self,
        system_information_class,
        system_information,
        system_information_length,
        return_length
    ):
        if system_information_class.symbolic:
            return self.state.solver.BVS(
                "retval_{}".format(self.display_name), self.arch.bits
            )

        class_type = self.state.solver.eval(system_information_class)

        if class_type == 5: #SystemProcessInformation
            sysinfo = self.state.solver.BVS(
                "System_process_info_{}".format(self.display_name), 184 * 8
            )
            self.state.memory.store(system_information, sysinfo, endness=archinfo.Endness.LE)

        if class_type == 0: #SystemProcessorInformation
            sysinfo = self.state.solver.BVS(
                "System_basic_info_{}".format(self.display_name), 44 * 8
            )
            self.state.memory.store(system_information, sysinfo, endness=archinfo.Endness.LE)

        return 0x0
