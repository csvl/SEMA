import angr
import logging
import os

from clogging.CustomFormatter import CustomFormatter
from CustomSimProcedure import CustomSimProcedure

from angr.procedures import SIM_LIBRARIES
from angr.calling_conventions import SimCCMicrosoftAMD64


class WindowsSimProcedure(CustomSimProcedure):

    def __init__(self):
        super().__init__()
        self.log_level = os.environ["LOG_LEVEL"]
        self.config_logger()
        self.init_sim_proc("windows")

    def config_logger(self):
        self.log = logging.getLogger("WindowsSimProcedure")
        ch = logging.StreamHandler()
        ch.setLevel(self.log_level)
        ch.setFormatter(CustomFormatter())
        self.log.addHandler(ch)
        self.log.propagate = False
        self.log.setLevel(self.log_level)
    
    def deal_with_alt_names(self, pkg_name, proc):
        new_proc = proc # TODO clone
        new_proc.__name__ = proc.ALT_NAMES
        new_proc.__qualname__ = proc.ALT_NAMES
        self.sim_proc[pkg_name][proc.ALT_NAMES] = new_proc
    
    def name_in_angr_simproc(self, name, simproc_names):
        for i in simproc_names:
            if name in angr.SIM_PROCEDURES[i]:
                return True
        return False

    def custom_hook_windows_symbols(self, proj):
        """_summary_
        TODO CH
        Args:
            proj (_type_): _description_
        """
        # self.ANG_CALLING_CONVENTION = {"__stdcall": SimCCStdcall, "__cdecl": SimCCCdecl}
        self.log.info("custom_hook_windows_symbols")
        proj.loader
        symbols = proj.loader.symbols

        excluded_simproc_name = ["win32","win_user32","ntdll","msvcr"]
        special_case_simproc_name = ["posix", "linux_kernel", "libc"]


        for lib in self.system_call_table:
            for key in self.system_call_table[lib]:
                name = self.system_call_table[lib][key]["name"]
                if (not self.name_in_angr_simproc(name, excluded_simproc_name) and len(self.system_call_table[lib][key]["arguments"]) != 0):
                    for symb in symbols:
                        if (name == symb.name and (not self.name_in_angr_simproc(name, special_case_simproc_name))
                            and name not in self.sim_proc["custom_package"]
                        ):
                            proj.hook_symbol(
                                name, SIM_LIBRARIES[lib].get(name, proj.arch)
                            )
                        if symb.name in self.sim_proc["custom_package"]:
                            proj.unhook(symb.rebased_addr)
                            if not self.amd64_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][symb.name]):
                                if symb.name not in self.CDECL_EXCEPT:
                                    self.std_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][symb.name])
                                else:
                                    self.exception_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][symb.name])

                        if symb.name and "ordinal" in symb.name:
                            # ex : ordinal.680.b'shell32.dll'
                            part_names = symb.name.split(".")
                            lib_part = part_names[2][2:] + ".dll"
                            ord_part = part_names[1]
                            try:
                                real_name = self.system_call_table[lib_part][ord_part]["name"]
                            except:
                                real_name = "nope"

                            if real_name == "nope":
                                pass
                            elif (real_name in self.sim_proc["custom_package"]):
                                proj.unhook(symb.rebased_addr)
                                if not self.amd64_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][name]):
                                    self.std_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][real_name])
                            elif lib_part == lib:
                                proj.unhook(symb.rebased_addr)
                                proj.hook(
                                    symb.rebased_addr,
                                    SIM_LIBRARIES[lib].get(real_name, proj.arch),
                                )

    def amd64_sim_proc_hook(self, project, name, sim_proc):
        if project.arch.name == "AMD64":
            project.hook(
                name,
                sim_proc(
                    cc=SimCCMicrosoftAMD64(project.arch)
                ),
            )
            return True
        return False