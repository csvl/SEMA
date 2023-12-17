import logging
import os
import angr

from clogging.CustomFormatter import CustomFormatter
from CustomSimProcedure import CustomSimProcedure
from angr.calling_conventions import  SimCCSystemVAMD64

class LinuxSimProcedure(CustomSimProcedure):

    def __init__(self):
        super().__init__()
        self.log_level = os.environ["LOG_LEVEL"]
        self.config_logger()
        self.init_sim_proc("linux")

    def config_logger(self):
        self.log = logging.getLogger("LinuxSimProcedure")
        ch = logging.StreamHandler()
        ch.setLevel(self.log_level)
        ch.setFormatter(CustomFormatter())
        self.log.addHandler(ch)
        self.log.propagate = False
        self.log.setLevel(self.log_level)

    def deal_with_alt_names(self, pkg_name, proc):
        for altname in proc.ALT_NAMES:
            self.sim_proc[pkg_name][altname] = proc

    def custom_hook_static(self, proj):
        self.log.info("custom_hook_static_linux")
        proj.loader
        symbols = proj.loader.symbols

        simproc64 = {"fopen64": "fopen"}
        angr_simproc_to_check = [
            "glibc",
            "libc",
            "posix",
            "linux_kernel",
            "win32",
            "win_user32",
            "ntdll",
            "msvcr"
        ]
        
        for symb in symbols:
            name = symb.name
            if not name:
                pass
            elif name == "readlink":
                if proj.arch.name == "X86":
                    proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES["posix"]["read"]())
                else:
                    self.amd64_sim_proc_hook(proj, symb.rebased_addr, angr.SIM_PROCEDURES["posix"]["read"])
            boo = False
            for simproc_to_check in angr_simproc_to_check:
                if name in angr.SIM_PROCEDURES[simproc_to_check]:
                    boo = True
                    if proj.arch.name != "X86":
                        self.amd64_sim_proc_hook(proj, symb.rebased_addr, angr.SIM_PROCEDURES[simproc_to_check][name])
                    break
            if boo : continue
            if name in simproc64:
                if proj.arch.name != "X86":
                    self.amd64_sim_proc_hook(proj, symb.rebased_addr, angr.SIM_PROCEDURES["libc"][simproc64[name]])
            elif "ordinal" in name:
                # ex : ordinal.680.b'shell32.dll'
                # import pdb; pdb.set_trace()
                part_names = name.split(".")
                lib_part = part_names[2][2:] + ".dll"
                ord_part = part_names[1]
                self.log.info(lib_part)
                self.log.info(ord_part)
                # symb.name = self.system_call_table[lib_part][ord_part]['name']
    
    def custom_hook_linux_symbols(self, proj):
        """_summary_
        TODO CH
        Args:
            proj (_type_): _description_
        """
        # self.ANG_CALLING_CONVENTION = {"__stdcall": SimCCStdcall, "__cdecl": SimCCCdecl}
        self.log.info("custom_hook_linux_symbols")
        proj.loader
        symbols = proj.loader.symbols

        for symb in symbols:
            if symb.name in self.sim_proc["custom_package"]:
                # if "CreateThread" in symb.name:
                #     self.create_thread.add(symb.rebased_addr)
                proj.unhook(symb.rebased_addr)
                if not self.amd64_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][symb.name]):
                    if symb.name not in self.CDECL_EXCEPT:
                        self.std_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][symb.name])
                    else:
                        self.exception_sim_proc_hook(proj, symb.rebased_addr, self.sim_proc["custom_package"][symb.name])


    def amd64_sim_proc_hook(self, project, name, sim_proc):
        if project.arch.name == "AMD64":
            project.hook(
                name,
                sim_proc(
                    cc=SimCCSystemVAMD64(project.arch)
                ),
            )
            return True
        return False
            