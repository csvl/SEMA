import logging
import os
import angr

from clogging.CustomFormatter import CustomFormatter
from CustomSimProcedure import CustomSimProcedure
from angr.calling_conventions import  SimCCSystemVAMD64


log_level = os.environ["LOG_LEVEL"]
logger = logging.getLogger("LinuxSimProcedure")
ch = logging.StreamHandler()
ch.setLevel(log_level)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)
logger.propagate = False
logger.setLevel(log_level)


class LinuxSimProcedure(CustomSimProcedure):

    def __init__(self, verbose = False):
        super().__init__(verbose)
        self.log = None
        self.setup("linux")

    # Set up the logger
    def config_logger(self):
        if self.log is None:
            self.log = logger
            self.log_level = log_level

    # Set properly the value in the sim_proc dictionary when meeting an ALT_NAME argument
    def deal_with_alt_names(self, pkg_name, proc):
        for altname in proc.ALT_NAMES:
            self.sim_proc[pkg_name][altname] = proc

    # Hooking method for static library
    def custom_hook_static(self, proj):
        if self.verbose: self.log.info("custom_hook_static_linux")
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
                if self.verbose:
                    self.log.info(lib_part)
                    self.log.info(ord_part)
                # symb.name = self.system_call_table[lib_part][ord_part]['name']
    
    # Hooking method for the custom package
    def custom_hook_linux_symbols(self, proj):
        """_summary_
        TODO CH
        Args:
            proj (_type_): _description_
        """
        # self.ANG_CALLING_CONVENTION = {"__stdcall": SimCCStdcall, "__cdecl": SimCCCdecl}
        if self.verbose: self.log.info("custom_hook_linux_symbols")
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

    # Hook of the type "SimCCSystemVAMD64" when project architecture is AMD64
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
    
    # Use the linux loader to get the syscall table
    def load_syscall_table(self, proj):
        self.system_call_table = self.linux_loader.load_table(proj)

            