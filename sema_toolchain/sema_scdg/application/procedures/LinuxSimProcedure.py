import os
import sys


import logging
import os
import angr

from clogging.CustomFormatter import CustomFormatter
from CustomSimProcedure import CustomSimProcedure
from angr.calling_conventions import  SimCCSystemVAMD64

try:
    log_level = os.environ["LOG_LEVEL"]
    logger = logging.getLogger("LinuxSimProcedure")
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
    logger.propagate = False
    logger.setLevel(log_level)
except Exception as e:
    print(e)

class LinuxSimProcedure(CustomSimProcedure):
    """
    Defines methods for customizing Linux simulation procedures.

    This class includes methods for setting up the logger, handling alternative names, customizing hooks for static libraries, and loading the syscall table using the Linux loader.
    """

    def __init__(self, verbose = False):
        """
        Initializes a Linux simulation procedure with optional verbosity.

        This method sets up the Linux environment for simulation procedures by initializing the logger and configuring the environment for Linux-specific procedures.
        """
        super().__init__(verbose)
        self.log = None
        self.setup("linux")

    def config_logger(self):
        """
        Configures the logger if it is not already set.

        This function sets up the logger for the Linux simulation procedure, initializing it with the specified log level if it is not already defined.
        """
        if self.log is None:
            self.log = logger
            self.log_level = log_level

    def deal_with_alt_names(self, pkg_name, proc):
        """
        Sets the value in the sim_proc dictionary for alternative names encountered.

        This function iterates through the alternative names of a procedure and assigns the procedure to the corresponding package name in the sim_proc dictionary.
        """
        for altname in proc.ALT_NAMES:
            self.sim_proc[pkg_name][altname] = proc

    def custom_hook_static(self, proj):
        """
        Applies custom static hooks for Linux symbols in the project.

        This function customizes hooking for specific Linux symbols, including handling different procedures based on the symbol name, architecture, and predefined simulation procedures.
        """
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

        def hook_readlink(symb, proj):
            if proj.arch.name == "X86":
                proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES["posix"]["read"]())
            else:
                self.amd64_sim_proc_hook(proj, symb.rebased_addr, angr.SIM_PROCEDURES["posix"]["read"])

        for symb in symbols:
            name = symb.name
            if name == "readlink":
                hook_readlink(symb, proj)
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
                part_names = name.split(".")
                if self.verbose:
                    lib_part = f"{part_names[2][2:]}.dll"
                    self.log.info(lib_part)
                    ord_part = part_names[1]
                    self.log.info(ord_part)

    # Hooking method for the custom package
    def custom_hook_linux_symbols(self, proj):
        """
        Customizes hooking for Linux symbols in the project.

        This function applies custom procedures to symbols from the custom package, handling exceptions and standard procedures based on the symbol name.
        """
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

    def amd64_sim_proc_hook(self, project, name, sim_proc):
        """
        Applies a simulation procedure hook for AMD64 architecture in the project.

        This function hooks the specified name with the provided simulation procedure, applying the System V AMD64 calling convention if the project architecture is AMD64.
        """
        if project.arch.name == "AMD64":
            project.hook(
                name,
                sim_proc(
                    cc=SimCCSystemVAMD64(project.arch)
                ),
            )
            return True
        return False

    def load_syscall_table(self, proj):
        """
        Loads the syscall table using the Linux loader in the project.

        This function initializes the system call table by loading it from the project using the Linux loader.
        """
        self.system_call_table = self.linux_loader.load_table(proj)
