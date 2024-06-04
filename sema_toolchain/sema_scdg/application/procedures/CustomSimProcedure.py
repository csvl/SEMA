import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import re
import angr
import keyword
import builtins
import os

from abc import ABC, abstractmethod
from angr.misc import autoimport
from angr.procedures import SIM_LIBRARIES
from angr.procedures.definitions import SimLibrary
from angr.calling_conventions import SimCCStdcall, SimCCCdecl, SimCCSystemVAMD64, SimCCMicrosoftAMD64
from DDLLoader import DDLLoader
from LinuxTableLoader import LinuxTableLoader

builtins = dir(__builtins__)

class CustomSimProcedure(ABC):
    """
    Abstract base class for custom simulation procedures.

    This class defines various attributes and methods for handling custom simulation procedures, loading libraries, setting calling conventions, and creating simprocedures.
    """
    EXCEPTIONS = [
        "ShellMessageBoxW",
        "ShellMessageBoxA",
        "wsprintfA",
        "wsprintfW",
        #"sprintf",
        #"??2@YAPAXI@Z"
    ]

    # __cdecl calling convention for these functions
    CDECL_EXCEPT = [
        "wsprintfW",
        "GetAdaptersInfo",
        "ShellMessageBoxA",
        "ShellMessageBoxW",
        "wsprintfA",
        "sprintf",
        "memcpy",
        "_ismbblead",
        "strlen",
        "printf",
        "rand",
        "strcat",
        "strcpy",
        "strcmp",
        "aloi",
        "sprintf"
        "??2@YAPAXI@Z", # new operator
        "memcpy",
        "memset",
        "strstr",
        "free",
        "rand",
        "_strdup",
        "atoi",
        "malloc",
        "strlen",
        "strcpy",
        "printf",
        "scanf",
        "srand",
        "fprintf",
        "strncmp",
        "wcslen"
    ]

    ANGR_LIBS = {
        "kernel32.dll": "kernel32.dll",
        "msvcrt.dll": "msvcrt.dll",
        "ntdll.dll": "ntdll.dll",
        "advapi32.dll": "advapi32.dll",
        "user32.dll": "user32.dll",
    }

    EVASION_LIBS = [
        "dwmapi.dll",
        "avghookx.dll",
        "avghooka.dll",
        "sbiedll.dll",
        "dbghelp.dll",
        "snxhk.dll",
        "api_log.dll",
        "dir_watch.dll",
        "vmcheck.dll",
        "wpespy.dll",
        "pstorec.dll",
        "snxhk64.dll",
        "sxIn.dll"
    ]

    ANGR_CALLING_CONVENTIONS_x86 = {
        "__stdcall": SimCCStdcall,
        "__cdecl": SimCCCdecl
    }

    ANGR_CALLING_CONVENTIONS_x86_64 = {
        "__stdcall": SimCCStdcall,
        "__cdecl": SimCCCdecl,
        "__fastcall": SimCCMicrosoftAMD64,# TODO 32 vs 64 bits
    }

    FASTCALL_EXCEPTION = [
        "_initterm",
        "__getmainargs",
        "__lconv_init"
    ]

    REG_dict = {  # not used
        "rdi",
        "rsi",
        "rdx",
        "r8",
        "rcx",
        "r10",
        "r9",
        "rax",
        "eax",
        "edx",
        "ebp",
        "edi",
        "ebx",
        "esi",
    }

    def __init__(self, verbose=False):
        """
        Initializes the Custom Simulation Procedure object.

        This method sets up attributes for handling custom simulation procedures, system call tables, and tracking found syscalls.
        """
        self.verbose = verbose
        self.sim_proc = {}
        self.system_call_table = {}
        self.syscall_found = {}

    def __already_setup(self):
        """
        Checks if the object is already set up with data.

        This function returns a boolean indicating whether the system call table is already populated with data.
        """
        return len(self.system_call_table) > 0

    def clear(self):
        """
        Clears all data structures within the object.

        This method empties the dictionaries `sim_proc`, `system_call_table`, and `syscall_found`.
        """
        self.sim_proc.clear()
        self.system_call_table.clear()
        self.syscall_found.clear()

    def setup(self, os):
        """
        Sets up the object for system call procedure initialization.

        If the object is not already set up, this method initializes loaders, configures logging if verbose, and initializes system call procedures based on the provided operating system.
        """
        if not self.__already_setup():
            self.ddl_loader = DDLLoader()
            self.linux_loader = LinuxTableLoader()
            if self.verbose:
                self.config_logger()
            self.init_sim_proc(os)

    @abstractmethod
    def load_syscall_table(self, proj):
        """
        Loads the system call table for the given project.

        This method is abstract and must be implemented in subclasses to define the behavior of loading the system call table for a specific project.
        """
        pass

    def get_gen_simproc(self):
        """
        Returns a dictionary containing generic simulation procedures.

        This method retrieves and returns specific simulation procedures from the `custom_package` dictionary.
        """
        custom_pack = self.sim_proc["custom_package"]
        return {
            "0": custom_pack["gen_simproc0"],
            "1": custom_pack["gen_simproc1"],
            "2": custom_pack["gen_simproc2"],
            "3": custom_pack["gen_simproc3"],
            "4": custom_pack["gen_simproc4"],
            "5": custom_pack["gen_simproc5"],
            "6": custom_pack["gen_simproc6"],
        }

    def get_custom_sim_proc(self):
        """
        Returns a dictionary containing custom simulation procedures.

        This method retrieves and returns specific custom simulation procedures from the `custom_package` dictionary.
        """
        custom_pack = self.sim_proc["custom_package"]
        return {
            "time": custom_pack["time"],
            "clock": custom_pack["clock"],
            "sigprocmask": custom_pack["sigprocmask"],
            "rt_sigprocmask": custom_pack["rt_sigprocmask"],
            "nanosleep": custom_pack["nanosleep"],
            "prctl": custom_pack["prctl"],
            "connect": custom_pack["connect"],
            "clone": custom_pack["clone"],
            "readlink": custom_pack["readlink"],
            "openat": custom_pack["openat"],
            "readv": custom_pack["readv"],
            "read": custom_pack["read"],
            "writev": custom_pack["writev"],
            "write": custom_pack["write"],
            "clock_gettime": custom_pack["clock_gettime"],
            "socketcall": custom_pack["socketcall"],
            "exit_group": custom_pack["exit"],
            "rt_sigaction": custom_pack["rt_sigaction"],
            "sigaction": custom_pack["rt_sigaction"],
            "gettimeofday": custom_pack["gettimeofday"],
            "getuid": custom_pack["getuid"],
            "geteuid": custom_pack["getuid"],
            "getgid": custom_pack["getgid"],
            "getegid": custom_pack["getgid"],
            "sendto": custom_pack["sendto"],
            "times": custom_pack["times"],
            "futex": custom_pack["futex"],
            "open": custom_pack["open"],
            "open64": custom_pack["open"],
            "setsid": custom_pack["setsid"],
            "chdir": custom_pack["chdir"],
            "getsockname": custom_pack["getsockname"],
            "select": custom_pack["select"],
            "_newselect": custom_pack["select"],
            "newfstat": custom_pack["fstat"],
            "fstat": custom_pack["fstat"],
            "fstat64": custom_pack["fstat"],
            "newstat": custom_pack["fstat"],
            "stat": custom_pack["fstat"],
            "stat64": custom_pack["fstat"],
            "socket": custom_pack["socket"],
            "set_thread_area": custom_pack["set_thread_area"],
            "unlink": custom_pack["unlink"],
        }

    def generic_sim_procedure(self, args, ret):
        """
        Creates a generic simulation procedure based on arguments and return type.

        This method dynamically generates a simulation procedure based on the provided arguments and return type.
        """
        s = "lambda self, " + ", ".join(args)
        if ret != "void":
            s += ': self.state.solver.BVS("retval_{}".format(self.display_name),self.arch.bits)'
        else:
            s += ": None"
        return eval(s)

    def create_sim_procedure(self, name, args, ret, args_mismatch):
        """
        Creates a custom simulation procedure based on the provided name, arguments, return type, and arguments mismatch flag.

        This method dynamically generates a custom simulation procedure with specific characteristics based on the input parameters.
        """
        contains = {"run": self.generic_sim_procedure(args, ret)}
        if args_mismatch:
            contains["ARGS_MISMATCH"] = True
        return type(name, (angr.SimProcedure,), contains)

    @abstractmethod
    def deal_with_alt_names(self, pkg_name, proc):
        """
        Defines the behavior for handling alternative names in simulation procedures.

        This method is abstract and must be implemented in subclasses to specify how to deal with alternative names in simulation procedures.
        """
        pass

    def init_sim_proc(self, os_name):
        """
        Initializes simulation procedures based on the provided operating system name.

        This method dynamically imports and organizes simulation procedures based on the specified operating system for further analysis.
        """
        path = f"{os.path.dirname(os.path.abspath(__file__))}/{os_name}"
        if self.verbose:
            self.log.debug(f"{os_name} lib path = {str(path)}")
        skip_dirs = ["definitions"]
        pkg = f"procedures.{os_name}"
        for pkg_name, package in autoimport.auto_import_packages(pkg, path, skip_dirs):
            for _, mod in autoimport.filter_module(package, type_req=type(os)):
                for name, proc in autoimport.filter_module(mod, type_req=type, subclass_req=angr.SimProcedure):
                    if hasattr(proc, "__provides__"):
                        for custom_pkg_name, custom_func_name in proc.__provides__:
                            if custom_pkg_name not in self.sim_proc:
                                self.sim_proc[custom_pkg_name] = {}
                            self.sim_proc[custom_pkg_name][custom_func_name] = proc
                    else:
                        if pkg_name not in self.sim_proc:
                            self.sim_proc[pkg_name] = {}
                        self.sim_proc[pkg_name][name] = proc
                        if hasattr(proc, "ALT_NAMES") and proc.ALT_NAMES:
                            self.deal_with_alt_names(pkg_name, proc)
                        if name == "UnresolvableJumpTarget":
                            self.sim_proc[pkg_name]["UnresolvableTarget"] = proc

    def create_lib_procedures(self, dlldict, libname, angrlib):
        """
        Creates library procedures based on the provided dictionary, library name, and angr library.

        This function iterates through the dictionary of procedures, extracts arguments, checks for argument mismatches, and creates custom simulation procedures for each procedure in the library.
        """
        procedures = {}
        for k, v in dlldict.items():
            name = k
            args = []
            for i, a in enumerate(v["arguments"]):
                if a["name"] is not None:
                    if keyword.iskeyword(a["name"]) or a["name"] in builtins:
                        args.append(f"arg{str(i)}")
                    else:
                        args.append(a["name"])
                elif a["type"] not in ["void", " void"]:
                    args.append(f"arg{str(i)}")

            if (v["cc"] == "__cdecl" and v["name"] not in self.EXCEPTIONS):
                self.EXCEPTIONS.append(v["name"])
            args_mismatch = False
            is_num = False
            try:
                a = int(name)
                is_num = True
            except ValueError:
                is_num = False

            if angrlib.has_prototype(name) and not is_num:
                ourargs = len(args)
                angrargs = len(angrlib.prototypes[name].args)
                if ourargs != angrargs:
                    if self.verbose:
                        self.log.warning(f"Procedure {name} in DLL {libname} has {ourargs} arguments in json and {angrargs} arguments in angr prototype. Taking number of arguments from json.")
                    args_mismatch = True
            sp = self.create_sim_procedure(name, args, v["returns"], args_mismatch)

            procedures[name] = sp
        return procedures

    def set_calling_conventions(self, lib_name, dlls_functions):
        """
        Sets calling conventions for a given library based on the provided information.

        This function determines and sets the calling conventions for the library, updating the default calling conventions for X86 and AMD64 architectures accordingly.
        """
        if lib_name in self.ANGR_LIBS:
            if self.verbose: self.log.info("Was in angr :" + str(lib_name))
            angrlib = SIM_LIBRARIES[self.ANGR_LIBS[lib_name]]
            cc = list(dlls_functions[lib_name].values())[0]["cc"]

            # Set properly calling conventions
            angrlib.set_default_cc("X86", self.ANGR_CALLING_CONVENTIONS_x86[cc])
            angrlib.default_ccs["X86"] = self.ANGR_CALLING_CONVENTIONS_x86[cc]
            angrlib.set_default_cc("AMD64", self.ANGR_CALLING_CONVENTIONS_x86_64[cc])
            angrlib.default_ccs["AMD64"] = self.ANGR_CALLING_CONVENTIONS_x86_64[cc]
        else:
            angrlib = SimLibrary()
            angrlib.set_library_names(lib_name)
            cc = list(dlls_functions[lib_name].values())[0]["cc"]
            angrlib.set_default_cc("X86", self.ANGR_CALLING_CONVENTIONS_x86[cc])
            angrlib.set_default_cc("AMD64", self.ANGR_CALLING_CONVENTIONS_x86_64[cc])
            SIM_LIBRARIES.update({lib_name: angrlib})
        return angrlib


    def loadlibs_proc(self, dlls_functions, project):
        """
        Loads library procedures and applies hooks to symbols based on the provided information.

        This function iterates through requested libraries, sets calling conventions, creates procedures, applies hooks to symbols, and updates the simulation procedures accordingly.
        """
        symbols = project.loader.symbols
        dic_symbols = {symb.name: symb.rebased_addr for symb in symbols}
        if self.verbose: self.log.debug(dic_symbols)

        for dllname in project.loader.requested_names:
            if dllname in dlls_functions.keys():
                if len(dlls_functions[dllname]) == 0 or dllname.startswith("syscalls"):
                    continue

                angrlib = self.set_calling_conventions(dllname, dlls_functions)
                procs = self.create_lib_procedures(dlls_functions[dllname], dllname, angrlib)

                newprocs = {}
                for name, simprocedure in procs.items():
                    if (not angrlib.has_implementation(name) and name not in self.sim_proc["custom_package"]):
                        newprocs[name] = simprocedure
                        if name in dic_symbols:
                            if project.arch.name == "AMD64":
                                self.amd64_sim_proc_hook(project, dic_symbols[name], simprocedure)
                            elif name not in self.EXCEPTIONS:
                                self.std_sim_proc_hook(project, dic_symbols[name], simprocedure)
                            elif name:
                                self.exception_sim_proc_hook(project, dic_symbols[name], simprocedure)
                    elif name in self.sim_proc["custom_package"]:
                        newprocs[name] = self.sim_proc["custom_package"][name]
                    if name in dic_symbols:
                        del dic_symbols[name]

                angrlib.add_all_from_dict(newprocs)

        project._sim_procedures = {
            addr: simprocedure for addr, simprocedure in project._sim_procedures.items()
        }

        # Force each object , check resolution of symbols
        # for obj in project.loader.initial_load_objects:
        #    project._register_object(obj,project.arch)
        ok = {}
        for name in dic_symbols:
            if name in self.sim_proc["custom_package"]:
                if project.arch.name == "AMD64":
                    self.amd64_sim_proc_hook(project, dic_symbols[name], self.sim_proc["custom_package"][name])
                else:
                    self.std_sim_proc_hook(project, dic_symbols[name], self.sim_proc["custom_package"][name])
                ok[name] = 1

        for s in ok:
            del dic_symbols[s]
        if self.verbose: self.log.info("No hooks for: %s", str(dic_symbols))

    def std_sim_proc_hook(self, proj, name, simproc):
        """
        Applies a standard calling convention hook to a symbol in the project.

        This function hooks the specified symbol in the project with a standard calling convention based on the project architecture.
        """
        proj.hook(
            name,
            simproc(cc=SimCCStdcall(proj.arch)),
        )

    def exception_sim_proc_hook(self, proj, name, simproc):
        """
        Applies an exception calling convention hook to a symbol in the project.

        This function hooks the specified symbol in the project with an exception calling convention based on the project architecture.
        """
        proj.hook(
            name,
            simproc(cc=SimCCCdecl(proj.arch)),
        )

    @abstractmethod
    def amd64_sim_proc_hook(self, project, name, sim_proc):
        """
        Defines an abstract method for applying an AMD64 specific simulation procedure hook to a symbol in the project.

        This method must be implemented in subclasses to handle the application of AMD64 simulation procedure hooks.
        """
        pass

    @abstractmethod
    def custom_hook_static(self, proj):
        """
        Defines an abstract method for applying custom static hooks in the project.

        This method must be implemented in subclasses to handle the application of custom static hooks in the project.
        """
        pass

    def custom_hook_no_symbols(self, proj):
        """
        Applies custom simulation procedures to the project's syscall library when no symbols are present.

        This function adds custom simulation procedures to the syscall library based on predefined custom and generic procedures, ensuring proper handling for functions not implemented.
        """
        if self.verbose: self.log.info("custom_hook_no_symbols")

        custom = self.get_custom_sim_proc()

        for key in custom:
            proj.simos.syscall_library.add(key, custom[key])  # TODO error
        for key in angr.SIM_PROCEDURES["posix"]:
            if key not in custom:
                proj.simos.syscall_library.add(key, angr.SIM_PROCEDURES["posix"][key])

        generic = self.get_gen_simproc()

        # Create stub simprocedure with proper number of args for functions not implemented
        for key in self.system_call_table:
            name = self.system_call_table[key]["name"]
            name = re.search("(?<=sys_)[^\]]+", name).group(0)
            if ((name not in custom)
                and (name not in angr.SIM_PROCEDURES["posix"])
                and (name not in angr.SIM_PROCEDURES["linux_kernel"])
                and self.system_call_table[key]["num_args"] != 0
            ):
                proj.simos.syscall_library.add(
                    name, generic[str(self.system_call_table[key]["num_args"])]
                )
