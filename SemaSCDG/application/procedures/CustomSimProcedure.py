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

    def __init__(self):
        self.sim_proc = {}
        self.system_call_table = {}

        self.ddl_loader = DDLLoader()
        self.linux_loader = LinuxTableLoader()

        self.syscall_found = {}

    def get_gen_simproc(self):
        custom_pack = self.sim_proc["custom_package"]
        generic = {}
        generic["0"] = custom_pack["gen_simproc0"]
        generic["1"] = custom_pack["gen_simproc1"]
        generic["2"] = custom_pack["gen_simproc2"]
        generic["3"] = custom_pack["gen_simproc3"]
        generic["4"] = custom_pack["gen_simproc4"]
        generic["5"] = custom_pack["gen_simproc5"]
        generic["6"] = custom_pack["gen_simproc6"]
        return generic
    
    def get_custom_sim_proc(self):
        custom_pack = self.sim_proc["custom_package"]
        custom = {
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
        return custom

    def generic_sim_procedure(self, args, ret):
        s = "lambda self, " + ", ".join(args)
        if ret != "void":
            s += ': self.state.solver.BVS("retval_{}".format(self.display_name),self.arch.bits)'
        else:
            s += ": None"
        return eval(s)

    def create_sim_procedure(self, name, args, ret, args_mismatch):
        contains = {"run": self.generic_sim_procedure(args, ret)}
        if args_mismatch:
            contains.update({"ARGS_MISMATCH": True})
        return type(name, (angr.SimProcedure,), contains)

    @abstractmethod
    def deal_with_alt_names(self, pkg_name, proc):
        pass

    def init_sim_proc(self, os_name):
        path = os.path.dirname(os.path.abspath(__file__)) + "/" + os_name
        self.log.debug(os_name + " lib path = " + str(path))
        skip_dirs = ["definitions"]
        pkg = "procedures." + os_name
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
        """_summary_
        TODO CH for manon
        Args:
            dlldict (_type_): _description_
            libname (_type_): _description_
            angrlib (_type_): _description_

        Returns:
            _type_: _description_
        """
        procedures = {}
        for k, v in dlldict.items():
            name = k
            args = []
            for i, a in enumerate(v["arguments"]):
                if a["name"] is not None:
                    if keyword.iskeyword(a["name"]) or a["name"] in builtins:
                        args.append("arg" + str(i))
                    else:
                        args.append(a["name"])
                elif a["type"] != "void" and a["type"] != " void":
                    args.append("arg" + str(i))

            if (
                v["cc"] == "__cdecl" and v["name"] not in self.EXCEPTIONS
            ):  # or v['name'] == 'wsprintfW':
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
                    self.log.warning(
                        "Procedure {} in DLL {} has {} arguments in json and {} arguments in angr prototype. "
                        "Taking number of arguments from json.".format(
                            name, libname, ourargs, angrargs
                        )
                    )
                    args_mismatch = True
            sp = self.create_sim_procedure(name, args, v["returns"], args_mismatch)

            procedures.update({name: sp})
        return procedures

    def set_calling_conventions(self, lib_name, dlls_functions):
        if lib_name in self.ANGR_LIBS:
            self.log.info("Was in angr :" + str(lib_name))
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
        """_summary_
        TODO CH for manon
        Args:
            dlls_functions (_type_): _description_
            project (_type_): _description_
        """
        symbols = project.loader.symbols
        dic_symbols = {symb.name: symb.rebased_addr for symb in symbols}
        self.log.debug(dic_symbols)

        for dllname in project.loader.requested_names:
            libname = dllname

            if libname in dlls_functions.keys():
                if len(dlls_functions[libname]) == 0 or libname.startswith("syscalls"):
                    continue
                
                angrlib = self.set_calling_conventions(libname, dlls_functions)

                procs = self.create_lib_procedures(dlls_functions[libname], libname, angrlib)

                newprocs = {}
                for name, simprocedure in procs.items():
                    if (not angrlib.has_implementation(name) and name not in self.sim_proc["custom_package"]):
                        newprocs[name] = simprocedure
                        if name in dic_symbols:
                            if project.arch.name == "AMD64":
                                self.amd64_sim_proc_hook(project, dic_symbols[name], simprocedure)
                            elif name not in self.EXCEPTIONS:
                                self.std_sim_proc_hook(project, dic_symbols[name], simprocedure)
                            elif name and name in self.EXCEPTIONS:
                                self.exception_sim_proc_hook(project, dic_symbols[name], simprocedure)
                    elif name in self.sim_proc["custom_package"]:
                        newprocs[name] = self.sim_proc["custom_package"][name]
                    else:
                        pass

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
        self.log.info("No hooks for: %s", str(dic_symbols))

    def std_sim_proc_hook(self, proj, name, simproc):
        proj.hook(
            name,
            simproc(cc=SimCCStdcall(proj.arch)),
        )

    def exception_sim_proc_hook(self, proj, name, simproc):
        proj.hook(
            name,
            simproc(cc=SimCCCdecl(proj.arch)),
        )

    @abstractmethod
    def amd64_sim_proc_hook(self, project, name, sim_proc):
        pass

    def custom_hook_static(self, proj):
        """_summary_
        TODO CH pre-post + automatization
        Args:
            proj (_type_): _description_
        """
        self.log.info("custom_hook_static")
        proj.loader
        symbols = proj.loader.symbols

        custom_pack = self.sim_proc["custom_package"]

        manual_link = {
            "LoadLibraryA": custom_pack["LoadLibraryA"],
            "LoadLibraryExA": custom_pack["LoadLibraryExA"],
            "LoadLibraryW": custom_pack["LoadLibraryW"],
            "LoadLibraryExW": custom_pack["LoadLibraryExW"],
            "GetProcAddress": custom_pack["GetProcAddress"],
            "GetModuleHandleExW": custom_pack["GetModuleHandleExW"],
            "GetModuleHandleExA": custom_pack["GetModuleHandleExA"],
            "GetModuleHandleW": custom_pack["GetModuleHandleW"],
            "GetModuleHandleA": custom_pack["GetModuleHandleA"],
            "GetModuleFileNameA": custom_pack["GetModuleFileNameA"],
            "GetModuleFileNameW": custom_pack["GetModuleFileNameW"],
            # "GetModuleFileNameExA": custom_pack["GetModuleFileNameExA"],
            # "GetModuleFileNameExW": custom_pack["GetModuleFileNameExW"],
        }

        ignore_simproc = {"LoadLibraryA", "LoadLibraryW"}
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
            if name in manual_link:
                proj.unhook(symb.rebased_addr)
                if proj.arch.name == "X86":
                    self.std_sim_proc_hook(proj, symb.rebased_addr, manual_link[name])
                else:
                    proj.hook(symb.rebased_addr, manual_link[name](cc=SimCCMicrosoftAMD64(proj.arch)))
            elif not name:
                pass
            elif name == "readlink":
                if proj.arch.name == "X86":
                    proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES["posix"]["read"]())
                else:
                    self.amd64_sim_proc_hook(proj, symb.rebased_addr, angr.SIM_PROCEDURES["posix"]["read"])
            elif name in ignore_simproc:
                pass
            boo = False
            for simproc_to_check in angr_simproc_to_check:
                if name in angr.SIM_PROCEDURES[simproc_to_check]:
                    boo = True
                    if proj.arch.name == "X86":
                        if proj.simos.name == "windows":
                            proj.hook(symb.rebased_addr, simproc_to_check[name]())
                    else:
                        self.amd64_sim_proc_hook(proj, symb.rebased_addr, simproc_to_check[name])
                    break
            if boo : continue
            if name in simproc64:
                if proj.arch.name == "X86":
                    if proj.simos.name == "windows":
                        proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES["libc"][simproc64[name]]())
                else:
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

    def custom_hook_no_symbols(self, proj):
        """_summary_
        TODO CH for manon
        Args:
            proj (_type_): _description_
        """
        self.log.info("custom_hook_no_symbols")

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
            if (
                (name not in custom)
                and (name not in angr.SIM_PROCEDURES["posix"])
                and (name not in angr.SIM_PROCEDURES["linux_kernel"])
                and self.system_call_table[key]["num_args"] != 0
            ):
                proj.simos.syscall_library.add(
                    name, generic[str(self.system_call_table[key]["num_args"])]
                )




