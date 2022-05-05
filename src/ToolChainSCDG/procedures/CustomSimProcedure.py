import logging
import re
import angr
import keyword
import builtins
import os

from angr.misc import autoimport
from angr.procedures import SIM_LIBRARIES
from angr.procedures.definitions import SimLibrary
from angr.calling_conventions import SimCCStdcall, SimCCCdecl

try:
    from ..clogging.CustomFormatter import CustomFormatter
except:
    from clogging.CustomFormatter import CustomFormatter

from .DDLLoader import DDLLoader
from .LinuxTableLoader import LinuxTableLoader

builtins = dir(__builtins__)

class CustomSimProcedure:

    EXCEPTIONS = [
        "ShellMessageBoxW",
        "ShellMessageBoxA",
        "ShellMessageBoxW",
        "ShellMessageBoxA",
        "wsprintfA",
        "wsprintfW",
    ]

    CDECL_EXCEPT = [
        "wsprintfW",
        "GetAdaptersInfo",
        "ShellMessageBoxA",
        "ShellMessageBoxW",
        "wsprintfA",
        "sprintf",
        "strcat"
    ]

    ANGR_LIBS = {
        "kernel32.dll": "kernel32.dll",
        "msvcrt.dll": "msvcrt.dll",
        "ntdll.dll": "ntdll.dll",
        "advapi32.dll": "advapi32.dll",
        "user32.dll": "user32.dll",
    }

    ## --- Functions where strings could/shoud be resolved with number of the argument -- ##
    FUNCTION_STRING = {
        "open": 0,
        "fopen": 0,
        "openat": 1,
        "write": 1,
        "opendir": 0,
        "readlink": 0,
        "ioctl": 2,
        "chdir": 0,
        "unlink": 0,
        "stat": 0,
        "stat64": 0,
        "lstat": 0,
        "lstat64": 0,
        "sethostname": 0,
        "system": 0,
        "chown": 0,
        "delete_module": 0,
        "init_module": 2,
        "swapoff": 0,
        "statfs": 0,
        "truncate": 0,
        "swapon": 0,
        "uselib": 0,
        "oldlstat": 0,
        "chroot": 0,
        "acct": 0,
        "rmdir": 0,
        "mkdir": 0,
        "access": 0,
        "oldstat": 0,
        "lchown": 0,
        "chmod": 0,
        "mknod": 0,
        "execve": 0,
        "creat": 0,
        "readlinkat": 1,
        "execve": [0, 1, 2],
        "open64": 0,
    }  # ,'RegCreateKeyW':1}

    ANGR_CALLING_CONVENTIONS = {
        "__stdcall": SimCCStdcall,
        "__cdecl": SimCCCdecl,
    }

    # Simprocedure that are not real syscall
    # ,'__libc_start_main':'__libc_start_main','__getmainargs':'__getmainargs'
    AVOID = {
        "_initterm": "_initterm",
        "__lconv_init": "__lconv_init",
        "__set_app_type": "__set_app_type",
        "PathTerminator": "PathTerminator",
    }

    # Max number of file descriptor, defined first in PLUGINS.POSIX
    MAX_FD = 8192

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

    # Subcall that can be performed by socket call
    SOCKETCALL_dic = {
        "connect",
        "bind",
        "socket",
        "listen",
        "accept",
        "getsockname",
        "getpeername",
        "socketpair",
        "send",
        "recv",
        "sendto",
        "recvfrom",
        "setsockopt",
        "getsockopt",
    }

    ## -------------- Manage returned value of specific function ----------------##
    def ret_open(state):
        posix = state.posix
        fd = posix.fd
        for ret in range(0, 8192):  # MAX_FD TODO
            if ret not in fd:
                return ret
                # return state.solver.BVV(ret, 64)
        return -1

    FUNCTION_RETURNS = {
        "open": ret_open,
        "openat": ret_open,
        "open64": ret_open,
        "socket": ret_open,
    }

    FUNCTION_HANDLER = {}

    def __init__(self, scdg, scdg_fin, is_from_tc, string_resolv=True, print_on=True, print_syscall=True):
        # ch = logging.StreamHandler() # TODO bug duplicate logs
        # ch.setLevel(logging.INFO)
        # ch.setFormatter(CustomFormatter())
        self.log = logging.getLogger("CustomSimProcedure")
        self.log.setLevel(logging.INFO)
        # self.log.addHandler(ch)
        # self.log.propagate = False

        self.is_from_tc = is_from_tc

        self.custom_simproc_windows = {}
        self.init_windows_sim_proc()

        self.custom_simproc = {}
        self.init_linux_sim_proc()

        self.ddl_loader = DDLLoader()
        self.linux_loader = LinuxTableLoader()

        self.system_call_table = {}

        self.string_resolv = string_resolv
        self.print_on = print_on

        self.scdg = scdg  # todo, not elegant
        self.scdg_fin = scdg_fin

        self.syscall_found = {}

        self.print_syscall = print_syscall
        
    def init_windows_sim_proc(self):
        # Import all classes under the current directory, and group them based on
        self.custom_simproc_windows.clear()
        path = os.path.dirname(os.path.abspath(__file__)) + "/windows"
        self.log.info("Windows lib path = " + str(path))
        skip_dirs = ["definitions"]
        pkg = "procedures.windows"
        if self.is_from_tc:
            pkg = "ToolChainSCDG.procedures.windows"
        for pkg_name, package in autoimport.auto_import_packages(
            pkg , path, skip_dirs
        ):
            for _, mod in autoimport.filter_module(package, type_req=type(os)):
                for name, proc in autoimport.filter_module(
                    mod, type_req=type, subclass_req=angr.SimProcedure
                ):
                    if hasattr(proc, "__provides__"):
                        for custom_pkg_name, custom_func_name in proc.__provides__:
                            if custom_pkg_name not in self.custom_simproc_windows:
                                self.custom_simproc_windows[custom_pkg_name] = {}
                            self.custom_simproc_windows[custom_pkg_name][
                                custom_func_name
                            ] = proc
                    else:
                        if pkg_name not in self.custom_simproc_windows:
                            self.custom_simproc_windows[pkg_name] = {}
                        self.custom_simproc_windows[pkg_name][name] = proc
                        if hasattr(proc, "ALT_NAMES") and proc.ALT_NAMES:
                            for altname in proc.ALT_NAMES:
                                self.custom_simproc_windows[pkg_name][altname] = proc
                        if name == "UnresolvableJumpTarget":
                            self.custom_simproc_windows[pkg_name][
                                "UnresolvableTarget"
                            ] = proc

        # self.log.info(self.custom_simproc_windows)

    def init_linux_sim_proc(self):
        self.custom_simproc.clear()
        path = os.path.dirname(os.path.abspath(__file__)) + "/linux"
        self.log.info("Linux lib path = " + str(path))
        skip_dirs = ["definitions"]
        pkg = "procedures.linux"
        if self.is_from_tc:
            pkg = "ToolChainSCDG.procedures.linux"
        for pkg_name, package in autoimport.auto_import_packages(
            pkg, path, skip_dirs
        ):
            for _, mod in autoimport.filter_module(package, type_req=type(os)):
                for name, proc in autoimport.filter_module(
                    mod, type_req=type, subclass_req=angr.SimProcedure
                ):
                    if hasattr(proc, "__provides__"):
                        for custom_pkg_name, custom_func_name in proc.__provides__:
                            if custom_pkg_name not in self.custom_simproc:
                                self.custom_simproc[custom_pkg_name] = {}
                            self.custom_simproc[custom_pkg_name][
                                custom_func_name
                            ] = proc
                    else:
                        if pkg_name not in self.custom_simproc:
                            self.custom_simproc[pkg_name] = {}
                        self.custom_simproc[pkg_name][name] = proc
                        if hasattr(proc, "ALT_NAMES") and proc.ALT_NAMES:
                            for altname in proc.ALT_NAMES:
                                self.custom_simproc[pkg_name][altname] = proc
                        if name == "UnresolvableJumpTarget":
                            self.custom_simproc[pkg_name]["UnresolvableTarget"] = proc

        # self.log.info(self.custom_simproc)

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

    def create_lib_procedures(self, dlldict, libname, angrlib):
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

    def loadlibs_proc(self, dlls_functions, project):
        symbols = project.loader.symbols
        dic_symbols = {symb.name: symb.rebased_addr for symb in symbols}
        self.log.info(dic_symbols)

        for dllname in project.loader.requested_names:
            libname = dllname
            if libname in dlls_functions.keys():
                if len(dlls_functions[libname]) == 0 or libname.startswith("syscalls"):
                    continue
                if libname in self.ANGR_LIBS:
                    self.log.info("Was in angr :" + str(libname))

                    angrlib = SIM_LIBRARIES[self.ANGR_LIBS[libname]]
                    cc = list(dlls_functions[libname].values())[0]["cc"]

                    # Set properly calling conventions
                    angrlib.set_default_cc("X86", self.ANGR_CALLING_CONVENTIONS[cc])
                    angrlib.default_ccs["X86"] = self.ANGR_CALLING_CONVENTIONS[cc]
                else:
                    angrlib = SimLibrary()
                    angrlib.set_library_names(libname)
                    cc = list(dlls_functions[libname].values())[0]["cc"]
                    angrlib.set_default_cc("X86", self.ANGR_CALLING_CONVENTIONS[cc])
                    SIM_LIBRARIES.update({libname: angrlib})

                procs = self.create_lib_procedures(
                    dlls_functions[libname], libname, angrlib
                )

                newprocs = {}
                for name, simprocedure in procs.items():

                    if (
                        not angrlib.has_implementation(name)
                        and name not in self.custom_simproc_windows["custom_package"]
                        and name not in self.custom_simproc["custom_package"]
                    ):
                        newprocs[name] = simprocedure
                        if name in dic_symbols and name not in self.EXCEPTIONS:

                            project.hook(
                                dic_symbols[name],
                                simprocedure(cc=SimCCStdcall(project.arch)),
                            )
                        if name in dic_symbols and name and name in self.EXCEPTIONS:
                            # import pdb; pdb.set_trace()
                            project.hook(
                                dic_symbols[name],
                                simprocedure(cc=SimCCCdecl(project.arch)),
                            )
                    elif name in self.custom_simproc_windows["custom_package"]:
                        newprocs[name] = self.custom_simproc_windows["custom_package"][
                            name
                        ]
                    elif name in self.custom_simproc["custom_package"]:
                        newprocs[name] = self.custom_simproc["custom_package"][name]
                    else:
                        pass

                    if name in dic_symbols:
                        del dic_symbols[name]

                angrlib.add_all_from_dict(newprocs)
                self.log.info('----------- Symbols after hook for libs ' + libname +'--------------------')
                self.log.info(dic_symbols)

        project._sim_procedures = {
            addr: simprocedure for addr, simprocedure in project._sim_procedures.items()
        }

        # Force each object , check resolution of symbols
        # for obj in project.loader.initial_load_objects:
        #    project._register_object(obj,project.arch)

        ok = {}
        for name in dic_symbols:
            if name in self.custom_simproc_windows["custom_package"]:
                project.hook(
                    dic_symbols[name],
                    self.custom_simproc_windows["custom_package"][name](
                        cc=SimCCStdcall(project.arch)
                    ),
                )
                ok[name] = 1
            if name in self.custom_simproc["custom_package"]:
                project.hook(
                    dic_symbols[name],
                    self.custom_simproc["custom_package"][name](
                        cc=SimCCStdcall(project.arch)
                    ),
                )
                ok[name] = 1

        for s in ok:
            del dic_symbols[s]
        self.log.info("No hooks for: %s", str(dic_symbols))
        # self.log.info(dic_symbols)

    def loadlibs(self, project):
        symbols = project.loader.symbols
        dic_symbols = {symb.name: symb.rebased_addr for symb in symbols}
        self.log.info(dic_symbols)

        for dllname in project.loader.requested_names:
            libname = dllname

            if libname in self.system_call_table.keys():
                if len(self.system_call_table[libname]) == 0 or libname.startswith(
                    "syscalls"
                ):
                    continue
                if libname in self.ANGR_LIBS:
                    self.log.info("Was in angr :" + str(libname))

                    angrlib = SIM_LIBRARIES[self.ANGR_LIBS[libname]]
                    cc = list(self.system_call_table[libname].values())[0]["cc"]

                    # Set properly calling conventions
                    angrlib.set_default_cc("X86", self.ANGR_CALLING_CONVENTIONS[cc])
                    angrlib.default_ccs["X86"] = self.ANGR_CALLING_CONVENTIONS[cc]
                else:
                    angrlib = SimLibrary()
                    angrlib.set_library_names(libname)
                    cc = list(self.system_call_table[libname].values())[0]["cc"]
                    angrlib.set_default_cc("X86", self.ANGR_CALLING_CONVENTIONS[cc])
                    SIM_LIBRARIES.update({libname: angrlib})

                procs = self.create_lib_procedures(
                    self.system_call_table[libname], libname, angrlib
                )

                newprocs = {}
                for name, simprocedure in procs.items():

                    if (
                        not angrlib.has_implementation(name)
                        and name not in self.custom_simproc_windows["custom_package"]
                        and name not in self.custom_simproc["custom_package"]
                    ):
                        newprocs[name] = simprocedure
                        if name in dic_symbols and name not in self.EXCEPTIONS:
                            project.hook(
                                dic_symbols[name],
                                simprocedure(cc=SimCCStdcall(project.arch)),
                            )
                        if name in dic_symbols and name and name in self.EXCEPTIONS:
                            # import pdb; pdb.set_trace()
                            project.hook(
                                dic_symbols[name],
                                simprocedure(cc=SimCCCdecl(project.arch)),
                            )
                    elif name in self.custom_simproc_windows["custom_package"]:
                        newprocs[name] = self.custom_simproc_windows["custom_package"][
                            name
                        ]
                    elif name in self.custom_simproc["custom_package"]:
                        newprocs[name] = self.custom_simproc["custom_package"][name]
                    else:
                        pass

                    if name in dic_symbols:
                        del dic_symbols[name]

                angrlib.add_all_from_dict(newprocs)
                self.log.info('----------- Symbols after hook for libs ' + libname +'--------------------')
                self.log.info(dic_symbols)
                
        project._sim_procedures = {
            addr: simprocedure for addr, simprocedure in project._sim_procedures.items()
        }

        # Force each object , check resolution of symbols
        # for obj in project.loader.initial_load_objects:
        #    project._register_object(obj,project.arch)

        ok = {}
        for name in dic_symbols:
            if name in self.custom_simproc_windows["custom_package"]:
                project.hook(
                    dic_symbols[name],
                    self.custom_simproc_windows["custom_package"][name](
                        cc=SimCCStdcall(project.arch)
                    ),
                )
                ok[name] = 1
            if name in self.custom_simproc["custom_package"]:
                project.hook(
                    dic_symbols[name],
                    self.custom_simproc["custom_package"][name](
                        cc=SimCCStdcall(project.arch)
                    ),
                )
                ok[name] = 1

        for s in ok:
            del dic_symbols[s]
        self.log.info("No hooks for: %s", str(dic_symbols))
        # self.log.info(dic_symbols)

    def add_call_debug(self, state):

        name = state.inspect.simprocedure_name
        sim_proc = state.inspect.simprocedure
        n_args = 0

        if name in self.AVOID:
            return

        if sim_proc:
            n_args = sim_proc.num_args

        self.add_syscall(name, n_args, state)

    def add_syscall(self, syscall, n_args, state):
        # global SCDG
        dic = {}

        name = syscall
        sim_proc = state.inspect.simprocedure
        name = state.inspect.simprocedure_name
        state.project
        args = sim_proc.arguments
        if not args:
            args = []

        regs = sim_proc.cc.ARG_REGS

        if name == "rt_sigaction" or name == "sigaction":
            state.inspect.simprocedure_result = state.solver.BVV(0, state.arch.bits)
            # self.log.info("Value of return value changed for sigaction to AVOID problem")

        # Get proto of the function
        for key in self.system_call_table.keys():
            if name in self.system_call_table[key]:
                self.system_call_table[key][name]
                # if PRINT_ON :
                #    self.log.info(callee['arguments'])

        if n_args > 0 and n_args < len(regs):
            regs = regs[0:n_args]
            for reg in regs:
                try:
                    reg = getattr(state.regs, reg)
                except:
                    reg = None
                # reg = get_register(state,reg)
                reg = self.proper_formating(state, reg)
                args.append(reg)

        dic["name"] = name

        # Transform if option enabled
        if self.string_resolv and syscall in self.FUNCTION_STRING and args:
            if isinstance(self.FUNCTION_STRING[syscall], int):
                arg_len = 1
            else:
                arg_len = len(self.FUNCTION_STRING[syscall])
            for i in range(arg_len):
                if arg_len > 1:
                    index_str = self.FUNCTION_STRING[syscall][i]
                else:
                    index_str = self.FUNCTION_STRING[syscall]
                arg_str = args[index_str]
                # import pdb; pdb.set_trace()
                if arg_str:
                    try:
                        string = state.mem[arg_str].string.concrete
                        if hasattr(string, "decode"):
                            args[index_str] = string.decode("utf-8")
                        else:
                            args[index_str] = string
                        if i > 0:
                            dic["ref_str"][(index_str + 1)] = arg_str
                        else:
                            dic["ref_str"] = {(index_str + 1): arg_str}
                        # self.log.info(string)
                    except Exception:
                        string = state.mem[arg_str].string.concrete
                        if hasattr(string, "decode"):
                            args[index_str] = string.decode("utf-8", errors="ignore")
                        else:
                            args[index_str] = string
                        if i > 0:
                            dic["ref_str"][(index_str + 1)] = arg_str
                        else:
                            dic["ref_str"] = {(index_str + 1): arg_str}

        if syscall in self.FUNCTION_HANDLER:
            self.FUNCTION_HANDLER[syscall](state)

        if args:
            for i in range(len(args)):
                args[i] = self.proper_formating(state, args[i])

        dic["args"] = args
        dic["addr_func"] = str(state.addr)
        if len(state.globals["addr_call"]) > 0:
            dic["addr"] = state.globals["addr_call"][-1]
        else:
            dic["addr"] = str(state.addr)
        # import pdb; pdb.set_trace()

        if syscall in self.FUNCTION_RETURNS:
            ret = self.FUNCTION_RETURNS[syscall](state)
            if self.print_on:
                self.log.info("return value of " + str(name) + " :" + str(ret))
            dic["ret"] = ret
        else:
            dic["ret"] = 0

        id = state.globals["id"]
        #print(id)

        if len(self.scdg) == 0:
            self.scdg.append([dic])
        else:
            #print(self.scdg[id])
            if len(self.scdg[id][-1]) != 0:
                # if same address and different name, we have an inline call (call to another simprocedure used during the hook), discard !
                if (
                    self.scdg[id][-1]["addr"] == dic["addr"]
                    and self.scdg[id][-1]["name"] != dic["name"]
                ):
                    # self.log.info('inline call !')
                    return

                self.scdg[id].append(dic)

            return

    def check_constraint(self, state, value):
        try:
            val = state.solver.eval_one(value)
            is_sao = hasattr(val, "to_claripy")
            if is_sao:
                val = val.to_claripy()

        except Exception:
            if self.print_on:
                self.log.info("Symbolic value encountered !")
            return value
        return val

    def proper_formating(self, state, value):
        """
        Take a state and a value (argument/return value) and return an appropriate reprensentation to use in SCDG.
        """
        if hasattr(value, "to_claripy"):
            value = value.to_claripy()

        if hasattr(value, "symbolic") and value.symbolic and hasattr(value, "name"):
            # self.log.info("case 1 formating")
            return value.name
        elif (
            hasattr(value, "symbolic") and value.symbolic and len(value.variables) == 1
        ):
            # import pdb; pdb.set_trace()
            # self.log.info("case 2 formating")
            # self.log.info(value.variables)

            return list(value.variables)[0]
        elif hasattr(value, "symbolic") and value.symbolic:
            # self.log.info('case 3 : multiple variables involved')
            # TODO improve this
            ret = "_".join(list(value.variables))

            return ret
        else:
            # self.log.info("case 4 formating")
            try:
                val = state.solver.eval_one(value)
                return val
            except:
                return value

    def add_call(self, state):
        name = state.inspect.simprocedure_name

        if name in self.AVOID:
            return

        sim_proc = state.inspect.simprocedure

        callee = None
        callee_arg = None
        ret_type = None
        if (
            sim_proc
            and sim_proc.is_syscall
            and str(sim_proc.syscall_number) in self.system_call_table
            and self.print_syscall
        ):
            self.log.info("Syscall detected")
            # self.log.info(sim_proc.syscall_number)
            self.log.info(state.inspect.simprocedure_result)
            self.log.info(self.system_call_table[str(sim_proc.syscall_number)])
            self.system_call_table[str(sim_proc.syscall_number)]["num_args"]

        # Get definition of windows syscall (e.g.:for extraction of possible strings)
        # TODO : Optimize this heavy loop
        for key in self.system_call_table.keys():
            if name in self.system_call_table[key]:
                callee = self.system_call_table[key][name]
                callee_arg = callee["arguments"]
                ret_type = callee["returns"]
                break
        if not callee and state.globals["loaded_libs"]:
            for k, lib in state.globals["loaded_libs"].items():
                if lib not in self.system_call_table.keys():
                    self.ddl_loader.load_more(lib, self.system_call_table)
                    # import pdb; pdb.set_trace()

        id = state.globals["id"]
        args = []
        if sim_proc:
            args = sim_proc.arguments
            sim_proc.num_args

            if not args:
                args = []

        if name:
            key_name = str(name)
            if not (key_name in self.syscall_found):
                self.syscall_found[key_name] = 1
            else:
                self.syscall_found[key_name] = self.syscall_found[key_name] + 1

        if name and self.print_on:
            self.log.info("Syscall found:  " + str(name) + str(args))

        if self.scdg[id][-1]["name"] == name and args:

            for i in range(len(args)):
                args[i] = self.proper_formating(state, args[i])
                temp = args[i]
                try:
                    if (
                        self.string_resolv
                        and callee_arg
                        and args[i] != 0
                        and (
                            "LPCWSTR" in callee_arg[i]["type"]
                            or "LPWSTR" in callee_arg[i]["type"]
                            or "wchar_t*const" in callee_arg[i]["type"]
                            or "OLECHAR" in callee_arg[i]["type"]
                            or "char*" in callee_arg[i]["type"]
                        )
                    ):
                        temp = args[i]
                        string = state.mem[args[i]].wstring.concrete

                        if hasattr(string, "decode"):
                            args[i] = string.decode("utf-8")
                        else:
                            args[i] = string

                        if self.debug_string:
                            # import pdb
                            # pdb.set_trace()
                            self.log.info("Args string Resolved : " + str(string))
                except:
                    args[i] = temp
                try:
                    if (
                        self.string_resolv
                        and callee_arg
                        and args[i] != 0
                        and (
                            "LPCSTR" in callee_arg[i]["type"]
                            or "LPSTR" in callee_arg[i]["type"]
                            or "const char*" in callee_arg[i]["type"]
                            or "LPCVOID" in callee_arg[i]["type"]
                            or "char*" in callee_arg[i]["type"]
                        )
                    ):
                        string = state.mem[args[i]].string.concrete
                        if hasattr(string, "decode"):
                            args[i] = string.decode("utf-8")
                        else:
                            args[i] = string
                except:
                    args[i] = temp

            if self.string_resolv and name in self.FUNCTION_STRING and args:
                index_str = self.FUNCTION_STRING[name]
                try:
                    string = state.mem[args[index_str]].string.concrete
                    if hasattr(string, "decode"):
                        args[index_str] = string.decode("utf-8")
                    else:
                        args[index_str] = string
                    dic["ref_str"] = {(index_str + 1): arg_str}  # TODO
                except Exception:
                    pass

            self.scdg[id][-1]["args"] = args
            

            if (
                name == "write"
                and len(self.scdg[id]) > 1
                and self.scdg[id][-2]["name"] == "write"
                and self.scdg[id][-1]["addr"] == self.scdg[id][-1]["addr"]
                and sim_proc.use_state_arguments
            ):
                self.scdg[id][-2]["args"][1] = str(self.scdg[id][-2]["args"][1]) + str(
                    self.scdg[id][-1]["args"][1]
                )
                self.scdg[id].pop()

        elif self.scdg[id][-1]["name"] == "writev" and name == "write" and args:
            self.scdg[id][-1]["name"] = "write"
            for i in range(len(args)):
                args[i] = self.proper_formating(state, args[i])
            self.scdg[id][-1]["args"] = args

            try:
                ret = state.solver.eval_one(state.inspect.simprocedure_result)
            except Exception:
                stub = state.inspect.simprocedure_result
                if hasattr(stub, "to_claripy"):
                    stub = stub.to_claripy()
                if hasattr(stub, "name"):
                    ret = stub.name
                else:
                    ret = str(stub)

            self.scdg[id][-1]["ret"] = ret
        elif self.scdg[id][-1]["name"] == "readv" and name == "read" and args:
            self.scdg[id][-1]["name"] = "read"
            for i in range(len(args)):
                args[i] = self.proper_formating(state, args[i])
            self.scdg[id][-1]["args"] = args
            try:
                ret = state.solver.eval_one(state.inspect.simprocedure_result)
            except Exception:
                stub = state.inspect.simprocedure_result
                if hasattr(stub, "to_claripy"):
                    stub = stub.to_claripy()
                if hasattr(stub, "name"):
                    ret = stub.name
                else:
                    ret = str(stub)

            self.scdg[id][-1]["ret"] = ret
        elif (
            self.scdg[id][-1]["name"] == "socketcall"
            and name in self.SOCKETCALL_dic
            and args
        ):
            self.scdg[id][-1]["name"] = name
            for i in range(len(args)):
                args[i] = self.proper_formating(state, args[i])
            self.scdg[id][-1]["args"] = args
            # import pdb; pdb.set_trace()
            try:
                ret = state.solver.eval_one(state.inspect.simprocedure_result)
            except Exception:
                stub = state.inspect.simprocedure_result
                if hasattr(stub, "to_claripy"):
                    stub = stub.to_claripy()
                if hasattr(stub, "name"):
                    ret = stub.name
                else:
                    ret = str(stub)

            self.scdg[id][-1]["ret"] = ret
        else:
            pass
        if ret_type and (
            "LPCSTR" in ret_type
            or "LPSTR" in ret_type
            or "const char*" in ret_type
            or "LPCVOID" in ret_type
            or "char*" in ret_type
            ):
            try: 
                retval = state.solver.eval_one(state.inspect.simprocedure_result)
                str_mem = state.mem[retval].string.concrete
                if hasattr(str_mem, "decode"):
                    str_mem = state.mem[retval].string.concrete.decode("utf-8")
                self.scdg[id][-1]["ret"] = str_mem
            except:
                self.scdg[id][-1]["ret"] = retval
        elif (
            self.scdg[id][-1]["ret"] != "symbolic"
            and name not in self.FUNCTION_RETURNS
        ):
            ret = -22
            try:
                ret = state.solver.eval_one(state.inspect.simprocedure_result)
            except Exception:
                stub = state.inspect.simprocedure_result
                if hasattr(stub, "to_claripy"):
                    stub = stub.to_claripy()
                if hasattr(stub, "name"):
                    ret = stub.name
                else:
                    ret = str(stub)

            self.scdg[id][-1]["ret"] = ret
        else:
            pass
        return

    def custom_hook_static(self, proj):
        """
        TODO pre-post + automatization
        """
        self.log.info("custom_hook_static")
        #proj.loader
        symbols = proj.loader.symbols

        custom_pack = self.custom_simproc_windows["custom_package"]

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
        }

        ignore_simproc = {"LoadLibraryA", "LoadLibraryW"}
        simproc64 = {"fopen64": "fopen"}
        for symb in symbols:
            name = symb.name
            if name in manual_link:
                proj.unhook(symb.rebased_addr)
                proj.hook(
                    symb.rebased_addr, manual_link[name](cc=SimCCStdcall(proj.arch))
                )
            elif not name:
                pass
            elif name == "readlink":
                proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES["posix"]["read"]())
            elif name in ignore_simproc:
                pass
            elif name in angr.SIM_PROCEDURES["glibc"]:
                proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES["glibc"][name]())
            elif name in angr.SIM_PROCEDURES["libc"]:
                proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES["libc"][name]())
            elif name in angr.SIM_PROCEDURES["posix"]:
                proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES["posix"][name]())
            elif name in angr.SIM_PROCEDURES["linux_kernel"]:
                proj.hook(
                    symb.rebased_addr, angr.SIM_PROCEDURES["linux_kernel"][name]()
                )
            elif name in angr.SIM_PROCEDURES["win32"]:
                proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES["win32"][name]())
            elif name in angr.SIM_PROCEDURES["win_user32"]:
                proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES["win_user32"][name]())
            elif name in angr.SIM_PROCEDURES["ntdll"]:
                proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES["ntdll"][name]())
            elif name in angr.SIM_PROCEDURES["msvcr"]:
                proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES["msvcr"][name]())
            # elif name in angr.SIM_PROCEDURES['advapi32'] :
            #    proj.hook(symb.rebased_addr, angr.SIM_PROCEDURES['advapi32'][name]())
            elif name in simproc64:
                proj.hook(
                    symb.rebased_addr, angr.SIM_PROCEDURES["libc"][simproc64[name]]()
                )
            elif "ordinal" in name:
                # ex : ordinal.680.b'shell32.dll'
                # import pdb; pdb.set_trace()
                part_names = name.split(".")
                lib_part = part_names[2][2:] + ".dll"
                ord_part = part_names[1]
                self.log.info(lib_part)
                self.log.info(ord_part)
                # symb.name = self.system_call_table[lib_part][ord_part]['name']
            else:
                pass

    def custom_hook_no_symbols(self, proj):
        self.log.info("custom_hook_no_symbols")

        custom_pack = self.custom_simproc["custom_package"]
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

        for key in custom:
            proj.simos.syscall_library.add(key, custom[key])  # TODO error
        for key in angr.SIM_PROCEDURES["posix"]:
            if key not in custom:
                proj.simos.syscall_library.add(key, angr.SIM_PROCEDURES["posix"][key])

        generic = {}
        generic["0"] = custom_pack["gen_simproc0"]
        generic["1"] = custom_pack["gen_simproc1"]
        generic["2"] = custom_pack["gen_simproc2"]
        generic["3"] = custom_pack["gen_simproc3"]
        generic["4"] = custom_pack["gen_simproc4"]
        generic["5"] = custom_pack["gen_simproc5"]
        generic["6"] = custom_pack["gen_simproc6"]

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

    def custom_hook_windows_symbols(self, proj):
        # self.ANG_CALLING_CONVENTION = {"__stdcall": SimCCStdcall, "__cdecl": SimCCCdecl}
        self.log.info("custom_hook_windows_symbols")
        #proj.loader
        symbols = proj.loader.symbols
        custom_pack = self.custom_simproc["custom_package"]
        generic = {}
        generic["0"] = custom_pack["gen_simproc0"]
        generic["1"] = custom_pack["gen_simproc1"]
        generic["2"] = custom_pack["gen_simproc2"]
        generic["3"] = custom_pack["gen_simproc3"]
        generic["4"] = custom_pack["gen_simproc4"]
        generic["5"] = custom_pack["gen_simproc5"]
        generic["6"] = custom_pack["gen_simproc6"]

        existing_proc = [
            "win32.dll",
            "win_user32.dll",
            "ntdll.dll",
            "msvcr.dll",
            "advapi32.dll",
        ]
        for lib in self.system_call_table:
            for key in self.system_call_table[lib]:
                name = self.system_call_table[lib][key]["name"]
                if (
                    (name not in angr.SIM_PROCEDURES["win32"])
                    and (name not in angr.SIM_PROCEDURES["win_user32"])
                    and (name not in angr.SIM_PROCEDURES["ntdll"])
                    and (name not in angr.SIM_PROCEDURES["msvcr"])
                    and len(self.system_call_table[lib][key]["arguments"]) != 0
                ):
                    symbols = proj.loader.symbols
                    for symb in symbols:
                        if (
                            name == symb.name
                            and (name not in angr.SIM_PROCEDURES["posix"])
                            and (name not in angr.SIM_PROCEDURES["linux_kernel"])
                            and (name not in angr.SIM_PROCEDURES["libc"])
                            and name
                            not in self.custom_simproc_windows["custom_package"]
                        ):
                            proj.hook_symbol(
                                name, SIM_LIBRARIES[lib].get(name, proj.arch)
                            )
                        if symb.name in self.custom_simproc_windows["custom_package"]:
                            proj.unhook(symb.rebased_addr)
                            if symb.name not in self.CDECL_EXCEPT:
                                proj.hook(
                                    symb.rebased_addr,
                                    self.custom_simproc_windows["custom_package"][
                                        symb.name
                                    ](cc=SimCCStdcall(proj.arch)),
                                )
                            else:
                                # import pdb; pdb.set_trace()
                                proj.hook(
                                    symb.rebased_addr,
                                    self.custom_simproc_windows["custom_package"][
                                        symb.name
                                    ](cc=SimCCCdecl(proj.arch)),
                                )

                        if symb.name and "ordinal" in symb.name:
                            # ex : ordinal.680.b'shell32.dll'
                            part_names = symb.name.split(".")
                            lib_part = part_names[2][2:] + ".dll"
                            ord_part = part_names[1]
                            try:
                                real_name = self.system_call_table[lib_part][ord_part][
                                    "name"
                                ]
                            except:
                                real_name = "nope"

                            if real_name == "nope":
                                pass
                            elif (
                                real_name
                                in self.custom_simproc_windows["custom_package"]
                            ):
                                proj.unhook(symb.rebased_addr)
                                proj.hook(
                                    symb.rebased_addr,
                                    self.custom_simproc_windows["custom_package"][
                                        #symb.name # before
                                        real_name
                                    ](cc=SimCCStdcall(proj.arch)),
                                )
                            elif lib_part == lib:
                                proj.unhook(symb.rebased_addr)
                                proj.hook(
                                    symb.rebased_addr,
                                    SIM_LIBRARIES[lib].get(real_name, proj.arch),
                                )
                            else:
                                pass

                else:
                    pass

    # Break at specific instruction and open debug mode.
    def debug_instr(self, state):
        if state.inspect.instruction == int(
            "0x004015a3", 16
        ) or state.inspect.instruction == int("0x0040159b", 16):
            self.log.info("Debug function\n\n")
            self.log.info(hex(state.inspect.instruction))
            import pdb
            pdb.set_trace()

    def debug_read(self, state):
        if state.solver.eval(state.inspect.mem_read_address) == int("0xf404120", 16):
            self.log.info("Read function\n\n")
            self.log.info(state.inspect.mem_read_address)
            import pdb
            pdb.set_trace()

    def debug_write(self, state):
        if state.solver.eval(state.inspect.mem_write_address) == int("0xf404120", 16):
            self.log.info("Write function\n\n")
            self.log.info(state.inspect.mem_write_address)
            import pdb
            pdb.set_trace()

    def add_addr_call(self, state):
        test = state.globals["addr_call"] + [state.scratch.ins_addr]
        state.globals["addr_call"] = test

    def rm_addr_call(self, state):
        calls = state.globals["addr_call"]
        if len(calls) > 1:
            state.globals["addr_call"] = calls[1:]

