import logging
from clogging.CustomFormatter import CustomFormatter

logger = logging.getLogger("SyscallToSCDGBuilder")
ch = logging.StreamHandler()
ch.setLevel(logging.INFO)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)
logger.propagate = False
logger.setLevel(logging.INFO)

class SyscallToSCDGBuilder:
    FUNCTION_CHAR = {
        "fputc": 0,
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
        "SetDefaultDllDirectories": 0,
        "CreateProcessA": [0, 1],
        "URLDownloadToFileA": [1,2],
        #"fputc": 0,
        #"send":
    }   # ,'RegCreateKeyW':1}

    FUNCTION_WSTRING = {
        'RegCreateKeyW':1,
        "CreateFileW": 0,
        "LoadStringW": 2,
        "GetLongPathNameW": [0, 1],
        "WideCharToMultiByte": 2,
        #"MultiByteToWideChar": 3,
        "RegOpenKeyExW": [0, 1],
        "RegQueryValueExW": [0, 1],
        "FindResourceW": 1
    }  # ,'RegCreateKeyW':1}

    FUNCTION_HANDLER = {}


    ## -------------- Manage returned value of specific function ----------------##
    # Max number of file descriptor, defined first in PLUGINS.POSIX
    MAX_FD = 8192
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

    # Simprocedure that are not real syscall
    # ,'__libc_start_main':'__libc_start_main','__getmainargs':'__getmainargs'
    AVOID = {
       # "_initterm": "_initterm",
        "__lconv_init": "__lconv_init",
        #"__set_app_type": "__set_app_type",
        "PathTerminator": "PathTerminator",
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

    def __init__(self, call_sim, scdg, string_resolv=True, print_syscall=True, verbose=False):
        self.log = logger
        self.call_sim = call_sim
        self.scdg = scdg
        self.string_resolv = string_resolv
        self.print_syscall = print_syscall
        self.verbose = verbose

    
    # (2) TODO manon: check correctness of the function with old project version
    # This function create the SCDG based on encounter syscall during execution -> very important for the project
    # Similar to add_SysCall but with more information (CH)
    def add_call(self, state):
        """_summary_
        TODO CH for manon
        Args:
            state (_type_): _description_
        """
        name = state.inspect.simprocedure_name

        if name in self.AVOID:
            return

        sim_proc = state.inspect.simprocedure

        callee = None
        callee_arg = None
        if (
            sim_proc
            and sim_proc.is_syscall
            and str(sim_proc.syscall_number) in self.call_sim.system_call_table
            and self.print_syscall
        ):
            self.log.info("syscall detected")
            # self.log.info(sim_proc.syscall_number)
            self.log.info(state.inspect.simprocedure_result)
            self.log.info(self.call_sim.system_call_table[str(sim_proc.syscall_number)])
            self.call_sim.system_call_table[str(sim_proc.syscall_number)]["num_args"]

        # Get definition of windows syscall (e.g.:for extraction of possible strings)
        # TODO : Optimize this heavy loop
        for key in self.call_sim.system_call_table.keys():
            if name in self.call_sim.system_call_table[key]:
                callee = self.call_sim.system_call_table[key][name]
                callee_arg = callee["arguments"]
                break
        if not callee and state.globals["loaded_libs"]:
            for k, lib in state.globals["loaded_libs"].items():
                if lib not in self.call_sim.system_call_table.keys():
                    self.call_sim.ddl_loader.load_more(lib, self.call_sim.system_call_table)
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
            if not (key_name in self.call_sim.syscall_found):
                self.call_sim.syscall_found[key_name] = 1
            else:
                self.call_sim.syscall_found[key_name] = self.call_sim.syscall_found[key_name] + 1
                

        if name and self.verbose:
            self.log.info("Syscall found:  " + str(name) + str(args))

        if self.scdg[id][-1]["name"] == name and args:
            # for i in range(len(args)):
            #     args[i] = self.proper_formating(state, args[i])
            #     temp = args[i]
            #     try:
            #         if (
            #             self.string_resolv
            #             and callee_arg
            #             and args[i] != 0
            #             and (
            #                 "LPCWSTR" in callee_arg[i]["type"]
            #                 or "LPWSTR" in callee_arg[i]["type"]
            #                 or "wchar_t*const" in callee_arg[i]["type"]
            #                 or "OLECHAR" in callee_arg[i]["type"]
            #             )
            #         ):

            #             temp = args[i]
            #             string = state.mem[args[i]].wstring.concrete

            #             if hasattr(string, "decode"):
            #                 args[i] = string.decode("utf-8")
            #             else:
            #                 args[i] = string

            #             if self.debug_string: # Rename
            #                 # import pdb

            #                 # pdb.set_trace()
            #                 self.log.info("Args string Resolved : " + str(string))
            #     except:
            #         args[i] = temp
            #     try:
            #         if (
            #             self.string_resolv
            #             and callee_arg
            #             and args[i] != 0
            #             and (
            #                 "LPCSTR" in callee_arg[i]["type"]
            #                 or "LPSTR" in callee_arg[i]["type"]
            #                 or "const char*" in callee_arg[i]["type"]
            #                 or "LPCVOID" in callee_arg[i]["type"]
            #             )
            #         ):
            #             string = state.mem[args[i]].string.concrete
            #             if hasattr(string, "decode"):
            #                 args[i] = string.decode("utf-8")
            #             else:
            #                 args[i] = string
            #     except:
            #         args[i] = temp
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
                            or "PWSTR" in callee_arg[i]["type"]
                            or "PCWSTR" in callee_arg[i]["type"]
                            or "LPCWCH" in callee_arg[i]["type"]
                        )
                    ):
                        string = state.mem[args[i]].wstring.concrete



                        if hasattr(string, "decode"):
                            args[i] = string.decode("utf-8")
                        else:
                            args[i] = string
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
                            #or "LPCVOID" in callee_arg[i]["type"]
                            or "PSTR" in callee_arg[i]["type"]
                            or "PCSTR" in callee_arg[i]["type"]
                            or "LPCH" in callee_arg[i]["type"]
                        )
                    ):
                        string = state.mem[args[i]].string.concrete
                        
                        if hasattr(string, "decode"):
                            args[i] = string.decode("utf-8")
                        else:
                            args[i] = string
                except:
                    args[i] = temp
                try:
                    if (
                        self.string_resolv
                        and callee_arg
                        and args[i] != 0
                        and (
                            "LPCTSTR" in callee_arg[i]["type"]
                            or "LPTSTR" in callee_arg[i]["type"]
                            or "PTSTR" in callee_arg[i]["type"]
                            or "PCTSTR" in callee_arg[i]["type"]
                            or "LPCCH" in callee_arg[i]["type"]
                        )
                    ):
                        string = ''
                        if state.solver.eval(state.memory.load(args[i]+1,1)) == 0x0:
                            string = state.mem[args[i]].wstring.concrete
                        else:
                            string = state.mem[args[i]].string.concrete
                            
                        if hasattr(string, "decode"):
                            args[i] = string.decode("utf-8")
                        else:
                            args[i] = string
                except:
                    args[i] = temp
                try:
                    if (
                        self.string_resolv
                        and callee_arg
                        and args[i] != 0
                        and (
                            "PCUNICODESTRING" in callee_arg[i]["type"]
                        )
                    ):
                        addr = state.memory.load(args[i]+4,4,endness=archinfo.Endness.LE)
                        args[i] = state.mem[addr].wstring.concrete
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
                    #dic["ref_str"] = {(index_str + 1): arg_str}  # TODO
                except Exception:
                    print("Error in string resolv")
                    
            if self.string_resolv and name in self.FUNCTION_WSTRING and args:
                index_str = self.FUNCTION_WSTRING[name]
                try:
                    string = state.mem[args[index_str]].wstring.concrete
                    args[index_str] = string
                    #dic["ref_str"] = {(index_str + 1): arg_str}  # TODO
                except Exception:
                    print("Error in string resolv")
            
            if self.string_resolv and name in self.FUNCTION_CHAR and args:
                index_str = self.FUNCTION_CHAR[name]
                try:
                    string = chr(args[index_str])
                    args[index_str] = string
                    #dic["ref_str"] = {(index_str + 1): arg_str}  # TODO
                except Exception:
                    print("Error in string resolv")

            self.scdg[id][-1]["args"] = args

            if self.scdg[id][-1]["ret"] != "symbolic" and name not in self.FUNCTION_RETURNS:
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

            return
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


    # (3) TODO manon: configurable eventually
    # state.inspect.b("simprocedure", when=angr.BP_BEFORE, action=self.call_sim.add_call_debug) in SemaSCDG.py
    def add_call_debug(self, state):
        name = state.inspect.simprocedure_name
        sim_proc = state.inspect.simprocedure
        n_args = 0

        if name in self.AVOID:
            return

        if sim_proc:
            n_args = sim_proc.num_args

        self.add_SysCall(name, n_args, state)

    # (2) TODO manon: check correctness of the function with old project version + refactor 
    # This function create the SCDG based on encounter syscall during execution -> very important for the project
    def add_SysCall(self, syscall, n_args, state):
        """_summary_
        TODO CH for manon
        Args:
            syscall (_type_): _description_
            n_args (_type_): _description_
            state (_type_): _description_

        Returns:
            _type_: _description_
        """
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

        # Get proto of the function
        for key in self.call_sim.system_call_table.keys():
            if name in self.call_sim.system_call_table[key]:
                self.call_sim.system_call_table[key][name]

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
                        pass
        
        if self.string_resolv and syscall in self.FUNCTION_WSTRING and args:
            if isinstance(self.FUNCTION_WSTRING[syscall], int):
                arg_len = 1
            else:
                arg_len = len(self.FUNCTION_WSTRING[syscall])
            for i in range(arg_len):
                if arg_len > 1:
                    index_str = self.FUNCTION_WSTRING[syscall][i]
                else:
                    index_str = self.FUNCTION_WSTRING[syscall]
                arg_str = args[index_str]
                # import pdb; pdb.set_trace()
                if arg_str:
                    try:
                        string = state.mem[arg_str].wstring.concrete
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
                        pass
        
        if self.string_resolv and syscall in self.FUNCTION_CHAR and args:
            if isinstance(self.FUNCTION_CHAR[syscall], int):
                arg_len = 1
            else:
                arg_len = len(self.FUNCTION_CHAR[syscall])
            for i in range(arg_len):
                if arg_len > 1:
                    index_str = self.FUNCTION_CHAR[syscall][i]
                else:
                    index_str = self.FUNCTION_CHAR[syscall]
                arg_str = args[index_str]
                # import pdb; pdb.set_trace()
                if arg_str:
                    try:
                        string = chr(arg_str)
                        args[index_str] = string
                        if i > 0:
                            dic["ref_str"][(index_str + 1)] = arg_str
                        else:
                            dic["ref_str"] = {(index_str + 1): arg_str}
                        # self.log.info(string)
                    except Exception:
                        pass
            

        if syscall in self.FUNCTION_HANDLER:
            self.FUNCTION_HANDLER[syscall](state)

        if args:
            for i in range(len(args)):
                args[i] = self.proper_formating(state, args[i])

        dic["args"] = args
        dic["addr_func"] = hex(state.addr)
        if len(state.globals["addr_call"]) > 0:
            dic["addr"] = hex(state.globals["addr_call"][-1])
        else:
            dic["addr"] = hex(state.addr)
        # import pdb; pdb.set_trace()

        if syscall in self.FUNCTION_RETURNS:
            ret = self.FUNCTION_RETURNS[syscall](state)
            if self.verbose:
                self.log.info("return value of " + str(name) + " :" + str(ret))
            dic["ret"] = hex(ret)
        else:
            dic["ret"] = hex(0)

        id = state.globals["id"]

        if len(self.scdg) == 0:
            self.scdg.append([dic])
        else:
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

    def add_addr_call(self, state):
        test = state.globals["addr_call"] + [state.scratch.ins_addr]
        state.globals["addr_call"] = test

    def rm_addr_call(self, state):
        calls = state.globals["addr_call"]
        if len(calls) > 1:
            state.globals["addr_call"] = calls[1:]

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
                return val # TODO hex(val) ?
            except:
                return value