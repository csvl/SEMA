import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import logging
import os
import archinfo
import configparser
import contextlib
import sys

from clogging.CustomFormatter import CustomFormatter

try:
    logger = logging.getLogger("SyscallToSCDG")
    log_level = os.environ["LOG_LEVEL"]
    ch = logging.StreamHandler()
    ch.setLevel(log_level)
    ch.setFormatter(CustomFormatter())
    logger.addHandler(ch)
    logger.propagate = False
    logger.setLevel(log_level)
except Exception as e:
    print(f"Error in SyscallToSCDG: {str(e)}")

class SyscallToSCDG:
    """
    Class to map syscalls to their corresponding SCDG nodes and handle syscall behavior.
    """
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

    def __init__(self, scdg):
        """
        Initialize the SyscallToSCDG object with the given SCDG.

        Args:
            scdg: The SCDG object to initialize the SyscallToSCDG with.
        """
        config = configparser.ConfigParser()
        config.read(sys.argv[1])
        self.config = config
        self.scdg = scdg
        self.string_resolv = config['SCDG_arg'].getboolean('string_resolve')
        self.print_syscall = config['SCDG_arg'].getboolean('print_syscall')
        self.__config_logger()

    def __config_logger(self):
        """
        Configure the logger for the SyscallToSCDG object.
        """
        self.log_level = log_level
        self.log = logger

    def set_call_sim(self, call_sim):
        """
        Set the call simulation for the SyscallToSCDG object.

        Args:
            call_sim: The call simulation object to set.
        """
        self.call_sim = call_sim

    def __decode_string(self, string):
        """
        Decode the given string if possible.

        Args:
            string: The string to decode.

        Returns:
            str: The decoded string.
        """
        return string.decode("utf-8") if hasattr(string, "decode") else string

    def add_call(self, state):
        """
        Add a syscall call to the SCDG based on the state.

        Args:
            state: The state containing information about the syscall.
        """
        name = state.inspect.simprocedure_name

        if name in self.AVOID:
            return

        sim_proc = state.inspect.simprocedure

        callee = None
        callee_arg = None
        if (sim_proc
            and sim_proc.is_syscall
            and str(sim_proc.syscall_number) in self.call_sim.system_call_table
            and self.print_syscall
        ):
            self.log.info("syscall detected")
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

        id = state.globals["id"]
        args = sim_proc.arguments if sim_proc else []

        if name:
            key_name = str(name)
            if key_name not in self.call_sim.syscall_found:
                self.call_sim.syscall_found[key_name] = 1
            else:
                self.call_sim.syscall_found[key_name] = self.call_sim.syscall_found[key_name] + 1
            self.log.info(f"Syscall found:  {str(name)}{str(args)}")

        if args:
            name_to_check =  self.scdg[id][-1]["name"]
            possibilities = { "writev": "write", "readv":"read", "socketcall": "" }
            if name_to_check == name:
                for i in range(len(args)):
                    args[i] = self.__proper_formating(state, args[i])
                    temp = args[i]
                    try:
                        args[i] = self.if_wstring_call(state, callee_arg, args, i)
                    except Exception:
                        args[i] = temp
                    try:
                        args[i] = self.if_string_concrete_call(state, callee_arg, args, i)
                    except Exception:
                        args[i] = temp
                    try:
                        args[i] = self.if_char_call(state, callee_arg, args, i)
                    except Exception:
                        args[i] = temp
                    try:
                        if (self.string_resolv and callee_arg and args[i] != 0 and ("PCUNICODESTRING" in callee_arg[i]["type"])):
                            addr = self.state.memory.load(args[i]+4,4,endness=archinfo.Endness.LE)
                            args[i] = self.state.mem[addr].wstring.concrete
                    except Exception:
                        args[i] = temp

                if self.string_resolv and args:
                    string_func = [self.FUNCTION_STRING, self.FUNCTION_WSTRING, self.FUNCTION_CHAR]
                    for i in range(len(string_func)):
                        func = string_func[i]
                        if name in func:
                            index_str = func[name]
                            try:
                                # FUNCTION_STRING
                                if i == 0:
                                    string = state.mem[args[index_str]].string.concrete
                                    args[index_str] = self.__decode_string(string)
                                # FUNCTION_WSTRING
                                elif i == 1:
                                    string = state.mem[args[index_str]].wstring.concrete
                                    args[index_str] = string
                                # FUNCTION_CHAR
                                elif i == 2:
                                    string = chr(args[index_str])
                                    args[index_str] = string
                            except Exception :
                                print("Error in string resolv")

                self.scdg[id][-1]["args"] = args

                if self.scdg[id][-1]["ret"] != "symbolic" and name not in self.FUNCTION_RETURNS:
                    ret = -22
                    try:
                        ret = state.solver.eval_one(state.inspect.simprocedure_result)
                    except Exception:
                        ret = self.switch_to_claripy(state)
                    self.scdg[id][-1]["ret"] = ret

                if (name == "write"
                    and len(self.scdg[id]) > 1
                    and self.scdg[id][-2]["name"] == "write"
                    and self.scdg[id][-1]["addr"] == self.scdg[id][-1]["addr"]
                    and sim_proc.use_state_arguments
                ):
                    self.scdg[id][-2]["args"][1] = str(self.scdg[id][-2]["args"][1]) + str(self.scdg[id][-1]["args"][1])
                    self.scdg[id].pop()

                return

            elif name_to_check in possibilities:
                if name_to_check != "socketcall":
                    self.scdg[id][-1]["name"] = possibilities[name_to_check]
                elif name in self.SOCKETCALL_dic:
                    self.scdg[id][-1]["name"] = name
                for i in range(len(args)):
                    args[i] = self.__proper_formating(state, args[i])
                self.scdg[id][-1]["args"] = args

                try:
                    ret = state.solver.eval_one(state.inspect.simprocedure_result)
                except Exception:
                    ret = self.switch_to_claripy(state)
                self.scdg[id][-1]["ret"] = ret

    def switch_to_claripy(self, state):
        """
        Switches the result to a claripy object if possible.

        Args:
            state: The state object containing information about the execution state.

        Returns:
            str: The name of the claripy object if available, else a string representation of the object.
        """
        stub = state.inspect.simprocedure_result
        if hasattr(stub, "to_claripy"):
            stub = stub.to_claripy()
        return stub.name if hasattr(stub, "name") else str(stub)

    def if_char_call(self, state, callee_arg, args, i):
        """
        Check and decode character arguments if string resolution is enabled.

        Args:
            state: The state object containing information about the execution state.
            callee_arg: The callee arguments dictionary.
            args: The arguments to check and decode.
            i: The index of the argument to process.

        Returns:
            str: The decoded string argument if applicable.
        """
        if (self.string_resolv and callee_arg and args[i] != 0 and
            ("LPCTSTR" in callee_arg[i]["type"]
            or "LPTSTR" in callee_arg[i]["type"]
            or "PTSTR" in callee_arg[i]["type"]
            or "PCTSTR" in callee_arg[i]["type"]
            or "LPCCH" in callee_arg[i]["type"]
        )):
            string = ''
            if state.solver.eval(state.memory.load(args[i]+1,1)) == 0x0:
                string = state.mem[args[i]].wstring.concrete
            else:
                string = state.mem[args[i]].string.concrete

            args[i] = self.__decode_string(string)
        return args[i]

    def if_string_concrete_call(self, state, callee_arg, args, i):
        """
        Check and decode string arguments if string resolution is enabled.

        Args:
            state: The state object containing information about the execution state.
            callee_arg: The callee arguments dictionary.
            args: The arguments to check and decode.
            i: The index of the argument to process.

        Returns:
            str: The decoded string argument if applicable.
        """
        if (self.string_resolv and callee_arg and args[i] != 0
            and ("LPCSTR" in callee_arg[i]["type"]
            or "LPSTR" in callee_arg[i]["type"]
            or "const char*" in callee_arg[i]["type"]
            or "PSTR" in callee_arg[i]["type"]
            or "PCSTR" in callee_arg[i]["type"]
            or "LPCH" in callee_arg[i]["type"]
        )):
            string = state.mem[args[i]].string.concrete
            args[i] = self.__decode_string(string)
        return args[i]

    def if_wstring_call(self, state, callee_arg, args, i):
        """
        Check and decode wide string arguments if string resolution is enabled.

        Args:
            state: The state object containing information about the execution state.
            callee_arg: The callee arguments dictionary.
            args: The arguments to check and decode.
            i: The index of the argument to process.

        Returns:
            str: The decoded wide string argument if applicable.
        """
        if (self.string_resolv and callee_arg and args[i] != 0 and
            ("LPCWSTR" in callee_arg[i]["type"]
            or "LPWSTR" in callee_arg[i]["type"]
            or "wchar_t*const" in callee_arg[i]["type"]
            or "OLECHAR" in callee_arg[i]["type"]
            or "PWSTR" in callee_arg[i]["type"]
            or "PCWSTR" in callee_arg[i]["type"]
            or "LPCWCH" in callee_arg[i]["type"]
        )):
            string = state.mem[args[i]].wstring.concrete

            args[i] = self.__decode_string(string)
        return args[i]

    def add_call_debug(self, state):
        """
        Add a syscall call to the SCDG for debugging purposes.

        Args:
            state: The state object containing information about the execution state.
        """
        name = state.inspect.simprocedure_name
        sim_proc = state.inspect.simprocedure
        n_args = 0

        if name in self.AVOID:
            return

        if sim_proc:
            n_args = sim_proc.num_args

        self.add_SysCall(name, n_args, state)


    def add_SysCall(self, syscall, n_args, state):
        """
        Add a syscall call to the SCDG based on the state information.

        Args:
            syscall: The name of the syscall.
            n_args: The number of arguments for the syscall.
            state: The state object containing information about the execution state.
        """
        dic = {}

        name = syscall
        sim_proc = state.inspect.simprocedure
        name = state.inspect.simprocedure_name
        state.project
        args = sim_proc.arguments or []

        regs = sim_proc.cc.ARG_REGS

        if name in ["rt_sigaction", "sigaction"]:
            state.inspect.simprocedure_result = state.solver.BVV(0, state.arch.bits)

        # Get proto of the function
        for key in self.call_sim.system_call_table.keys():
            if name in self.call_sim.system_call_table[key]:
                self.call_sim.system_call_table[key][name]

        if n_args > 0 and n_args < len(regs):
            regs = regs[:n_args]
            for reg in regs:
                try:
                    reg = getattr(state.regs, reg)
                except Exception:
                    reg = None
                reg = self.__proper_formating(state, reg)
                args.append(reg)

        dic["name"] = name

        # Transform if option enabled
        if self.string_resolv and args:
            args, dic = self.__check_syscall_string(syscall, state, args, dic)

        if syscall in self.FUNCTION_HANDLER:
            self.FUNCTION_HANDLER[syscall](state)

        if args:
            for i in range(len(args)):
                args[i] = self.__proper_formating(state, args[i])

        dic["args"] = args
        dic["addr_func"] = hex(state.addr)
        if len(state.globals["addr_call"]) > 0:
            dic["addr"] = hex(state.globals["addr_call"][-1])
        else:
            dic["addr"] = hex(state.addr)

        if syscall in self.FUNCTION_RETURNS:
            ret = self.FUNCTION_RETURNS[syscall](state)
            self.log.info(f"return value of {str(name)} :{str(ret)}")
            dic["ret"] = hex(ret)
        else:
            dic["ret"] = hex(0)

        id = state.globals["id"]

        if len(self.scdg) == 0:
            self.scdg.append([dic])
        else:
            if len(self.scdg[id][-1]) != 0:
                # if same address and different name, we have an inline call (call to another simprocedure used during the hook), discard !
                if (self.scdg[id][-1]["addr"] == dic["addr"] and self.scdg[id][-1]["name"] != dic["name"]):
                    return

                self.scdg[id].append(dic)

            return

    def __check_syscall_string(self, syscall, state, args, dic):
        """
        Check and decode string arguments based on the syscall type.

        Args:
            syscall: The name of the syscall.
            state: The state object containing information about the execution state.
            args: The arguments to check and decode.
            dic: The dictionary to update with reference strings.

        Returns:
            tuple: The updated arguments and dictionary.
        """
        possibilities = {"string": self.FUNCTION_STRING, "wstring": self.FUNCTION_WSTRING, "char": self.FUNCTION_CHAR}
        for string_function, value in possibilities.items():
            if syscall in string_function:
                if isinstance(value[syscall], int):
                    arg_len = 1
                else:
                    arg_len = len(possibilities[string_function][syscall])
                for i in range(arg_len):
                    index_str = (
                        possibilities[string_function][syscall][i]
                        if arg_len > 1
                        else possibilities[string_function][syscall]
                    )
                    if arg_str := args[index_str]:
                        with contextlib.suppress(Exception):
                            if string_function == "char":
                                string = chr(arg_str)
                                args[index_str] = string
                            elif string_function == "string":
                                string = state.mem[arg_str].string.concrete
                                args[index_str] = self.__decode_string(string)
                            elif string_function == "wstring":
                                string = state.mem[arg_str].wstring.concrete
                                args[index_str] = self.__decode_string(string)
                            if i > 0:
                                dic["ref_str"][(index_str + 1)] = arg_str
                            else:
                                dic["ref_str"] = {(index_str + 1): arg_str}
        return args, dic

    def add_addr_call(self, state):
        """
        Add the current instruction address to the list of addresses in the global state.

        Args:
            state: The state object containing information about the execution state.
        """
        test = state.globals["addr_call"] + [state.scratch.ins_addr]
        state.globals["addr_call"] = test

    def rm_addr_call(self, state):
        """
        Remove the first address from the list of addresses in the global state if there is more than one address.

        Args:
            state: The state object containing information about the execution state.
        """
        calls = state.globals["addr_call"]
        if len(calls) > 1:
            state.globals["addr_call"] = calls[1:]

    def __proper_formating(self, state, value):
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

            return list(value.variables)[0]
        elif hasattr(value, "symbolic") and value.symbolic:
            return "_".join(list(value.variables))
        else:
            try:
                return state.solver.eval_one(value)
            except Exception:
                return value
