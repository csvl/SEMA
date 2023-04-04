#!/usr/bin/env python3
import os
import sys

# for pypy3
# sys.path.insert(0, '/usr/local/lib')
# sys.path.insert(0, os.path.expanduser('~/lib'))
# sys.path.insert(0, os.path.expanduser('/home/crochetch/Documents/toolchain_malware_analysis/penv/lib'))

import json as json_dumper
from builtins import open as open_file
import threading
import time
#from tkinter import E

# from submodules.claripy import claripy
import claripy
import cle
import monkeyhex  # this will format numerical results in hexadecimal
import logging
from capstone import *

# Syscall table stuff
import angr

# Personnal stuf
try:
    from .helper.GraphBuilder import *
    from .procedures.CustomSimProcedure import *
    from .plugin.PluginEnvVar import *
    from .plugin.PluginAtom import *
    from .explorer.ToolChainExplorerDFS import ToolChainExplorerDFS
    from .explorer.ToolChainExplorerCDFS import ToolChainExplorerCDFS
    from .explorer.ToolChainExplorerBFS import ToolChainExplorerBFS
    from .explorer.ToolChainExplorerCBFS import ToolChainExplorerCBFS
    from .clogging.CustomFormatter import CustomFormatter
    from .helper.ArgumentParserSCDG import ArgumentParserSCDG
    from .sandboxes.CuckooInterface import CuckooInterface
except:
    from helper.GraphBuilder import *
    from procedures.CustomSimProcedure import *
    from plugin.PluginEnvVar import *
    from plugin.PluginAtom import *
    from explorer.ToolChainExplorerDFS import ToolChainExplorerDFS
    from explorer.ToolChainExplorerCDFS import ToolChainExplorerCDFS
    from explorer.ToolChainExplorerBFS import ToolChainExplorerBFS
    from explorer.ToolChainExplorerCBFS import ToolChainExplorerCBFS
    from clogging.CustomFormatter import CustomFormatter
    from helper.ArgumentParserSCDG import ArgumentParserSCDG
    from sandboxes.CuckooInterface import CuckooInterface

import subprocess
import nose
import avatar2 as avatar2

import angr
import claripy

from unipacker.core import Sample, SimpleClient, UnpackerEngine
from unipacker.utils import RepeatedTimer, InvalidPEFile
from unipacker.unpackers import get_unpacker
from angr_targets import AvatarGDBConcreteTarget

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


class ToolChainSCDG:
    """
    TODO
    """

    BINARY_OEP = None
    UNPACK_ADDRESS = None  # unpacking address
    VENV_DETECTED = None   # address for virtual environment obfuscation detection
    BINARY_EXECUTION_END = None

    def __init__(
        self,
        timeout=600,
        max_end_state=600,
        max_step=50000,
        timeout_tab=[1200, 2400, 3600],
        jump_it=1,
        loop_counter_concrete=102400,
        jump_dict={},
        jump_concrete_dict={},
        max_simul_state=5,
        max_in_pause_stach=500,
        fast_main=False,
        force_symbolique_return=False,
        string_resolv=True,
        print_on=False,
        print_sm_step=False,
        print_syscall=False,
        debug_error=False,
        debug_string=False,
        is_packed=False,
        concrete_target_is_local = False,
        is_from_tc = False
    ):
        self.start_time = time.time()
        self.timeout = timeout  # In seconds
        self.max_end_state = max_end_state
        self.max_step = max_step
        self.timeout_tab = timeout_tab

        # Option relative to loop
        self.jump_it = jump_it
        self.loop_counter_concrete = loop_counter_concrete
        self.jump_dict = jump_dict
        self.jump_concrete_dict = jump_concrete_dict

        # Options relative to stash management
        self.max_simul_state = max_simul_state
        self.max_in_pause_stach = max_in_pause_stach

        self.fast_main = fast_main
        self.force_symbolique_return = force_symbolique_return

        self.print_on = print_on
        self.print_sm_step = print_sm_step
        self.print_syscall = print_syscall
        self.debug_error = debug_error
        self.debug_string = debug_string

        self.scdg = []
        self.scdg_fin = []

        # logging.getLogger("avatar").setLevel("DEBUG") #sim_manager
        # logging.getLogger("lifter").setLevel("DEBUG") #sim_manager
        # logging.getLogger("avatar2").setLevel("DEBUG") #sim_manager
        # logging.getLogger('angr').setLevel('DEBUG')
        #logging.getLogger('angr.engines.vex.heavy.heavy').setLevel('DEBUG')
        # logging.getLogger('angr_targets').setLevel('DEBUG')
        # logging.getLogger('pygdbmi').setLevel('DEBUG')
        # logging.getLogger('pygdbmi.IoManager').setLevel('DEBUG')
        # logging.getLogger('state_plugin.concrete').setLevel('DEBUG')
        # logging.getLogger('cle').setLevel('DEBUG')

        # create console handler with a higher log level
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(CustomFormatter())
        self.log = logging.getLogger("ToolChainSCDG")
        self.log.setLevel(logging.DEBUG)
        if not self.log.handlers:
            self.log.addHandler(ch)
            self.log.propagate = False
        else:
            self.log.removeHandler(self.log.handlers[0])
            self.log.addHandler(ch)
            self.log.propagate = False
            

        self.call_sim = CustomSimProcedure(
            self.scdg, self.scdg_fin, 
            string_resolv=string_resolv, print_on=print_on, 
            print_syscall=print_syscall, is_from_tc=is_from_tc
        )
        self.eval_time = False

        self.unpack_mode = None
        self.is_packed = is_packed
        self.concrete_target_is_local = concrete_target_is_local

    def build_scdg(self, args, nameFile, expl_method, family):
        # Create directory to store SCDG if it doesn't exist
        self.scdg.clear()
        self.scdg_fin.clear()
        self.call_sim.syscall_found.clear()
        self.call_sim.system_call_table.clear()
        try:
            os.stat(args.exp_dir)
        except:
            os.makedirs(args.exp_dir)

        if args.exp_dir != "output/save-SCDG/"+family+"/":
            setup = open_file(args.exp_dir + "setup.txt", "w")
            setup.write(str(self.jump_it) + "\n")
            setup.write(str(self.loop_counter_concrete) + "\n")
            setup.write(str(self.max_simul_state) + "\n")
            setup.write(str(self.max_in_pause_stach) + "\n")
            setup.write(str(self.max_step) + "\n")
            setup.write(str(self.max_end_state))
            setup.close()

        # Take name of the sample without full path
        if "/" in nameFile:
            nameFileShort = nameFile.split("/")[-1]
        else:
            nameFileShort = nameFile

        title = "--- Building SCDG of " + nameFileShort + " ---"
        self.log.info("\n" + "-" * len(title) + "\n" + title + "\n" + "-" * len(title))

        #####################################################
        ##########      Project creation         ############
        #####################################################
        """
        TODO : Note for further works : support_selfmodifying_code should be investigated
        """

        # Load a binary into a project = control base
        proj = None
        cuckoo = None
        if self.is_packed and self.unpack_mode == "symbion":
            # nameFile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
            #                               os.path.join('..', 'binaries',
            #                               'tests','x86_64',
            #                               'packed_elf64'))
                        
            #nameFile = "/home/crochetch/Documents/toolchain_malware_analysis/src/submodules/binaries/tests/x86_64/packed_elf64"
            #st = os.stat(nameFile)
            #os.chmod(nameFile, st.st_mode | stat.S_IEXEC)


            print(nameFile)
            analysis = nameFile

            proj = angr.Project(
                nameFile,
                use_sim_procedures=True,
                load_options={
                    "auto_load_libs": True
                },  # ,load_options={"auto_load_libs":False}
                support_selfmodifying_code=True,
                # arch="",
            )

            # Getting from a binary file to its representation in a virtual address space
            main_obj = proj.loader.main_object
            os_obj = main_obj.os

            self.log.info("OS recognized as : " + str(os_obj))
            self.log.info("CPU architecture recognized as : " + str(proj.arch))

            # First set everything up

            GDB_SERVER_IP = '127.0.0.1'
            GDB_SERVER_PORT = 9876

            if not self.concrete_target_is_local:
                filename = "cuckoo_ubuntu18.04"
                gos = "linux"
                if "win" in os_obj:
                    if False:
                        filename = "win7_x64_cuckoo"
                    else:
                        filename = "win10"
                    gos = "windows"

                cuckoo = CuckooInterface(name=filename, ossys="linux", guestos=gos, create_vm=False)
                GDB_SERVER_IP = cuckoo.start_sandbox(GDB_SERVER_PORT)
                cuckoo.load_analysis(analysis)
                remote_binary=cuckoo.start_analysis(analysis)       
                print(GDB_SERVER_IP)     
            else:
                # TODO use the one in sandbox
                print("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,nameFile))
                subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,nameFile),
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE,
                                        shell=True)
            avatar_gdb = None
            local_ddl_path = self.call_sim.ddl_loader.calls_dir.replace("calls","windows7_ddls")
            try:
                self.log.info("AvatarGDBConcreteTarget("+ GDB_SERVER_IP+","+ str(GDB_SERVER_PORT) +")")
                avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86,
                                                    GDB_SERVER_IP, GDB_SERVER_PORT,remote_binary,local_ddl_path)  # TODO modify to send file and update gdbserver conf
            except Exception as e:
                time.sleep(5)
                self.log.info("AvatarGDBConcreteTarget failure")
                try:
                    avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, # TODO 
                                                    GDB_SERVER_IP, GDB_SERVER_PORT,remote_binary,local_ddl_path) 
                except Exception as ee:
                    exit(-1)
            print(nameFile)   
            print(avatar_gdb) 
            
            self.call_sim.system_call_table = self.call_sim.ddl_loader.load(proj,True if (self.is_packed and False) else False)
            
            preload = []
            for lib in self.call_sim.system_call_table:
                #for key in self.call_sim.system_call_table[lib]: 
                print(lib)
                    #preload.append(lib)
            print(proj.loader.shared_objects)
            
            proj = angr.Project(
                nameFile,
                use_sim_procedures=True,
                load_options={
                    "auto_load_libs": True,
                    "load_debug_info": True,
                    "preload_libs": preload
                },  # ,load_options={"auto_load_libs":False}
                support_selfmodifying_code=True,
                concrete_target=avatar_gdb
            )
            #self.call_sim.system_call_table.clear()
            #print(proj.concrete_target.avatar.get_info_sharelib_targets(local_ddl_path))
            
            for lib in proj.concrete_target.avatar.get_info_sharelib_targets(local_ddl_path)[0]:
                print(lib["id"]) # TODO lowercase folder
                if lib["target-name"] == lib["host-name"] :
                    print("Changed")
                #if "kernel" not in lib["target-name"].lower():
                #preload.append(lib["id"].replace("C:\\",self.call_sim.ddl_loader.calls_dir.replace("calls","windows7_ddls/C:/")).replace("\\","/").replace("system","System")) # 
            #exit()
            proj = angr.Project(
                nameFile,
                use_sim_procedures=True,
                load_options={
                    "auto_load_libs": False,
                    "load_debug_info": True,
                    "preload_libs": preload
                },  # ,load_options={"auto_load_libs":False}
                support_selfmodifying_code=True,
                concrete_target=avatar_gdb
            )
            for lib in self.call_sim.system_call_table:
                print(proj.loader.find_all_symbols(lib))
            print("biatch")
            #for obj in proj.loader.all_objects:
            #    print(obj)
            #exit()
        elif self.is_packed and self.unpack_mode == "unipacker":
            try:
                unpacker_heartbeat = RepeatedTimer(120, print, "- still running -", file=sys.stderr)
                event = threading.Event()
                client = SimpleClient(event)
                sample = Sample(nameFile)
                unpacked_file_path = nameFile.replace(nameFileShort,"unpacked_"+nameFileShort)
                engine = UnpackerEngine(sample, unpacked_file_path)
                self.log.info("Unpacking process with unipacker")
                engine.register_client(client)
                unpacker_heartbeat.start()
                threading.Thread(target=engine.emu).start()
                event.wait()
                unpacker_heartbeat.stop()
                engine.stop()
                nameFile = unpacked_file_path
                proj = angr.Project(
                    nameFile,
                    use_sim_procedures=True,
                    load_options={
                        "auto_load_libs": True
                    },  # ,load_options={"auto_load_libs":False}
                    support_selfmodifying_code=True,
                    # arch="",
                )
            except InvalidPEFile as e:
                self.unpack_mode = "symbion"
                self.build_scdg(args, nameFile, expl_method)
                return
        else:
            # if nameFile.endswith(".bin") or nameFile.endswith(".dmp"):
            #     main_opt = {'backend': 'blob', "arch":"x86","simos":"windows"}#cle.Blob(nameFile,arch=avatar2.archs.x86.X86,binary_stream=True)
            #     #nameFile = loader
            #     main_opt = {} #0x0005f227 0x400000 0x001191f7
            #     proj = angr.Project(
            #         nameFile,
            #         use_sim_procedures=True,
            #         load_options={
            #             "auto_load_libs": True
            #         },  # ,load_options={"auto_load_libs":False}
            #         support_selfmodifying_code=True if not nameFile.endswith(".dmp") else False,
            #         main_opts=main_opt,
            #         #simos = "windows"if nameFile.endswith(".bin") or nameFile.endswith(".dmp") else None
            #         # arch="",
            #     )
            #     main_obj = proj.loader.main_object
            #     first_sec = False
            #     libs = []
            #     dll = []
            #     for sec in main_obj.sections:
            #         name = sec.name.replace("\x00", "")
            #         if not first_sec:
            #             first_sec = True
            #         else:
            #             if "KERNELBASE.dll" in name:
            #                 name = name.replace("KERNELBASE.dll","KernelBase.dll")
            #             dll.append(name.split("\\")[-1])
            #             print(dll)
            #             libs.append(name.replace("C:\\",self.call_sim.ddl_loader.calls_dir.replace("calls","windows10_ddls/C:/")).replace("\\","/")) # .replace("system","System") 
            #             self.log.info(name)
            #             #self.log.info(dump_file["sections"][name])
            #     t_0x0548 = proj.loader.main_object.get_thread_registers_by_id() # 0x1b30 0x0548 0x13c4 0x1ecc 0x760
            #     print(t_0x0548)
            #     print(hex(t_0x0548["eip"]) )
            #     # print(proj.loader.memory[t_0x0548["esp"]])
            #     main_opt = {"entry_point":t_0x0548["eip"]} # "entry_point":t_0x0548["eip"]
            #     print(main_opt)
            #     #exit()
            #     proj = angr.Project(
            #         nameFile,
            #         use_sim_procedures=True, # if not nameFile.endswith(".dmp") else False,
            #         load_options={
            #             "auto_load_libs": True,
            #             "load_debug_info": True,
            #             #"preload_libs": libs,
            #         },  # ,load_options={"auto_load_libs":False}
            #         support_selfmodifying_code=True, #if not nameFile.endswith(".dmp") else False,
            #         main_opts=main_opt,
            #         #simos = "windows"if nameFile.endswith(".bin") or nameFile.endswith(".dmp") else None
            #         # arch="",
            #     )
            #     symbs = proj.loader.symbols
            #     for symb in symbs:
            #         print(symb)
            #     print(symbs)
            #     print(proj.loader.shared_objects)
            #     print(proj.loader.all_objects)
            #     print(proj.loader.requested_names)
            #     print(proj.loader.initial_load_objects)
            #     for register in t_0x0548:
            #         print(register,hex(t_0x0548[register]))
            #     #exit()
                
            # else:
            main_opt = {}
            libs  = []
            symbs = None
            dll = None
            main_opt = {"entry_point": 0x401500} # 0x4014e0
            proj = angr.Project(
                nameFile,
                use_sim_procedures=True, #if not nameFile.endswith(".dmp") else False,
                load_options={
                    "auto_load_libs": True,
                    "load_debug_info": True,
                    #"preload_libs": libs,
                },  # ,load_options={"auto_load_libs":False}
                support_selfmodifying_code=True, # if not nameFile.endswith(".dmp") else False,
                #main_opts=main_opt,
                #simos = "windows"if nameFile.endswith(".bin") or nameFile.endswith(".dmp") else None
                # arch="",
            )
            
            symbs = proj.loader.symbols
            for symb in symbs:
                print(symb)
            print(symbs)
            print(proj.loader.shared_objects)
            print(proj.loader.all_objects)
            print(proj.loader.requested_names)
            print(proj.loader.initial_load_objects)
            #exit()
            # for register in t_0x0548:
            #     print(register,hex(t_0x0548[register]))
            # exit()
            #     proj.loader.memory[t_0x0548[register]] 
            
                

        # Getting from a binary file to its representation in a virtual address space
        main_obj = proj.loader.main_object
        os_obj = main_obj.os

        # Informations about program
        if self.print_on:
            self.log.info("Libraries used are :\n" + str(proj.loader.requested_names))
            self.log.info("OS recognized as : " + str(os_obj))
            self.log.info("CPU architecture recognized as : " + str(proj.arch))
            self.log.info(
                "Entry point of the binary recognized as : " + hex(proj.entry)
            )
            self.log.info(
                "Min/Max addresses of the binary recognized as : " + str(proj.loader)
            )
            self.log.info(
                "Stack executable ?  " + str(main_obj.execstack)
            )  # TODO could be use for heuristic ?
            self.log.info("Binary position-independent ?  " + str(main_obj.pic))
            self.log.info("Exploration method:  " + str(expl_method))
        #exit()
        # Defining arguments given to the program (minimum is filename)
        args_binary = [nameFileShort]
        if args.n_args:
            for i in range(args.n_args):
                args_binary.append(claripy.BVS("arg" + str(i), 8 * 16))
        #exit()
        # Load pre-defined syscall table
        if os_obj == "windows":
            self.call_sim.system_call_table = self.call_sim.ddl_loader.load(proj,True if (self.is_packed and False) else False,dll)
        else:
            self.call_sim.system_call_table = self.call_sim.linux_loader.load_table(proj)

        # TODO : Maybe useless : Try to directly go into main (optimize some binary in windows)
        addr_main = proj.loader.find_symbol("main")
        if addr_main and self.fast_main:
            addr = addr_main.rebased_addr
        else:
            addr = proj.entry #

        if self.debug_error:
            pass
            # options.add(angr.options.TRACK_JMP_ACTIONS)
            # options.add(angr.options.TRACK_CONSTRAINT_ACTIONS)
            # options.add(angr.options.TRACK_JMP_ACTIONS)
        print(self.is_packed)
        if self.is_packed and self.unpack_mode == "symbion":
            options = {angr.options.SYMBION_SYNC_CLE}
            options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC) 
            #options.add(angr.options.SYNC_CLE_BACKEND_CONCRETE)
        else:
            # Create initial state of the binary
            # options = {angr.options.USE_SYSTEM_TIMES}
            options = set() # angr.options.SIMPLIFY_MEMORY_READS
            options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            options.add(angr.options.USE_SYSTEM_TIMES) 
            options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY) # remove path
            options.add(angr.options.SIMPLIFY_MEMORY_READS)
            options.add(angr.options.SIMPLIFY_MEMORY_WRITES)
            options.add(angr.options.SIMPLIFY_CONSTRAINTS)
            
            # options.add(angr.options.UNICORN)
            # options.add(angr.options.UNICORN_SYM_REGS_SUPPORT)
            # options.add(angr.options.UNICORN_HANDLE_TRANSMIT_SYSCALL)
            
            options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
            options.add(angr.options.SYMBOLIC_INITIAL_VALUES)

        # Contains a program's memory, registers, filesystem data... any "live data" that can be changed by execution has a home in the state
        self.log.info("Entry_state address = " + str(hex(addr)))
        #exit()
        state = proj.factory.entry_state(
            addr=addr, args=args_binary, add_options=options
        )
        
        # for register in t_0x0548:
        #     state.registers.store(reg, val)
        
        print(state.registers)
        
            
        #exit(0)
        #state.options.discard("LAZY_SOLVES")
        # For environment variable mainly
        state.register_plugin( 
            "plugin_env_var", PluginEnvVar()
        )  
        state.register_plugin( 
            "plugin_atom", PluginAtom()
        )  
        if not (self.is_packed and self.unpack_mode == "symbion") or True: # and False
            # TODO jn
            #heap_address = proj.concrete_target.get_heap_address()
            #heap_address_content = proj.concrete_target.read_address(heap_address)
            # print("Heap address = " + str(hex(heap_address)))
            # print("Heap address content = " + str(hex(heap_address_content)))
            state.register_plugin(
                "heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc() # heap_size=0x1000000 heap_base=heap_address_content
            )
            #print("Heap address = " + str(hex(heap_address)))
            #exit()
            # Memory block to store environment variable
            if not (self.is_packed and self.unpack_mode == "symbion"):
                state.plugin_env_var.env_block = state.heap.malloc(32767)
                for i in range(32767):
                    c = state.solver.BVS("c_env_block{}".format(i), 8)
                    state.memory.store(state.plugin_env_var.env_block + i, c)
        
        if os_obj == "windows" :
            ComSpec = "ComSpec=C:\Windows\system32\cmd.exe\0".encode("utf-8")
            ComSpec_bv = state.solver.BVV(ComSpec)
            state.memory.store(state.plugin_env_var.env_block, ComSpec_bv)
            state.plugin_env_var.env_var["COMSPEC"] = "C:\Windows\system32\cmd.exe\0"
        state.plugin_env_var.expl_method = expl_method

        # Constraint arguments to ASCII
        for i in range(1, len(args_binary)):
            for byte in args_binary[i].chop(8):
                # state.add_constraints(byte != '\x00') # null
                state.add_constraints(byte >= " ")  # '\x20'
                state.add_constraints(byte <= "~")  # '\x7e'

        # Creation of file with concrete content for cleanware
        # TODO WORK in Progress, need to think about automation of the process (like an argument with file name to create)
        if False:
            clean_files = ["share/file/magic.mgc"]
            for n in clean_files:
                f = open_file("malware-inputs/clean/" + n, "rb")
                cont = f.read()
                simfile = angr.SimFile(n, content=cont)
                f.close()
                simfile.set_state(state)

        #### Custom Hooking ####
        # Mechanism by which angr replaces library code with a python summary
        # When performing simulation, at every step angr checks if the current
        # address has been hooked, and if so, runs the hook instead of the binary
        # code at that address.

        if os_obj == "windows":
            self.call_sim.loadlibs(proj, symbs=symbs,dll=dll)
        
        self.call_sim.custom_hook_static(proj)

        if os_obj != "windows":
            self.call_sim.custom_hook_no_symbols(proj)
        else:
            # pass
            self.call_sim.custom_hook_windows_symbols(proj,True if (self.is_packed and False) else False,symbs)

        # Creation of simulation manager, primary interface in angr for performing execution
        simgr = proj.factory.simulation_manager(state)

        #####################################################
        ##########         Exploration           ############
        #####################################################

        # Improved "Break point"
        state.inspect.b("simprocedure", when=angr.BP_AFTER, action=self.call_sim.add_call)
        state.inspect.b("simprocedure", when=angr.BP_BEFORE, action=self.call_sim.add_call_debug)
        state.inspect.b("call", when=angr.BP_BEFORE, action=self.call_sim.add_addr_call)
        state.inspect.b("call", when=angr.BP_AFTER, action=self.call_sim.rm_addr_call)

        dump_file = {}
        dump_file = self.print_memory_info(main_obj, dump_file)
        

        # Improved Break point for debugging purpose for specific read/write/instructions
        if self.debug_error:
            pass
            # state.inspect.b('instruction',when=angr.BP_BEFORE, action=debug_instr)
            # state.inspect.b('mem_read',when=angr.BP_BEFORE, action=debug_read)
            # state.inspect.b('mem_write',when=angr.BP_BEFORE, action=debug_write)
            
        
        # TODO : make plugins out of these globals values
        # Globals is a simple dict already managed by Angr which is deeply copied from states to states
        simgr.active[0].globals["id"] = 0
        simgr.active[0].globals["JumpExcedeed"] = False
        simgr.active[0].globals["JumpTable"] = {}
        simgr.active[0].globals["n_steps"] = 0
        simgr.active[0].globals["last_instr"] = 0
        simgr.active[0].globals["counter_instr"] = 0
        simgr.active[0].globals["loaded_libs"] = {}
        simgr.active[0].globals["addr_call"] = []

        if self.is_packed and self.unpack_mode == "symbion":   
            self.log.info("Concolic unpacking process with Symbion")
            
            # cuckoo.start_analysis()            
            # cuckoo.stop_sandbox() 
            # unpack_add = cuckoo.get_address("UNPACK_ADDRESS")

            # unpack_add = 0x8048879
            # self.log.info("execute concretly")
            # new_concrete_state = self.execute_concretly(proj, state, unpack_add, [])
            # for i in range(0,4): # 5
            #     new_concrete_state = self.execute_concretly(proj, state, unpack_add, [])
            # simgr = proj.factory.simgr(new_concrete_state)
            
            # not_packed
            # STARTING_DECISION_ADDRESS = 0x401775
            # DROP_V1 = 0x401807
            # DROP_V2 = 0x401839
            # MALWARE_EXECUTION_END = 0x401879
            # FAKE_CC = 0x401861
            # VENV_DETECTED = 0x401847

            # self.log.info("[1]Executing malware concretely until address: " + hex(STARTING_DECISION_ADDRESS))
            # state = self.execute_concretly(proj, state, STARTING_DECISION_ADDRESS, [])

            # # declaring symbolic buffer
            # arg0 = claripy.BVS('arg0', 8 * 32)
            # symbolic_buffer_address = state.regs.esp + 0x18
            # state.memory.store(state.solver.eval(symbolic_buffer_address), arg0)

            # self.log.info("[2]Symbolically executing malware to find dropping of second stage [ address:  " + hex(DROP_V1) + " ]")
            # proj.use_sim_procedures = True
            # proj.concrete_target = None
            # proj.factory.concrete_engine = None
            #exit(0)
            # proj = angr.Project(
            #     nameFile,
            #     use_sim_procedures=True,
            #     load_options={
            #         "auto_load_libs": True
            #     },  # ,load_options={"auto_load_libs":False}
            #     support_selfmodifying_code=True,
            #     # arch="",
            # )
            # args_binary = [nameFileShort]
            # if args.n_args:
            #     for i in range(args.n_args):
            #         args_binary.append(claripy.BVS("arg" + str(i), 8 * 16))

            # # Load pre-defined syscall table
            # if os_obj == "windows":
            #     self.call_sim.system_call_table = self.call_sim.ddl_loader.load(proj)
            # else:
            #     self.call_sim.system_call_table = self.call_sim.linux_loader.load_table(
            #         proj
            #     )

            # # TODO : Maybe useless : Try to directly go into main (optimize some binary in windows)
            # addr_main = proj.loader.find_symbol("main")
            # if addr_main and self.fast_main:
            #     addr = addr_main.rebased_addr
            # else:
            #     addr = None

            # # Create initial state of the binary
            # # options = {angr.options.USE_SYSTEM_TIMES}
            # options = {angr.options.SIMPLIFY_MEMORY_READS}
            # options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            # options.add(angr.options.USE_SYSTEM_TIMES)
            # options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            # options.add(angr.options.SIMPLIFY_MEMORY_READS)
            # options.add(angr.options.SIMPLIFY_MEMORY_WRITES)
            # options.add(angr.options.SIMPLIFY_CONSTRAINTS)
            # # options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
            # options.add(angr.options.SYMBOLIC_INITIAL_VALUES)
            
            # new_concrete_state.options = options
            
            # new_concrete_state.options.discard("LAZY_SOLVES")
            # # For environment variable mainly
            # new_concrete_state.register_plugin( 
            #     "plugin_env_var", PluginEnvVar()
            # )  
            # new_concrete_state.register_plugin(
            #         "heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc() # heap_size=0x1000000
            #     )
            #     # Memory block to store environment variable
            # new_concrete_state.plugin_env_var.env_block = new_concrete_state.heap.malloc(32767)
            # for i in range(32767):
            #     c = new_concrete_state.solver.BVS("c_env_block{}".format(i), 8)
            #     new_concrete_state.memory.store(new_concrete_state.plugin_env_var.env_block + i, c)
            
            # if os_obj == "windows" :
            #     ComSpec = "ComSpec=C:\Windows\system32\cmd.exe\0".encode("utf-8")
            #     ComSpec_bv = new_concrete_state.solver.BVV(ComSpec)
            #     new_concrete_state.memory.store(new_concrete_state.plugin_env_var.env_block, ComSpec_bv)
            #     new_concrete_state.plugin_env_var.env_var["COMSPEC"] = "C:\Windows\system32\cmd.exe\0"
            # new_concrete_state.plugin_env_var.expl_method = expl_method
            
            # if os_obj == "windows":
            #     self.call_sim.loadlibs(proj)
            
            # self.call_sim.custom_hook_static(proj)

            # if os_obj != "windows":
            #     self.call_sim.custom_hook_no_symbols(proj)
            # else:
            #     # pass
            #     self.call_sim.custom_hook_windows_symbols(proj)
            
            # simgr = proj.factory.simulation_manager(new_concrete_state)
            
            # new_concrete_state.inspect.b("simprocedure", when=angr.BP_AFTER, action=self.call_sim.add_call)
            # new_concrete_state.inspect.b("simprocedure", when=angr.BP_BEFORE, action=self.call_sim.add_call_debug)
            # new_concrete_state.inspect.b("call", when=angr.BP_BEFORE, action=self.call_sim.add_addr_call)
            # new_concrete_state.inspect.b("call", when=angr.BP_AFTER, action=self.call_sim.rm_addr_call)
            # # exploration = simgr.explore(find=DROP_V1, avoid=[FAKE_CC, DROP_V2, VENV_DETECTED])
            # # self.log.info("CACA")
            # # new_symbolic_state = exploration.stashes['found'][0]

            # self.log.info("[3]Executing malware concretely with solution found until the end " + hex(MALWARE_EXECUTION_END))
            # self.execute_concretly(proj, new_symbolic_state, MALWARE_EXECUTION_END, [(symbolic_buffer_address, arg0)], [])
            # print("[4]Malware execution ends, the configuration value is: " + hex(
            #    new_symbolic_state.solver.eval(arg0, cast_to=int)))
            
            #packed
            UNPACKING_FINISHED = 0x41EA02 # 0x41EA02 # 0x41EA02 #0x41EA02 0x41e930 0x40162c
            STARTING_DECISION_ADDRESS = 0x401775 #0x41e930 #0x401775 #  proj.entry # 0x41e930
            DROP_V1 = 0x401807
            DROP_V2 = 0x401839
            MALWARE_EXECUTION_END = 0x401879
            FAKE_CC = 0x401861
            VENV_DETECTED = 0x401847
            # self.log.info("[1]Let get program symbols")
            # print(avatar_gdb.avatar.get_info_function_targets())
            self.log.info("[0]Let the malware unpack itself")
            state = self.execute_concretly(proj, state, UNPACKING_FINISHED)
            # # print("cac  a")
            print(dump_file["sections"]["UPX1"])
            #exit()
            #self.log.info("[1]Let get program symbols")
            print(proj.concrete_target.avatar.get_info_sharelib_targets(local_ddl_path))
            # print(proj.concrete_target.avatar.get_info_reg_targets())
            print(proj.concrete_target.get_mappings())
            print(proj.concrete_target.get_heap_address())
            #exit(0)
            self.log.info("[1]Executing malware concretely until address: " + hex(STARTING_DECISION_ADDRESS))
            state = self.execute_concretly(proj, state, STARTING_DECISION_ADDRESS, [])
            print(proj.concrete_target.save_dump(dump_file["sections"]["UPX1"]["vaddr"],dump_file["sections"]["UPX1"]["vaddr"]+dump_file["sections"]["UPX1"]["memsize"]))
            #self.log.info("[1]Let get program symbols")
            # print(proj.concrete_target.avatar.get_info_function_targets())
            # print(proj.concrete_target.avatar.get_info_reg_targets())
            mapps = proj.concrete_target.get_mappings()
            for map in mapps:
                print(map)
            print(proj.loader.main_object.threads)
            #exit(0)
            state.concrete.sync()
            state.concrete = None
            #exit(0)
            proj.concrete_target = None
            proj.loader.concrete = None
            proj.factory.concrete_engine = None
            # reass = proj.analyses.Reassembler()
            # reass.symbolize()
            #exit(0)
            # # # # # # declaring symbolic buffer
            # arg0 = claripy.BVS('arg0', 8 * 32)
            # symbolic_buffer_address = state.regs.esp + 0x18
            # state.memory.store(state.solver.eval(symbolic_buffer_address), arg0)
            
            # args_binary = [nameFileShort]
            # if args.n_args:
            #     for i in range(args.n_args):
            #         args_binary.append(claripy.BVS("arg" + str(i), 8 * 16))
            
            # for i in range(1, len(args_binary)):
            #     for byte in args_binary[i].chop(8):
            #         # state.add_constraints(byte != '\x00') # null
            #         state.add_constraints(byte >= " ")  # '\x20'
            #         state.add_constraints(byte <= "~")  # '\x7e'

            #.log.info("[2]Symbolically executing malware to find dropping of second stage [ address:  " + hex(DROP_V1) + " ] [" + hex(state.addr) + " ]")
            # # proj.use_sim_procedures = True
            # # #exit(0)
            # state = proj.factory.entry_state(
            #     addr=UNPACKING_FINISHED, args=args_binary, add_options=options
            # )
            
            # proj.use_sim_procedures = False
            # proj.loader = cle.Loader(proj.filename, concrete_target=None, **{
            #             "auto_load_libs": True
            # })
            #proj.loader.concrete = None
            
            # state.options.discard(angr.options.SYMBION_SYNC_CLE)
            # state.options.discard(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)
            
            # proj.loader.main_object = None
            # proj.entry = UNPACKING_FINISHED
            # proj.simos.configure_project()
            # dump_file = {}
            # main_obj = proj.loader.main_object
            # os_obj = main_obj.os
            # self.print_memory_info(main_obj, dump_file)
            
            # # Load pre-defined syscall table
            # if os_obj == "windows":
            #     self.call_sim.system_call_table = self.call_sim.ddl_loader.load(proj)
            # else:
            #     self.call_sim.system_call_table = self.call_sim.linux_loader.load_table(proj)
            
            # if os_obj == "windows":
            #     self.call_sim.loadlibs(proj)
            
            # self.call_sim.custom_hook_static(proj)

            # if os_obj != "windows":
            #     self.call_sim.custom_hook_no_symbols(proj)
            # else:
            #     # pass
            #     self.call_sim.custom_hook_windows_symbols(proj)
                
            #simgr = proj.factory.simulation_manager(state1)
            simgr = proj.factory.simgr(state)
            
            # simgr._techniques = []
            # simgr.active.pop()
            # #print(state1)
            #simgr.active.append(state2)
            
            # dump_file = {}
            # self.print_memory_info(main_obj, dump_file)
            
            state.inspect.b("simprocedure", when=angr.BP_AFTER, action=self.call_sim.add_call)
            state.inspect.b("simprocedure", when=angr.BP_BEFORE, action=self.call_sim.add_call_debug)
            state.inspect.b("call", when=angr.BP_BEFORE, action=self.call_sim.add_addr_call)
            state.inspect.b("call", when=angr.BP_AFTER, action=self.call_sim.rm_addr_call)
            # # simgr.use_technique(exploration_tech)
            # exploration = simgr.explore(find=DROP_V1, avoid=[FAKE_CC, DROP_V2, VENV_DETECTED])
            # state = exploration.stashes['found'][0]
            
            #simgr = proj.factory.simgr(state)
              # Improved "Break point"

            simgr.active[0].globals["id"] = 0
            simgr.active[0].globals["JumpExcedeed"] = False
            simgr.active[0].globals["JumpTable"] = {}
            simgr.active[0].globals["n_steps"] = 0
            simgr.active[0].globals["last_instr"] = 0
            simgr.active[0].globals["counter_instr"] = 0
            simgr.active[0].globals["loaded_libs"] = {}
            simgr.active[0].globals["addr_call"] = []
            print(simgr)
            print(state)
            #exit(0)

            #self.log.info("[3]Executing malware concretely with solution found until the end " + hex(MALWARE_EXECUTION_END))
            #self.execute_concretly(proj, new_symbolic_state, MALWARE_EXECUTION_END, [(symbolic_buffer_address, arg0)], [])


        self.scdg.append(
            [
                {
                    "name": "main",
                    "args": [str(args) for args in args_binary],
                    "addr": state.addr,
                    "ret": "symbolic",
                    "addr_func": state.addr,
                }
            ]
        )

        self.jump_dict[0] = {}
        self.jump_concrete_dict[0] = {}

        # The stash where states are moved to wait
        # until some space becomes available in Active stash.
        # The size of the space in this stash is a parameter of
        # the toolchain. If new states appear and there is no
        # space available in the Pause stash, some states are
        # dropped.
        simgr.stashes["pause"] = []

        # The stash where states leading to new
        # instruction addresses (not yet explored) of the binary
        # are kept. If CDFS or CBFS are not used, this stash
        # merges with the pause stash.
        simgr.stashes["new_addr"] = []

        # The stash where states exceeding the
        # threshold related to number of steps are moved. If
        # new states are needed and there is no state available
        # in pause stash, states in this stash are used to resume
        # exploration (their step counter are put back to zero).
        simgr.stashes["ExcessLoop"] = []

        # The stash where states which exceed the
        # threshold related to loops are moved. If new states
        # are needed and there is no state available in pause
        # or ExcessStep stash, states in this stash are used to
        # resume exploration (their loop counter are put back
        # to zero).
        simgr.stashes["ExcessStep"] = []

        simgr.stashes["temp"]
        
        print(simgr.stashes)

        exploration_tech = ToolChainExplorerDFS(
            simgr, 0, args.exp_dir, nameFileShort, self
        )
        if expl_method == "CDFS":
            exploration_tech = ToolChainExplorerCDFS(
                simgr, 0, args.exp_dir, nameFileShort, self
            )
        elif expl_method == "CBFS":
            exploration_tech = ToolChainExplorerCBFS(
                simgr, 0, args.exp_dir, nameFileShort, self
            )
        elif expl_method == "BFS":
            exploration_tech = ToolChainExplorerBFS(
                simgr, 0, args.exp_dir, nameFileShort, self
            )

        self.log.info(proj.loader.all_pe_objects)
        self.log.info(proj.loader.extern_object)
        self.log.info(proj.loader.symbols)
        #exit()
        simgr.use_technique(exploration_tech)

        self.log.info(
            "\n------------------------------\nStart -State of simulation manager :\n "
            + str(simgr)
            + "\n------------------------------"
        )

        if self.print_on:
            self.log.info("Libraries used are :\n" + str(proj.loader.requested_names))
            self.log.info("OS recognized as : " + str(os_obj))
            self.log.info("CPU architecture recognized as : " + str(proj.arch))
            self.log.info(
                "Entry point of the binary recognized as : " + hex(proj.entry)
            )
            self.log.info(
                "Min/Max addresses of the binary recognized as : " + str(proj.loader)
            )
            self.log.info(
                "Stack executable ?  " + str(main_obj.execstack)
            )  # TODO could be use for heuristic ?
            self.log.info("Binary position-independent ?  " + str(main_obj.pic))
            self.log.info("Exploration method:  " + str(expl_method))
            
        simgr.run()

        self.log.info(
            "\n------------------------------\nEnd - State of simulation manager :\n "
            + str(simgr)
            + "\n------------------------------"
        )
        
        print(simgr.errored)

        self.log.info("Syscall Found:" + str(self.call_sim.syscall_found))

        elapsed_time = time.time() - self.start_time
        self.log.info("Total execution time to build scdg: " + str(elapsed_time))


        self.build_scdg_fin(args, nameFileShort, main_obj, state, simgr)

        g = GraphBuilder(
            name=nameFileShort,
            mapping="mapping.txt",
            merge_call=(not args.disjoint_union),
            comp_args=(not args.not_comp_args),
            min_size=args.min_size,
            ignore_zero=(not args.not_ignore_zero),
            odir=args.dir,
            verbose=args.verbose,
            familly=family
        )
        g.build_graph(self.scdg_fin, format_out=args.format_out)
        
        # print("Heap address = " + str(hex(heap_address)))
        # print("Heap address content = " + str(hex(heap_address_content)))

    def build_scdg_fin(self, args, nameFileShort, main_obj, state, simgr):
        dump_file = {}
        dump_id = 0
        dic_hash_SCDG = {}
        # Add all traces with relevant content to graph construction
        for stateDead in simgr.deadended:
            hashVal = hash(str(self.scdg[stateDead.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "deadendend",
                    "trace": self.scdg[stateDead.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg[state.globals["id"]])

        for state in simgr.active:
            hashVal = hash(str(self.scdg[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "active",
                    "trace": self.scdg[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg[state.globals["id"]])

        for error in simgr.errored:
            hashVal = hash(str(self.scdg[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "errored",
                    "trace": self.scdg[error.state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg[state.globals["id"]])

        for state in simgr.stashes["ExcessLoop"]:
            hashVal = hash(str(self.scdg[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "ExcessLoop",
                    "trace": self.scdg[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg[state.globals["id"]])

        for state in simgr.stashes["ExcessStep"]:
            hashVal = hash(str(self.scdg[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "ExcessStep",
                    "trace": self.scdg[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg[state.globals["id"]])

        for state in simgr.unconstrained:
            hashVal = hash(str(self.scdg[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "unconstrained",
                    "trace": self.scdg[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg[state.globals["id"]])

        self.print_memory_info(main_obj, dump_file)
        if args.discard_SCDG:
            # self.log.info(dump_file)
            ofilename = args.exp_dir + nameFileShort + "_SCDG.json"
            self.log.info(ofilename)
            save_SCDG = open_file(ofilename, "w")
            # self.log.info(dump_file)
            json_dumper.dump(dump_file, save_SCDG)  # ,indent=4)
            save_SCDG.close()

    def execute_concretly(
        self, p, state, address, memory_concretize=[], register_concretize=[], timeout=0
    ):
        simgr = p.factory.simgr(state)
        simgr.use_technique(
            angr.exploration_techniques.Symbion(
                find=[address],
                memory_concretize=memory_concretize,
                register_concretize=register_concretize,
                timeout=timeout,
            )
        )
        exploration = simgr.run()
        return exploration.stashes["found"][0]

    def print_memory_info(self, main_obj, dump_file):
        dump_file["sections"] = {}
        for sec in main_obj.sections:
            name = sec.name.replace("\x00", "")
            try:
                info_sec = {
                    "vaddr": sec.vaddr,
                    "memsize": sec.memsize,
                    "is_readable": sec.is_readable,
                    "is_writable": sec.is_writable,
                    "is_executable": sec.is_executable,
                }
            except:
                info_sec = {
                    "vaddr": sec.vaddr,
                    "memsize": sec.memsize,
                    "is_readable": None,
                    "is_writable": None,
                    "is_executable": None,
                }
            dump_file["sections"][name] = info_sec
            self.log.info(name)
            self.log.info(dump_file["sections"][name])
        return dump_file

def main():
    toolc = ToolChainSCDG(
        print_sm_step=True,
        print_syscall=True,
        debug_error=True,
        debug_string=True,
        print_on=True,
    )
    args_parser = ArgumentParserSCDG(toolc)
    args, nameFile, expl_method, familly = args_parser.parse_arguments()

    if os.path.isfile(nameFile):
        toolc.log.info("You decide to analyse a single binary: "+ nameFile)
        toolc.build_scdg(args, nameFile, expl_method, familly)
    else:
        last_familiy = "unknown"
        if os.path.isdir(nameFile):
            subfolder = [os.path.join(nameFile, f) for f in os.listdir(nameFile) if os.path.isdir(os.path.join(nameFile, f))]
            for folder in subfolder:
                toolc.log.info("You are currently building SCDG for " + folder)
                files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f))]
                for file  in files:
                    args.exp_dir = args.exp_dir.exp_dir.replace(last_familiy,folder.split("/")[-1])
                    toolc.build_scdg(args, file, expl_method,folder.split("/")[-1])
                toolc.families += last_familiy
                last_familiy = folder.split("/")[-1]
        else:
            toolc.log.info("Error: you should insert a folder containing malware classified in their family folders\n(Example: databases/malware-inputs/Sample_paper")
            exit(-1)

if __name__ == "__main__":
    main()
