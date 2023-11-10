#!/usr/bin/env python3
import datetime
import os
import sys

import json as json_dumper
from builtins import open as open_file
import threading
import time

import claripy
#import monkeyhex  # this will format numerical results in hexadecimal
import logging
from capstone import *

import angr

import gc
import pandas as pd
import logging
import progressbar
import configparser

from SCDGHelper.GraphBuilder import *
from SCDGHelper.SyscallToSCDG import SyscallToSCDGBuilder
from procedures.CustomSimProcedure import *
from procedures.LinuxSimProcedure import LinuxSimProcedure
from procedures.WindowsSimProcedure import WindowsSimProcedure
from plugin.PluginEnvVar import *
from plugin.PluginThread import *
from plugin.PluginLocaleInfo import *
from plugin.PluginRegistery import *
from plugin.PluginHooks import *
from plugin.PluginWideChar import *
from plugin.PluginResources import *
from plugin.PluginEvasion import *
from plugin.PluginCommands import *
from plugin.PluginIoC import *
from plugin.PluginAtom import *
from explorer.SemaExplorerDFS import SemaExplorerDFS
from explorer.SemaExplorerCDFS import SemaExplorerCDFS
from explorer.SemaExplorerBFS import SemaExplorerBFS
from explorer.SemaExplorerCBFS import SemaExplorerCBFS
from explorer.SemaExplorerSDFS import SemaExplorerSDFS
from explorer.SemaExplorerDBFS import SemaExplorerDBFS
from explorer.SemaExplorerAnotherCDFS import SemaExplorerAnotherCDFS
from explorer.SemaThreadCDFS import SemaThreadCDFS
from clogging.CustomFormatter import CustomFormatter
from clogging.LogBookFormatter import * # TODO
from clogging.DataManager import DataManager
#from SCDGHelper.ArgumentParserSCDG import ArgumentParserSCDG
from sandboxes.CuckooInterface import CuckooInterface

import avatar2 as avatar2

from unipacker.core import Sample, SimpleClient, UnpackerEngine
from unipacker.utils import RepeatedTimer, InvalidPEFile
#from angr_targets import AvatarGDBConcreteTarget # TODO FIX in submodule

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

class SemaSCDG():
    """
    TODO
    """
    def __init__(self):
        config = configparser.ConfigParser()
        config.read('config.ini')
        self.start_time = time.time()

        # TODO : not proposed in the web app -> add if useful
        self.fast_main = config['SCDG_arg'].getboolean('fast_main')

        self.verbose = config['SCDG_arg'].getboolean('verbose')
        self.print_syscall = config['SCDG_arg'].getboolean('print_syscall')
        self.string_resolve = config['SCDG_arg'].getboolean('string_resolve')
        self.concrete_target_is_local = config['SCDG_arg'].getboolean('concrete_target_is_local')
        self.is_packed = config['SCDG_arg'].getboolean('is_packed')
        self.unpack_mode = config['SCDG_arg']['packing_type']
        self.keep_inter_scdg = config['SCDG_arg'].getboolean('keep_inter_scdg')
        self.pre_run_thread = config['SCDG_arg'].getboolean('pre_run_thread')
        self.post_run_thread = config['SCDG_arg'].getboolean('post_run_thread')
        self.approximate = config['SCDG_arg'].getboolean('approximate')
        self.track_command = config['SCDG_arg'].getboolean('track_command')
        self.ioc_report = config['SCDG_arg'].getboolean('ioc_report')
        self.hooks_enable = config['SCDG_arg'].getboolean('hooks_enable')
        self.sim_file = config['SCDG_arg'].getboolean('sim_file')
        self.count_block_enable = config['SCDG_arg'].getboolean('count_block_enable')
        self.plugin_enable = config['SCDG_arg'].getboolean('plugin_enable')
        self.expl_method = config['SCDG_arg']["expl_method"]
        self.family = config['SCDG_arg']['family']
        self.exp_dir = config['SCDG_arg']['exp_dir'] + "/" + self.family
        self.binary_path = config['SCDG_arg']['binary_path']
        self.n_args = int(config['SCDG_arg']['n_args'])
        self.csv_file = config['SCDG_arg']['csv_file']

        self.config = config
        self.log = logging.getLogger("SemaSCDG")
        self.store_data = self.csv_file != ""

        self.scdg_graph = []
        self.scdg_fin = []
        self.new = {}
        
        self.hooks = PluginHooks()
        self.commands = PluginCommands()
        self.ioc = PluginIoC()
        self.data_manager = DataManager(logger=self.log, verbose=config['SCDG_arg'].getboolean('print_address'))

        self.families = []
        
        self.nb_exps = 0
        self.current_exps = 0
        self.current_exp_dir = 0

    #Save the configuration of the experiment in a json file
    def save_conf(self, path):
        param = dict()
        sections = self.config.sections()
        for section in sections:
            items=self.config.items(section)
            param[section]=dict(items)
        with open(os.path.join(path, "scdg_conf.json"), "w") as f:
            json.dump(param, f, indent=4)

    # Create and return an angr project
    def init_angr_project(self, namefile, preload_libs=[], concrete_target=None, support_selfmodifying_code=None, simos=None, arch=None, auto_load_libs=False, load_debug_info= False):
        proj = angr.Project(
            namefile,
            use_sim_procedures=True,
            load_options={
                "auto_load_libs": auto_load_libs,
                "load_debug_info": load_debug_info,
                "preload_libs": preload_libs
            }, 
            support_selfmodifying_code = support_selfmodifying_code,
            simos = simos,
            arch = arch,
            concrete_target = concrete_target,
            default_analysis_mode="symbolic" if not self.approximate else "symbolic_approximating"
        )
        return proj
    
    # Print informations about program
    def print_program_info(self, proj, main_obj, os_obj):
        self.log.info("Libraries used are :\n" + str(proj.loader.requested_names))
        self.log.info("OS recognized as : " + str(os_obj))
        self.log.info("CPU architecture recognized as : " + str(proj.arch))
        self.log.info("Entry point of the binary recognized as : " + hex(proj.entry))
        self.log.info("Min/Max addresses of the binary recognized as : " + str(proj.loader))
        self.log.info("Stack executable ?  " + str(main_obj.execstack))  # TODO could be use for heuristic ?
        self.log.info("Binary position-independent ?  " + str(main_obj.pic))
        self.log.info("Exploration method:  " + str(self.expl_method))

    # Get state options from config file and return a set containing them
    def get_angr_state_options(self):
        options = set()
        for option in self.config["ANGR_State_options_to_add"] :
            if self.config["ANGR_State_options_to_add"].getboolean(option):
                options.add(str.upper(option))
        return options
    
    # Load and setup plugins set to true in config file
    def load_plugin(self, state, proj, nameFileShort, options, exp_dir):
        plugin_available = self.config["Plugins_to_load"]
        for plugin in plugin_available:
            if self.config["Plugins_to_load"].getboolean(plugin):
                if plugin == "plugin_env_var" :
                    state.register_plugin(plugin, PluginEnvVar(self.expl_method))
                    state.plugin_env_var.setup_plugin() 
                elif plugin == "plugin_locale_info" :
                    state.register_plugin(plugin, PluginLocaleInfo()) 
                    state.plugin_locale_info.setup_plugin()
                elif plugin == "plugin_resources" :
                    state.register_plugin(plugin, PluginResources())
                    state.plugin_resources.setup_plugin()
                elif plugin == "plugin_widechar" : 
                    state.register_plugin(plugin, PluginWideChar())
                elif plugin == "plugin_registery" :
                    state.register_plugin(plugin, PluginRegistery())
                    state.plugin_registery.setup_plugin()
                elif plugin == "plugin_atom" :
                    state.register_plugin(plugin, PluginAtom())
                elif plugin == "plugin_thread" :
                    state.register_plugin("plugin_thread", PluginThread(self, exp_dir, proj, nameFileShort, options))

    # Set improved "Break point"
    def set_breakpoints(self, state):      
        state.inspect.b("simprocedure", when=angr.BP_AFTER, action=self.syscall_to_scdg_builder.add_call)
        state.inspect.b("simprocedure", when=angr.BP_BEFORE, action=self.syscall_to_scdg_builder.add_call_debug)
        state.inspect.b("call", when=angr.BP_BEFORE, action=self.syscall_to_scdg_builder.add_addr_call)
        state.inspect.b("call", when=angr.BP_AFTER, action=self.syscall_to_scdg_builder.rm_addr_call)
        
        if self.count_block_enable:
            state.inspect.b("instruction",when=angr.BP_BEFORE, action=self.data_manager.print_state_address)
            state.inspect.b("instruction",when=angr.BP_AFTER, action=self.data_manager.add_instr_addr)
            state.inspect.b("irsb",when=angr.BP_BEFORE, action=self.data_manager.add_block_addr)

    #Setup angr project, runs it and build the SCDG graph
    def run(self, exp_dir):
        # Create directory to store SCDG if it doesn't exist
        self.scdg_graph.clear()
        self.scdg_fin.clear()
        # self.call_sim.syscall_found.clear()
        # self.call_sim.system_call_table.clear()
        
        # TODO check if PE file get /GUARD option (VS code) with leaf
        
        self.start_time = time.time()

        # Create a Dataframe for future data if a csv file is specified
        if self.store_data:
            self.data_manager.setup_csv(exp_dir + self.csv_file)
        
        # Setup the output directory
        self.log.info("Results wil be saved into : " + exp_dir)
        try:
            os.makedirs(exp_dir)
        except:
            pass
            
        # Save the configuration used
        self.save_conf(exp_dir)

        # Take name of the sample without full path
        if "/" in self.binary_path:
            nameFileShort = self.binary_path.split("/")[-1]
        else:
            nameFileShort = self.binary_path
        self.data_manager.data["nameFileShort"] = nameFileShort
        try:
            os.stat(exp_dir + nameFileShort)
        except:
            os.makedirs(exp_dir + nameFileShort)
        fileHandler = logging.FileHandler(exp_dir + nameFileShort + "/" + "scdg.ans")
        fileHandler.setFormatter(CustomFormatter())
        #logging.getLogger().handlers.clear()
        try:
            logging.getLogger().removeHandler(fileHandler)
        except:
            self.log.warning("Exception remove filehandler")
            pass
        
        logging.getLogger().addHandler(fileHandler)

        exp_dir = exp_dir + nameFileShort + "/"
        
        title = "--- Building SCDG of " + self.family  +"/" + nameFileShort  + " ---"
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
        dll=None
        if self.is_packed and self.packing_type == "symbion":
            # nameFile = os.path.join(os.path.dirname(os.path.realpath(__file__)),
            #                               os.path.join('..', 'binaries',
            #                               'tests','x86_64',
            #                               'packed_elf64'))
                        
            #nameFile = "/home/crochetch/Documents/toolchain_malware_analysis/src/submodules/binaries/tests/x86_64/packed_elf64"
            #st = os.stat(nameFile)
            #os.chmod(nameFile, st.st_mode | stat.S_IEXEC)
            print(nameFile)
            analysis = nameFile

            proj = self.init_angr_project(nameFile, auto_load_libs=True, support_selfmodifying_code=True)

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
            
            proj = self.init_angr_project(nameFile, preload_libs=preload, auto_load_libs=True, load_debug_info=True, support_selfmodifying_code=True, concrete_target=avatar_gdb)

            #self.call_sim.system_call_table.clear()
            #print(proj.concrete_target.avatar.get_info_sharelib_targets(local_ddl_path))
            
            for lib in proj.concrete_target.avatar.get_info_sharelib_targets(local_ddl_path)[0]:
                print(lib["id"]) # TODO lowercase folder
                if lib["target-name"] == lib["host-name"] :
                    print("Changed")
                #if "kernel" not in lib["target-name"].lower():
                #preload.append(lib["id"].replace("C:\\",self.call_sim.ddl_loader.calls_dir.replace("calls","windows7_ddls/C:/")).replace("\\","/").replace("system","System")) # 
            #exit()
            proj = self.init_angr_project(nameFile, auto_load_libs=False, load_debug_info=True, preload_libs=preload, support_selfmodifying_code=True, concrete_target=avatar_gdb)

            for lib in self.call_sim.system_call_table:
                print(proj.loader.find_all_symbols(lib))
            #for obj in proj.loader.all_objects:
            #    print(obj)
            #exit()
        elif self.is_packed and self.packing_type == "unipacker":
            try:
                #TODO : replace by a function
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
                proj = self.init_angr_project(nameFile, auto_load_libs=True, support_selfmodifying_code=True)
            except InvalidPEFile as e:
                self.packing_type = "symbion"
                self.run("database/SCDG/runs/" + self.exp_dir + "/")
                return
        else:  
            #TODO : replace by a function
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

            #simos = "windows"if nameFile.endswith(".bin") or nameFile.endswith(".dmp") else None
            proj = self.init_angr_project(self.binary_path, support_selfmodifying_code=True, auto_load_libs=True, load_debug_info=True, simos=None)

        main_obj = proj.loader.main_object
        os_obj = main_obj.os
        if self.count_block_enable:
            self.data_manager.count_block(proj=proj, main_obj= main_obj)
            
        if self.verbose:
            self.print_program_info(proj=proj, main_obj = main_obj, os_obj = os_obj)


        # Load pre-defined syscall table
        if os_obj == "windows":
            #Create window custom sim proc
            self.call_sim = WindowsSimProcedure()
            self.call_sim.system_call_table = self.call_sim.ddl_loader.load(proj,True if (self.is_packed and False) else False,dll)
        else:
            #Create linux custom sim proc
            self.call_sim = LinuxSimProcedure()
            self.call_sim.system_call_table = self.call_sim.linux_loader.load_table(proj)
           
        self.syscall_to_scdg_builder = SyscallToSCDGBuilder(self.call_sim, self.scdg_graph, self.string_resolve, self.print_syscall, self.verbose)
            
        self.log.info("System call table loaded")
        self.log.info("System call table size : " + str(len(self.call_sim.system_call_table)))
        
        # Create initial state of the binary

        # Defining arguments given to the program (minimum is filename)
        args_binary = [nameFileShort] 
        if self.n_args:
            for i in range(self.n_args):
                args_binary.append(claripy.BVS("arg" + str(i), 8 * 16))

        # TODO : Maybe useless : Try to directly go into main (optimize some binary in windows)
        r = r2pipe.open(self.inputs)
        out_r2 = r.cmd('f ~sym._main')
        out_r2 = r.cmd('f ~sym._main')   
        addr_main = proj.loader.find_symbol("main")
        if addr_main and self.fast_main:
            addr = addr_main.rebased_addr
        elif out_r2:
            addr= None
            try:
                iter = out_r2.split("\n")
                for s in iter:
                    if s.endswith("._main"):
                        addr = int(s.split(" ")[0],16)
            except:
                pass
        else:
            # Take the entry point specify in config file
            addr = self.config["SCDG_arg"]["entry_addr"]
            if addr != "None":
                #Convert string into hexadecimal
                addr = hex(int(addr, 16))
            else:
                addr = None
        self.log.info("Entry_state address = " + str(addr))
        
        options = self.get_angr_state_options()

        state = proj.factory.entry_state(
            addr=addr, args=args_binary, add_options=options
        )

        cont = ""
        if self.sim_file:
            with open_file(self.binary_path, "rb") as f:
                cont = f.read()
            simfile = angr.SimFile(nameFileShort, content=cont)
            state.fs.insert(nameFileShort, simfile)
            pagefile = angr.SimFile("pagefile.sys", content=cont)
            state.fs.insert("pagefile.sys", pagefile)
        
        state.options.discard("LAZY_SOLVES") 
        if not (self.is_packed and self.packing_type == "symbion") or True:
            state.register_plugin(
                "heap", 
                angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc(heap_size=0x10000000)
            )
            #state.libc.max_variable_size = 0x20000000*2 + 0x18000000
            #state.libc.max_memcpy_size   = 0x20000000*2
        
        # Enable plugins set to true in config file
        if self.plugin_enable:
            self.load_plugin(state, proj, nameFileShort, options, exp_dir)

        # Create ProcessHeap struct and set heapflages to 0
        tib_addr = state.regs.fs.concat(state.solver.BVV(0, 16))
        if proj.arch.name == "AMD64":
            peb_addr = state.mem[tib_addr + 0x60].qword.resolved
            ProcessHeap = peb_addr + 0x500 #0x18
            state.mem[peb_addr + 0x10].qword = ProcessHeap
            state.mem[ProcessHeap + 0x18].dword = 0x0 # heapflags windowsvistaorgreater
            state.mem[ProcessHeap + 0x70].dword = 0x0 # heapflags else
        else:
            peb_addr = state.mem[tib_addr + 0x30].dword.resolved
            ProcessHeap = peb_addr + 0x500
            state.mem[peb_addr + 0x18].dword = ProcessHeap
            state.mem[ProcessHeap+0xc].dword = 0x0 #heapflags windowsvistaorgreater
            state.mem[ProcessHeap+0x40].dword = 0x0 #heapflags else
        
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
            self.call_sim.loadlibs_proc(self.call_sim.system_call_table, proj) #TODO mbs=symbs,dll=dll)
        
        self.call_sim.custom_hook_static(proj)

        if os_obj != "windows":
            self.call_sim.custom_hook_linux_symbols(proj)
            self.call_sim.custom_hook_no_symbols(proj)
        else:
            self.call_sim.custom_hook_windows_symbols(proj)  #TODO ue if (self.is_packed and False) else False,symbs)

        if self.hooks_enable:
            self.hooks.initialization(cont, is_64bits=True if proj.arch.name == "AMD64" else False)
            self.hooks.hook(state,proj,self.call_sim)
                
        # Creation of simulation managerinline_call, primary interface in angr for performing execution
        
        simgr = proj.factory.simulation_manager(state)
        
        dump_file = {}
        self.print_memory_info(main_obj, dump_file)    
        
        #####################################################
        ##########         Exploration           ############
        #####################################################

        if self.pre_run_thread:
            state.plugin_thread.pre_run_thread(cont, self.binary_path)

        self.set_breakpoints(state)

        # TODO : make plugins out of these globals values
        # Globals is a simple dict already managed by Angr which is deeply copied from states to states
        
        # (3) TODO manon: move that but as serena purposes car je ne sais pas ahah
        for sec in main_obj.sections:
            name = sec.name.replace("\x00", "")
            if name == ".rsrc":
                simgr.active[0].globals["rsrc"] = sec.vaddr
        
        self.scdg_graph.append(
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

        exploration_tech = self.get_exploration_tech(nameFileShort, simgr, exp_dir)
        #exploration_tech_2 = Threading()
        
        self.log.info(proj.loader.all_pe_objects)
        self.log.info(proj.loader.extern_object)
        self.log.info(proj.loader.symbols)
        
        #simgr.use_technique(DFS())
        simgr.use_technique(exploration_tech)
        
        self.log.info(
            "\n------------------------------\nStart -State of simulation manager :\n "
            + str(simgr)
            + "\n------------------------------"
        )
        
        simgr.run()

        self.log.info(
            "\n------------------------------\nEnd - State of simulation manager :\n "
            + str(simgr)
            + "\n------------------------------"
        )
        
        if self.post_run_thread:
            state.plugin_thread.post_run_thread(simgr)
        
        elapsed_time = time.time() - self.start_time
        self.data_manager.data["elapsed_time"] = elapsed_time
        self.log.info("Total execution time: " + str(elapsed_time))

        if self.count_block_enable and self.verbose:
            self.data_manager.print_block_info()
        
        self.log.info("Syscalls Found:" + str(self.call_sim.syscall_found))
        self.log.info("Loaded libraries:" + str(proj.loader.requested_names))
        
        if self.plugin_enable :
            if self.store_data :
                if self.verbose:
                    self.data_manager.get_plugin_data(state, simgr, to_store=True, verbose=True)
                else :
                    self.data_manager.get_plugin_data(state, simgr, to_store=True)
            elif self.verbose :
                self.data_manager.get_plugin_data(state, simgr, to_store=False, verbose=True)
        
        if self.track_command:
            self.commands.track(simgr, self.scdg_graph, exp_dir)
        if self.ioc_report:
            self.ioc.build_ioc(self.scdg_graph, exp_dir)

        # Build SCDG
        self.build_scdg(main_obj, state, simgr, exp_dir)
        
        g = GraphBuilder(
            name=nameFileShort,
            mapping="mapping.txt", # (2) TODO manon: make this configurable, i propose a mapping file with the name of the binary and the absolute path to avoid errors
            merge_call=(not self.config['build_graph_arg'].getboolean('disjoint_union')),
            comp_args=(not self.config['build_graph_arg'].getboolean('not_comp_args')),
            min_size=int(self.config['build_graph_arg']['min_size']),
            ignore_zero=(not self.config['build_graph_arg'].getboolean('not_ignore_zero')),
            three_edges=self.config['build_graph_arg'].getboolean('three_edges'),
            odir=exp_dir,
            verbose=self.verbose,
            family=self.family
        )
        g.build_graph(self.scdg_fin, graph_output=self.config['build_graph_arg']['graph_output'])
        
        if self.store_data:
            self.data_manager.save_to_csv(proj, self.family, self.call_sim, csv_file_path=exp_dir + self.csv_file)

        logging.getLogger().removeHandler(fileHandler)

    def get_exploration_tech(self, nameFileShort, simgr, exp_dir):
        exploration_tech = SemaExplorerDFS(
            simgr, exp_dir, nameFileShort, self.scdg_graph, self.call_sim
        )
        if self.expl_method == "CDFS":
            exploration_tech = SemaExplorerCDFS(
                 simgr, exp_dir, nameFileShort, self.scdg_graph, self.call_sim
            )
        # elif self.expl_method == "CBFS":
        #     exploration_tech = SemaExplorerCBFS(
        #         simgr, exp_dir, nameFileShort, self.scdg_graph, self.call_sim
        #     )
        # elif self.expl_method == "BFS":
        #     exploration_tech = SemaExplorerBFS(
        #         simgr, exp_dir, nameFileShort, self.scdg_graph, self.call_sim
        #     )
        # elif self.expl_method == "SCDFS":
        #     exploration_tech = SemaExplorerAnotherCDFS(
        #         simgr, exp_dir, nameFileShort, self.scdg_graph, self.call_sim
        #     )
        # elif self.expl_method == "DBFS":
        #     exploration_tech = SemaExplorerDBFS(
        #         simgr, exp_dir, nameFileShort, self.scdg_graph, self.call_sim
        #     )
        # elif self.expl_method == "SDFS":
        #     exploration_tech = SemaExplorerSDFS(
        #         simgr, exp_dir, nameFileShort, self.scdg_graph, self.call_sim
        #     )
        # elif self.expl_method == "ThreadCDFS":
        #     exploration_tech = SemaThreadCDFS(
        #         simgr, exp_dir, nameFileShort, self.scdg_graph, self.call_sim
        #     )
            
        return exploration_tech

    #Construct the SCDG with the stashes content
    def build_scdg(self, main_obj, state, simgr, exp_dir):
        dump_file = {}
        dump_id = 0
        dic_hash_SCDG = {}
        # Add all traces with relevant content to graph construction
        stashes = {
            "deadended" : simgr.deadended,
            "active" : simgr.active,
            "errored" : simgr.errored,
            "pause" : simgr.pause, 
            "ExcessLoop" : simgr.stashes["ExcessLoop"],
            "ExcessStep" : simgr.stashes["ExcessStep"],
            "unconstrained" : simgr.unconstrained,
            "new_addr" : simgr.stashes["new_addr"],
            "deadbeef" : simgr.stashes["deadbeef"],
            "lost" : simgr.stashes["lost"]
        }
        for stash_name in stashes:
            for state in stashes[stash_name]:
                present_state = state
                if stash_name == "errored":
                    present_state = state.state
                hashVal = hash(str(self.scdg_graph[present_state.globals["id"]]))
                if hashVal not in dic_hash_SCDG:
                    dic_hash_SCDG[hashVal] = 1
                    dump_file[dump_id] = {
                        "status": stash_name,
                        "trace": self.scdg_graph[present_state.globals["id"]],
                    }
                    dump_id = dump_id + 1
                    self.scdg_fin.append(self.scdg_graph[present_state.globals["id"]])
                
        self.print_memory_info(main_obj, dump_file)
        
        if self.keep_inter_scdg:
            ofilename = exp_dir  + "inter_SCDG.json"
            self.log.info(ofilename)
            list_obj = []
            # Check if file exists
            if os.path.isfile(ofilename):
                with open(ofilename) as fp:
                    list_obj = json_dumper.load(fp)
            save_SCDG = open_file(ofilename, "w")
            list_obj.append(dump_file)
            json_dumper.dump(list_obj, save_SCDG)  # ,indent=4)
            save_SCDG.close()
            
    def print_memory_info(self, main_obj, dump_file):
        dump_file["sections"] = {}
        for sec in main_obj.sections:
            name = sec.name.replace("\x00", "")
            info_sec = {
                "vaddr": sec.vaddr,
                "memsize": sec.memsize,
                "is_readable": sec.is_readable,
                "is_writable": sec.is_writable,
                "is_executable": sec.is_executable,
            }
            dump_file["sections"][name] = info_sec
            self.log.info(name)
            self.log.info(dump_file["sections"][name])

    #Setup a logger, detect if the path to analyze is a single file or a directory and launch the run() function
    def start_scdg(self):
        sys.setrecursionlimit(10000)
        gc.collect()
        
        self.binary_path = "".join(self.binary_path.rstrip())
        self.nb_exps = 0
        self.current_exps = 0
        
        # (3) TODO manon: make this configurable, different level of logging
        if self.verbose:
            #logging.getLogger("SemaSCDG").handlers.clear()
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(CustomFormatter())
            self.log.addHandler(ch)
            self.log.propagate = False
            logging.getLogger("angr").setLevel("INFO")
            logging.getLogger('claripy').setLevel('INFO')
            self.log.setLevel(logging.INFO)
        else :
            self.log.setLevel(logging.ERROR)
        # import resource

        # rsrc = resource.RLIMIT_DATA
        # soft, hard = resource.getrlimit(rsrc)
        # self.log.info('Soft limit starts as  :', soft)

        # resource.setrlimit(rsrc, (1024*1024*1024*10, hard)) #limit to 10 gigabyte

        # soft, hard = resource.getrlimit(rsrc)
        # self.log.info('Soft limit changed to :', soft)
        if os.path.isfile(self.binary_path):
            self.nb_exps = 1
            self.log.info("You decide to analyse a single binary: "+ self.binary_path)
            # *|CURSOR_MARCADOR|*
            self.run( "database/SCDG/runs/" + self.exp_dir + "/")
            self.current_exps = 1
        else:
            last_family = "Unknown"
            if os.path.isdir(self.binary_path):
                subfolder = [os.path.join(self.binary_path, f) for f in os.listdir(self.binary_path) if os.path.isdir(os.path.join(self.binary_path, f))]
               
                for folder in subfolder:
                    files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f)) and not f.endswith(".zip")]
                    self.nb_exps += len(files)
                    
                self.log.info(self.nb_exps)
               
                bar_f = progressbar.ProgressBar(max_value=len(subfolder))
                bar_f.start()
                ffc = 0
                for folder in subfolder:
                    gc.collect()
                    self.log.info("You are currently building SCDG for " + folder)
                    files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f)) and not f.endswith(".zip")]
                    bar = progressbar.ProgressBar(max_value=len(files))
                    bar.start()
                    fc = 0
                    current_family = folder.split("/")[-1]
                    self.exp_dir = self.exp_dir.replace(last_family,current_family) 
                    for file in files:
                        self.binary_path = file
                        self.family = current_family
                        self.run( "database/SCDG/runs/" + self.exp_dir + "/")
                        fc+=1
                        self.current_exps += 1
                        bar.update(fc)
                    self.families += current_family
                    last_family = current_family
                    bar.finish()
                    ffc+=1
                    bar_f.update(ffc)
                bar_f.finish()
            else:
                self.log.info("Error: you should insert a folder containing malware classified in their family folders\n(Example: databases/Binaries/malware-win/small_train")
                exit(-1)

def main():
    toolc = SemaSCDG()
    toolc.start_scdg()

if __name__ == "__main__":
    main()
