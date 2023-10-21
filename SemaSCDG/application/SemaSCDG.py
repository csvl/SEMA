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
import configparser

from SCDGHelper.GraphBuilder import *
from procedures.CustomSimProcedure import *
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
from explorer.SemaExploreDFS_Modif import SemaExplorerDFS_Modif
from explorer.SemaThreadCDFS import SemaThreadCDFS
from clogging.CustomFormatter import CustomFormatter
from clogging.LogBookFormatter import * # TODO
#from SCDGHelper.ArgumentParserSCDG import ArgumentParserSCDG
from sandboxes.CuckooInterface import CuckooInterface

import avatar2 as avatar2

from unipacker.core import Sample, SimpleClient, UnpackerEngine
from unipacker.utils import RepeatedTimer, InvalidPEFile
#from angr_targets import AvatarGDBConcreteTarget # TODO FIX in submodule

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# (2) TODO manon: Use python code convention for module, classes, etc
class SemaSCDG():
    """
    TODO
    """
    #TODO Christophe : check config files -> good ? 
    def __init__(self):
        config = configparser.ConfigParser()
        config.read('config.ini')
        self.start_time = time.time()

        # TODO Christophe : not proposed in the web app -> add if useful
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
        self.hooks_enable = config['SCDG_arg'].getboolean('hooks')
        self.sim_file = config['SCDG_arg'].getboolean('sim_file')
        self.count_block = config['SCDG_arg'].getboolean('count_block')
        self.expl_method = config['SCDG_arg']["expl_method"]
        self.family = config['SCDG_arg']['family']
        self.exp_dir = config['SCDG_arg']['exp_dir'] + "/" + self.family
        self.binary_path = config['SCDG_arg']['binary_path']
        self.n_args = int(config['SCDG_arg']['n_args'])
        self.csv_file = config['SCDG_arg']['csv_file']

        self.config = config

        self.scdg_graph = []
        self.scdg_fin = []
        self.new = {}

        self.call_sim = CustomSimProcedure(
            self.scdg_graph, self.scdg_fin, 
            string_resolv=self.string_resolve, verbose=self.verbose, 
            print_syscall=self.print_syscall
        )
        
        self.hooks = PluginHooks()
        self.commands = PluginCommands()
        self.ioc = PluginIoC()
        
        self.families = []
        
        self.nb_exps = 0
        self.current_exps = 0
        self.current_exp_dir = 0

    #Save the configuration of the experiment in a json file
    def save_conf(self, path):
        attributes = {}
        for attr in dir(self):
            if not attr.startswith("__") and not callable(getattr(self, attr)):
                value = getattr(self, attr)
                try:
                    json.dumps(value)
                    attributes[attr] = value
                except TypeError:
                    pass
        with open(os.path.join(path, "scdg_conf.json"), "w") as f:
            json.dump(attributes, f, indent=4)

    #Check if the csv file exists, if not, create and return a Dataframe
    def setup_csv(self):
        try:
            df = pd.read_csv(self.csv_file,sep=";")
            self.log.info(df)
        except:
            df = pd.DataFrame(
                columns=["family",
                            "filename", 
                            "time",
                            "date",
                            "Syscall found", 
                            "EnvVar found",
                            "Locale found",
                            "Resources found",
                            "Registry found",
                            "Address found", 
                            "Libraries",
                            "OS",
                            "CPU architecture",
                            "Entry point",
                            "Min/Max addresses",
                            "Stack executable",
                            "Binary position-independent",
                            "Total number of blocks",
                            "Total number of instr",
                            "Number of blocks visited",
                            "Number of instr visited",
                            ]) # TODO add frame type
        return df
    
    def save_to_csv(self, df, proj, stats):
        to_append = pd.DataFrame({"family":self.family,
                    "filename": stats["nameFileShort"], 
                    "time": stats["elapsed_time"],
                    "date":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    
                    "Syscall found": json.dumps(self.call_sim.syscall_found),  # (3) TODO manon: with the configuration of plugins, verify that the plugin is enable before 
                    "EnvVar found": json.dumps(stats["total_env_var"]), 
                    "Locale found": json.dumps(stats["total_locale"]), 
                    "Resources found": json.dumps(stats["total_res"]), 
                    "Registry found": json.dumps(stats["total_registery"]), 
                    
                    "Number Address found": 0, 
                    "Number Syscall found": len(self.call_sim.syscall_found), 
                    "Libraries":str(proj.loader.requested_names),
                    "OS": proj.loader.main_object.os,
                    "CPU architecture": proj.loader.main_object.arch.name,
                    "Entry point": proj.loader.main_object.entry,
                    "Min/Max addresses": str(proj.loader.main_object.mapped_base) + "/" + str(proj.loader.main_object.max_addr),
                    "Stack executable": proj.loader.main_object.execstack,
                    "Binary position-independent:": proj.loader.main_object.pic,
                    "Total number of blocks": stats["nbblocks"],
                    "Total number of instr": stats["nbinstr"],
                    "Number of blocks visited": len(stats["block_dict"]),
                    "Number of instr visited": len(stats["instr_dict"]),
                }, index=[1])
        df = pd.concat([df, to_append], ignore_index=True)
        self.log.info(self.csv_file)
        df.to_csv(self.exp_dir + self.csv_file, index=False,sep=";")


    def build_scdg(self):
        # Create directory to store SCDG if it doesn't exist
        self.scdg_graph.clear()
        self.scdg_fin.clear()
        self.call_sim.syscall_found.clear()
        self.call_sim.system_call_table.clear()
        stats = dict()
        
        # TODO check if PE file get /GUARD option (VS code) with leaf
        
        self.start_time = time.time()

        df = None
        if self.csv_file != "":
            df = self.setup_csv()
        
        self.exp_dir = "database/SCDG/runs/" + self.exp_dir + "/"
        try:
            os.makedirs(self.exp_dir)
        except:
            self.log.warning("The specified output directory already exists and can contain files from previous experiment")
            
        
        self.save_conf(self.exp_dir)
        #self.save_conf(vars(args), exp_dir) #todo -> Add 1 argument in save_conf + modify -> it gives different information about the conf

        # Take name of the sample without full path
        self.log.info("Results wil be saved into : " + self.exp_dir)
        if "/" in self.binary_path:
            nameFileShort = self.binary_path.split("/")[-1]
        else:
            nameFileShort = self.binary_path
        stats["nameFileShort"] = nameFileShort
        try:
            os.stat(self.exp_dir + nameFileShort)
        except:
            os.makedirs(self.exp_dir + nameFileShort)
        fileHandler = logging.FileHandler(self.exp_dir + nameFileShort + "/" + "scdg.ans")
        fileHandler.setFormatter(CustomFormatter())
        #logging.getLogger().handlers.clear()
        try:
            logging.getLogger().removeHandler(fileHandler)
        except:
            self.log.info("Exception remove filehandler")
            pass
        
        logging.getLogger().addHandler(fileHandler)

        self.exp_dir = self.exp_dir + nameFileShort + "/"
        
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
        elif self.is_packed and self.packing_type == "unipacker":
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
                self.packing_type = "symbion"
                self.build_scdg(nameFile)
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
            dll = None
            main_opt = {"entry_point": 0x401500} # 0x4014e0
            proj = angr.Project(
                    self.binary_path,
                    use_sim_procedures=True,
                    load_options={
                        "auto_load_libs": True,
                        "load_debug_info": True,
                        #"preload_libs": libs,
                    },  # ,load_options={"auto_load_libs":False}
                    support_selfmodifying_code=True,
                    #main_opts=main_opt,
                    #simos = "windows"if nameFile.endswith(".bin") or nameFile.endswith(".dmp") else None
                    # arch="",
                    default_analysis_mode="symbolic" if not self.approximate else "symbolic_approximating",
            )

        # Getting from a binary file to its representation in a virtual address space
        main_obj = proj.loader.main_object
        os_obj = main_obj.os

        nbinstr = 0
        nbblocks = 0
        vaddr = 0
        memsize = 0
        if self.count_block:
            # count total number of blocks and instructions
            for sec in main_obj.sections:
                name = sec.name.replace("\x00", "")
                if name == ".text":
                    vaddr = sec.vaddr
                    memsize = sec.memsize
            i = vaddr
            
            while i < vaddr + memsize:
                block = proj.factory.block(i)
                nbinstr += block.instructions
                nbblocks += 1
                if len(block.bytes) == 0:
                    i += 1
                    nbblocks -= 1
                else:
                    i += len(block.bytes)
        stats["nbblocks"] = nbblocks  
        stats["nbinstr"] = nbinstr 
            
        # Informations about program
        if self.verbose:
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
            self.log.info("Exploration method:  " + str(self.expl_method))

        # Defining arguments given to the program (minimum is filename)
        args_binary = [nameFileShort] 
        if self.n_args:
            for i in range(self.n_args):
                args_binary.append(claripy.BVS("arg" + str(i), 8 * 16))

        # Load pre-defined syscall table
        if os_obj == "windows":
            self.call_sim.system_call_table = self.call_sim.ddl_loader.load(proj,True if (self.is_packed and False) else False,dll)
        else:
           self.call_sim.system_call_table = self.call_sim.linux_loader.load_table(proj)
           
        self.log.info("System call table loaded")
        self.log.info("System call table size : " + str(len(self.call_sim.system_call_table)))
        
        # TODO : Maybe useless : Try to directly go into main (optimize some binary in windows)
        addr_main = proj.loader.find_symbol("main")
        if addr_main and self.fast_main:
            addr = addr_main.rebased_addr
        else:
            addr = None

        # (3) TODO manon: make this configurable, this part is used to start the execution at a specific address
        # Wabot
        # addr = 0x004081fc
        # addr = 0x00401500
        # addr = 0x00406fac
        
        # MagicRAT
        # addr = 0x40139a # 
        # addr = 0x6f7100 # 0x5f4f10 0x01187c00 0x40139a
        # addr = 0x06fda90
        # addr = 0x06f7e90
        
        # Create initial state of the binary
        # (3) TODO manon: make this configurable
        options = {angr.options.MEMORY_CHUNK_INDIVIDUAL_READS} #{angr.options.USE_SYSTEM_TIMES} # {angr.options.SIMPLIFY_MEMORY_READS} # angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS {angr.options.SYMBOLIC_INITIAL_VALUES
        # options.add(angr.options.EFFICIENT_STATE_MERGING)
        # options.add(angr.options.DOWNSIZE_Z3)
        options.add(angr.options.USE_SYSTEM_TIMES)
        # options.add(angr.options.OPTIMIZE_IR)
        # options.add(angr.options.FAST_MEMORY)
        # options.add(angr.options.SIMPLIFY_MEMORY_READS)
        # options.add(angr.options.SIMPLIFY_MEMORY_WRITES)
        # options.add(angr.options.SIMPLIFY_CONSTRAINTS)
        # options.add(angr.options.SYMBOLIC_INITIAL_VALUES)
        # options.add(angr.options.CPUID_SYMBOLIC)
        options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        # options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        # options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
        # options.add(angr.options.MEMORY_CHUNK_INDIVIDUAL_READS)
        # options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
            
        # options.add(angr.options.UNICORN)
        # options.add(angr.options.UNICORN_SYM_REGS_SUPPORT)
        # options.add(angr.options.UNICORN_HANDLE_TRANSMIT_SYSCALL)
        if self.verbose:
            pass
            # options.add(angr.options.TRACK_JMP_ACTIONS)
            # options.add(angr.options.TRACK_CONSTRAINT_ACTIONS)
            # options.add(angr.options.TRACK_JMP_ACTIONS)

        self.log.info("Entry_state address = " + str(addr))
        # Contains a program's memory, registers, filesystem data... any "live data" that can be changed by execution has a home in the state
        state = proj.factory.entry_state(
            addr=addr, args=args_binary, add_options=options
        )
        # import pdb
        # pdb.set_trace()
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
        
        # (3) TODO manon: make this configurable to enable/disable the plugins
        state.register_plugin("plugin_env_var", PluginEnvVar()) 
        state.plugin_env_var.setup_plugin(self.expl_method)
                    
        state.register_plugin("plugin_locale_info", PluginLocaleInfo()) 
        state.plugin_locale_info.setup_plugin()
        
        state.register_plugin("plugin_resources", PluginResources())
        state.plugin_resources.setup_plugin()
        
        state.register_plugin("plugin_widechar", PluginWideChar())
                
        state.register_plugin("plugin_registery", PluginRegistery())
        state.plugin_registery.setup_plugin()
        
        state.register_plugin("plugin_atom", PluginAtom())  
        
        state.register_plugin("plugin_thread", PluginThread(self, self.exp_dir, proj, nameFileShort, options))
        
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
            self.call_sim.loadlibs(proj) #TODO mbs=symbs,dll=dll)
        
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
        
        nthread = None #if args.sthread <= 1 else args.sthread # TODO not working -> implement state_step
        simgr = proj.factory.simulation_manager(state,threads=nthread)
        
        dump_file = {}
        self.print_memory_info(main_obj, dump_file)    
        
        #####################################################
        ##########         Exploration           ############
        #####################################################

        # (3) TODO manon: move that to PluginHook
        # This function is used to show the addresses exectuted with : state.inspect.b("instruction",when=angr.BP_BEFORE, action=nothing)
        # Peut etre rename la function
        # Rajouter un parameter eventuellement pour ajouter ou non la feature

        def nothing(state):
            if False:
                print(hex(state.addr))
                    
        instr_dict = {}
        def count(state):
            if state.addr not in instr_dict:
                instr_dict[state.addr] = 1
                
        block_dict = {}
        def countblock(state):
            if state.inspect.address not in block_dict:
                block_dict[state.inspect.address] = 1
                
        # Improved "Break point"
        
        if self.pre_run_thread:
            state.plugin_thread.pre_run_thread(cont, self.binary_path)
                
        state.inspect.b("simprocedure", when=angr.BP_AFTER, action=self.call_sim.add_call)
        state.inspect.b("simprocedure", when=angr.BP_BEFORE, action=self.call_sim.add_call_debug)
        state.inspect.b("call", when=angr.BP_BEFORE, action=self.call_sim.add_addr_call)
        state.inspect.b("call", when=angr.BP_AFTER, action=self.call_sim.rm_addr_call)
        
        if self.count_block:
            state.inspect.b("instruction",when=angr.BP_BEFORE, action=nothing)
            state.inspect.b("instruction",when=angr.BP_AFTER, action=count)
            state.inspect.b("irsb",when=angr.BP_BEFORE, action=countblock)

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

        exploration_tech = self.get_exploration_tech(nameFileShort, simgr)
        
        self.log.info(proj.loader.all_pe_objects)
        self.log.info(proj.loader.extern_object)
        self.log.info(proj.loader.symbols)
        
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
        
        if self.count_block:
            self.log.info("Total number of blocks: " + str(nbblocks))
            self.log.info("Total number of instr: " + str(nbinstr))
            self.log.info("Number of blocks visited: " + str(len(block_dict)))
            self.log.info("Number of instr visited: " + str(len(instr_dict)))
        
        self.log.info("Syscalls Found:" + str(self.call_sim.syscall_found))
        self.log.info("Loaded libraries:" + str(proj.loader.requested_names))
        
        total_env_var = state.plugin_env_var.ending_state(simgr)
        stats["total_env_var"] = total_env_var
                    
        total_registery = state.plugin_registery.ending_state(simgr)
        stats["total_registery"] = total_registery
                    
        total_locale = state.plugin_locale_info.ending_state(simgr)
        stats["total_locale"] = total_locale
                    
        total_res = state.plugin_resources.ending_state(simgr)
        stats["total_res"] = total_res
                    
        self.log.info("Environment variables:" + str(total_env_var))
        self.log.info("Registery variables:" + str(total_registery))
        self.log.info("Locale informations variables:" + str(total_locale))
        self.log.info("Resources variables:" + str(total_res))
        
        elapsed_time = time.time() - self.start_time
        stats["elapsed_time"] = elapsed_time
        self.log.info("Total execution time: " + str(elapsed_time))
        
        if self.track_command:
            self.commands.track(simgr, self.scdg_graph, self.exp_dir)
        if self.ioc_report:
            self.ioc.build_ioc(self.scdg_graph, self.exp_dir)
        # Build SCDG
        self.log.info(self.exp_dir)
        self.build_scdg_fin(nameFileShort, main_obj, state, simgr)
        
        g = GraphBuilder(
            name=nameFileShort,
            mapping="mapping.txt", # (2) TODO manon: make this configurable, i propose a mapping file with the name of the binary and the absolute path to avoid errors
            merge_call=(not self.config['build_graph_arg'].getboolean('disjoint_union')),
            comp_args=(not self.config['build_graph_arg'].getboolean('not_comp_args')),
            min_size=int(self.config['build_graph_arg']['min_size']),
            ignore_zero=(not self.config['build_graph_arg'].getboolean('not_ignore_zero')),
            three_edges=self.config['build_graph_arg'].getboolean('three_edges'),
            odir=self.exp_dir,
            verbose=self.verbose,
            family=self.family
        )
        g.build_graph(self.scdg_fin, graph_output=self.config['build_graph_arg']['graph_output'])
        
        if df is not None:
            stats["block_dict"] = block_dict
            stats["instr_dict"] = instr_dict
            self.save_to_csv(df, proj=proj, stats=stats)

        logging.getLogger().removeHandler(fileHandler)

    def get_exploration_tech(self, nameFileShort, simgr):
        # exploration_tech = SemaExplorerDFS(
        #     simgr, 0, self.exp_dir, nameFileShort, self
        # )
        # if self.expl_method == "CDFS":
        #     exploration_tech = SemaExplorerCDFS(
        #         simgr, 0, self.exp_dir, nameFileShort, self
        #     )
        # elif self.expl_method == "CBFS":
        #     exploration_tech = SemaExplorerCBFS(
        #         simgr, 0, self.exp_dir, nameFileShort, self
        #     )
        # elif self.expl_method == "BFS":
        #     exploration_tech = SemaExplorerBFS(
        #         simgr, 0, self.exp_dir, nameFileShort, self
        #     )
        # elif self.expl_method == "SCDFS":
        #     exploration_tech = SemaExplorerAnotherCDFS(
        #         simgr, 0, self.exp_dir, nameFileShort, self
        #     )
        # elif self.expl_method == "DBFS":
        #     exploration_tech = SemaExplorerDBFS(
        #         simgr, 0, self.exp_dir, nameFileShort, self
        #     )
        # elif self.expl_method == "SDFS":
        #     exploration_tech = SemaExplorerSDFS(
        #         simgr, 0, self.exp_dir, nameFileShort, self
        #     )
        # elif self.expl_method == "ThreadCDFS":
        #     exploration_tech = SemaThreadCDFS(
        #         simgr, 0, self.exp_dir, nameFileShort, self
        #     )

        exploration_tech = SemaExplorerDFS_Modif(
            simgr, self.exp_dir, nameFileShort, self.scdg_graph, self.call_sim
        )
            
        return exploration_tech



        

    def build_scdg_fin(self, nameFileShort, main_obj, state, simgr):
        dump_file = {}
        dump_id = 0
        dic_hash_SCDG = {}
        # (3) TODO manon: refactor if time, a litle bit ugly now :(
        # Add all traces with relevant content to graph construction
        for stateDead in simgr.deadended:
            hashVal = hash(str(self.scdg_graph[stateDead.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "deadended",
                    "trace": self.scdg_graph[stateDead.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg_graph[stateDead.globals["id"]])

        for state in simgr.active:
            hashVal = hash(str(self.scdg_graph[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "active",
                    "trace": self.scdg_graph[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])

        for error in simgr.errored:
            hashVal = hash(str(self.scdg_graph[error.state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "errored",
                    "trace": self.scdg_graph[error.state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg_graph[error.state.globals["id"]])

        for state in simgr.pause:
            hashVal = hash(str(self.scdg_graph[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "pause",
                    "trace": self.scdg_graph[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])

        for state in simgr.stashes["ExcessLoop"]:
            hashVal = hash(str(self.scdg_graph[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "ExcessLoop",
                    "trace": self.scdg_graph[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])

        for state in simgr.stashes["ExcessStep"]:
            hashVal = hash(str(self.scdg_graph[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "ExcessStep",
                    "trace": self.scdg_graph[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])

        for state in simgr.unconstrained:
            hashVal = hash(str(self.scdg_graph[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "unconstrained",
                    "trace": self.scdg_graph[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])
                
        for state in simgr.stashes["new_addr"]:
            hashVal = hash(str(self.scdg_graph[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "new_addr",
                    "trace": self.scdg_graph[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])
                
        for state in simgr.stashes["deadbeef"]:
            hashVal = hash(str(self.scdg_graph[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "deadbeef",
                    "trace": self.scdg_graph[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])
                
        for state in simgr.stashes["lost"]:
            hashVal = hash(str(self.scdg_graph[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "lost",
                    "trace": self.scdg_graph[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])
                
        self.print_memory_info(main_obj, dump_file)
        
        if self.keep_inter_scdg:
            # self.log.info(dump_file)
            ofilename = self.exp_dir  + "inter_SCDG.json"
            self.log.info(ofilename)
            list_obj = []
            # Check if file exists
            if os.path.isfile(ofilename):
                # Read JSON file
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

    def start_scdg(self):
        sys.setrecursionlimit(10000)
        gc.collect()
        
        self.binary_path = "".join(self.binary_path.rstrip())
        self.nb_exps = 0
        self.current_exps = 0
        
        # (3) TODO manon: make this configurable, different level of logging
        if self.verbose:
            logging.getLogger("SemaSCDG").handlers.clear()
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(CustomFormatter())
            self.log = logging.getLogger("SemaSCDG")
            self.log.addHandler(ch)
            self.log.propagate = False
            logging.getLogger("angr").setLevel("INFO")
            logging.getLogger('claripy').setLevel('INFO')
            self.log.setLevel(logging.INFO)
        else :
            self.log = logging.getLogger("SemaSCDG")
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
            # TODO update family
            self.log.info("You decide to analyse a single binary: "+ self.binary_path)
            # *|CURSOR_MARCADOR|*
            self.build_scdg()
            self.current_exps = 1
        else:
            import progressbar
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
                        self.build_scdg()
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

            
