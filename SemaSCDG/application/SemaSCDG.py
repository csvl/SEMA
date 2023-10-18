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
from explorer.SemaThreadCDFS import SemaThreadCDFS
from clogging.CustomFormatter import CustomFormatter
from clogging.LogBookFormatter import * # TODO
from SCDGHelper.ArgumentParserSCDG import ArgumentParserSCDG
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

    BINARY_OEP = None
    UNPACK_ADDRESS = None  # unpacking address
    VENV_DETECTED = None   # address for virtual environment obfuscation detection
    BINARY_EXECUTION_END = None
    # (2) TODO manon: cleanup the arguments (file config ? + better propagation of the argument to the different classes, ie explorers) 
    def __init__(
        self,
        timeout=600,
        max_end_state=600,
        max_step=10000000000000,
        timeout_tab=[1200, 2400, 3600],
        jump_it=10000000000000000000000000,
        loop_counter_concrete=10000000000000000000000000,
        jump_dict={},
        jump_concrete_dict={},
        max_simul_state=1,
        max_in_pause_stach=500,
        fast_main=False,
        force_symbolique_return=False,
        string_resolv=True,
        print_on=True,
        print_sm_step=False,
        print_syscall=False,
        debug_error=False,
        debug_string=False,
        is_packed=False,
        concrete_target_is_local = False
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
        
        self.new = {}
                
        #logging.getLogger("angr").setLevel("WARNING")
        #logging.getLogger("angr").setLevel("DEBUG")
        
        # create console handler with a higher log level

        self.call_sim = CustomSimProcedure(
            self.scdg, self.scdg_fin, 
            string_resolv=string_resolv, print_on=print_on, 
            print_syscall=print_syscall
        )
        
        self.hooks = PluginHooks()
        self.commands = PluginCommands()
        self.ioc = PluginIoC()
        self.eval_time = False
        
        self.families = []
        self.inputs = None
        self.expl_method = None
        self.family = None
        
        self.nb_exps = 0
        self.current_exps = 0
        self.current_exp_dir = 0
        self.keep_inter_scdg = False
        
        self.unpack_mode = None
        self.is_packed = is_packed
        self.concrete_target_is_local = concrete_target_is_local
        

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

    #Save the syscall table in a json file
    def save_sys_call_table(self, table, path):
        with open(os.path.join(path, "sys_call_table.json"), "w") as f:
            json.dump(table, f, indent=4)


    def build_scdg(self, args, is_fl=False, csv_file=None):
        # Create directory to store SCDG if it doesn't exist
        self.scdg.clear()
        self.scdg_fin.clear()
        self.call_sim.syscall_found.clear()
        self.call_sim.system_call_table.clear()
        
        # TODO check if PE file get /GUARD option (VS code) with leaf
        
        self.start_time = time.time()
        # (3) TODO manon: make it works with new version of pandas
        if csv_file:
            try:
                df = pd.read_csv(csv_file,sep=";")
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
        
        exp_dir = "database/SCDG/runs/" + args.exp_dir + "/"
        nargs = args.n_args
        disjoint_union = args.disjoint_union
        not_comp_args = args.not_comp_args
        min_size = args.min_size
        not_ignore_zero = args.not_ignore_zero
        three_edges = args.three_edges
        verbose = args.verbose_scdg
        format_out_json = args.json # TODO refactor if we add more 
        self.keep_inter_scdg = args.keep_inter_SCDG
        try:
            os.makedirs(exp_dir)
        except:
            self.log.warning("The specified output directory already exists and can contain files from previous experiment")
            
        
        self.save_conf(exp_dir)
        #self.save_conf(vars(args), exp_dir) #todo -> Add 1 argument in save_conf + modify -> it gives different information about the conf

        # Take name of the sample without full path
        self.log.info("Results wil be saved into : " + exp_dir)
        if "/" in self.inputs:
            nameFileShort = self.inputs.split("/")[-1]
        else:
            nameFileShort = self.inputs
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
            self.log.info("Exception remove filehandler")
            pass
        
        logging.getLogger().addHandler(fileHandler)
        #self.log.info(csv_file)

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
        dll = None
        proj = angr.Project(
                    self.inputs,
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
                    default_analysis_mode="symbolic" if not args.approximate else "symbolic_approximating",
        )

        # Getting from a binary file to its representation in a virtual address space
        main_obj = proj.loader.main_object
        os_obj = main_obj.os

        nbinstr = 0
        nbblocks = 0
        vaddr = 0
        memsize = 0
        if args.count_block:
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
            self.log.info("Exploration method:  " + str(self.expl_method))

        # Defining arguments given to the program (minimum is filename)
        args_binary = [nameFileShort] 
        if args.n_args:
            for i in range(args.n_args):
                args_binary.append(claripy.BVS("arg" + str(i), 8 * 16))

        # Load pre-defined syscall table
        if os_obj == "windows":
            self.call_sim.system_call_table = self.call_sim.ddl_loader.load(proj,True if (self.is_packed and False) else False,dll)
        else:
           self.call_sim.system_call_table = self.call_sim.linux_loader.load_table(proj)
           
        self.log.info("System call table loaded")
        self.log.info("System call table size : " + str(len(self.call_sim.system_call_table)))
        self.save_sys_call_table(self.call_sim.system_call_table, exp_dir)
        self.log.info("System call table saved at : " + exp_dir + "sys_call_table.json")
        #self.log.info("System call table : " + str(self.call_sim.system_call_table))
        

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
        if self.debug_error:
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
        if args.sim_file:
            with open_file(self.inputs, "rb") as f:
                cont = f.read()
            simfile = angr.SimFile(nameFileShort, content=cont)
            state.fs.insert(nameFileShort, simfile)
            pagefile = angr.SimFile("pagefile.sys", content=cont)
            state.fs.insert("pagefile.sys", pagefile)
        
        state.options.discard("LAZY_SOLVES") 
        if not (self.is_packed and self.unpack_mode == "symbion") or True:
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
        
        state.register_plugin("plugin_thread", PluginThread(self, exp_dir, proj, nameFileShort, options, args))
        
        # Create ProcessHeap struct and set heapflages to 0
        if proj.arch.name == "AMD64":
            tib_addr = state.regs.fs.concat(state.solver.BVV(0, 16))
            peb_addr = state.mem[tib_addr + 0x60].qword.resolved
            ProcessHeap = peb_addr + 0x500 #0x18
            state.mem[peb_addr + 0x10].qword = ProcessHeap
            state.mem[ProcessHeap + 0x18].dword = 0x0 # heapflags windowsvistaorgreater
            state.mem[ProcessHeap + 0x70].dword = 0x0 # heapflags else
        else:
            tib_addr = state.regs.fs.concat(state.solver.BVV(0, 16))
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

        if args.hooks:
            self.hooks.initialization(cont, is_64bits=True if proj.arch.name == "AMD64" else False)
            self.hooks.hook(state,proj,self.call_sim)
                
        # Creation of simulation managerinline_call, primary interface in angr for performing execution
        
        nthread = None if args.sthread <= 1 else args.sthread # TODO not working -> implement state_step
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
        
        if args.pre_run_thread:
            state.plugin_thread.pre_run_thread(cont, self.inputs)
                
        state.inspect.b("simprocedure", when=angr.BP_AFTER, action=self.call_sim.add_call)
        state.inspect.b("simprocedure", when=angr.BP_BEFORE, action=self.call_sim.add_call_debug)
        state.inspect.b("call", when=angr.BP_BEFORE, action=self.call_sim.add_addr_call)
        state.inspect.b("call", when=angr.BP_AFTER, action=self.call_sim.rm_addr_call)
        
        if args.count_block:
            state.inspect.b("instruction",when=angr.BP_BEFORE, action=nothing)
            state.inspect.b("instruction",when=angr.BP_AFTER, action=count)
            state.inspect.b("irsb",when=angr.BP_BEFORE, action=countblock)

        # TODO : make plugins out of these globals values
        # Globals is a simple dict already managed by Angr which is deeply copied from states to states
        
        self.setup_stash(simgr) 
        if args.runtime_run_thread:
            simgr.active[0].globals["is_thread"] = True
        
        # (3) TODO manon: move that but as serena purposes car je ne sais pas ahah
        for sec in main_obj.sections:
            name = sec.name.replace("\x00", "")
            if name == ".rsrc":
                simgr.active[0].globals["rsrc"] = sec.vaddr
        
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
        
        simgr.stashes["deadbeef"] = []
        
        simgr.stashes["lost"] = []
        
        exploration_tech = self.get_exploration_tech(args, exp_dir, nameFileShort, simgr)
        
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
        
        if args.post_run_thread:
            state.plugin_thread.post_run_thread(simgr)
        
        if args.count_block:
            self.log.info("Total number of blocks: " + str(nbblocks))
            self.log.info("Total number of instr: " + str(nbinstr))
            self.log.info("Number of blocks visited: " + str(len(block_dict)))
            self.log.info("Number of instr visited: " + str(len(instr_dict)))
        
        self.log.info("Syscalls Found:" + str(self.call_sim.syscall_found))
        self.log.info("Loaded libraries:" + str(proj.loader.requested_names))
        
        total_env_var = state.plugin_env_var.ending_state(simgr)
                    
        total_registery = state.plugin_registery.ending_state(simgr)
                    
        total_locale = state.plugin_locale_info.ending_state(simgr)
                    
        total_res = state.plugin_resources.ending_state(simgr)
                    
        self.log.info("Environment variables:" + str(total_env_var))
        self.log.info("Registery variables:" + str(total_registery))
        self.log.info("Locale informations variables:" + str(total_locale))
        self.log.info("Resources variables:" + str(total_res))
        
        elapsed_time = time.time() - self.start_time
        self.log.info("Total execution time: " + str(elapsed_time))
        
        if args.track_command:
            self.commands.track(simgr, self.scdg, exp_dir)
        if args.ioc_report:
            self.ioc.build_ioc(self.scdg, exp_dir)
        # Build SCDG
        self.log.info(exp_dir)
        self.build_scdg_fin(exp_dir, nameFileShort, main_obj, state, simgr)
        
        g = GraphBuilder(
            name=nameFileShort,
            mapping="mapping.txt", # (2) TODO manon: make this configurable, i propose a mapping file with the name of the binary and the absolute path to avoid errors
            merge_call=(not disjoint_union),
            comp_args=(not not_comp_args),
            min_size=min_size,
            ignore_zero=(not not_ignore_zero),
            three_edges=three_edges,
            odir=exp_dir,
            verbose=verbose,
            family=self.family
        )
        g.build_graph(self.scdg_fin, format_out_json=format_out_json)
        
        # (3) TODO manon: make this work with new version of pandas :(
        if csv_file:
            df = df.concat({"family":self.family,
                            "filename": nameFileShort, 
                             "time": elapsed_time,
                             "date":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                             
                             "Syscall found": json.dumps(self.call_sim.syscall_found),  # (3) TODO manon: with the configuration of plugins, verify that the plugin is enable before 
                             "EnvVar found": json.dumps(total_env_var), 
                             "Locale found": json.dumps(total_locale), 
                             "Resources found": json.dumps(total_res), 
                             "Registry found": json.dumps(total_registery), 
                             
                             "Number Address found": 0, 
                             "Number Syscall found": len(self.call_sim.syscall_found), 
                             "Libraries":str(proj.loader.requested_names),
                             "OS": proj.loader.main_object.os,
                             "CPU architecture": proj.loader.main_object.arch.name,
                             "Entry point": proj.loader.main_object.entry,
                             "Min/Max addresses": str(proj.loader.main_object.mapped_base) + "/" + str(proj.loader.main_object.max_addr),
                             "Stack executable": proj.loader.main_object.execstack,
                             "Binary position-independent:": proj.loader.main_object.pic,
                             "Total number of blocks": nbblocks,
                             "Total number of instr": nbinstr,
                             "Number of blocks visited": len(block_dict),
                             "Number of instr visited": len(instr_dict),
                            }, 
                           ignore_index=True)
            self.log.info(csv_file)
            df.to_csv(csv_file, index=False,sep=";")
        logging.getLogger().removeHandler(fileHandler)

    def get_exploration_tech(self, args, exp_dir, nameFileShort, simgr):
        exploration_tech = SemaExplorerDFS(
            simgr, 0, exp_dir, nameFileShort, self
        )
        if self.expl_method == "CDFS":
            exploration_tech = SemaExplorerCDFS(
                simgr, 0, exp_dir, nameFileShort, self
            )
        elif self.expl_method == "CBFS":
            exploration_tech = SemaExplorerCBFS(
                simgr, 0, exp_dir, nameFileShort, self
            )
        elif self.expl_method == "BFS":
            exploration_tech = SemaExplorerBFS(
                simgr, 0, exp_dir, nameFileShort, self
            )
        elif self.expl_method == "SCDFS":
            exploration_tech = SemaExplorerAnotherCDFS(
                simgr, 0, args.exp_dir, nameFileShort, self
            )
        elif self.expl_method == "DBFS":
            exploration_tech = SemaExplorerDBFS(
                simgr, 0, args.exp_dir, nameFileShort, self
            )
        elif self.expl_method == "SDFS":
            exploration_tech = SemaExplorerSDFS(
                simgr, 0, args.exp_dir, nameFileShort, self
            )
        elif self.expl_method == "ThreadCDFS":
            exploration_tech = SemaThreadCDFS(
                simgr, 0, args.exp_dir, nameFileShort, self
            )
            
        return exploration_tech


    def setup_stash(self, tsimgr):
        tsimgr.active[0].globals["id"] = 0
        tsimgr.active[0].globals["JumpExcedeed"] = False
        tsimgr.active[0].globals["JumpTable"] = {}
        tsimgr.active[0].globals["n_steps"] = 0
        tsimgr.active[0].globals["n_forks"] = 0
        tsimgr.active[0].globals["last_instr"] = 0
        tsimgr.active[0].globals["counter_instr"] = 0
        tsimgr.active[0].globals["loaded_libs"] = {}
        tsimgr.active[0].globals["addr_call"] = []
        tsimgr.active[0].globals["loop"] = 0
        tsimgr.active[0].globals["crypt_algo"] = 0
        tsimgr.active[0].globals["crypt_result"] = 0
        tsimgr.active[0].globals["n_buffer"] = 0
        tsimgr.active[0].globals["n_calls"] = 0
        tsimgr.active[0].globals["recv"] = 0
        tsimgr.active[0].globals["rsrc"] = 0
        tsimgr.active[0].globals["resources"] = {}
        tsimgr.active[0].globals["df"] = 0
        tsimgr.active[0].globals["files"] = {}
        tsimgr.active[0].globals["n_calls_recv"] = 0
        tsimgr.active[0].globals["n_calls_send"] = 0
        tsimgr.active[0].globals["n_buffer_send"] = 0
        tsimgr.active[0].globals["buffer_send"] = []
        tsimgr.active[0].globals["files"] = {}
        tsimgr.active[0].globals["FindFirstFile"] = 0
        tsimgr.active[0].globals["FindNextFile"] = 0
        tsimgr.active[0].globals["GetMessageA"] = 0
        tsimgr.active[0].globals["GetLastError"] = claripy.BVS("last_error", 32)
        tsimgr.active[0].globals["HeapSize"] = {}
        tsimgr.active[0].globals["CreateThread"] = 0
        tsimgr.active[0].globals["CreateRemoteThread"] = 0
        tsimgr.active[0].globals["condition"] = ""
        tsimgr.active[0].globals["files_fd"] = {}
        tsimgr.active[0].globals["create_thread_address"] = []
        tsimgr.active[0].globals["is_thread"] = False
        tsimgr.active[0].globals["recv"] = 0
        tsimgr.active[0].globals["allow_web_interaction"] = False
        

    def build_scdg_fin(self, exp_dir, nameFileShort, main_obj, state, simgr):
        dump_file = {}
        dump_id = 0
        dic_hash_SCDG = {}
        # (3) TODO manon: refactor if time, a litle bit ugly now :(
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
                self.scdg_fin.append(self.scdg[stateDead.globals["id"]])

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
            hashVal = hash(str(self.scdg[error.state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "errored",
                    "trace": self.scdg[error.state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg[error.state.globals["id"]])

        for state in simgr.pause:
            hashVal = hash(str(self.scdg[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "pause",
                    "trace": self.scdg[state.globals["id"]],
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
                
        for state in simgr.stashes["new_addr"]:
            hashVal = hash(str(self.scdg[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "new_addr",
                    "trace": self.scdg[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg[state.globals["id"]])
                
        for state in simgr.stashes["deadbeef"]:
            hashVal = hash(str(self.scdg[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "deadbeef",
                    "trace": self.scdg[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg[state.globals["id"]])
                
        for state in simgr.stashes["lost"]:
            hashVal = hash(str(self.scdg[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "lost",
                    "trace": self.scdg[state.globals["id"]],
                }
                dump_id = dump_id + 1
                self.scdg_fin.append(self.scdg[state.globals["id"]])
                
        self.print_memory_info(main_obj, dump_file)
        
        if self.keep_inter_scdg:
            # self.log.info(dump_file)
            ofilename = exp_dir  + "inter_SCDG.json"
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

    def start_scdg(self, args, is_fl=False,csv_file=None):
        sys.setrecursionlimit(10000)
        gc.collect()
        
        self.inputs = "".join(self.inputs.rstrip())
        self.nb_exps = 0
        self.current_exps = 0
        
        # (3) TODO manon: make this configurable, different level of logging
        if args.verbose_scdg:
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
        if os.path.isfile(self.inputs):
            self.nb_exps = 1
            # TODO update family
            self.log.info("You decide to analyse a single binary: "+ self.inputs)
            # *|CURSOR_MARCADOR|*
            self.build_scdg(args,is_fl=is_fl,csv_file=csv_file)
            self.current_exps = 1
        else:
            import progressbar
            last_family = "Unknown"
            if os.path.isdir(self.inputs):
                subfolder = [os.path.join(self.inputs, f) for f in os.listdir(self.inputs) if os.path.isdir(os.path.join(self.inputs, f))]
               
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
                    if not is_fl:
                        args.exp_dir = args.exp_dir.replace(last_family,current_family) 
                    else:
                        args["exp_dir"] = args["exp_dir"].replace(last_family,current_family) 
                    for file in files:
                        self.inputs = file
                        self.family = current_family
                        self.build_scdg(args, is_fl, csv_file=csv_file)
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
    toolc = SemaSCDG(
        print_sm_step=True,
        print_syscall=True,
        debug_error=True,
        debug_string=True,
        print_on=True
    )
    args_parser = ArgumentParserSCDG()
    args = args_parser.parse_arguments()
    toolc = args_parser.update_tool(args, toolc)
    toolc.start_scdg(args, is_fl=False,csv_file=None)

if __name__ == "__main__":
    main()

            
