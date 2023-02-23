#!/usr/bin/env python3
from ast import arg
import datetime
import os
import sys
from collections import defaultdict
from typing import Optional, Set, List, Tuple, Dict, TYPE_CHECKING
from angr.knowledge_plugins.functions import Function
# for pypy3
# sys.path.insert(0, '/usr/local/lib')
# sys.path.insert(0, os.path.expanduser('~/lib'))
# sys.path.insert(0, os.path.expanduser('/home/crochetch/Documents/toolchain_malware_analysis/penv/lib'))
from pprint import pprint, pformat
from collections import defaultdict

import json as json_dumper
from builtins import open as open_file
import threading
import time

# from submodules.claripy import claripy
import claripy
import monkeyhex  # this will format numerical results in hexadecimal
import logging
from capstone import *
from angrutils import * 
# Syscall table stuff
import angr
from angr.sim_type import SimTypeInt, SimTypePointer, SimTypeArray, SimTypeChar

import gc

# Personnal stuf
try:
    from .helper.GraphBuilder import *
    from .procedures.CustomSimProcedure import *
    from .plugin.PluginEnvVar import *
    from .plugin.PluginLocaleInfo import *
    from .plugin.PluginRegistery import *
    from .plugin.PluginHooks import *
    from .plugin.PluginWideChar import *
    from .plugin.PluginResources import *
    from .plugin.PluginEvasion import *
    from .explorer.SemaExplorerDFS import SemaExplorerDFS
    from .explorer.SemaExplorerCDFS import SemaExplorerCDFS
    from .explorer.SemaExplorerBFS import SemaExplorerBFS
    from .explorer.SemaExplorerCBFS import SemaExplorerCBFS
    from .explorer.SemaExplorerSDFS import SemaExplorerSDFS
    from .explorer.SemaExplorerDBFS import SemaExplorerDBFS
    from .explorer.SemaThreadCDFS import SemaThreadCDFS
    from .explorer.SemaExplorerAnotherCDFS import SemaExplorerAnotherCDFS
    from .clogging.CustomFormatter import CustomFormatter
    from .clogging.LogBookFormatter import *
    from .helper.ArgumentParserSCDG import ArgumentParserSCDG
except:
    from helper.GraphBuilder import *
    from procedures.CustomSimProcedure import *
    from plugin.PluginEnvVar import *
    from plugin.PluginLocaleInfo import *
    from plugin.PluginRegistery import *
    from plugin.PluginHooks import *
    from plugin.PluginWideChar import *
    from plugin.PluginResources import *
    from plugin.PluginEvasion import *
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
    from helper.ArgumentParserSCDG import ArgumentParserSCDG

import angr
import claripy
import pandas as pd

import matplotlib.pyplot as plt
import numpy as np

import shutil

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

class SemaSCDG:
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
        max_step=10000000000000,
        timeout_tab=[1200, 2400, 3600],
        jump_it=10000000000000,
        loop_counter_concrete=1000000000000,
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
        is_from_tc = False,
        is_from_web = False,
        is_fl = False
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
            print_syscall=print_syscall, is_from_tc=is_from_tc, is_from_web=is_from_web
        )
        
        self.hooks = PluginHooks()
        self.eval_time = False
        
        self.families = []
        self.inputs = None
        self.expl_method = None
        self.familly = None
        
        self.nb_exps = 0
        self.current_exps = 0
        self.current_exp_dir = 0
        self.discard_scdg = True
        
    def save_conf(self, args, path):
        with open(os.path.join(path, "scdg_conf.json"), "w") as f:
            json.dump(args, f, indent=4)

    def build_scdg(self, args, is_fl=False, csv_file=None):
        # Create directory to store SCDG if it doesn't exist
        self.scdg.clear()
        self.scdg_fin.clear()
        self.call_sim.syscall_found.clear()
        self.call_sim.system_call_table.clear()
        
        # TODO check if PE file get /GUARD option (VS code) with leaf
        
        self.start_time = time.time()
        if csv_file:
            try:
                df = pd.read_csv(csv_file,sep=";")
                print(df)
            except:
                df = pd.DataFrame(
                    columns=["familly",
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
        
        if not is_fl:
            exp_dir = args.exp_dir
            nargs = args.n_args
            disjoint_union = args.disjoint_union
            not_comp_args = args.not_comp_args
            min_size = args.min_size
            not_ignore_zero = args.not_ignore_zero
            three_edges = args.three_edges
            dir = args.dir
            verbose = args.verbose_scdg
            format_out_json = args.json # TODO refactor if we add more 
            self.discard_scdg = args.discard_SCDG
        else:
            exp_dir = args["exp_dir"]
            nargs = args["n_args"]
            disjoint_union = args["disjoint_union"]
            not_comp_args = args["not_comp_args"]
            min_size = args["min_size"]
            not_ignore_zero = args["not_ignore_zero"]
            three_edges = args["three_edges"]
            dir = args["dir"]
            verbose = args["verbose_scdg"]
            format_out_json = args["json"]
            self.discard_scdg = args["discard_SCDG"]
        try:
            os.stat(args.exp_dir)
        except:
            os.makedirs(exp_dir)
            
        self.log.info(args)

        if exp_dir != "output/runs/"+ str(self.current_exp_dir) + "/":
            setup = open_file("src/output/runs/"+ str(self.current_exp_dir) + "/" + "setup.txt", "w")
            setup.write(str(self.jump_it) + "\n")
            setup.write(str(self.loop_counter_concrete) + "\n")
            setup.write(str(self.max_simul_state) + "\n")
            setup.write(str(self.max_in_pause_stach) + "\n")
            setup.write(str(self.max_step) + "\n")
            setup.write(str(self.max_end_state))
            setup.close()

        # Take name of the sample without full path
        if "/" in self.inputs:
            nameFileShort = self.inputs.split("/")[-1]
        else:
            nameFileShort = self.inputs
        try:
            os.stat(exp_dir + "/" +  nameFileShort)
        except:
            os.makedirs(exp_dir + "/" +  nameFileShort)
        
        fileHandler = logging.FileHandler(exp_dir + "/" + nameFileShort + "/" + "scdg.log")
        fileHandler.setFormatter(CustomFormatter())
        #logging.getLogger().handlers.clear()
        try:
            logging.getLogger().removeHandler(fileHandler)
        except:
            self.log.info("Exeption remove filehandle")
            pass
        
        logging.getLogger().addHandler(fileHandler)
        self.log.info(csv_file)


        exp_dir = exp_dir + "/" + nameFileShort + "/"
        #dir = dir + "/" + nameFileShort + "/"
        print(exp_dir,dir)
        
        title = "--- Building SCDG of " + self.familly  +"/" + nameFileShort  + " ---"
        self.log.info("\n" + "-" * len(title) + "\n" + title + "\n" + "-" * len(title))

        #####################################################
        ##########      Project creation         ############
        #####################################################
        """
        TODO : Note for further works : support_selfmodifying_code should be investigated
        """

        # Load a binary into a project = control base
        proj = angr.Project(
                self.inputs,
                use_sim_procedures=True,
                load_options={
                    "auto_load_libs": True
                },  # ,load_options={"auto_load_libs":False}
                support_selfmodifying_code=True,
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
                "Entry point of the binary recognized as : " + str(proj.entry)
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
        args_binary = [nameFileShort] #, ,"-developer-build", "-opensource", "-nomake examples", "-nomake tests",'CFLAGS=-mno-aes',"-mno-aes" 'LDFLAGS="-L/usr/local/lib"'] ,"-msse3"
        if args.n_args:
            for i in range(args.n_args):
                args_binary.append(claripy.BVS("arg" + str(i), 8 * 16))

        # Load pre-defined syscall table
        if os_obj == "windows":
            self.call_sim.system_call_table = self.call_sim.ddl_loader.load(proj)
        else:
           self.call_sim.system_call_table = self.call_sim.linux_loader.load_table(proj)
        

        # TODO : Maybe useless : Try to directly go into main (optimize some binary in windows)
        addr_main = proj.loader.find_symbol("main")
        if addr_main and self.fast_main:
            addr = addr_main.rebased_addr
        else:
            addr = None

        # Wabot
        # addr = 0x004081fc
        # addr = 0x00401500
        # addr = 0x00406fac
        
        # MagicRAT
        # addr = 0x40139a # 
        # addr = 0x6f7100 # 0x5f4f10 0x01187c00 0x40139a
        
        # Create initial state of the binary
        options =  {angr.options.USE_SYSTEM_TIMES} # angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS {angr.options.SYMBOLIC_INITIAL_VALUES
        # options.add(angr.options.EFFICIENT_STATE_MERGING)
        # options.add(angr.options.DOWNSIZE_Z3)
        
        # Already present in "symbolic mode"
        # options.add(angr.options.OPTIMIZE_IR)
        # options.add(angr.options.FAST_MEMORY)
        
        # options.add(angr.options.SIMPLIFY_MEMORY_READS)
        # options.add(angr.options.SIMPLIFY_MEMORY_WRITES)
        # options.add(angr.options.SIMPLIFY_CONSTRAINTS)
        # options.add(angr.options.SYMBOLIC_INITIAL_VALUES)
        
        # options.add(angr.options.CPUID_SYMBOLIC) # for sse3 support
        
        options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS) # remove for magicRAT
        options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
         
        options.add(angr.options.MEMORY_CHUNK_INDIVIDUAL_READS)
        # options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
        # options.add(angr.options.TRACK_JMP_ACTIONS)
        # options.add(angr.options.TRACK_CONSTRAINT_ACTIONS)
        # options.add(angr.options.TRACK_JMP_ACTIONS)

        self.log.info("Entry_state address = " + str(addr))
        # Contains a program's memory, registers, filesystem data... any "live data" that can be changed by execution has a home in the state
        state = proj.factory.entry_state(
            addr=addr, args=args_binary, add_options=options
        )
        
        if args.sim_file:
            with open_file(self.inputs, "rb") as f:
                cont = f.read()
            simfile = angr.SimFile(nameFileShort, content=cont)
            state.fs.insert(nameFileShort, simfile)
        
        state.options.discard("LAZY_SOLVES") 
        state.register_plugin(
            "heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc(heap_size=int(64*4096*10*10*10*4*2*2*2*2*2*2)) # heap_size = 0x10000000
        ) #heap_size = 0x10000000
        
        state.libc.max_variable_size = 0x20000000*2 + 0x18000000#128 * 3
        # # Allocate memory for the OSVERSIONINFOW structure and initialize its size field
        # os_version_info_size = 24 + 128 * state.arch.bytes
        # os_version_info_ptr = state.heap._malloc(os_version_info_size)
        # state.memory.store(os_version_info_ptr, SimTypeInt().with_arch(state.arch), size=os_version_info_size)

        
        self.setup_env_var_plugin(state)
        self.setup_locale_info_plugin(state)
        self.setup_resources_plugin(state)
        self.setup_widechar_plugin(state)
        self.setup_registery_plugin(state)
        
        
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
        # for i in range(1, len(args_binary)):
        #    for byte in args_binary[i].chop(8):
        #        # state.add_constraints(byte != '\x00') # null
        #        state.add_constraints(byte >= " ")  # '\x20'
        #        state.add_constraints(byte <= "~")  # '\x7e'

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
            self.call_sim.loadlibs(proj)
        
        self.call_sim.custom_hook_static(proj)

        if os_obj != "windows":
            self.call_sim.custom_hook_no_symbols(proj)
        else:
            self.call_sim.custom_hook_windows_symbols(proj)

        if args.sim_file:
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
        
        def nothing(state):
            if True:
                self.log.info(hex(state.addr))
        
        def weed_sig_pass(state):
            if state.addr == 0x401000:
                state.regs.eax = 0x1       
                    
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
            thread_func = ["CreateThread","CreateRemoteThread"]
            for thread_f in thread_func:
                if thread_f in main_obj.imports:
                    self.log.info("CreateThread - Import addresses")
                    self.log.info(main_obj.imports[thread_f])
                    self.log.info("CreateThread - Relative address")
                    self.log.info(0x400000 + main_obj.imports[thread_f].relative_addr)
                    createThreadAddr = int.to_bytes(0x400000 + main_obj.imports[thread_f].relative_addr,length=4, byteorder='little', signed=True)
                
                    pe_header       = int.from_bytes(cont[0x3c:0x40],"little")
                    size_of_headers = int.from_bytes(cont[pe_header+0x54:pe_header+0x54+4],"little")
                    base_of_code    = int.from_bytes(cont[pe_header+0x2c:pe_header+0x2c+4],"little")
                    image_base      = int.from_bytes(cont[pe_header+0x34:pe_header+0x34+4],"little")
                    total           = base_of_code+image_base-size_of_headers
                    jmp_create_thread = [m.start()+total for m in re.finditer(b"\xff\x25"+createThreadAddr,cont)]
                    jmp_create_thread.reverse()
                    call_create_thred = [m.start()+total for m in re.finditer(b"\xff\x15"+createThreadAddr,cont)]
                    call_create_thred.reverse()
                    
                    self.log.info("CreateThread - JMP addresses")
                    self.log.info(jmp_create_thread)
                    self.log.info("CreateThread - CALL addresses")
                    self.log.info(call_create_thred) 
                
                    addresses = [0x400000 + main_obj.imports[thread_f].relative_addr] + jmp_create_thread + call_create_thred
                    
                    # some error, see penv-fix/angr
                    # TODO serena try both
                    proj_static = angr.Project(
                        self.inputs,
                        use_sim_procedures=True,
                        load_options={
                            "auto_load_libs": True
                        },  # ,load_options={"auto_load_libs":False}
                        support_selfmodifying_code=True,
                        # arch="",
                        default_analysis_mode="static",
                    )
                    cfg =  proj_static.analyses.CFG(show_progressbar=True,
                                            detect_tail_calls=True,
                                            force_complete_scan=True,
                                            force_smart_scan=False,
                                            force_segment=True,
                                            function_prologues=True,
                                            use_patches=False,
                                            data_references=True,
                                            normalize=True,
                                            function_starts=addresses,
                                            #context_sensitivity_level=2, # base 0
                                            cross_references=False, # can bug
                                            #sp_tracking_track_memory=True, # not x86
                                            skip_unmapped_addrs=False,
                                            exclude_sparse_regions=False,
                                            skip_specific_regions=False,
                                            indirect_jump_target_limit=100000*1000,
                                            nodecode_window_size=512*2,
                                            nodecode_threshold=0.3*2,
                                            nodecode_step=16483*2)
                    
                    # self.log.info("Plot CFG")
                    # plot_cfg(cfg, "cfg", asminst=True, 
                    #          remove_imports=True, debug_info=True,
                    #          remove_path_terminator=True)  
                    
                    
                    # shutil.move("cfg.png",exp_dir + "/" + nameFileShort + "/" + "cfg.png")

                    # copy_state = state.copy()
                    # copy_state.globals["id"] = 0
                    # copy_state.globals["JumpExcedeed"] = False
                    # copy_state.globals["JumpTable"] = {}
                    # copy_state.globals["n_steps"] = 0
                    # copy_state.globals["last_instr"] = 0
                    # copy_state.globals["counter_instr"] = 0
                    # copy_state.globals["loaded_libs"] = {}
                    # copy_state.globals["addr_call"] = []
                    # copy_state.globals["loop"] = 0
                    # copy_state.globals["crypt_algo"] = 0
                    # copy_state.globals["crypt_result"] = 0
                    
                    # copy_state.globals["n_buffer"] = 0
                    # copy_state.globals["rsrc"] = 0
                    # copy_state.globals["n_calls_recv"] = 0
                    
                    # copy_state.globals["n_calls_send"] = 0
                    # copy_state.globals["n_buffer_send"] = 0
                    # copy_state.globals["buffer_send"] = []
                    
                    # copy_state.globals["files"] = {}
            
                    # #proj.analyses.CompleteCallingConventions(recover_variables=True)
                    # cfg =  proj.analyses.CFGEmulated(keep_state=True,
                    #                                  initial_state=copy_state,
                    #                                  show_progressbar=True)
                
                    # self.manage_thread(exp_dir, nameFileShort, proj, options, state, cfg, 0x400000 + main_obj.imports[thread_f].relative_addr)
                    
                    self.log.info("Proceeding JMP threads:")
                    if len(jmp_create_thread) > 0:
                        for jmp in jmp_create_thread:
                            self.log.info(hex(jmp))    
                            self.manage_thread(exp_dir, nameFileShort, proj, options, state, cfg, jmp) # proj_static
                    self.log.info("Proceeding CALL threads:")      
                    if len(call_create_thred) > 0:
                        for call in call_create_thred:
                            self.log.info(hex(call))      
                            self.manage_thread(exp_dir, nameFileShort, proj, options, state, cfg, call)
                            
                    print('end')
                    #exit()
                
        state.inspect.b("simprocedure", when=angr.BP_AFTER, action=self.call_sim.add_call)
        state.inspect.b("simprocedure", when=angr.BP_BEFORE, action=self.call_sim.add_call_debug)
        state.inspect.b("call", when=angr.BP_BEFORE, action=self.call_sim.add_addr_call)
        state.inspect.b("call", when=angr.BP_AFTER, action=self.call_sim.rm_addr_call)
        
        if args.count_block:
            # state.inspect.b("instruction",when=angr.BP_BEFORE, action=weed_sig_pass)
            state.inspect.b("instruction",when=angr.BP_BEFORE, action=nothing)
            state.inspect.b("instruction",when=angr.BP_AFTER, action=count)
            state.inspect.b("irsb",when=angr.BP_BEFORE, action=countblock)

        # TODO : make plugins out of these globals values
        # Globals is a simple dict already managed by Angr which is deeply copied from states to states
        
        self.setup_stash(simgr) 
        if args.runtime_run_thread:
            simgr.active[0].globals["is_thread"] = True
        
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
            self.log.info("Run post-thread analysis")
            done = []
            for state in simgr.deadended + simgr.active + simgr.stashes["pause"]:
                if len(state.globals["create_thread_address"]) > 0:
                    self.log.info(state.globals["create_thread_address"])
                    for elem in state.globals["create_thread_address"]:
                        if elem not in done:
                            self.log.info(state.globals["create_thread_address"])
                            self.log.info(elem)
                            self.run_thread(exp_dir, nameFileShort, proj, options,None,state=elem["new_state"],args=args)
                            done.append(elem)
        
        if args.count_block:
            self.log.info("Total number of blocks: " + str(nbblocks))
            self.log.info("Total number of instr: " + str(nbinstr))
            self.log.info("Number of blocks visited: " + str(len(block_dict)))
            self.log.info("Number of instr visited: " + str(len(instr_dict)))
        
        self.log.info("Syscalls Found:" + str(self.call_sim.syscall_found))
        self.log.info("Loaded libraries:" + str(proj.loader.requested_names))
        
        
        total_env_var = {}
        for sstate in simgr.deadended + simgr.active + simgr.stashes["pause"]:
            for key in sstate.plugin_env_var.env_var_requested.keys():
                if key not in total_env_var:
                    total_env_var[key] = []
                    if sstate.plugin_env_var.env_var_requested[key] not in total_env_var[key]:
                        total_env_var[key].append(sstate.plugin_env_var.env_var_requested[key])
                else:
                    if sstate.plugin_env_var.env_var_requested[key] not in total_env_var[key]:
                        total_env_var[key].append(sstate.plugin_env_var.env_var_requested[key])
                    
        total_registery = {}
        for sstate in simgr.deadended + simgr.active + simgr.stashes["pause"]:
            for key in sstate.plugin_registery.registery.keys():
                if key not in total_registery:
                    total_registery[key] = []
                    if sstate.plugin_registery.registery[key] not in total_registery[key]:
                        total_registery[key].append(sstate.plugin_registery.registery[key])
                else:
                    if sstate.plugin_registery.registery[key] not in total_registery[key]:
                        total_registery[key].append(sstate.plugin_registery.registery[key])
                    
        total_locale = {}
        for sstate in simgr.deadended + simgr.active + simgr.stashes["pause"]:
            for key in sstate.plugin_locale_info.locale_info.keys():
                if key not in total_locale:
                    total_locale[key] = []
                    if sstate.plugin_locale_info.locale_info[key] not in total_locale[key]:
                        total_locale[key].append(sstate.plugin_locale_info.locale_info[key])
                else:
                    if sstate.plugin_locale_info.locale_info[key] not in total_locale[key]:
                        total_locale[key].append(sstate.plugin_locale_info.locale_info[key])
                    
        total_res = {}
        for sstate in simgr.deadended + simgr.active + simgr.stashes["pause"]:
            for key in sstate.plugin_resources.resources.keys():
                if key not in total_res:
                    total_res[key] = []
                    if sstate.plugin_resources.resources[key] not in total_res[key]:
                        total_res[key].append(sstate.plugin_resources.resources[key])
                else:
                    if sstate.plugin_resources.resources[key] not in total_res[key]:
                        total_res[key].append(sstate.plugin_resources.resources[key])
                    
        self.log.info("Environment variables:" + str(total_env_var))
        self.log.info("Registery variables:" + str(total_registery))
        self.log.info("Locale informations variables:" + str(total_locale))
        self.log.info("Resources variables:" + str(total_res))
        
        elapsed_time = time.time() - self.start_time
        self.log.info("Total execution time: " + str(elapsed_time))
        
        # Track the buffer containing commands
        if args.track_command:
            for state in simgr.deadended + simgr.active + simgr.stashes["pause"]:
                buffers_recv = []
                calls_recv = {}
                calls_send = {}
                brutto_result = ""
                for key, symbol in state.solver.get_variables("buffer"):
                    eve = state.solver.eval(symbol)
                    if eve != 0:
                        try:
                            command = state.mem[eve].string.concrete
                            if len(command) > 0:
                                if hasattr(command,'decode'):
                                    command= command.decode('utf-8')
                                buffers_recv.append(command)
                            else:
                                buffers_recv.append(hex(eve))
                        except:
                            buffers_recv.append(hex(eve))
                if len(buffers_recv) > 0:
                    print(buffers_recv)
                buffers_send = []
                #for symbol in state.globals["buffer_send"]:
                for buf,l in state.globals["buffer_send"]:
                    eve = state.solver.eval(state.memory.load(buf,l))
                    if eve != 0:
                        try:
                            command = state.mem[eve].string.concrete
                            if len(command) > 0:
                                if hasattr(command,'decode'):
                                    command= command.decode('utf-8')
                                buffers_send.append(command)
                            else:
                                buffers_send.append(hex(eve))
                        except:
                            buffers_send.append(hex(eve))           
                        # if hasattr(command,'decode'):
                        #     command= command.decode('utf-8')
                        # buffers_send.append(command)
                if len(buffers_send) > 0:
                    print(buffers_send)
                recv_cnt = 0
                send_cnt = 0
                if len(buffers_recv) > 0:
                    brutto_result += hex(state.addr) + " : "  + "\n"
                    # for buf in buffers_recv:
                    #     brutto_result += "     - " + buf + "\n"
                    for dic in self.scdg[state.globals["id"]][state.globals["n_calls_recv"]:]:
                        if dic["name"]  not in calls_recv:
                            brutto_result += "         * " + dic["name"] 
                            if "recv" in dic["name"]:
                                brutto_result += "(" + str(buffers_recv[recv_cnt]) + ")"
                                recv_cnt += 1
                            brutto_result += "\n"
                            calls_recv[dic["name"] ] = 1
                if len(buffers_send) > 0:
                    brutto_result += hex(state.addr) + " : "  + "\n"
                    # for buf in buffers_recv:
                    #     brutto_result += "     - " + buf + "\n"
                    for dic in self.scdg[state.globals["id"]][state.globals["n_calls_send"]:]:
                        if dic["name"]  not in calls_send:
                            brutto_result += "         * " + dic["name"] 
                            if "send" in dic["name"]:
                                brutto_result += "(" + str(buffers_send[send_cnt]) + ")"
                                send_cnt += 1
                            brutto_result += "\n"
                            calls_send[dic["name"] ] = 1
                
                
                try:
                    with open_file(exp_dir + "commands.log", 'r') as f:
                        content = f.read()
                        with open_file(exp_dir + "commands.log", 'w') as f:
                            f.write(content + brutto_result + '\n')
                except:
                    with open_file(exp_dir + "commands.log", 'w') as f:
                        f.write(brutto_result + '\n')
            #self.warzone(exp_dir,simgr,tracked)
        
        # Build SCDG
        self.build_scdg_fin(exp_dir, nameFileShort, main_obj, state, simgr)
        g = GraphBuilder(
            name=nameFileShort,
            mapping="mapping.txt",
            merge_call=(not disjoint_union),
            comp_args=(not not_comp_args),
            min_size=min_size,
            ignore_zero=(not not_ignore_zero),
            three_edges=three_edges,
            odir=dir,
            verbose=verbose,
            familly=self.familly
        )
        g.build_graph(self.scdg_fin, format_out_json=format_out_json)
        
        if csv_file:
            df = df.append({"familly":self.familly,
                            "filename": nameFileShort, 
                             "time": elapsed_time,
                             "date":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                             
                             "Syscall found": json.dumps(self.call_sim.syscall_found), 
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
            print(csv_file)
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

    def manage_thread(self, exp_dir, nameFileShort, proj, options, state, cfg, jmp):
        if jmp not in cfg.kb.functions:
            self.log.info("jmp NOT IN cfg.kb.functions")    
            node = cfg.get_any_node(jmp)
            if node is None:
                self.log.warning("%r is not in the CFG. Skip calling convention analysis at call sites.", jmp)
                return
            in_edges = cfg.graph.in_edges(node, data=True)
            call_sites_by_function: Dict['Function',List[Tuple[int,int]]] = defaultdict(list)
            for src, _, data in in_edges:
                edge_type = data.get('jumpkind', 'Ijk_Call')
                if edge_type != 'Ijk_Call':
                    continue
                if not cfg.kb.functions.contains_addr(src.function_address):
                    continue
                caller = cfg.kb.functions[src.function_address]
                cc_analysis = proj.analyses.CallingConvention(caller, cfg=cfg, analyze_callsites=True)
                caller = cc_analysis.kb.functions[src.function_address]
                if caller.is_simprocedure:
                                # do not analyze SimProcedures
                    continue
                call_sites_by_function[caller].append((src.addr, src.instruction_addrs[-1]))
            call_sites_by_function_list = list(call_sites_by_function.items())[:3]
            for caller, call_sites in call_sites_by_function_list:
                print(call_sites)
                for site in call_sites:
                    self.run_thread(exp_dir, nameFileShort, proj, options, site)
                    
                for b in caller.block_addrs:
                    print(b)
                    self.run_thread(exp_dir, nameFileShort, proj, options, [b])
            self.run_thread(exp_dir, nameFileShort, proj, options, [jmp])
            return
        
        self.log.info("jmp IN cfg.kb.functions")    
        f = cfg.kb.functions[jmp]
        f.calling_convention = SimCCStdcall(proj.arch)
       
        #f.calling_convention = SimCCStdcall(proj.arch)
        self.log.info(f.name)
        #blank_state = proj.factory.blank_state()
                    
        prop = proj.analyses.Propagator(func=f, base_state=state)
        # Collect all the refs
        proj.analyses.XRefs(func=f, replacements=prop.replacements)
        #thread_func = cfg.kb.functions[jmp]
        self.log.info("Thread func:")
        self.log.info(f)
        _ = proj.analyses.VariableRecoveryFast(f) # TODO usefull ?
        cc_analysis = proj.analyses.CallingConvention(f, cfg=cfg, analyze_callsites=True)
        self.log.info("Thread args:")
        self.log.info(cc_analysis.prototype.args)  
        node = cfg.get_any_node(jmp)
        if node is None:
            self.log.warning("%r is not in the CFG. Skip calling convention analysis at call sites.", jmp)
        in_edges = cfg.graph.in_edges(node, data=True)
        call_sites_by_function: Dict['Function',List[Tuple[int,int]]] = defaultdict(list)
        for src, _, data in in_edges:
            print(src)
            print(data)
            edge_type = data.get('jumpkind', 'Ijk_Call')
            print(edge_type)
            print("")
            # if edge_type != 'Ijk_Call':
            #     continue
            # if not cc_analysis.kb.functions.contains_addr(src.function_address):
            #     continue
            caller = cc_analysis.kb.functions[src.function_address]
            # if caller.is_simprocedure:
            #                 # do not analyze SimProcedures
            #     continue
            call_sites_by_function[caller].append((src.addr, src.instruction_addrs[-1]))
        call_sites_by_function_list = list(call_sites_by_function.items())[:3]
        self.log.info("Call sites list:")
        self.log.info(call_sites_by_function_list)
        for caller, call_sites in call_sites_by_function_list:
            self.log.info("Call sites")
            self.log.info(call_sites)
            for site in call_sites:
                self.run_thread(exp_dir, nameFileShort, proj, options, site)
        self.log.info("Blocks sites list:")
        self.log.info(f.block_addrs)
        for b in f.block_addrs:
            self.log.info("Blocks address")
            self.log.info(b)
            self.run_thread(exp_dir, nameFileShort, proj, options,[b])

    def run_thread(self, exp_dir, nameFileShort, proj, options, site, state=None, args=None):
        #exit()
        if not state: # pre thread
            tstate = proj.factory.entry_state(addr=site[0], add_options=options)
        else:         # post thread
            tstate=state
            #tstate.globals["id"] = tstate.globals["id"] + 1
        
        if args:
            nthread = None if args.sthread <= 1 else args.sthread
        else:
            nthread = None
            
        tsimgr = proj.factory.simulation_manager(tstate,threads=nthread)
        tsimgr._techniques = []  
        
        if not state:
            tstate.options.discard("LAZY_SOLVES")
            tstate.register_plugin("heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc(heap_size =int(64*4096*10*10*10*4*2)))
            
            self.setup_env_var_plugin(tstate)
            self.setup_locale_info_plugin(tstate)
            self.setup_resources_plugin(tstate)
            self.setup_widechar_plugin(tstate)
            self.setup_registery_plugin(tstate)
                                
            # Create ProcessHeap struct and set heapflages to 0
            tib_addr = tstate.regs.fs.concat(tstate.solver.BVV(0, 16))
            peb_addr = tstate.mem[tib_addr + 0x30].dword.resolved
            ProcessHeap = peb_addr + 0x500
            tstate.mem[peb_addr + 0x18].dword = ProcessHeap
            tstate.mem[ProcessHeap+0xc].dword = 0x0  #heapflags windowsvistaorgreater
            tstate.mem[ProcessHeap+0x40].dword = 0x0 #heapflags else
            
            self.hooks.hook(tstate,proj)
                
            tstate.inspect.b("simprocedure", when=angr.BP_AFTER, action=self.call_sim.add_call)
            tstate.inspect.b("simprocedure", when=angr.BP_BEFORE, action=self.call_sim.add_call_debug)
            tstate.inspect.b("call", when=angr.BP_BEFORE, action=self.call_sim.add_addr_call)
            tstate.inspect.b("call", when=angr.BP_AFTER, action=self.call_sim.rm_addr_call)
            
            tsimgr.stashes["pause"] = []
            tsimgr.stashes["new_addr"] = []
            tsimgr.stashes["ExcessLoop"] = []
            tsimgr.stashes["ExcessStep"] = []          
            tsimgr.stashes["deadbeef"] = []
            tsimgr.stashes["lost"] = []
            
        self.setup_stash(tsimgr)
        tsimgr.active[0].globals["is_thread"] = True
                            
        exploration_tech_thread = self.get_exploration_tech(args, exp_dir, nameFileShort, tsimgr)
        tsimgr.use_technique(exploration_tech_thread)

        self.log.info("\n------------------------------\nStart -State of simulation manager :\n "
                     + str(tsimgr)
                    + "\n------------------------------")
                                
        tsimgr.run()
        self.build_scdg_fin(exp_dir, nameFileShort, proj.loader.main_object, tstate, tsimgr)

    def setup_env_var_plugin(self, tstate):
        tstate.register_plugin("plugin_env_var", PluginEnvVar())  # For environment variable mainly
        tstate.plugin_env_var.env_block = tstate.heap.malloc(32767) 
        for i in range(32767):
            c = tstate.solver.BVS("c_env_block{}".format(i), 8)
            tstate.memory.store(tstate.plugin_env_var.env_block + i, c)
        
        windows_env_vars = {
            "ALLUSERSPROFILE": "C:\\ProgramData",
            "APPDATA": "C:\\Users\\ElNiak\\AppData\\Roaming",
            "CommonProgramFiles": "C:\\Program Files\\Common Files",
            "COMPUTERNAME": "ElNiak",
            "COMSPEC": "C:\\Windows\\system32\\cmd.exe",
            "DRIVERDATA": "C:\\Windows\\System32\\Drivers\\DriverData",
            "HOMEDRIVE": "C:",
            "HOMEPATH": "\\Users\\ElNiak",
            "LOCALAPPDATA": "C:\\Users\\ElNiak\\AppData\\Local",
            "LOGONSERVER": "\\\\[DomainControllerName]",
            "NUMBER_OF_PROCESSORS": "8",
            "OS": "Windows_NT",
            "Path": "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
            "PATHEXT": ".COM;.EXE;.BAT;.CMD;.VBS;.VBgetenvE;.JS;.JSE;.WSF;.WSH;.MSC",
            "PROCESSOR_ARCHITECTURE": "AMD64",
            "PROCESSOR_IDENTIFIER": "Intel64 Family 6 Model 58 Stepping 9, GenuineIntel",
            "PROCESSOR_LEVEL": "6",
            "PROCESSOR_REVISION": "3a09",
            "ProgramData": "C:\\ProgramData",
            "ProgramFiles": "C:\\Program Files",
            "ProgramFiles(x86)": "C:\\Program Files (x86)",
            "ProgramW6432": "C:\\Program Files",
            "PSModulePath": "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules\\",
            "PUBLIC": "C:\\Users\\Public",
            "SystemDrive": "C:",
            "SystemRoot": "C:\\Windows",
            "TEMP": "C:\\Users\\ElNiak\\AppData\\Local\\Temp",
            "TMP": "C:\\Users\\ElNiak\\AppData\\Local\\Temp",
            "USERPROFILE": "C:\\Users\\ElNiak",
            "windir": "C:\\Windows",
            
            "QT_NO_CPU_FEATURE":"", # rdrand
            "UNICODEMAP_JP":"unicode-ascii",
            "QT_LOGGING_TO_CONSOLE":"0",
            "QT_ASSUME_STDERR_HAS_CONSOLE":"0",
            "QT_HASH_SEED":"0",
            "QT_FORCE_STDERR_LOGGING":"0",
            "QT_USE_NATIVE_WINDOWS":"1",
            "QT_MESSAGE_PATTERN": "", #"[%{time yyyyMMdd h:mm:ss.zzz t} %{if-debug}D%{endif}%{if-info}I%{endif}%{if-warning}W%{endif}%{if-critical}C%{endif}%{if-fatal}F%{endif}] %{file}:%{line} - %{message}\0\0"
        }
        env_var_str = b""
        for env_var in windows_env_vars.keys():
            env_var_val = (env_var + "=")
            env_var_val += (windows_env_vars[env_var] + "\x00\x00")
            env_var_str += env_var_val.encode("utf-8")
            tstate.plugin_env_var.env_var[env_var.upper()] = windows_env_vars[env_var]
            # wenv_var_val = (env_var + "=")
            # wenv_var_val += (windows_env_vars[env_var] + "\x00\x00")
            #wenv_var_str += wenv_var_val.encode("utf-8")
            tstate.plugin_env_var.wenv_var[env_var.upper().encode("utf-16-le")] = windows_env_vars[env_var].encode("utf-16-le")
        
        env_var_bv = tstate.solver.BVV(env_var_str)
        tstate.memory.store(tstate.plugin_env_var.env_block, env_var_bv)
        tstate.plugin_env_var.expl_method = self.expl_method
        
    def setup_locale_info_plugin(self, tstate):
        tstate.register_plugin("plugin_locale_info", PluginLocaleInfo())  # For locale info mainly
        tstate.plugin_locale_info.locale_info_block = tstate.heap.malloc(32767) 
        for i in range(32767):
            c = tstate.solver.BVS("c_locale_info_block{}".format(i), 8)
            tstate.memory.store(tstate.plugin_locale_info.locale_info_block + i, c)
        tstate.plugin_locale_info.expl_method = self.expl_method
        
    def setup_resources_plugin(self, tstate):
        tstate.register_plugin("plugin_resources", PluginResources())  # For locale info mainly
        tstate.plugin_resources.res_block = tstate.heap.malloc(32767) 
        for i in range(32767):
            c = tstate.solver.BVS("c_res_block{}".format(i), 8)
            tstate.memory.store(tstate.plugin_resources.res_block + i, c)
        
        tstate.plugin_resources.expl_method = self.expl_method
    
    def setup_widechar_plugin(self, tstate):
        tstate.register_plugin("plugin_widechar", PluginWideChar())  # For locale info mainly
        
            
    def setup_registery_plugin(self, tstate):
        tstate.register_plugin("plugin_registery", PluginRegistery())  # For registeries info mainly
        tstate.plugin_registery.registery_block = tstate.heap.malloc(32767) 
        for i in range(32767):
            c = tstate.solver.BVS("c_registery_block{}".format(i), 8)
            tstate.memory.store(tstate.plugin_registery.registery_block + i, c)

        tstate.plugin_registery.expl_method = self.expl_method

    def setup_stash(self, tsimgr):
        tsimgr.active[0].globals["id"] = 0
        tsimgr.active[0].globals["JumpExcedeed"] = False
        tsimgr.active[0].globals["JumpTable"] = {}
        tsimgr.active[0].globals["n_steps"] = 0
        tsimgr.active[0].globals["last_instr"] = 0
        tsimgr.active[0].globals["counter_instr"] = 0
        tsimgr.active[0].globals["loaded_libs"] = {}
        tsimgr.active[0].globals["addr_call"] = []
        tsimgr.active[0].globals["loop"] = 0
        
        tsimgr.active[0].globals["crypt_algo"] = 0
        tsimgr.active[0].globals["crypt_result"] = 0
                                
        tsimgr.active[0].globals["n_buffer"] = 0
        tsimgr.active[0].globals["rsrc"] = 0
        tsimgr.active[0].globals["n_calls_recv"] = 0
                            
        tsimgr.active[0].globals["n_calls_send"] = 0
        tsimgr.active[0].globals["n_buffer_send"] = 0
        tsimgr.active[0].globals["buffer_send"] = []
                            
        tsimgr.active[0].globals["files"] = {}
        
        tsimgr.active[0].globals["df"]  = 0
                
        tsimgr.active[0].globals["create_thread_address"] = []
        tsimgr.active[0].globals["is_thread"] = False
        
        tsimgr.active[0].globals["FindFirstFile"] = 0
        tsimgr.active[0].globals["FindNextFile"] = 0
        tsimgr.active[0].globals["GetMessageA"] = 0
        tsimgr.active[0].globals["GetLastError"] = claripy.BVS("last_error", 32)
        tsimgr.active[0].globals["recv"] = 0
        tsimgr.active[0].globals["HeapSize"] = {}
        
        tsimgr.active[0].globals["allow_web_interaction"] = False
        
        #exit()

    def warzone(self,exp_dir,simgr,tracked):
        dump_file = {}
        dump_id = 0
        
        for state in simgr.deadended:
            dump_file[dump_id] = {"status" : "dead",
                                  "buffers" : tracked[state.globals["id"]],
                                  "trace" : self.scdg[state.globals["id"]][state.globals["n_calls_recv"]:]
                                  }
            dump_id = dump_id + 1
            
        for state in simgr.active:
            dump_file[dump_id] = {"status" : "active",
                                  "buffers" : tracked[state.globals["id"]],
                                  "trace" : self.scdg[state.globals["id"]][state.globals["n_calls_recv"]:]
                                  }
            dump_id = dump_id + 1
            
        for state in simgr.stashes["pause"]:
            dump_file[dump_id] = {"status" : "pause",
                                  "buffers" : tracked[state.globals["id"]],
                                  "trace" : list(set(dic["name"] for dic in self.scdg[state.globals["id"]][state.globals["n_calls_recv"]:]))
                                  }
            dump_id = dump_id + 1
                
                
        ofilename = exp_dir + "warzone.json"
        self.log.info(ofilename)
        save_SCDG = open_file(ofilename, "w")
        json_dumper.dump(dump_file, save_SCDG)
        save_SCDG.close()

    def build_scdg_fin(self, exp_dir, nameFileShort, main_obj, state, simgr):
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
                
        for error in simgr.pause:
            hashVal = hash(str(self.scdg[state.globals["id"]]))
            if hashVal not in dic_hash_SCDG:
                dic_hash_SCDG[hashVal] = 1
                dump_file[dump_id] = {
                    "status": "pause",
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
        
        if self.discard_scdg:
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
        
        if args.verbose_scdg:
            logging.getLogger("SemaSCDG").handlers.clear()
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(CustomFormatter())
            self.log = logging.getLogger("SemaSCDG")
            self.log.addHandler(ch)
            self.log.propagate = False
            logging.getLogger("angr").setLevel("WARNING")
            logging.getLogger('claripy').setLevel('WARNING')
            self.log.setLevel(logging.INFO)
        else:
            # logging.getLogger('claripy').disabled = True
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(CustomFormatter())
            self.log = logging.getLogger("SemaSCDG")
            self.log.addHandler(ch)
            self.log.propagate = False
            self.log.setLevel(logging.INFO)
        
        # import resource

        # rsrc = resource.RLIMIT_DATA
        # soft, hard = resource.getrlimit(rsrc)
        # print('Soft limit starts as  :', soft)

        # resource.setrlimit(rsrc, (1024*1024*1024*10, hard)) #limit to 10 gigabyte

        # soft, hard = resource.getrlimit(rsrc)
        # print('Soft limit changed to :', soft)

        print(self.inputs)
        if os.path.isfile(self.inputs):
            self.nb_exps = 1
            # TODO update familly
            self.log.info("You decide to analyse a single binary: "+ self.inputs)
            # *|CURSOR_MARCADOR|*
            try:
                self.build_scdg(args,is_fl=is_fl,csv_file=csv_file)
            except Exception as e:
                self.log.info(e)
                self.log.info("Error: "+file+" is not a valid binary")
            self.current_exps = 1
        else:
            import progressbar
            last_familiy = "unknown"
            if os.path.isdir(self.inputs):
                subfolder = [os.path.join(self.inputs, f) for f in os.listdir(self.inputs) if os.path.isdir(os.path.join(self.inputs, f))]
               
                for folder in subfolder:
                    files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f)) and not f.endswith(".zip")]
                    self.nb_exps += len(files)
                    
                print(self.nb_exps)
               
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
                        args.exp_dir = args.exp_dir.replace(last_familiy,current_family) 
                    else:
                        args["exp_dir"] = args["exp_dir"].replace(last_familiy,current_family) 
                    for file in files:
                        self.inputs = file
                        self.familly = current_family
                        #try:
                        self.build_scdg(args, is_fl, csv_file=csv_file)
                        # except Exception as e:
                        #     self.log.info(e)
                        #     self.log.info("Error: "+file+" is not a valid binary")
                        fc+=1
                        self.current_exps += 1
                        bar.update(fc)
                    self.families += current_family
                    last_familiy = current_family
                    bar.finish()
                    ffc+=1
                    bar_f.update(ffc)
                bar_f.finish()
            else:
                self.log.info("Error: you should insert a folder containing malware classified in their family folders\n(Example: databases/malware-inputs/Sample_paper")
                exit(-1)


def main():
    toolc = SemaSCDG(
        print_sm_step=True,
        print_syscall=True,
        debug_error=True,
        debug_string=True,
        print_on=True,
        is_from_web=False
    )
    args_parser = ArgumentParserSCDG(toolc)
    args = args_parser.parse_arguments()
    args_parser.update_tool(args)
    toolc.start_scdg(args, is_fl=False,csv_file=None)


if __name__ == "__main__":
    
    main()
            
