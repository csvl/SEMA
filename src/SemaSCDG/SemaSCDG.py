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

# Syscall table stuff
import angr

# Personnal stuf
try:
    from .helper.GraphBuilder import *
    from .procedures.CustomSimProcedure import *
    from .plugin.PluginEnvVar import *
    from .plugin.PluginHooks import *
    from .plugin.PluginEvasion import *
    from .explorer.SemaExplorerDFS import SemaExplorerDFS
    from .explorer.SemaExplorerCDFS import SemaExplorerCDFS
    from .explorer.SemaExplorerBFS import SemaExplorerBFS
    from .explorer.SemaExplorerCBFS import SemaExplorerCBFS
    from .explorer.SemaExplorerSDFS import SemaExplorerSDFS
    from .explorer.SemaExplorerDBFS import SemaExplorerDBFS
    from .explorer.SemaExplorerAnotherCDFS import SemaExplorerAnotherCDFS
    from .clogging.CustomFormatter import CustomFormatter
    from .clogging.LogBookFormatter import *
    from .helper.ArgumentParserSCDG import ArgumentParserSCDG
except:
    from helper.GraphBuilder import *
    from procedures.CustomSimProcedure import *
    from plugin.PluginEnvVar import *
    from plugin.PluginHooks import *
    from plugin.PluginEvasion import *
    from explorer.SemaExplorerDFS import SemaExplorerDFS
    from explorer.SemaExplorerCDFS import SemaExplorerCDFS
    from explorer.SemaExplorerBFS import SemaExplorerBFS
    from explorer.SemaExplorerCBFS import SemaExplorerCBFS
    from explorer.SemaExplorerSDFS import SemaExplorerSDFS
    from explorer.SemaExplorerDBFS import SemaExplorerDBFS
    from explorer.SemaExplorerAnotherCDFS import SemaExplorerAnotherCDFS
    from clogging.CustomFormatter import CustomFormatter
    from clogging.LogBookFormatter import * # TODO
    from helper.ArgumentParserSCDG import ArgumentParserSCDG

import angr
import claripy
import pandas as pd

import matplotlib.pyplot as plt
import numpy as np


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
        
        
        
    def save_conf(self, args, path):
        with open(os.path.join(path, "scdg_conf.json"), "w") as f:
            json.dump(args, f, indent=4)

    def build_scdg(self, args, is_fl=False, csv_file=None):
        # Create directory to store SCDG if it doesn't exist
        self.scdg.clear()
        self.scdg_fin.clear()
        self.call_sim.syscall_found.clear()
        self.call_sim.system_call_table.clear()
        
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
            discard_SCDG = args.discard_SCDG
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
            discard_SCDG = args["discard_SCDG"]
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
                default_analysis_mode="symbolic",
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
        args_binary = [nameFileShort]
        if args.n_args:
            for i in range(args.n_args):
                args_binary.append(claripy.BVS("arg" + str(i), 8 * 16))

        # Load pre-defined syscall table
        if os_obj == "windows":
            self.call_sim.system_call_table = self.call_sim.ddl_loader.load(proj)
        else:
           self.call_sim.system_call_table = self.call_sim.linux_loader.load_table(
                proj
            )
        

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
        # Create initial state of the binary
        
        options =  {angr.options.MEMORY_CHUNK_INDIVIDUAL_READS} # angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS {angr.options.SYMBOLIC_INITIAL_VALUES
        options.add(angr.options.EFFICIENT_STATE_MERGING)
        options.add(angr.options.DOWNSIZE_Z3)
        
        # Already present in "symbolic mode"
        # options.add(angr.options.OPTIMIZE_IR)
        # options.add(angr.options.FAST_MEMORY)
        # options.add(angr.options.SIMPLIFY_MEMORY_READS)
        # options.add(angr.options.SIMPLIFY_MEMORY_WRITES)
        # options.add(angr.options.SIMPLIFY_CONSTRAINTS)
        # options.add(angr.options.SYMBOLIC_INITIAL_VALUES)
        
        options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS)
        options.add(angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY)
         
        options.add(angr.options.USE_SYSTEM_TIMES)
        #options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
        # options.add(angr.options.TRACK_JMP_ACTIONS)
        # options.add(angr.options.TRACK_CONSTRAINT_ACTIONS)
        # options.add(angr.options.TRACK_JMP_ACTIONS)

        self.log.info("Entry_state address = " + str(addr))
        # Contains a program's memory, registers, filesystem data... any "live data" that can be changed by execution has a home in the state
        state = proj.factory.entry_state(
            addr=addr, args=args_binary, add_options=options
        )
        
        if args.sim_file:
            f = open_file(self.inputs, "rb")
            cont = f.read()
            simfile = angr.SimFile(nameFileShort, content=cont)
            state.fs.insert(nameFileShort, simfile)
        
        
        state.options.discard("LAZY_SOLVES")
        state.register_plugin(
            "heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc(heap_size = 0x10000000) # heap_size = 0x10000000
        )
        #heap_size = 0x10000000
        state.register_plugin(
            "plugin_env_var", PluginEnvVar()
        )  # For environment variable mainly
        state.plugin_env_var.env_block = state.heap.malloc(32767) 
        for i in range(32767):
            c = state.solver.BVS("c_env_block{}".format(i), 8)
            state.memory.store(state.plugin_env_var.env_block + i, c)
        ComSpec = "ComSpec=C:\Windows\system32\cmd.exe\0".encode("utf-8")
        ComSpec_bv = state.solver.BVV(ComSpec)
        state.memory.store(state.plugin_env_var.env_block, ComSpec_bv)
        state.plugin_env_var.env_var["COMSPEC"] = "C:\Windows\system32\cmd.exe\0"
        state.plugin_env_var.expl_method = self.expl_method
        
        # Create ProcessHeap struct and set heapflages to 0
        tib_addr = state.regs.fs.concat(state.solver.BVV(0, 16))
        peb_addr = state.mem[tib_addr + 0x30].dword.resolved
        ProcessHeap = peb_addr + 0x500
        state.mem[peb_addr + 0x18].dword = ProcessHeap
        state.mem[ProcessHeap+0xc].dword = 0x0 #heapflags windowsvistaorgreater
        state.mem[ProcessHeap+0x40].dword = 0x0 #heapflags else
        
        
        # Constraint arguments to ASCII
        #for i in range(1, len(args_binary)):
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
            self.hooks.internal_functions_hooks = {
                # for warzone
                "copy": b'\x56\x33\xf6\x39\x74\x24\x08\x76\x0d\x8a\x04\x16\x88\x04\x0e\x46\x3b\x74\x24\x08\x72\xf3\x5e',
                "copy_2":  b'\x55\x8b\xec\x56\x8b\x75\x08\x85\xf6\x74\x11\x57\x8b\xf9\x2b\xfa\x8a\x02\x88\x04\x17\x42\x83\xee\x01\x75\xf5\x5f\x8b\xc1\x5e\x5d',
                "copy_3":  b'\x55\x8b\xec\x83\x7d\x10\x00\x8b\x4d\x08\x56\x8b\xf1\x74\x12\x8b\x55\x0c\x8a\x02\xff\x4d\x10\x88\x01\x41\x42\x83\x7d\x10\x00\x75\xf1\x8b\xc6\x5e\x5d',
                "crc32": b'\x53\x55\x56\x33\xf6\x8b\xda\x8b\xe9\x39\x35\x04\xac\x41\x00\x75\x38\x57\x8b\xfe\xb9\x00\xa8\x41\x00\x6a\x08\x8b\xc7\x5a\xa8\x01\x74\x09\xd1\xe8\x35\x20\x83\xb8\xed\xeb\x02\xd1\xe8\x4a\x75\xee\x89\x01\x47\x83\xc1\x04\x81\xff\x00\x01\x00\x00\x72\xdb\xc7\x05\x04\xac\x41\x00\x01\x00\x00\x00\x5f\x83\xc9\xff\x85\xdb\x74\x1a\x0f\xb6\x04\x2e\x33\xc1\xc1\xe9\x08\x25\xff\x00\x00\x00\x33\x0c\x85\x00\xa8\x41\x00\x46\x3b\xf3\x72\xe6\x5e\xf7\xd1\x5d\x8b\xc1\x5b',
                "murmurhash": b'\x55\x8b\xec\x53\x8b\xda\x8b\xc3\x99\x83\xe2\x03\x56\x57\x8d\x3c\x02\x8b\x55\x08\xc1\xff\x02\x8d\x34\xb9\xf7\xdf\x74\x23\x69\x04\xbe\x51\x2d\x9e\xcc\xc1\xc0\x0f\x69\xc0\x93\x35\x87\x1b\x33\xc2\xc1\xc0\x0d\x6b\xd0\x05\x81\xea\x9c\x94\xab\x19\x83\xc7\x01\x75\xdd\x8b\xc3\x33\xc9\x83\xe0\x03\x83\xe8\x01\x74\x1a\x83\xe8\x01\x74\x0c\x83\xe8\x01\x75\x26\x0f\xb6\x4e\x02\xc1\xe1\x10\x0f\xb6\x46\x01\xc1\xe0\x08\x33\xc8\x0f\xb6\x06\x33\xc1\x69\xc0\x51\x2d\x9e\xcc\xc1\xc0\x0f\x69\xc0\x93\x35\x87\x1b\x33\xd0\x33\xd3\x8b\xc2\xc1\xe8\x10\x33\xc2\x69\xc8\x6b\xca\xeb\x85\x5f\x5e\x5b\x8b\xc1\xc1\xe8\x0d\x33\xc1\x69\xc0\x35\xae\xb2\xc2\x8b\xc8\xc1\xe9\x10\x33\xc8\x8b\x45\x0c\x89\x08\x5d',
                "murmurhash2": b'\x55\x8b\xec\x83\xec\x2c\x8b\x45\x08\x89\x45\xe0\x8b\x45\x0c\x99\x83\xe2\x03\x03\xc2\xc1\xf8\x02\x89\x45\xec\x8b\x45\x10\x89\x45\xf8\xc7\x45\xd8\x51\x2d\x9e\xcc\xc7\x45\xd4\x93\x35\x87\x1b\x8b\x45\xec\x8b\x4d\xe0\x8d\x04\x81\x89\x45\xdc\x8b\x45\xec\xf7\xd8\x89\x45\xf0\xeb\x07\x8b\x45\xf0\x40\x89\x45\xf0\x83\x7d\xf0\x00\x74\x59\xff\x75\xf0\xff\x75\xdc\xe8\x59\x2d\xfe\xff\x59\x59\x89\x45\xf4\x69\x45\xf4\x51\x2d\x9e\xcc\x89\x45\xf4\x6a\x0f\xff\x75\xf4\xe8\x1e\x2d\xfe\xff\x59\x59\x89\x45\xf4\x69\x45\xf4\x93\x35\x87\x1b\x89\x45\xf4\x8b\x45\xf8\x33\x45\xf4\x89\x45\xf8\x6a\x0d\xff\x75\xf8\xe8\xfc\x2c\xfe\xff\x59\x59\x89\x45\xf8\x6b\x45\xf8\x05\x2d\x9c\x94\xab\x19\x89\x45\xf8\xeb\x9a\x8b\x45\xec\x8b\x4d\xe0\x8d\x04\x81\x89\x45\xe4\x83\x65\xfc\x00\x8b\x45\x0c\x83\xe0\x03\x89\x45\xe8\x83\x7d\xe8\x01\x74\x39\x83\x7d\xe8\x02\x74\x1d\x83\x7d\xe8\x03\x74\x02\xeb\x6a\x33\xc0\x40\xd1\xe0\x8b\x4d\xe4\x0f\xb6\x04\x01\xc1\xe0\x10\x33\x45\xfc\x89\x45\xfc\x33\xc0\x40\xc1\xe0\x00\x8b\x4d\xe4\x0f\xb6\x04\x01\xc1\xe0\x08\x33\x45\xfc\x89\x45\xfc\x33\xc0\x40\x6b\xc0\x00\x8b\x4d\xe4\x0f\xb6\x04\x01\x33\x45\xfc\x89\x45\xfc\x69\x45\xfc\x51\x2d\x9e\xcc\x89\x45\xfc\x6a\x0f\xff\x75\xfc\xe8\x6a\x2c\xfe\xff\x59\x59\x89\x45\xfc\x69\x45\xfc\x93\x35\x87\x1b\x89\x45\xfc\x8b\x45\xf8\x33\x45\xfc\x89\x45\xf8\x8b\x45\xf8\x33\x45\x0c\x89\x45\xf8\xff\x75\xf8\xe8\x71\x2c\xfe\xff\x59\x89\x45\xf8\x8b\x45\x14\x8b\x4d\xf8\x89\x08\xc9',
                "findstart": b'\x55\x8b\xec\x83\xec\x14\xc6\x45\xff\x00\xc7\x45\xf4\x90\x1d\x42\x00\xc6\x45\xf8\x4d\xc6\x45\xf9\x5a\xc6\x45\xfa\x90\xc6\x45\xfb\x00\x83\x65\xf0\x00\x0f\xb6\x45\xff\x85\xc0\x75\x42\x6a\x04\xff\x75\xf4\x8d\x45\xf8\x50\xe8\x12\xf5\xfd\xff\x83\xc4\x0c\x89\x45\xec\x83\x7d\xec\x00\x75\x0b\xc6\x45\xff\x01\x8b\x45\xf4\xeb\x21\xeb\x07\x8b\x45\xf4\x48\x89\x45\xf4\x8b\x45\xf0\x40\x89\x45\xf0\x81\x7d\xf0\xe8\x03\x00\x00\x75\x04\x83\x65\xf0\x00\xeb\xb6\x33\xc0\xc9',
                "findstart2": b'\x55\x8b\xec\x51\xb9\x0e\x5c\x41\x00\xc7\x45\xfc\x4d\x5a\x90\x00\x8d\x45\xfc\x8b\x00\x3b\x01\x74\x03\x49\xeb\xf4\x8b\xc1\xc9',
                "findstart3": b'\x55\x8b\xec\x51\x53\x56\xbe\x23\x33\x41\x00\xc7\x45\xfc\x4d\x5a\x90\x00\x33\xdb\x6a\x04\x8d\x45\xfc\x56\x50\xe8\xbd\xdc\xfe\xff\x83\xc4\x0c\x85\xc0\x74\x13\x33\xc9\x8d\x43\x01\x4e\x81\xfb\xe7\x03\x00\x00\x0f\x45\xc8\x8b\xd9\xeb\xda\x8b\xc6\x5e\x5b\xc9',
                "findstart4": b'\x55\x8b\xec\x51\x53\x56\xbe\xa2\x1c\x41\x00\xc7\x45\xfc\x4d\x5a\x90\x00\x33\xdb\x6a\x04\x8d\x45\xfc\x56\x50\xe8\x3e\xf3\xfe\xff\x83\xc4\x0c\x85\xc0\x74\x13\x33\xc9\x8d\x43\x01\x4e\x81\xfb\xe7\x03\x00\x00\x0f\x45\xc8\x8b\xd9\xeb\xda\x8b\xc6\x5e\x5b\xc9',
                "findstart5": b'\x55\x8b\xec\x51\xb9\xe5\x17\x42\x00\xc7\x45\xfc\x4d\x5a\x90\x00\x8d\x45\xfc\x8b\x00\x3b\x01\x74\x03\x49\xeb\xf4\x8b\xc1\xc9',
                # For wabot
                # FUN_004031e8:004031fe(c), FUN_004031e8:0040325a(j), FUN_00403264:00403281(c), FUN_00403264:00403297(c), FUN_004042f4:0040430e(c
                # "weed":b'\x53\x56\x51\x8b\xd8\x8b\x73\x0c\x85\xf6\x75\x04\x33\xc0\xeb\x26\x6a\x00\x8d\x44\x24\x04\x50\x56\x8b\x43\x14\x50\x8b\x03\x50\xe8\x0c\xe8\xff\xff\x85\xc0\x75\x07\xe8\x3b\xe8\xff\xff\xeb\x02\x33\xc0\x33\xd2\x89\x53\x0c\x5a\x5e\x5b\xc3',
                # "weed2": b'\x66\x81\x7e\x04\xb3\xd7',
                # "weed3":b'\xe8\x91\xff\xff\xff',
                # "weed4":b'\xe8\x13\x52\xff\xff\xb8\x44\xff\x40\x00\xe8\x99\x4f\xff\xff\xe8\x2c\x4d\xff\xff\x8b\x15\xf0\xe9\x40\x00\xb8\x44\xff\x40\x00\xe8\x38\x6a\xff\xff\xe8\x9f\x52\xff\xff\xe8\x12\x4d\xff\xff\xb8\x44\xff\x40\x00\xe8\x50\x53\xff\xff\xe8\x03\x4d\xff\xff',
                "weed5":b'\x55\x8b\xec\x83\xc4\xf0\xb8\x0c\xd8\x40\x00\xe8\xcc\x6f\xff\xff\xb8\x20\xd9\x40\x00\xe8\x96\x75\xff\xff\xba\x34\xd9\x40\x00\xb8\x44\xff\x40\x00\xe8\x13\x52\xff\xff\xb8\x44\xff\x40\x00\xe8\x99\x4f\xff\xff\xe8\x2c\x4d\xff\xff\x8b\x15\xf0\xe9\x40\x00\xb8\x44\xff\x40\x00\xe8\x38\x6a\xff\xff\xe8\x9f\x52\xff\xff\xe8\x12\x4d\xff\xff\xb8\x44\xff\x40\x00\xe8\x50\x53\xff\xff\xe8\x03\x4d\xff\xff\xa1\x08\xea\x40\x00\xc7\x00\x01\x00\x00\x00\xa1\x18\xea\x40\x00\xba\x50\xd9\x40\x00\xe8\xed\x64\xff\xff\xa1\x14\xea\x40\x00\x33\xd2\x89\x10\xb9\x68\xd9\x40\x00\xba\x74\xd9\x40\x00\xb8\x80\xd9\x40\x00\xe8\xd8\x83\xff\xff\xa1\x08\xea\x40\x00\x66\x8b\x00',
                # "clear_stack": b'\x68\x57\x6b\x40\x00',
                # SakulaRAT
                "rewriting": b'\x8b\x45\xf8\x8b\x5d\xf0\x39\xd8\x74\x97',
                # AsyncRat
                #"returns": b'\x83\xc4\x34\x5b\x5e\xc3'
                #"TODO": b'\x55\x8b\xec\x83\xc4\xf0\xb8\xf0\x76\x48\x00\xe8\x80\xec\xf7\xff\xa1\x0c\x1e\x49\x00\x8b\x00\xe8\x9c\x66\xfd\xff\x8b\x0d\xa8\x1f\x49\x00\xa1\x0c\x1e\x49\x00\x8b\x00\x8b\x15\x48\x74\x48\x00\xe8\x9c\x66\xfd\xff'#b'\x55\x8b\xec\x83\xc4\xf0\xb8\xf0\x76\x48\x00\xe8\x80\xec\xf7\xff\xa1\x0c\x1e\x49\x00\x8b\x00\xe8\x9c\x66\xfd\xff'
                
            }
            self.hooks.initialization(cont)
            self.hooks.hook(state,proj)
                
        # Creation of simulation managerinline_call, primary interface in angr for performing execution
        simgr = proj.factory.simulation_manager(state)
        
        dump_file = {}
        self.print_memory_info(main_obj, dump_file)
        print(self.call_sim.create_thread)
        
        # getModuleHandle
        lib = "kernel32.dll"
        symb = proj.loader.find_symbol(lib)
        if symb:
            print(symb.rebased_addr)
            lib_addr = symb.rebased_addr
        else:
            extern = proj.loader.extern_object
            addr = extern.get_pseudo_addr(lib)
            print(addr)
            lib_addr = addr
            
        # run(self, lib_handle, name_addr):
        # getProcAddress =self.call_sim.custom_simproc_windows["custom_package"]["GetProcAddress"]
        # print(getProcAddress)
        # print(state.solver.eval(ret_expr))
        # arguments = [state.solver.eval(ret_expr),claripy.StringS("CreateThread",size=len("CreateThread"))]
        # e_args = [ state.solver.BVV(a,state.arch.bits) if isinstance(a, int) else a for a in arguments ]
        # p = getProcAddress(project=proj,cc=SimCCStdcall(proj.arch))
        # ret_expr =  p.execute(state, None, arguments=e_args).ret_expr
        # print(ret_expr)
        
        # call rel32, the E8 rel32 direct near call encoding, where the rel32 field is target - end_of_call_insn
        #print(main_obj.imports)
        
        if args.pre_run_thread and False:
            print(main_obj.imports["CreateThread"])
            print(0x400000 + main_obj.imports["CreateThread"].relative_addr)
            createThreadAddr = int.to_bytes(0x400000 + main_obj.imports["CreateThread"].relative_addr,length=4, byteorder='little', signed=True)
            print(createThreadAddr)
            print(len(createThreadAddr))
            print(type(createThreadAddr))
            
            name = "CreateThread"
            self.log.info("GetProcAddress: " + str(name))
            # import pdb; pdb.set_trace()
            symb = proj.loader.find_symbol(name)
            if symb:
                # Yeah ! Symbols exist and it is already hooked (normaly)
                print(symb.rebased_addr) # cross_references=True,
            cfg =  proj.analyses.CFG(show_progressbar=True,
                                    detect_tail_calls=True,
                                    force_complete_scan=False,
                                    force_smart_scan=True,
                                    force_segment=False,
                                    use_patches=True,
                                    data_references=True,
                                    normalize=True,
                                    #context_sensitivity_level=2, # base 0
                                    #cross_references=True,
                                    skip_unmapped_addrs=False,
                                    nodecode_window_size=512*2,
                                    indirect_jump_target_limit=100000*10,
                                    nodecode_threshold=0.3*2,
                                    nodecode_step=16483*2)

            #proj.analyses.CompleteCallingConventions(recover_variables=True)
            
            #cfg =  proj.analyses.CFGEmulated(keep_state=True)
            
            #cfg.do_full_xrefs(state)
                    
            #print(main_obj.imports["CreateThread"].rebased_addr)
            print(int.from_bytes(createThreadAddr,"little"))
            pe_header = int.from_bytes(cont[0x3c:0x40],"little")
            size_of_headers = int.from_bytes(cont[pe_header+0x54:pe_header+0x54+4],"little")
            base_of_code = int.from_bytes(cont[pe_header+0x2c:pe_header+0x2c+4],"little")
            image_base = int.from_bytes(cont[pe_header+0x34:pe_header+0x34+4],"little")
            total = base_of_code+image_base-size_of_headers
            jmp_create_thred = [m.start()+total for m in re.finditer(b"\xff\x25"+createThreadAddr,cont)]
            print(jmp_create_thred)
            create_thread_ref = []
            for jmp in jmp_create_thred:
                f = cfg.functions[jmp]
                f.calling_convention = SimCCStdcall(proj.arch)
                print(f.name)
                blank_state = proj.factory.blank_state()
                
                
                prop = proj.analyses.Propagator(func=f, base_state=state)
                # Collect all the refs
                proj.analyses.XRefs(func=f, replacements=prop.replacements)
                thread_func = cfg.kb.functions[jmp]
                print(thread_func)
                print(thread_func.get_call_sites())
                print(thread_func.functions_called())
                print(thread_func.string_references())
                print(thread_func.get_call_target(jmp))
                print(thread_func.get_call_return(jmp))
                
                timenow_cp_xrefs = proj.kb.xrefs.get_xrefs_by_dst(jmp)  # the constant in the constant pool
                timenow_xrefs = proj.kb.xrefs.get_xrefs_by_ins_addr(jmp)  # the value in .bss
                print(timenow_cp_xrefs)
                print(timenow_xrefs)
                
                for xref in timenow_cp_xrefs:
                    print(xref)
                    print(xref.ins_addr)
                    thread_state = proj.factory.call_state(
                        addr=xref.ins_addr, add_options=options
                    )
                    print(thread_state)
                
                    # thread_func = cfg.kb.functions[xref.ins_addr]
                    # print(thread_func)
                    
                    
                    block = proj.factory.block(xref.ins_addr)
                    print(block)
                
                    
                    var_rec = proj.analyses.VariableRecoveryFast(thread_func)
                    
                    print(var_rec)
                    
                    cc_analysis = proj.analyses.CallingConvention(thread_func, cfg=cfg, analyze_callsites=True)
                    print(cc_analysis.prototype.args)
                    
                    for c in cc_analysis._analyze_callsites():
                        print(c.args)
                        print(c.return_value_used)
                        
                    node = cc_analysis._cfg.get_any_node(cc_analysis._function.addr)
                    if node is None:
                        l.warning("%r is not in the CFG. Skip calling convention analysis at call sites.", self._function)

                    facts = [ ]
                    in_edges = cc_analysis._cfg.graph.in_edges(node, data=True)

                    call_sites_by_function: Dict['Function',List[Tuple[int,int]]] = defaultdict(list)
                    for src, _, data in in_edges:
                        edge_type = data.get('jumpkind', 'Ijk_Call')
                        if edge_type != 'Ijk_Call':
                            continue
                        if not cc_analysis.kb.functions.contains_addr(src.function_address):
                            continue
                        caller = cc_analysis.kb.functions[src.function_address]
                        if caller.is_simprocedure:
                            # do not analyze SimProcedures
                            continue
                        call_sites_by_function[caller].append((src.addr, src.instruction_addrs[-1]))

                    call_sites_by_function_list = list(call_sites_by_function.items())[:3]
                    for caller, call_sites in call_sites_by_function_list:
                        print(call_sites)
                        for site in call_sites:
                            #if 
                            pass
                    
                    print(cc_analysis.cc.int_args)
                    for a in cc_analysis.cc.int_args:
                        print(a)
                    for arg in cc_analysis.prototype.args:
                        print(arg)
                        print(type(arg))
                    
                    arg_locs = cc_analysis.cc.arg_locs(cc_analysis.prototype)
                    get_args = cc_analysis.cc.get_args(thread_state, cc_analysis.prototype,stack_base=xref.ins_addr-0x18)
                    print(arg_locs)
                    print(get_args)
                
                    lpThreadAttributes = get_args[0]
                    dwStackSize = get_args[1]
                    lpStartAddress = get_args[2]
                    lpParameter = get_args[3]
                    dwCreationFlags = get_args[4]
                    lpThreadId = get_args[5]
                        
                    print(cc_analysis.cc.get_arg_info(state, cc_analysis.prototype))
                    for arg in arg_locs:
                        print(arg)
                        print(thread_state.regs.sp)
                        print(arg.get_value(thread_state,base_of_code))
                        
                    vm = cc_analysis.kb.variables[jmp]
                    print(vm)
                    input_variables = vm.input_variables()
                    print(input_variables)
                    input_args = cc_analysis._args_from_vars(input_variables, vm)
                    print(input_args)
                    
                    # cc_maker = proj.analyses.decompiler.CallSiteMaker(thread_func)   
                    # print(cc_maker.result_block)
                
                    check_func = proj.factory.callable(xref.ins_addr, concrete_only=False, cc=SimCCStdcall(proj.arch))
                    exit()
                    print("[+] Running angr callable with concrete arguments")
                    ret_val = check_func(lpThreadAttributes,dwStackSize,lpStartAddress,lpParameter,dwCreationFlags,lpThreadId)
                    stdout = check_func.result_state.posix.dumps(1) 
                    print("ret_val: %s" % ret_val)
                    print("stdout: %s" % stdout)
        
                print(f)
                print(f.get_call_sites())
                print(f.string_references())
                print(f.functions_called())
                print(f.get_call_target(jmp))
                print(f.get_call_return(jmp))
                
                # thread_func = cfg.kb.functions[0x4111d0]
                # print(thread_func)
                # print(thread_func.get_call_sites())
                # print(thread_func.string_references())
                
                thread_func = cfg.kb.functions[0x4010d0]
                print(thread_func)
                print(thread_func.get_call_sites())
                print(thread_func.functions_called())
                print(thread_func.string_references())
                print(thread_func.get_call_target(0x4010d0))
                print(thread_func.get_call_return(0x4010d0))
                
                timenow_cp_xrefs = proj.kb.xrefs.get_xrefs_by_dst(0x4010d0)  # the constant in the constant pool
                timenow_xrefs = proj.kb.xrefs.get_xrefs_by_ins_addr(0x4010d0)  # the value in .bss
                print(timenow_cp_xrefs)
                print(timenow_xrefs)
            
            # for addr in cfg.kb.functions:
            #     print(hex(addr))
            #     print(cfg.kb.functions[addr])
            # print("This is the graph:", cfg.graph)
            # print("It has %d nodes and %d edges" % (len(cfg.graph.nodes()), len(cfg.graph.edges())))
            # print(cfg.kb.functions)
            
            # thread_func = cfg.kb.functions[symb.rebased_addr]
            # print(thread_func)
            # print(thread_func.get_call_sites())
            # thread_func = cfg.kb.functions[main_obj.imports["CreateThread"].relative_addr]
            # print(thread_func)
            # thread_func = cfg.kb.functions[0x400000 + main_obj.imports["CreateThread"].relative_addr]
            # print(thread_func)
        
        
            
        
                
            
            # name = "CreateThread"
            # self.log.info("GetProcAddress: " + str(name))
            # # import pdb; pdb.set_trace()
            # symb = proj.loader.find_symbol(name)
            # if symb:
            #     # Yeah ! Symbols exist and it is already hooked (normaly)
            #     print(symb.rebased_addr)

            # # import pdb; pdb.set_trace()
            # if lib not in SIM_LIBRARIES:
            #     try:
            #         # import pdb; pdb.set_trace()
            #         str_lib = str(lib)
            #         if ".dll" not in lib:
            #             lib = str_lib + ".dll"
            #         proj.loader.requested_names.add(lib)
            #         self.call_sim.loadlibs_proc(
            #             self.call_sim.ddl_loader.load(proj), proj
            #         )
            #     except Exception as inst:
            #         # self.log.warning(type(inst))    # the exception instance
            #         self.log.warning(inst)  # __str__ allows args to be printed directly,
            #         exc_type, exc_obj, exc_tb = sys.exc_info()
            #         # fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            #         self.log.warning(exc_type, exc_obj)
            #         self.log.info("GetProcAddress: Fail to load dynamically lib " + str(lib))
            #         exit(-1)

            # self.log.info("GetProcAddress - Query to lib : " + str(lib))

            # if symb:
            #     # Yeah ! Symbols exist and it is already hooked (normally)
            #     print(symb.rebased_addr)
            # #else:
            # self.log.info("GetProcAddress: Symbol not found")
            # extern = proj.loader.extern_object
            # addr = extern.get_pseudo_addr(name)
            # print(addr)
            
            exit()
        #####################################################
        ##########         Exploration           ############
        #####################################################
        
        def nothing(state):
            if False:
                print(hex(state.addr))
        
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
            if "CreateThread" in main_obj.imports:
                print(main_obj.imports["CreateThread"])
                print(0x400000 + main_obj.imports["CreateThread"].relative_addr)
                createThreadAddr = int.to_bytes(0x400000 + main_obj.imports["CreateThread"].relative_addr,length=4, byteorder='little', signed=True)
            
                pe_header       = int.from_bytes(cont[0x3c:0x40],"little")
                size_of_headers = int.from_bytes(cont[pe_header+0x54:pe_header+0x54+4],"little")
                base_of_code    = int.from_bytes(cont[pe_header+0x2c:pe_header+0x2c+4],"little")
                image_base      = int.from_bytes(cont[pe_header+0x34:pe_header+0x34+4],"little")
                total           = base_of_code+image_base-size_of_headers
                jmp_create_thread = [m.start()+total for m in re.finditer(b"\xff\x25"+createThreadAddr,cont)]
                jmp_create_thread.reverse()
                call_create_thred = [m.start()+total for m in re.finditer(b"\xff\x15"+createThreadAddr,cont)]
                call_create_thred.reverse()
                print(jmp_create_thread)
                print(call_create_thred)
                print(0x400000 + main_obj.imports["CreateThread"].relative_addr)
                
               
                addresses = [0x400000 + main_obj.imports["CreateThread"].relative_addr] + jmp_create_thread + call_create_thred
                
                # some error, see penv-fix/angr
                # TODO serena try both
                cfg =  proj.analyses.CFG(show_progressbar=True,
                                        detect_tail_calls=True,
                                        force_complete_scan=True,
                                        force_smart_scan=False,
                                        force_segment=True,
                                        use_patches=False,
                                        data_references=True,
                                        normalize=True,
                                        function_starts=addresses,
                                        #context_sensitivity_level=2, # base 0
                                        cross_references=True, # can bug
                                        #sp_tracking_track_memory=True, # not x86
                                        skip_unmapped_addrs=False,
                                        exclude_sparse_regions=False,
                                        skip_specific_regions=False,
                                        nodecode_window_size=512*2,
                                        indirect_jump_target_limit=100000*100,
                                        nodecode_threshold=0.3*2,
                                        nodecode_step=16483*2)

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
            
                #self.manage_thread(exp_dir, nameFileShort, proj, options, state, cfg, 0x400000 + main_obj.imports["CreateThread"].relative_addr)
                if len(jmp_create_thread) > 0:
                    for jmp in jmp_create_thread:
                        self.manage_thread(exp_dir, nameFileShort, proj, options, state, cfg, jmp)
                if len(call_create_thred) > 0:
                    for call in call_create_thred:
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
        
        simgr.active[0].globals["id"] = 0
        simgr.active[0].globals["JumpExcedeed"] = False
        simgr.active[0].globals["JumpTable"] = {}
        simgr.active[0].globals["n_steps"] = 0
        simgr.active[0].globals["last_instr"] = 0
        simgr.active[0].globals["counter_instr"] = 0
        simgr.active[0].globals["loaded_libs"] = {}
        simgr.active[0].globals["addr_call"] = []
        simgr.active[0].globals["loop"] = 0
        simgr.active[0].globals["crypt_algo"] = 0
        simgr.active[0].globals["crypt_result"] = 0
        
        simgr.active[0].globals["n_buffer"] = 0
        simgr.active[0].globals["rsrc"] = 0
        simgr.active[0].globals["n_calls"] = 0
        simgr.active[0].globals["resources"] = {}
        simgr.active[0].globals["df"] = 0
        simgr.active[0].globals["files"] = {}
        simgr.active[0].globals["n_calls_recv"] = 0
        simgr.active[0].globals["n_calls_send"] = 0
        simgr.active[0].globals["n_buffer_send"] = 0
        simgr.active[0].globals["buffer_send"] = []
        
        simgr.active[0].globals["files"] = {}
        
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
        
        if args.count_block:
            self.log.info("Total number of blocks: " + str(nbblocks))
            self.log.info("Total number of instr: " + str(nbinstr))
            self.log.info("Number of blocks visited: " + str(len(block_dict)))
            self.log.info("Number of instr visited: " + str(len(instr_dict)))
        
        self.log.info("Syscalls Found:" + str(self.call_sim.syscall_found))
        
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
        self.build_scdg_fin(exp_dir, nameFileShort, main_obj, state, simgr, discard_SCDG)
        

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
                            }, ignore_index=True)
            print(csv_file)
            df.to_csv(csv_file, index=False,sep=";")
        logging.getLogger().removeHandler(fileHandler)

    def manage_thread(self, exp_dir, nameFileShort, proj, options, state, cfg, jmp):
        print(jmp)
        if jmp not in cfg.kb.functions:
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
        f = cfg.functions[jmp]
        print("coucou")
        #f.calling_convention = SimCCStdcall(proj.arch)
        print(f.name)
        #blank_state = proj.factory.blank_state()
                    
        prop = proj.analyses.Propagator(func=f, base_state=state)
        # Collect all the refs
        proj.analyses.XRefs(func=f, replacements=prop.replacements)
        thread_func = cfg.kb.functions[jmp]
        print(thread_func)
        _ = proj.analyses.VariableRecoveryFast(thread_func) # TODO usefull ?
        cc_analysis = proj.analyses.CallingConvention(thread_func, cfg=cfg, analyze_callsites=True)
        print(cc_analysis.prototype.args)  
        node = cfg.get_any_node(cc_analysis._function.addr)
        if node is None:
            self.log.warning("%r is not in the CFG. Skip calling convention analysis at call sites.", jmp)
        in_edges = cfg.graph.in_edges(node, data=True)
        call_sites_by_function: Dict['Function',List[Tuple[int,int]]] = defaultdict(list)
        for src, _, data in in_edges:
            edge_type = data.get('jumpkind', 'Ijk_Call')
            if edge_type != 'Ijk_Call':
                continue
            if not cc_analysis.kb.functions.contains_addr(src.function_address):
                continue
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
        for b in thread_func.block_addrs:
            print(b)
            self.run_thread(exp_dir, nameFileShort, proj, options,[b])

    def run_thread(self, exp_dir, nameFileShort, proj, options, site):
        tstate = proj.factory.entry_state(
                                addr=site[0], add_options=options
                            )
        tsimgr = proj.factory.simulation_manager(tstate)
                                
        tstate.options.discard("LAZY_SOLVES")
        tstate.register_plugin(
                                "heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc(heap_size = 0x10000000) # heap_size = 0x10000000
                            )
                                
        tstate.register_plugin(
                                "plugin_env_var", PluginEnvVar()
                            )  # For environment variable mainly
        tstate.plugin_env_var.env_block = tstate.heap.malloc(32767) 
        for i in range(32767):
            c = tstate.solver.BVS("c_env_block{}".format(i), 8)
            tstate.memory.store(tstate.plugin_env_var.env_block + i, c)
        ComSpec = "ComSpec=C:\Windows\system32\cmd.exe\0".encode("utf-8")
        ComSpec_bv = tstate.solver.BVV(ComSpec)
        tstate.memory.store(tstate.plugin_env_var.env_block, ComSpec_bv)
        tstate.plugin_env_var.env_var["COMSPEC"] = "C:\Windows\system32\cmd.exe\0"
        tstate.plugin_env_var.expl_method = self.expl_method
                            
        # Create ProcessHeap struct and set heapflages to 0
        tib_addr = tstate.regs.fs.concat(tstate.solver.BVV(0, 16))
        peb_addr = tstate.mem[tib_addr + 0x30].dword.resolved
        ProcessHeap = peb_addr + 0x500
        tstate.mem[peb_addr + 0x18].dword = ProcessHeap
        tstate.mem[ProcessHeap+0xc].dword = 0x0  #heapflags windowsvistaorgreater
        tstate.mem[ProcessHeap+0x40].dword = 0x0 #heapflags else
            
            
        tstate.inspect.b("simprocedure", when=angr.BP_AFTER, action=self.call_sim.add_call)
        tstate.inspect.b("simprocedure", when=angr.BP_BEFORE, action=self.call_sim.add_call_debug)
        tstate.inspect.b("call", when=angr.BP_BEFORE, action=self.call_sim.add_addr_call)
        tstate.inspect.b("call", when=angr.BP_AFTER, action=self.call_sim.rm_addr_call)
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
                            
        exploration_tech_thread = SemaExplorerCBFS(
                                tsimgr, 0, exp_dir, nameFileShort, self
                            )
        tsimgr.use_technique(exploration_tech_thread)

        self.log.info(
                                    "\n------------------------------\nStart -State of simulation manager :\n "
                                    + str(tsimgr)
                                    + "\n------------------------------"
                                )
                                
        tsimgr.run()

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

    def build_scdg_fin(self, exp_dir, nameFileShort, main_obj, state, simgr, discard_SCDG):
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
                

        self.print_memory_info(main_obj, dump_file)
        if discard_SCDG:
            # self.log.info(dump_file)
            ofilename = exp_dir  + "inter_SCDG.json"
            self.log.info(ofilename)
            save_SCDG = open_file(ofilename, "w")
            json_dumper.dump(dump_file, save_SCDG)  # ,indent=4)
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
        self.inputs = "".join(self.inputs.rstrip())
        self.nb_exps = 0
        self.current_exps = 0
        
        if args.verbose_scdg:
            #logging.getLogger().handlers.clear()
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(CustomFormatter())
            self.log = logging.getLogger("SemaSCDG")
            self.log.addHandler(ch)
            self.log.propagate = False
            logging.getLogger("angr").setLevel("INFO")
            logging.getLogger('claripy').setLevel('INFO')
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
        
        import resource

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
            
