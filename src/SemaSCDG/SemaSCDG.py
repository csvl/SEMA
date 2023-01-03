#!/usr/bin/env python3
from ast import arg
import datetime
import os
import sys

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
    from .plugin.Hooks import *
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
    from plugin.Hooks import *
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
        max_step=1000000,
        timeout_tab=[1200, 2400, 3600],
        jump_it=100,
        loop_counter_concrete=1000000,
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
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(CustomFormatter())
        self.log = logging.getLogger("SemaSCDG")
        self.log.addHandler(ch)
        self.log.propagate = False

        self.call_sim = CustomSimProcedure(
            self.scdg, self.scdg_fin, 
            string_resolv=string_resolv, print_on=print_on, 
            print_syscall=print_syscall, is_from_tc=is_from_tc, is_from_web=is_from_web
        )
        
        self.hooks = Hooks()
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
        
        self.log.info(args)
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
            
        if verbose:
            logging.getLogger("angr").setLevel("WARNING")
            logging.getLogger('claripy').setLevel('WARNING')
        self.log.setLevel(logging.INFO)

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
        logging.getLogger().addHandler(fileHandler)


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
            )

        # Getting from a binary file to its representation in a virtual address space
        main_obj = proj.loader.main_object
        os_obj = main_obj.os

        if args.count_block:
            # count total number of blocks and instructions
            vaddr = 0
            memsize = 0
            for sec in main_obj.sections:
                name = sec.name.replace("\x00", "")
                if name == ".text":
                    vaddr = sec.vaddr
                    memsize = sec.memsize
            i = vaddr
            nbinstr = 0
            nbblocks = 0
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

        # Create initial state of the binary
        
        options = {angr.options.SYMBOLIC_INITIAL_VALUES}
        options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        options.add(angr.options.SIMPLIFY_MEMORY_READS)
        options.add(angr.options.SIMPLIFY_MEMORY_WRITES)
        options.add(angr.options.SIMPLIFY_CONSTRAINTS)
        options.add(angr.options.USE_SYSTEM_TIMES)
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
            f = open_file(self.inputs, "rb")
            cont = f.read()
            simfile = angr.SimFile(nameFileShort, content=cont)
            state.fs.insert(nameFileShort, simfile)
        
        
        state.options.discard("LAZY_SOLVES")
        state.register_plugin(
            "heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc(heap_size = 0x10000000)
        )
        
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

        self.hooks.initialization(cont)
        self.hooks.hook(state,proj)
                
        # Creation of simulation manager, primary interface in angr for performing execution
        simgr = proj.factory.simulation_manager(state)
        
        dump_file = {}
        self.print_memory_info(main_obj, dump_file)
        
        #####################################################
        ##########         Exploration           ############
        #####################################################
        
        def nothing(state):
            pass
                
        instr_dict = {}
        def count(state):
            if state.addr not in instr_dict:
                instr_dict[state.addr] = 1
                
        block_dict = {}
        def countblock(state):
            if state.inspect.address not in block_dict:
                block_dict[state.inspect.address] = 1
                
        # Improved "Break point"
        
        state.inspect.b(
            "simprocedure", when=angr.BP_AFTER, action=self.call_sim.add_call
        )
        state.inspect.b(
            "simprocedure", when=angr.BP_BEFORE, action=self.call_sim.add_call_debug
        )
        state.inspect.b("call", when=angr.BP_BEFORE, action=self.call_sim.add_addr_call)
        state.inspect.b("call", when=angr.BP_AFTER, action=self.call_sim.rm_addr_call)
        
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
        
        print("total nb blocks: " + str(nbblocks))
        print("total nb instr: " + str(nbinstr))
        
        print("nb blocks visited: " + str(len(block_dict)))
        print("nb instr visited: " + str(len(instr_dict)))
        
        self.log.info("Syscall Found:" + str(self.call_sim.syscall_found))
        
        elapsed_time = time.time() - self.start_time
        self.log.info("Total execution time: " + str(elapsed_time))
        
        # Track the buffer containing commands
        
        brutto_result = ""
        for state in simgr.deadended + simgr.active + simgr.stashes["pause"]:
            buffers = []
            calls = {}
            for key, symbol in state.solver.get_variables("buffer"):
                eve = state.solver.eval(symbol)
                if eve != 0:
                    buffers.append(hex(eve))
            if len(buffers) != 0:
                brutto_result += hex(state.addr) + " : "  + "\n"
                for buf in buffers:
                    brutto_result += "     - " + buf + "\n"
                for dic in self.scdg[state.globals["id"]][state.globals["n_calls"]:]:
                    if dic["name"]  not in calls:
                        brutto_result += "         * " + dic["name"]  + "\n"
                        calls[dic["name"] ] = 1
            
        with open_file("out.log", 'w') as f:
            f.write(brutto_result + '\n')
            
        # Build SCDG
        #self.warzone(nameFileShort,simgr,tracked)
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
                            }, ignore_index=True)
            print(csv_file)
            df.to_csv(csv_file, index=False,sep=";")

    def warzone(self,nameFileShort,simgr,tracked):
        dump_file = {}
        dump_id = 0
        
        for state in simgr.deadended:
            dump_file[dump_id] = {"status" : "dead",
                                  "buffers" : tracked[state.globals["id"]],
                                  "trace" : self.scdg[state.globals["id"]][state.globals["n_calls"]:]
                                  }
            dump_id = dump_id + 1
            
        for state in simgr.active:
            dump_file[dump_id] = {"status" : "active",
                                  "buffers" : tracked[state.globals["id"]],
                                  "trace" : self.scdg[state.globals["id"]][state.globals["n_calls"]:]
                                  }
            dump_id = dump_id + 1
            
        for state in simgr.stashes["pause"]:
            dump_file[dump_id] = {"status" : "pause",
                                  "buffers" : tracked[state.globals["id"]],
                                  "trace" : list(set(dic["name"] for dic in self.scdg[state.globals["id"]][state.globals["n_calls"]:]))
                                  }
            dump_id = dump_id + 1
                
                
        ofilename = nameFileShort + "_warzone.json"
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
        print(self.inputs)
        if os.path.isfile(self.inputs):
            self.nb_exps = 1
            # TODO update familly
            self.log.info("You decide to analyse a single binary: "+ self.inputs)
            # *|CURSOR_MARCADOR|*
            self.build_scdg(args,is_fl=is_fl,csv_file=csv_file)
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
                        self.build_scdg(args, is_fl, csv_file=csv_file)
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
    )
    args_parser = ArgumentParserSCDG(toolc)
    args, nameFile, expl_method = args_parser.parse_arguments()
    toolc.build_scdg(args, nameFile, expl_method)


if __name__ == "__main__":
    main()
            
