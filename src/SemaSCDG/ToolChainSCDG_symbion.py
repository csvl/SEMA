#!/usr/bin/env python3
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

# Personnal stuf
from helper.GraphBuilder import *

# Syscall table stuff
import angr

from procedures.CustomSimProcedure import *
from Breakpoints import *
from plugin.PluginEnvVar import *
from plugin.PluginEvasion import *
from explorer.ToolChainExplorerDFS import ToolChainExplorerDFS
from explorer.ToolChainExplorerCDFS import ToolChainExplorerCDFS
from explorer.ToolChainExplorerBFS import ToolChainExplorerBFS
from explorer.ToolChainExplorerCBFS import ToolChainExplorerCBFS
from explorer.ToolChainExplorerSDFS import SemaExplorerSDFS
#from Trigger import *
#from sandboxes.CuckooInterface import CuckooInterface

import subprocess
import nose
import avatar2 as avatar2


import angr
import claripy
from clogging.CustomFormatter import CustomFormatter
from helper.ArgumentParserSCDG import ArgumentParserSCDG

from unipacker.core import Sample, SimpleClient, UnpackerEngine
from unipacker.utils import RepeatedTimer
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
        max_step=1000000,
        timeout_tab=[1200, 2400, 3600],
        jump_it=100,
        loop_counter_concrete=3000,
        jump_dict={},
        jump_concrete_dict={},
        max_simul_state=1,
        max_in_pause_stach=100,
        fast_main=False,
        force_symbolique_return=False,
        string_resolv=True,
        print_on=True,
        print_sm_step=False,
        print_syscall=False,
        debug_error=False,
        debug_string=False,
        is_packed=False,
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

                
        #logging.getLogger("angr").setLevel("WARNING")
        #logging.getLogger("angr").setLevel("DEBUG")
        #logging.getLogger("avatar.targets").setLevel("DEBUG")
        logging.getLogger("angr_targets").setLevel("DEBUG")
        #logging.getLogger("pygdbmi.gdbcontroller").setLevel("DEBUG")
        #logging.getLogger("pygdbmi.IoManager").setLevel("DEBUG")
        # create console handler with a higher log level
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        ch.setFormatter(CustomFormatter())
        self.log = logging.getLogger("ToolChainSCDG")
        self.log.setLevel(logging.INFO)
        self.log.addHandler(ch)
        self.log.propagate = False

        self.call_sim = CustomSimProcedure(
            self.scdg, self.scdg_fin, string_resolv, print_on
        )
        self.call_sim = CustomSimProcedure(
            self.scdg, self.scdg_fin, string_resolv, print_on
        )
        self.breakpoints = Breakpoints(-1)
        self.eval_time = False

        self.unpack_mode = None
        self.is_packed = is_packed
        

    def build_scdg(self, args, nameFile, expl_method):
        # logging.getLogger('angr').setLevel('WARNING')
        # logging.getLogger('angr').setLevel('INFO')
        # Create directory to store SCDG if it doesn't exist
        import os
        #unpacker_heartbeat = RepeatedTimer(120, print, "- still running -", file=sys.stderr)

        try:
            os.stat(args.exp_dir)
        except:
            os.makedirs(args.exp_dir)

        if args.exp_dir != "output/save-SCDG/":
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
            
        if True:
            GDB_SERVER_IP = '192.168.122.113'
            GDB_SERVER_PORT = 9876
            avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, GDB_SERVER_IP, GDB_SERVER_PORT)
            proj = angr.Project(nameFile, concrete_target=avatar_gdb, use_sim_procedures=True,page_size=0x1000)
       

        # Getting from a binary file to its representation in a virtual address space
        main_obj = proj.loader.main_object
        os_obj = main_obj.os

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
            self.log.info("Exploration method:  " + str(expl_method))

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
        
        #options = {angr.options.SYMBOLIC_INITIAL_VALUES}
        #options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
        #options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
        #options.add(angr.options.SIMPLIFY_MEMORY_READS)
        #options.add(angr.options.SIMPLIFY_MEMORY_WRITES)
        #options.add(angr.options.SIMPLIFY_CONSTRAINTS)
        # options.add(angr.options.SYMBOLIC_WRITE_ADDRESSES)
        # options.add{angr.options.USE_SYSTEM_TIMES}
        # options.add(angr.options.TRACK_JMP_ACTIONS)
        # options.add(angr.options.TRACK_CONSTRAINT_ACTIONS)
        # options.add(angr.options.TRACK_JMP_ACTIONS)

        if True:
            options = {angr.options.SYMBION_SYNC_CLE}
            options.add(angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS)
            options.add(angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY)
            options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC) 

        self.log.info("Entry_state address = " + str(addr))
        # Contains a program's memory, registers, filesystem data... any "live data" that can be changed by execution has a home in the state
        state = proj.factory.entry_state(
            addr=addr, args=args_binary, add_options=options
        )
        f = open_file(nameFile, "rb")
        cont = f.read()
        simfile = angr.SimFile(nameFileShort, content=cont)
        state.fs.insert(nameFileShort, simfile)
        heap_address = proj.concrete_target.get_heap_address()
        heap_address_content = proj.concrete_target.read_address(heap_address)
        print(hex(heap_address_content))
        state.register_plugin(
            "heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc(heap_base=heap_address_content)
            )
        print(state.memory.load(heap_address_content,10))
        #heap_size = 4096 * 4096
        
        #state.register_plugin(
        #    "plugin_env_var", PluginEnvVar()
        #)  # For environment variable mainly
        #state.plugin_env_var.env_block = state.heap.malloc(32767) 
        #for i in range(32767):
        #    c = state.solver.BVS("c_env_block{}".format(i), 8)
        #    state.memory.store(state.plugin_env_var.env_block + i, c)
        #ComSpec = "ComSpec=C:\Windows\system32\cmd.exe\0".encode("utf-8")
        #ComSpec_bv = state.solver.BVV(ComSpec)
        #state.memory.store(state.plugin_env_var.env_block, ComSpec_bv)
        #state.plugin_env_var.env_var["COMSPEC"] = "C:\Windows\system32\cmd.exe\0"
        #state.plugin_env_var.expl_method = expl_method

        # Save the evasion techniques in a plugin
        #state.register_plugin(
        #    "plugin_evasion", PluginEvasion()
        #)
        
        # Create ProcessHeap struct and set heapflages to 0
        #tib_addr = state.regs.fs.concat(state.solver.BVV(0, 16))
        #peb_addr = state.mem[tib_addr + 0x30].dword.resolved
        #ProcessHeap = peb_addr + 0x500
        #state.mem[peb_addr + 0x18].dword = ProcessHeap
        #state.mem[ProcessHeap+0xc].dword = 0x0 #heapflags windowsvistaorgreater
        #state.mem[ProcessHeap+0x40].dword = 0x0 #heapflags else
        
        
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
            self.call_sim.loadlibs(proj)
        self.call_sim.custom_hook_static(proj)

        if os_obj != "windows":
            self.call_sim.custom_hook_no_symbols(proj)
        else:
            self.call_sim.custom_hook_windows_symbols(proj)

        #self.breakpoints.initialization(cont)
        #self.breakpoints.Hooks(state,proj)
                
        # Creation of simulation manager, primary interface in angr for performing execution
        simgr = proj.factory.simulation_manager(state)
        
        dump_file = {}
        self.print_memory_info(main_obj, dump_file)
        
        #####################################################
        ##########         Exploration           ############
        #####################################################

        # Improved "Break point"
        
        state.inspect.b(
            "simprocedure", when=angr.BP_AFTER, action=self.call_sim.add_call
        )
        state.inspect.b(
            "simprocedure", when=angr.BP_BEFORE, action=self.call_sim.add_call_debug
        )
        state.inspect.b("call", when=angr.BP_BEFORE, action=self.call_sim.add_addr_call)
        state.inspect.b("call", when=angr.BP_AFTER, action=self.call_sim.rm_addr_call)
        
        #state.inspect.b('instruction',when=angr.BP_BEFORE, action=self.breakpoints.debug_instr)
        
        #def print_irsb(state):
        #    irsb = proj.factory.block(state.addr).vex
        #state.inspect.b('irsb',when=angr.BP_BEFORE, action=print_irsb)
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
        simgr.active[0].globals["loop"] = 0
        simgr.active[0].globals["crypt_algo"] = 0
        simgr.active[0].globals["crypt_result"] = 0
        simgr.active[0].globals["n_buffer"] = 0


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

        simgr.stashes["found"] = []

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
        if True:
            exploration_tech = SemaExplorerSDFS(
                simgr, 0, args.exp_dir, nameFileShort, self, proj
            )
      

        if False:
            print("[1] Executing malware concretely until address: " + hex(0x4014d1))
            concrete_state = self.execute_concretly(proj, state, 0x4014d1)

            print("[2] Executing malware symbolically until address:  " + hex(0x401487))
            symbolic_state = self.execute_symbolically(proj, concrete_state, 0x401487, args, nameFileShort)

            print("[3] Executing malware concretely until address: " + hex(0x40148F))
            concrete_state = self.execute_concretly(proj, symbolic_state, 0x40148F)

            print("[4] Executing malware symbolically until address:  " + hex(0x401288))
            symbolic_state = self.execute_symbolically(proj, concrete_state, 0x401288, args, nameFileShort)
    
            print("[5] Malware execution ends")
            print(symbolic_state)
            
        #0x401492
        if True:
            tech = angr.exploration_techniques.Symbion(
                find=[0x401000]
            )
            simgr.use_technique(tech)
            exploration = simgr.run()
            simgr.move(
                from_stash="found",
                to_stash="active",
                filter_func=lambda s: True,
            )
            simgr.remove_technique(tech)
            #simgr.active.append(exploration.stashes['found'][0])
            simgr.use_technique(exploration_tech)
            simgr.run()
            
        #self.log.info(
        #    "\n------------------------------\nStart -State of simulation manager :\n "
        #    + str(simgr)
        #    + "\n------------------------------"
        #)
        
        

        #self.log.info(
        #    "\n------------------------------\nEnd - State of simulation manager :\n "
        #    + str(simgr)
        #    + "\n------------------------------"
        #)
        
        self.log.info("Syscall Found:" + str(self.call_sim.syscall_found))
        
        elapsed_time = time.time() - self.start_time
        self.log.info("Total execution time: " + str(elapsed_time))
        
        self.build_scdg_fin(args, nameFileShort, main_obj, state, simgr)
        

        g = GraphBuilder(
            name=nameFileShort,
            mapping="databases/mapping.txt",
            merge_call=(not args.disjoint_union),
            comp_args=(not args.not_comp_args),
            min_size=args.min_size,
            ignore_zero=(not args.not_ignore_zero),
            odir=args.dir,
            verbose=args.verbose,
        )
        g.build_graph(self.scdg_fin, format_out=args.format_out)

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

        
    def execute_concretly(self, p, state, address):
        simgr = p.factory.simgr(state)
        exploration_tech = angr.exploration_techniques.Symbion(
            find=[address]
        )
        simgr.use_technique(exploration_tech)
        exploration = simgr.run()
        return exploration.stashes['found'][0]
    
    def execute_symbolically(self, p, state, address, args, nameFileShort):
        simgr = p.factory.simgr(state)
        exploration_tech = SemaExplorerSDFS(
            simgr, 0, args.exp_dir, nameFileShort, self, p, find = address
        )
        simgr.use_technique(exploration_tech)
        exploration = simgr.run()
        return exploration.stashes['found'][0]

def main():
    toolc = ToolChainSCDG(
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
            
