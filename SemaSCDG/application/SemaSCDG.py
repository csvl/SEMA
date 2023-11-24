#!/usr/bin/env python3
import os
import sys

import json as json_dumper
from builtins import open as open_file
import time

import claripy
#import monkeyhex  # this will format numerical results in hexadecimal
import logging
from capstone import *

import angr
import gc
import logging
import progressbar
import configparser

from SCDGHelper.GraphBuilder import *
from SCDGHelper.SyscallToSCDG import SyscallToSCDGBuilder
from plugin.PluginManager import PluginManager
from procedures.LinuxSimProcedure import LinuxSimProcedure
from procedures.WindowsSimProcedure import WindowsSimProcedure
from explorer.SemaExplorerManager import SemaExplorerManager
from clogging.CustomFormatter import CustomFormatter
from clogging.LogBookFormatter import * # TODO
from clogging.DataManager import DataManager

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

class SemaSCDG():
    """
    TODO
    """
    def __init__(self):
        self.start_time = time.time()

        config = configparser.ConfigParser()
        config.read('config.ini')
        self.config = config
        self.get_config_param(self.config)

        self.log = logging.getLogger("SemaSCDG")
        self.store_data = self.csv_file != ""

        self.scdg_graph = []
        self.scdg_fin = []
        self.new = {}
        self.nameFileShort = ""
        self.content = ""

        self.plugins = PluginManager()
        self.hooks = self.plugins.get_plugin_hooks()
        self.commands = self.plugins.get_plugin_commands()
        self.ioc = self.plugins.get_plugin_ioc()
        self.packing_manager = self.plugins.get_plugin_packing()

        self.data_manager = DataManager(logger=self.log, verbose=config['SCDG_arg'].getboolean('print_address'))

        self.explorer_manager = SemaExplorerManager()

        self.families = []
        self.nb_exps = 0
        self.current_exps = 0
        self.current_exp_dir = 0

    #Get the parameters from config file
    def get_config_param(self, config):
        # TODO : not proposed in the web app -> add if useful
        self.fast_main = config['SCDG_arg'].getboolean('fast_main')

        self.verbose = config['SCDG_arg'].getboolean('verbose')
        self.print_syscall = config['SCDG_arg'].getboolean('print_syscall')
        self.string_resolve = config['SCDG_arg'].getboolean('string_resolve')
        self.concrete_target_is_local = config['SCDG_arg'].getboolean('concrete_target_is_local')
        self.is_packed = config['SCDG_arg'].getboolean('is_packed')
        self.unpack_mode = config['SCDG_arg']['packing_type']
        self.keep_inter_scdg = config['SCDG_arg'].getboolean('keep_inter_scdg')
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

    # Return an angr project depending on the packing method (if any)
    def deal_with_packing(self):
        if self.is_packed :
            if self.packing_type == "symbion":
                proj_init = self.init_angr_project(self.binary_path, auto_load_libs=True, support_selfmodifying_code=True)
                preload, avatar_gdb = self.packing_manager.setup_symbion(self.binary_path, proj_init, self.concrete_target_is_local, self.call_sim, self.log)
                proj = self.init_angr_project(self.binary_path, auto_load_libs=False, load_debug_info=True, preload_libs=preload, support_selfmodifying_code=True, concrete_target=avatar_gdb)

                for lib in self.call_sim.system_call_table:
                    print(proj.loader.find_all_symbols(lib))

            elif self.packing_type == "unipacker":
                nameFile_unpacked = self.packing_manager.setup_unipacker(self.binary_path, self.nameFileShort, self.log)
                proj = self.init_angr_project(nameFile_unpacked, auto_load_libs=True, support_selfmodifying_code=True)
        else:  
            if self.binary_path.endswith(".bin") or self.binary_path.endswith(".dmp"):
                # TODO : implement function -> see PluginPacking.py
                self.packing_manager.setup_bin_dmp()
            else:
                # default behaviour
                proj = self.init_angr_project(self.binary_path, support_selfmodifying_code=True, auto_load_libs=True, load_debug_info=True, simos=None)
        return proj

    def setup_simproc_scdg_builder(self, proj, os_obj):
        # Load pre-defined syscall table
        if os_obj == "windows":
            self.call_sim = WindowsSimProcedure()
            self.call_sim.system_call_table = self.call_sim.ddl_loader.load(proj, False , None)
        else:
            self.call_sim = LinuxSimProcedure()
            self.call_sim.system_call_table = self.call_sim.linux_loader.load_table(proj)
           
        self.syscall_to_scdg_builder = SyscallToSCDGBuilder(self.call_sim, self.scdg_graph, self.string_resolve, self.print_syscall, self.verbose)
            
        self.log.info("System call table loaded")
        self.log.info("System call table size : " + str(len(self.call_sim.system_call_table)))

    def get_entry_addr(self, proj):
        # TODO : Maybe useless : Try to directly go into main (optimize some binary in windows)
        addr_main = proj.loader.find_symbol("main")
        if addr_main and self.fast_main:
            addr = addr_main.rebased_addr
        else:
            # Take the entry point specify in config file
            addr = self.config["SCDG_arg"]["entry_addr"]
            if addr != "None":
                #Convert string into hexadecimal
                addr = hex(int(addr, 16))
            else:
                addr = None
        self.log.info("Entry_state address = " + str(addr))
        return addr
    
    # Defining arguments given to the program (minimum is filename)
    def get_binary_args(self):
        args_binary = [self.nameFileShort] 
        if self.n_args:
            for i in range(self.n_args):
                args_binary.append(claripy.BVS("arg" + str(i), 8 * 16))
        return args_binary

    def handle_simfile(self, state):
        if self.sim_file:
            with open_file(self.binary_path, "rb") as f:
                self.content = f.read()
            simfile = angr.SimFile(self.nameFileShort, content=self.content)
            state.fs.insert(self.nameFileShort, simfile)
            pagefile = angr.SimFile("pagefile.sys", content=self.content)
            state.fs.insert("pagefile.sys", pagefile)

    # Create ProcessHeap struct and set heapflages to 0
    def setup_heap(self, state, proj):
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

    # Create initial state of the binary
    def create_binary_init_state(self, proj):
        args_binary = self.get_binary_args()

        entry_addr = self.get_entry_addr(proj)
        
        options = self.get_angr_state_options()

        state = proj.factory.entry_state(addr=entry_addr, args=args_binary, add_options=options)

        self.handle_simfile(state)
        
        state.options.discard("LAZY_SOLVES") 
        if not (self.is_packed and self.packing_type == "symbion") or True:
            state.register_plugin(
                "heap", 
                angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc(heap_size=0x10000000)
            )
        
        # Enable plugins set to true in config file
        if self.plugin_enable:
            self.plugins.load_plugin(state, self.config)

        self.setup_heap(state, proj)
        
        # Constraint arguments to ASCII
        for i in range(1, len(args_binary)):
           for byte in args_binary[i].chop(8):
               # state.add_constraints(byte != '\x00') # null
               state.add_constraints(byte >= " ".encode("utf8"))  # '\x20'
               state.add_constraints(byte <= "~".encode("utf8"))  # '\x7e'
            
        return state, args_binary
    
    # Processing before run
    def run_setup(self, exp_dir):
        self.scdg_graph.clear()
        self.scdg_fin.clear()
        
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
            self.nameFileShort = self.binary_path.split("/")[-1]
        else:
            self.nameFileShort = self.binary_path
        self.data_manager.data["nameFileShort"] = self.nameFileShort
        try:
            os.stat(exp_dir + self.nameFileShort)
        except:
            os.makedirs(exp_dir + self.nameFileShort)

        #Set log handler
        fileHandler = logging.FileHandler(exp_dir + self.nameFileShort + "/" + "scdg.ans")
        fileHandler.setFormatter(CustomFormatter())
        try:
            logging.getLogger().removeHandler(fileHandler)
        except:
            self.log.warning("Exception remove filehandler")
            pass
        
        logging.getLogger().addHandler(fileHandler)

        exp_dir = exp_dir + self.nameFileShort + "/"

        return exp_dir, fileHandler
    
    def setup_hooks(self, proj, state, os_obj):
        if os_obj == "windows":
            self.call_sim.loadlibs_proc(self.call_sim.system_call_table, proj) #TODO mbs=symbs,dll=dll)
        
        self.call_sim.custom_hook_static(proj)

        if os_obj != "windows":
            self.call_sim.custom_hook_linux_symbols(proj)
            self.call_sim.custom_hook_no_symbols(proj)
        else:
            self.call_sim.custom_hook_windows_symbols(proj)  #TODO ue if (self.is_packed and False) else False,symbs)

        if self.hooks_enable:
            self.hooks.initialization(self.content, is_64bits=True if proj.arch.name == "AMD64" else False)
            self.hooks.hook(state,proj,self.call_sim)

    #Setup angr project, runs it and build the SCDG graph
    def run(self, exp_dir):

        exp_dir, fileHandler = self.run_setup(exp_dir)
        
        title = "--- Building SCDG of " + self.family  +"/" + self.nameFileShort  + " ---"
        self.log.info("\n" + "-" * len(title) + "\n" + title + "\n" + "-" * len(title))

        #####################################################
        ##########      Project creation         ############
        #####################################################
        """
        TODO : Note for further works : support_selfmodifying_code should be investigated
        """

        proj = self.deal_with_packing()

        main_obj = proj.loader.main_object
        os_obj = main_obj.os
        if self.count_block_enable:
            self.data_manager.count_block(proj, main_obj)
            
        if self.verbose:
            self.print_program_info(proj, main_obj, os_obj)

        self.setup_simproc_scdg_builder(proj, os_obj)
        
        state, args_binary = self.create_binary_init_state(proj)

        
        #### Custom Hooking ####
        # Mechanism by which angr replaces library code with a python summary
        # When performing simulation, at every step angr checks if the current
        # address has been hooked, and if so, runs the hook instead of the binary
        # code at that address.

        self.setup_hooks(proj, state, os_obj)
                
        # Creation of simulation managerinline_call, primary interface in angr for performing execution
        
        simgr = proj.factory.simulation_manager(state)
        
        dump_file = {}
        self.print_memory_info(main_obj, dump_file)    
        
        #####################################################
        ##########         Exploration           ############
        #####################################################

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

        exploration_tech = self.explorer_manager.get_exploration_tech(self.nameFileShort, simgr, exp_dir, proj, self.expl_method, self.scdg_graph, self.call_sim)
        
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
        
        #####################################################
        ##########         Data collection       ############
        #####################################################
    
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

        ####################################################
        ##########         SCDG build           ############
        ####################################################

        self.build_scdg(main_obj, state, simgr, exp_dir)
        
        g = GraphBuilder(
            name=self.nameFileShort,
            mapping=exp_dir + "mapping_" + self.nameFileShort + ".txt",
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
