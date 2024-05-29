#!/usr/bin/env python3
import os
import sys
import time
import argparse
import r2pipe

import claripy
import contextlib
import logging
from capstone import *

import angr
import gc
import progressbar
import configparser

import json as json_dumper
from builtins import open as open_file

args_parser = argparse.ArgumentParser(description="SCDG module arguments")
args_parser.add_argument('config_file', type=str, help='The relative path to the config file')
args = args_parser.parse_args()

config = configparser.ConfigParser()
file = config.read(sys.argv[1])
if file == []:
    raise FileNotFoundError("Config file not found")
log_level_sema = config['SCDG_arg'].get('log_level_sema')
log_level_angr = config['SCDG_arg'].get('log_level_angr')
log_level_claripy = config['SCDG_arg'].get('log_level_claripy')
os.environ["LOG_LEVEL"] = log_level_sema

from helper.GraphBuilder import *
from helper.SyscallToSCDG import SyscallToSCDG
from plugin.PluginManager import PluginManager
from procedures.LinuxSimProcedure import LinuxSimProcedure
from procedures.WindowsSimProcedure import WindowsSimProcedure
from explorer.SemaExplorerManager import SemaExplorerManager
from clogging.CustomFormatter import CustomFormatter
from clogging.LogBookFormatter import * # TODO
from clogging.DataManager import DataManager

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))

# Setup the logging system and set it to the level specified in the config file
logger = logging.getLogger("SemaSCDG")
ch = logging.StreamHandler()
ch.setLevel(log_level_sema)
ch.setFormatter(CustomFormatter())
logger.addHandler(ch)
logger.propagate = False
logging.getLogger("angr").setLevel(log_level_angr)
logging.getLogger('claripy').setLevel(log_level_claripy)
logger.setLevel(log_level_sema)

class SemaSCDG():
    """
    Class for managing the SemaSCDG application, including setting up configurations, creating angr projects, running exploration, building SCDG graphs, and handling various analysis tasks.

    This class encapsulates the functionality for initializing the application, setting up configurations, creating angr projects, running exploration, building SCDG graphs, and managing analysis tasks.
    """
    def __init__(self):
        """
        Initializes the SemaSCDG application with configurations, log settings, plugins, and other necessary components.

        This method sets up the application environment, including configurations, logging, plugins, and directories for storing results.
        """
        self.config = config
        config.read(sys.argv[1])
        self.get_config_param(self.config)
        self.log = logger
        self.log_level_sema = log_level_sema
        self.log_level_angr = log_level_angr
        self.log_level_claripy= log_level_claripy

        self.store_data = self.csv_file != ""
        self.scdg_graph = []
        self.new = {}
        self.nameFileShort = ""
        self.content = ""

        self.plugins = PluginManager()
        self.packing_manager = self.plugins.get_plugin_packing()
        self.data_manager = DataManager()
        self.explorer_manager = SemaExplorerManager()

        self.nb_exps = 0
        self.current_exps = 0
        self.current_exp_dir = 0

        self.windows_simproc = WindowsSimProcedure(verbose=True)
        self.linux_simproc = LinuxSimProcedure(verbose=True)
        self.syscall_to_scdg_builder = SyscallToSCDG(self.scdg_graph)
        self.graph_builder = GraphBuilder()

        # Setup the output directory
        self.log.info(f"Results will be saved into : {self.mapping_dir}")
        with contextlib.suppress(Exception):
            os.makedirs(self.mapping_dir)
        self.save_conf()

    def get_config_param(self, config):
        """
        Extracts configuration parameters from the provided config object.

        This function retrieves various configuration parameters needed for the SemaSCDG application from the config object.
        """
        output_dir = "database/SCDG/runs/"
        self.fast_main = config['SCDG_arg'].getboolean('fast_main')
        self.concrete_target_is_local = config['SCDG_arg'].getboolean('concrete_target_is_local')
        self.is_packed = config['SCDG_arg'].getboolean('is_packed')
        self.packing_type = config['SCDG_arg']['packing_type']
        self.keep_inter_scdg = config['SCDG_arg'].getboolean('keep_inter_scdg')
        self.approximate = config['SCDG_arg'].getboolean('approximate')
        self.track_command = config['Plugins_to_load'].getboolean('plugin_track_command')
        self.ioc_report = config['Plugins_to_load'].getboolean('plugin_ioc_report')
        self.hooks_enable = config['Plugins_to_load'].getboolean('plugin_hooks')
        self.sim_file = config['SCDG_arg'].getboolean('sim_file')
        self.count_block_enable = config['SCDG_arg'].getboolean('count_block_enable')
        self.plugin_enable = config['SCDG_arg'].getboolean('plugin_enable')
        self.expl_method = config['SCDG_arg']["expl_method"]
        self.family = config['SCDG_arg']['family']
        self.exp_dir_name = config['SCDG_arg']['exp_dir']
        self.exp_dir = output_dir + self.exp_dir_name + "/" + self.family
        self.mapping_dir = output_dir + self.exp_dir_name + "/"
        self.binary_path = config['SCDG_arg']['binary_path']
        self.n_args = int(config['SCDG_arg']['n_args'])
        self.csv_file = config['SCDG_arg']['csv_file']
        self.csv_path = output_dir + self.exp_dir_name + "/" + self.csv_file
        self.conf_path = output_dir + self.exp_dir_name + "/scdg_conf.json"
        self.pre_run_thread = config['SCDG_arg'].getboolean('pre_run_thread')
        self.runtime_run_thread = config['SCDG_arg'].getboolean('runtime_run_thread')
        self.post_run_thread = config['SCDG_arg'].getboolean('post_run_thread')

    def save_conf(self):
        """
        Saves the configuration of the experiment in a JSON file.

        This function converts the configuration parameters into a dictionary and writes them to a JSON file for future reference.
        """
        param = {}
        sections = self.config.sections()
        for section in sections:
            items=self.config.items(section)
            param[section]=dict(items)
        with open(self.conf_path, "w") as f:
            json.dump(param, f, indent=4)

    def init_angr_project(self, namefile, preload_libs=[], concrete_target=None, support_selfmodifying_code=None, simos=None, arch=None, auto_load_libs=False, load_debug_info= False):
        """
        Initializes and returns an angr Project object with specified parameters.

        This function creates an angr Project object with the provided parameters for analysis and symbolic execution.
        """
        return angr.Project(
            namefile,
            use_sim_procedures=True,
            load_options={
                "auto_load_libs": auto_load_libs,
                "load_debug_info": load_debug_info,
                "preload_libs": preload_libs,
            },
            support_selfmodifying_code=support_selfmodifying_code,
            simos=simos,
            arch=arch,
            concrete_target=concrete_target,
            default_analysis_mode=(
                "symbolic_approximating" if self.approximate else "symbolic"
            ),
        )

    def print_program_info(self, proj, main_obj, os_obj):
        """
        Prints information about the program, including libraries used, OS recognition, CPU architecture, entry point, memory addresses, stack executability, binary position independence, and exploration method.

        This function logs various details about the program, such as libraries, OS, CPU architecture, entry point, memory addresses, stack properties, binary position independence, and exploration method.
        """
        self.log.info(f"Libraries used are :\n {str(proj.loader.requested_names)}")
        self.log.info(f"OS recognized as : {str(os_obj)}")
        self.log.info(f"CPU architecture recognized as : {str(proj.arch)}")
        self.log.info(f"Entry point of the binary recognized as : {hex(proj.entry)}")
        self.log.info(f"Min/Max addresses of the binary recognized as : {str(proj.loader)}")
        self.log.info(f"Stack executable ?  {str(main_obj.execstack)}")
        self.log.info(f"Binary position-independent ?  {str(main_obj.pic)}")
        self.log.info(f"Exploration method:  {str(self.expl_method)}")

    def get_angr_state_options(self):
        """
        Retrieves and returns a set of angr state options based on the configuration settings.

        This function reads the ANGR state options from the configuration, converts them to uppercase strings, and returns them as a set.
        """
        options = set()
        for option in self.config["ANGR_State_options_to_add"] :
            if self.config["ANGR_State_options_to_add"].getboolean(option):
                options.add(str.upper(option))
        return options

    def set_breakpoints(self, state):
        """
        Sets breakpoints for various inspection actions in the given state.

        This function sets breakpoints for different inspection actions based on the state provided, such as adding calls, debugging calls, printing state addresses, adding instruction addresses, and adding block addresses.
        """
        state.inspect.b("simprocedure", when=angr.BP_AFTER, action=self.syscall_to_scdg_builder.add_call)
        state.inspect.b("simprocedure", when=angr.BP_BEFORE, action=self.syscall_to_scdg_builder.add_call_debug)
        state.inspect.b("call", when=angr.BP_BEFORE, action=self.syscall_to_scdg_builder.add_addr_call)
        state.inspect.b("call", when=angr.BP_AFTER, action=self.syscall_to_scdg_builder.rm_addr_call)

        if self.count_block_enable:
            state.inspect.b("instruction",when=angr.BP_BEFORE, action=self.data_manager.print_state_address)
            state.inspect.b("instruction",when=angr.BP_AFTER, action=self.data_manager.add_instr_addr)
            state.inspect.b("irsb",when=angr.BP_BEFORE, action=self.data_manager.add_block_addr)

    def deal_with_packing(self):
        """
        Handles different packing scenarios for the binary analysis process.

        This function determines the appropriate actions based on the packing type and binary path, setting up the analysis environment accordingly.
        """
        if self.is_packed:
            if self.packing_type == "symbion":
                proj_init = self.init_angr_project(self.binary_path, auto_load_libs=True, support_selfmodifying_code=True)
                preload, avatar_gdb = self.packing_manager.setup_symbion(self.binary_path, proj_init, self.concrete_target_is_local, self.call_sim, self.log)
                proj = self.init_angr_project(self.binary_path, auto_load_libs=False, load_debug_info=True, preload_libs=preload, support_selfmodifying_code=True, concrete_target=avatar_gdb)

                for lib in self.call_sim.system_call_table:
                    print(proj.loader.find_all_symbols(lib))

            elif self.packing_type == "unipacker":
                nameFile_unpacked = self.packing_manager.setup_unipacker(self.binary_path, self.nameFileShort, self.log)
                proj = self.init_angr_project(nameFile_unpacked, auto_load_libs=True, support_selfmodifying_code=True)
        elif self.binary_path.endswith(".bin") or self.binary_path.endswith(".dmp"):
            # TODO : implement function -> see PluginPacking.py
            self.packing_manager.setup_bin_dmp()
        else:
            # default behaviour
            proj = self.init_angr_project(self.binary_path, support_selfmodifying_code=True, auto_load_libs=True, load_debug_info=True, simos=None)
        return proj

    def setup_simproc_scdg_builder(self, proj, os_obj):
        """
        Sets up the system call procedure and builder based on the operating system.

        This function initializes the appropriate system call procedure and builder based on the operating system, loads the syscall table, and logs the system call table information.
        """
        # Load pre-defined syscall table
        if os_obj == "windows":
            self.call_sim = self.windows_simproc
            self.call_sim.setup("windows")
        else:
            self.call_sim = self.linux_simproc
            self.call_sim.setup("linux")

        self.call_sim.load_syscall_table(proj)

        self.syscall_to_scdg_builder.set_call_sim(self.call_sim)

        self.log.info("System call table loaded")
        self.log.debug(f"System call table size : {len(self.call_sim.system_call_table)}")

    def get_entry_addr(self, proj):
        """
        Retrieves the entry address for the analysis from the provided project.

        This function searches for the entry address in the project, considering the 'fast_main' flag and configuration settings, and returns the entry address in hexadecimal format.
        """
        # TODO : Maybe useless : Try to directly go into main (optimize some binary in windows)
        r = r2pipe.open(self.binary_path)
        out_r2 = r.cmd('f ~sym._main')
        out_r2 = r.cmd('f ~sym._main')
        addr_main = proj.loader.find_symbol("main")
        if addr_main and self.fast_main:
            addr = addr_main.rebased_addr
        elif out_r2:
            addr= None
            with contextlib.suppress(Exception):
                iter = out_r2.split("\n")
                for s in iter:
                    if s.endswith("._main"):
                        addr = int(s.split(" ")[0],16)
        else:
            # Take the entry point specify in config file
            addr = self.config["SCDG_arg"]["entry_addr"]
            if addr != "None":
                #Convert string into hexadecimal
                addr = hex(int(addr, 16))
            else:
                addr = None
        self.log.info(f"Entry_state address = {str(addr)}")
        return addr

    def get_binary_args(self):
        """
        Generates symbolic arguments for the binary analysis.

        This function creates a list of binary arguments, including the binary name and symbolic arguments based on the number of arguments specified.
        """
        args_binary = [self.nameFileShort]
        if self.n_args:
            for i in range(self.n_args):
                args_binary.append(claripy.BVS("arg" + str(i), 8 * 16))
        return args_binary

    def handle_simfile(self, state):
        """
        Handles the simulation file by inserting it into the state file system.

        This function reads the simulation file content, creates SimFile objects, and inserts them into the state file system if the simulation file flag is set.
        """
        if self.sim_file:
            with open_file(self.binary_path, "rb") as f:
                self.content = f.read()
            simfile = angr.SimFile(self.nameFileShort, content=self.content)
            state.fs.insert(self.nameFileShort, simfile)
            pagefile = angr.SimFile("pagefile.sys", content=self.content)
            state.fs.insert("pagefile.sys", pagefile)

    def setup_heap(self, state, proj):
        """
        Sets up the heap memory structure in the state based on the architecture.

        This function configures the heap memory structure in the state based on the architecture of the project, adjusting memory addresses and values accordingly.
        """
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

    def create_binary_init_state(self, proj):
        """
        Creates the initial state for binary analysis with specified arguments, entry address, and options.

        This function constructs the initial state for binary analysis, incorporating binary arguments, entry address, angr state options, simulation file handling, heap setup, plugin loading, and constraint enforcement for ASCII characters.
        """
        args_binary = self.get_binary_args()

        entry_addr = self.get_entry_addr(proj)

        options = self.get_angr_state_options()

        state = proj.factory.entry_state(addr=entry_addr, args=args_binary, add_options=options)

        self.handle_simfile(state)

        state.options.discard("LAZY_SOLVES")
        state.register_plugin(
            "heap",
            angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc()
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

    def run_setup(self, exp_dir):
        """
        Runs the setup process for the experiment directory.

        This function prepares the experiment directory by setting up a CSV file, extracting the sample name, creating directories, configuring log handlers, and returning the updated experiment directory path and file handler.
        """
        # TODO check if PE file get /GUARD option (VS code) with leaf

        # Create a Dataframe for future data if a csv file is specified
        if self.store_data:
            self.data_manager.setup_csv(self.csv_path)

        # Take name of the sample without full path
        if "/" in self.binary_path:
            self.nameFileShort = self.binary_path.split("/")[-1]
        else:
            self.nameFileShort = self.binary_path
        self.data_manager.data["nameFileShort"] = self.nameFileShort
        try:
            os.stat(exp_dir + self.nameFileShort)
        except Exception:
            os.makedirs(exp_dir + self.nameFileShort)

        #Set log handler
        fileHandler = logging.FileHandler(exp_dir + self.nameFileShort + "/" + "scdg.ans")
        fileHandler.setFormatter(CustomFormatter())
        try:
            logging.getLogger().removeHandler(fileHandler)
        except Exception:
            self.log.warning("Exception remove filehandler")

        logging.getLogger().addHandler(fileHandler)

        exp_dir = exp_dir + self.nameFileShort + "/"

        return exp_dir, fileHandler

    def setup_hooks(self, proj, state, os_obj):
        """
        Sets up hooks for the binary analysis based on the operating system.

        This function configures hooks for the binary analysis, including loading libraries, setting custom hooks, and initializing hooks based on the operating system.
        """
        if os_obj == "windows":
            self.call_sim.loadlibs_proc(self.call_sim.system_call_table, proj) #TODO mbs=symbs,dll=dll)

        self.call_sim.custom_hook_static(proj)

        if os_obj != "windows":
            self.call_sim.custom_hook_linux_symbols(proj)
            self.call_sim.custom_hook_no_symbols(proj)
        else:
            self.call_sim.custom_hook_windows_symbols(proj)  #TODO ue if (self.is_packed and False) else False,symbs)

        if self.hooks_enable:
            self.plugins.enable_plugin_hooks(self, self.content, state, proj, self.call_sim)

    def project_creation(self):
        """Handles project creation and initial analysis setup."""
        proj = self.deal_with_packing()
        main_obj = proj.loader.main_object
        os_obj = main_obj.os
        if self.count_block_enable:
            self.data_manager.count_block(proj, main_obj)
        self.print_program_info(proj, main_obj, os_obj)
        self.setup_simproc_scdg_builder(proj, os_obj)
        state, args_binary = self.create_binary_init_state(proj)
        return proj, main_obj, os_obj, state, args_binary

    def perform_exploration(self, exp_dir, proj, simgr):
        """
        Performs the exploration process for the binary analysis.

        This function sets up the exploration technique, handles runtime thread settings, logs loader information, runs the simulation manager, and records the exploration time.
        """
        exploration_tech = self.explorer_manager.get_exploration_tech(self.nameFileShort, simgr, exp_dir, proj, self.expl_method, self.scdg_graph, self.call_sim)

        if self.runtime_run_thread:
            simgr.active[0].globals["is_thread"] = True

        self.log.info(proj.loader.all_pe_objects)
        self.log.info(proj.loader.extern_object)
        self.log.info(proj.loader.symbols)

        simgr.use_technique(exploration_tech)

        self.log.info(
            "\n------------------------------\nStart -State of simulation manager :\n "
            + str(simgr)
            + "\n------------------------------"
        )

        start_explo_time = time.time()
        simgr.run()
        self.data_manager.data["exploration_time"] = time.time() - start_explo_time

        self.log.info(
            "\n------------------------------\nEnd - State of simulation manager :\n "
            + str(simgr)
            + "\n------------------------------"
        )

    def collect_data(self, exp_dir, proj, state, simgr, execution_time):
        """
        Collects and processes data after the binary analysis.

        This function handles the collection of execution time, printing block information, logging syscall details, loading plugin data, tracking commands, and building an IOC (Indicator of Compromise) report.
        """
        self.data_manager.data["execution_time"] = execution_time
        self.log.info(f"Total execution time: {execution_time}")

        if self.count_block_enable:
            self.data_manager.print_block_info()

        self.log.debug(f"Syscalls Found:{self.call_sim.syscall_found}")
        self.log.debug(f"Loaded libraries:{proj.loader.requested_names}")

        if self.plugin_enable:
            self.data_manager.get_plugin_data(state, simgr, to_store=self.store_data)

        if self.track_command:
            self.plugins.enable_plugin_commands(self, simgr, self.scdg_graph, exp_dir)
        if self.ioc_report:
            self.plugins.enable_plugin_ioc(self, self.scdg_graph, exp_dir)

    def run(self, exp_dir):
        """
        Runs the complete analysis process for the binary.

        This function orchestrates the entire analysis process, including setting up the environment, creating the initial state, configuring hooks, exploration, data collection, SCDG (System Call Dependency Graph) construction, and finalization steps.
        """
        start_execution_time = time.time()

        exp_dir, self.fileHandler = self.run_setup(exp_dir)

        title = f"--- Building SCDG of {self.family}/{self.nameFileShort} ---"
        self.log.info("\n" + "-" * len(title) + "\n" + title + "\n" + "-" * len(title))

        # Project creation
        proj, main_obj, os_obj, state, args_binary = self.project_creation()

        # Custom Hooking
        start_hooking_time = time.time()
        self.setup_hooks(proj, state, os_obj)
        self.data_manager.data["hooking_time"] = time.time() - start_hooking_time

        # Creation of simulation managerinline_call, primary interface in angr for performing execution
        simgr = proj.factory.simulation_manager(state)
        dump_file = {}
        self.print_memory_info(main_obj, dump_file)

        # Exploration
        if self.pre_run_thread:
            state.plugin_thread.pre_run_thread(self.content, self.inputs)

        self.set_breakpoints(state)

        # (3) TODO: move that but as serena purposes
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

        self.perform_exploration(exp_dir, proj, simgr)

        if self.post_run_thread:
            state.plugin_thread.post_run_thread(simgr)

        # Data collection
        execution_time = time.time() - start_execution_time

        self.collect_data(exp_dir, proj, state, simgr, execution_time)

        # SCDG build
        stashes_content = self.get_stashes_content(main_obj, state, simgr, exp_dir)

        self.graph_builder.build(
            stashes_content,
            f"{self.mapping_dir}mapping_{self.exp_dir_name}.txt",
            f"{self.exp_dir}/{self.nameFileShort}",
            self.family,
        )

        if self.store_data:
            self.data_manager.save_to_csv(proj, self.family, self.call_sim, self.csv_path)

        self.end_run()

    def end_run(self):
        """
        Finalizes the binary analysis process by clearing resources and data structures.

        This function removes handlers, clears simulation data, and resets various components to conclude the analysis.
        """
        logging.getLogger().removeHandler(self.fileHandler)
        with contextlib.suppress(Exception):
            self.call_sim.clear()
        self.scdg_graph.clear()
        self.graph_builder.clear()
        self.data_manager.clear()

    def get_stashes_content(self, main_obj, state, simgr, exp_dir):
        """
        Constructs System Call Dependency Graph (SCDG) content from simulation stashes.

        Processes simulation stashes to extract relevant traces for graph construction, ensuring uniqueness based on hash values.
        """
        dump_file = {}
        dump_id = 0
        dic_hash_SCDG = {}
        scdg_fin = []
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
                    scdg_fin.append(self.scdg_graph[present_state.globals["id"]])

        self.print_memory_info(main_obj, dump_file)

        if self.keep_inter_scdg:
            self.keep_inter_scdg_meth(exp_dir, dump_file)
        return scdg_fin

    def keep_inter_scdg_meth(self, exp_dir, dump_file):
        """
        Keeps an intermediate System Call Dependency Graph (SCDG) by updating a JSON file with new data.

        Appends the provided data to the existing JSON file or creates a new one if it does not exist.
        """
        ofilename = f"{exp_dir}inter_SCDG.json"
        self.log.debug(ofilename)
        list_obj = []
        if os.path.isfile(ofilename):
            with open(ofilename) as fp:
                list_obj = json_dumper.load(fp)
        list_obj.append(dump_file)
        with open(ofilename, "w") as save_SCDG:
            json_dumper.dump(list_obj, save_SCDG)

    def print_memory_info(self, main_obj, dump_file):
        """
        Prints memory section information for the main object.

        This function extracts and logs details about memory sections, including virtual address, memory size, and permissions.
        """
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

def __handle_exception(e, sema_scdg, crashed_samples):
    """
    Handles exceptions during the binary analysis process.

    This function manages different types of exceptions, logs errors, ends the analysis run, and keeps track of crashed samples.
    """
    if isinstance(e, KeyboardInterrupt):
        print("Interrupted by user")
        sys.exit(-1)
    sema_scdg.log.error("This sample has crashed")
    sema_scdg.end_run()
    crashed_samples.append(sema_scdg.binary_path)

def __process_folder(folder, sema_scdg, crashed_samples):
    """
    Processes files in a folder for building the System Call Dependency Graph (SCDG).

    This function iterates through files in a folder, sets up the analysis environment for each file, runs the analysis, handles exceptions, and updates progress.
    """
    sema_scdg.log.info(f"You are currently building SCDG for {folder}")
    files = [os.path.join(folder, f) for f in os.listdir(folder) if os.path.isfile(os.path.join(folder, f)) and not f.endswith(".zip")]
    current_family = folder.split("/")[-1]
    current_exp_dir = sema_scdg.exp_dir.replace(sema_scdg.family, current_family)
    sema_scdg = SemaSCDG()
    with progressbar.ProgressBar(max_value=len(files)) as bar_f:
        for file in files:
            sema_scdg.exp_dir = current_exp_dir
            sema_scdg.binary_path = file
            sema_scdg.family = current_family
            try:
                sema_scdg.run(f"{sema_scdg.exp_dir}/")
            except Exception as e:
                __handle_exception(e, sema_scdg, crashed_samples)
            bar_f.next()
            del sema_scdg
            claripy.ast.bv._bvv_cache = {}
            gc.collect()
            sema_scdg = SemaSCDG()

def start_scdg():
    """
    Starts the System Call Dependency Graph (SCDG) analysis process.

    This function initiates the analysis by determining whether to analyze a single binary or multiple binaries in a folder, running the analysis, handling exceptions, and reporting any crashed samples.
    """
    config = configparser.ConfigParser()
    file = config.read(sys.argv[1])
    if file == []:
        raise FileNotFoundError("Config file not found")
    log_level_sema = config['SCDG_arg'].get('log_level_sema')
    os.environ["LOG_LEVEL"] = log_level_sema

    crashed_samples = []
    binary_path = "".join(config['SCDG_arg']['binary_path'].rstrip())
    sema_scdg = SemaSCDG()

    if os.path.isfile(binary_path):
        sema_scdg.log.info(f"You decide to analyse a single binary: {sema_scdg.binary_path}")
        sema_scdg.run(f"{sema_scdg.exp_dir}/")
    elif os.path.isdir(sema_scdg.binary_path):
        subfolder = [os.path.join(sema_scdg.binary_path, f) for f in os.listdir(sema_scdg.binary_path) if os.path.isdir(os.path.join(sema_scdg.binary_path, f))]
        if not subfolder:
            __process_folder(sema_scdg.binary_path, sema_scdg, crashed_samples)
        with progressbar.ProgressBar(max_value=len(subfolder)) as bar_f:
            for folder in subfolder:
                __process_folder(folder, sema_scdg, crashed_samples)
                bar_f.next()
    else:
        sema_scdg.log.error("Error: you should insert a folder containing malware classified in their family folders\n(Example: databases/Binaries/malware-win/small_train")
        raise FileNotFoundError("No correct subfolder or binary found")

    if crashed_samples:
        sema_scdg.log.warning(
            f"{len(crashed_samples)} sample(s) has(ve) crashed, see 'scdg.ans' file for log details or run the samples individually to see error details"
        )
        for i in crashed_samples:
            print("\t" + i)


if __name__ == "__main__":
    start_scdg()
