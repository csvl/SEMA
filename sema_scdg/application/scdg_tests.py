import unittest
import sys, os
import configparser
import networkx as nx
import matplotlib.pyplot as plt
import pandas as pd

sys.path.insert(0, '/sema-scdg/application/')

from SCDGApp import get_args, parse_json_request
from SemaSCDG import SemaSCDG
from explorer.SemaExplorer import SemaExplorer
from helper.SyscallToSCDG import SyscallToSCDG
from helper.GraphBuilder import GraphBuilder

config = configparser.ConfigParser()


class TestSCDG(unittest.TestCase):

    def test_config_scdg(self):
        sema_scdg = SemaSCDG()
        self.assertEqual(sema_scdg.fast_main, False)
        self.assertEqual(sema_scdg.concrete_target_is_local, False)
        self.assertEqual(sema_scdg.is_packed, False)
        self.assertEqual(sema_scdg.packing_type, "symbion")
        self.assertEqual(sema_scdg.keep_inter_scdg, False)
        self.assertEqual(sema_scdg.approximate, False)
        self.assertEqual(sema_scdg.track_command, False)
        self.assertEqual(sema_scdg.ioc_report, False)
        self.assertEqual(sema_scdg.hooks_enable, False)
        self.assertEqual(sema_scdg.sim_file, False)
        self.assertEqual(sema_scdg.count_block_enable, True)
        self.assertEqual(sema_scdg.plugin_enable, True)
        self.assertEqual(sema_scdg.expl_method, "CDFS")
        self.assertEqual(sema_scdg.family, "Binaryfamily")
        self.assertEqual(sema_scdg.exp_dir_name, "ExpDirName")
        self.assertEqual(sema_scdg.binary_path, "test_data/00a8c63b42803a887b12865ba5f388bf")
        self.assertEqual(sema_scdg.n_args, 1)
        self.assertEqual(sema_scdg.csv_file, "stats.csv")
        self.assertEqual(sema_scdg.pre_run_thread, False)
        self.assertEqual(sema_scdg.runtime_run_thread, False)
        self.assertEqual(sema_scdg.post_run_thread, False)
        self.assertEqual(sema_scdg.log_level, "INFO")

    def test_config_explorer(self):
        sema_explorer = SemaExplorer(None, "", "", [], None)
        self.assertEqual(sema_explorer.eval_time, False)
        self.assertEqual(sema_explorer.timeout, 150)
        self.assertEqual(sema_explorer.max_end_state, 600)
        self.assertEqual(sema_explorer.max_step, 50000)
        self.assertEqual(sema_explorer.jump_it, 3)
        self.assertEqual(sema_explorer.loop_counter_concrete, 10240)
        self.assertEqual(sema_explorer.max_simul_state, 5)
        self.assertEqual(sema_explorer.max_in_pause_stach, 200)
        self.assertEqual(sema_explorer.timeout_tab, [1200, 2400, 3600])
        self.assertEqual(sema_explorer.log_level, "INFO")

    def test_config_syscall_to_SCDG(self):
        syscall_to_scdg = SyscallToSCDG(None)
        self.assertEqual(syscall_to_scdg.string_resolv, True)
        self.assertEqual(syscall_to_scdg.print_syscall, False)

    def test_config_graph_builder(self):
        graph_builder = GraphBuilder()
        self.assertEqual(graph_builder.graph_output, "gs")
        self.assertEqual(graph_builder.MERGE_CALL, True)
        self.assertEqual(graph_builder.COMP_ARGS, True)
        self.assertEqual(graph_builder.log_level, "INFO")
        self.assertEqual(graph_builder.MIN_SIZE, 3)
        self.assertEqual(graph_builder.IGNORE_ZERO, True)
        self.assertEqual(graph_builder.three_edges, True)

    def test_config_angr_options(self):
        sema_scdg = SemaSCDG()
        options = sema_scdg.get_angr_state_options()
        self.assertEqual(len(options), 4)
        self.assertEqual("MEMORY_CHUNK_INDIVIDUAL_READS" in options, True)
        self.assertEqual("USE_SYSTEM_TIMES" in options, True)
        self.assertEqual("ZERO_FILL_UNCONSTRAINED_REGISTERS" in options, True)
        self.assertEqual("ZERO_FILL_UNCONSTRAINED_MEMORY" in options, True)

    def test_config_plugin(self):
        sema_scdg = SemaSCDG()
        exp_dir, sema_scdg.fileHandler = sema_scdg.run_setup(sema_scdg.exp_dir + "/")
        proj = sema_scdg.deal_with_packing()
        main_obj = proj.loader.main_object
        os_obj = main_obj.os
        sema_scdg.setup_simproc_scdg_builder(proj, os_obj)
        state, args_binary = sema_scdg.create_binary_init_state(proj)
        self.assertEqual(state.has_plugin("plugin_env_var"), True)
        self.assertEqual(state.has_plugin("plugin_locale_info"), True)
        self.assertEqual(state.has_plugin("plugin_resources"), True)
        self.assertEqual(state.has_plugin("plugin_widechar"), True)
        self.assertEqual(state.has_plugin("plugin_registery"), False)
        self.assertEqual(state.has_plugin("plugin_atom"), False)

    def test_REST_scdg_args(self):
        scdg_args = get_args()
        expected_result = [{'expl_method': 
                            [{'name': 'DFS', 'help': 'Depth First Search', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True},
                              {'name': 'BFS', 'help': 'Breadth First Search', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True},
                              {'name': 'CDFS', 'help': 'Custom Depth First Search (Default)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True},
                              {'name': 'CBFS', 'help': 'Custom Breadth First Search', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True},
                              {'name': 'DBFS', 'help': 'TODO', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True},
                              {'name': 'SDFS', 'help': 'TODO', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True},
                              {'name': 'SCDFS', 'help': 'TODO', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True}],
                            'graph_output': 
                                [{'name': 'gs', 'help': '.GS format', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True},
                                {'name': 'json', 'help': '.JSON format', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True}],
                            'packing_type': 
                                [{'name': 'symbion', 'help': 'Concolic unpacking method (linux | windows [in progress])', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True},
                                {'name': 'unipacker', 'help': 'Emulation unpacking method (windows only)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True}]},
                        {'log_level': 
                            [{'name': 'INFO', 'help': 'Info, warning and error logs', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True}, 
                             {'name': 'DEBUG', 'help': 'All logs and debug logs', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True}, 
                             {'name': 'WARNING', 'help': 'Only Warning and error logs', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True}, 
                             {'name': 'ERROR', 'help': 'no log', 'type': 'bool', 'default': False, 'is_mutually_exclusive': True}], 
                        'Packed malware': 
                            [{'name': 'is_packed', 'help': 'Is the binary packed ? (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False},
                            {'name': 'concrete_target_is_local', 'help': 'Use a local GDB server instead of using cuckoo (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}],
                        'SCDG exploration techniques parameters': 
                            [{'name': 'jump_it', 'help': 'Number of iteration allowed for a symbolic loop (default : 3) ', 'type': "<class 'int'>", 'default': 3, 'is_mutually_exclusive': False}, 
                             {'name': 'max_in_pause_stach', 'help': 'Number of states allowed in pause stash (default : 200)', 'type': "<class 'int'>", 'default': 200, 'is_mutually_exclusive': False}, 
                             {'name': 'max_step', 'help': 'Maximum number of steps allowed for a state (default : 50 000)', 'type': "<class 'int'>", 'default': 50000, 'is_mutually_exclusive': False}, 
                             {'name': 'max_end_state', 'help': 'Number of deadended state required to stop (default : 600)', 'type': "<class 'int'>", 'default': 600, 'is_mutually_exclusive': False}, 
                             {'name': 'max_simul_state', 'help': 'Number of simultaneous states we explore with simulation manager (default : 5)', 'type': "<class 'int'>", 'default': 5, 'is_mutually_exclusive': False}]}, 
                        {'Binary parameters': 
                            [{'name': 'n_args', 'help': 'Number of symbolic arguments given to the binary (default : 0)', 'type': "<class 'int'>", 'default': 1, 'is_mutually_exclusive': False},
                             {'name': 'loop_counter_concrete', 'help': 'How many times a loop can loop (default : 10240)', 'type': "<class 'int'>", 'default': 10240, 'is_mutually_exclusive': False}], 
                        'RATs custom parameters': 
                            [{'name': 'count_block_enable', 'help': 'Count block (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'sim_file', 'help': 'Create SimFile with binary  TODO (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'plugin_track_command', 'help': 'Track command loop of RATs  (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'plugin_ioc_report', 'help': 'produces and IoC report  (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'plugin_hooks', 'help': 'activates the hooks for time-consuming functions  (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}], 
                        'SCDG creation parameter': 
                            [{'name': 'min_size', 'help': 'Minimum size required for a trace to be used in SCDG (default : 3)', 'type': "<class 'int'>", 'default': 3, 'is_mutually_exclusive': False}, 
                             {'name': 'disjoint_union', 'help': 'Do we merge traces or use disjoint union ? (default : merge)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'not_comp_args', 'help': 'Do we compare arguments to add new nodes when building graph ? (default : comparison enabled)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'three_edges', 'help': 'Do we use the three-edges strategy ? (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'not_ignore_zero', 'help': 'Do we ignore zero when building graph ? (default : Discard zero)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'keep_inter_SCDG', 'help': 'keep intermediate SCDG in file  (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'eval_time', 'help': 'Keep intermediate SCDG in file  (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}]}, 
                        {'Thread parameter': 
                            [{'name': 'pre_run_thread', 'help': 'TODO (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'runtime_run_thread', 'help': 'TODO (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'post_run_thread', 'help': 'TODO (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}], 
                        'Global parameter': 
                            [{'name': 'approximate', 'help': 'Symbolic approximation (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'fast_main', 'help': 'Jump directly to the main method of the binary', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'timeout', 'help': 'Timeout in seconds before ending extraction (default : 1000)', 'type': "<class 'int'>", 'default': 1000, 'is_mutually_exclusive': False}, 
                             {'name': 'string_resolve', 'help': 'Do we try to resolv references of string (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'exp_dir', 'help': ' Name of the output directory', 'type': 'None', 'default': 'Test', 'is_mutually_exclusive': False}, 
                             {'name': 'print_syscall', 'help': 'Verbose output indicating syscalls  (default : False)', 'type': 'bool', 'default': False, 'is_mutually_exclusive': False}, 
                             {'name': 'family', 'help': 'family of the malware (default : Unknown)', 'type': 'None', 'default': 'Unknown', 'is_mutually_exclusive': False}, 
                             {'name': 'binary_path', 'help': 'Name of the binary to analyze', 'type': 'None', 'default': None, 'is_mutually_exclusive': False}]}]
        self.assertEqual(scdg_args, expected_result)
        

    def test_REST_scdg_parse_args(self):
        web_app_input = {'scdg_enable': 'scdg_enable', 'expl_method': 'CDFS', 'graph_output': 'gs', 
                'is_packed': 'false', 'concrete_target_is_local': 'false', 
                'jump_it': '3', 'max_in_pause_stach': '200', 'max_step': '50000', 
                'max_end_state': '600', 'max_simul_state': '10', 'log_level': 'WARNING', 
                'n_args': '1', 'loop_counter_concrete': '10240', 'count_block_enable': 'false', 
                'sim_file': 'false', 'plugin_track_command': 'false', 'plugin_ioc_report': 'false', 'plugin_hooks': 'false', 
                'min_size': '3', 'disjoint_union': 'false', 'not_comp_args': 'false', 'three_edges': 'false', 
                'not_ignore_zero': 'false', 'keep_inter_SCDG': 'false', 'eval_time': 'false', 'approximate': 'false', 
                'fast_main': 'false', 'timeout': '1000', 'string_resolve': 'true', 'exp_dir': 'Test', 'print_syscall': 'false', 
                'family': 'Unknown', 'binary_path': 'test/test', 'pre_run_thread': 'false', 'runtime_run_thread': 'false', 'post_run_thread': 'false'}
        parse_json_request(web_app_input)
        file = config.read(sys.argv[1])
        if file == []:
            raise FileNotFoundError("Config file not found")

        # Check that the value have been updated in the config file
        self.assertEqual(config['SCDG_arg'].getboolean('fast_main'), False)
        self.assertEqual(config['SCDG_arg'].getboolean('concrete_target_is_local'), False)
        self.assertEqual(config['SCDG_arg'].getboolean('is_packed'), False)
        self.assertEqual(config['SCDG_arg'].getboolean('keep_inter_scdg'), False)
        self.assertEqual(config['SCDG_arg'].getboolean('approximate'), False)
        self.assertEqual(config['SCDG_arg'].getboolean('sim_file'), False)
        self.assertEqual(config['SCDG_arg'].getboolean('count_block_enable'), False)
        self.assertEqual(config['SCDG_arg']["expl_method"], "CDFS")
        self.assertEqual(config['SCDG_arg']['family'], "Unknown")
        self.assertEqual(config['SCDG_arg']['exp_dir'], "Test")
        self.assertEqual(config['SCDG_arg']['binary_path'], 'test/test')
        self.assertEqual(config['SCDG_arg']['log_level'], "WARNING")
        self.assertEqual(int(config['SCDG_arg']['n_args']), 1)
        self.assertEqual(config['SCDG_arg'].getboolean('pre_run_thread'), False)
        self.assertEqual(config['SCDG_arg'].getboolean('runtime_run_thread'), False)
        self.assertEqual(config['SCDG_arg'].getboolean('post_run_thread'), False)
        self.assertEqual(config['SCDG_arg'].getboolean('string_resolve'), True)
        self.assertEqual(config['SCDG_arg'].getboolean('print_syscall'), False)

        self.assertEqual(config['Plugins_to_load'].getboolean('plugin_track_command'), False)
        self.assertEqual(config['Plugins_to_load'].getboolean('plugin_ioc_report'), False)
        self.assertEqual(config['Plugins_to_load'].getboolean('plugin_hooks'), False)

        self.assertEqual(config['build_graph_arg']['graph_output'], "gs")
        self.assertEqual(int(config['build_graph_arg']['min_size']), 3)
        self.assertEqual(config['build_graph_arg'].getboolean('disjoint_union'), False)
        self.assertEqual(config['build_graph_arg'].getboolean('not_comp_args'), False)
        self.assertEqual(config['build_graph_arg'].getboolean('three_edges'), False)
        self.assertEqual(config['build_graph_arg'].getboolean('not_ignore_zero'), False)

        self.assertEqual(int(config['explorer_arg']['jump_it']), 3)
        self.assertEqual(int(config['explorer_arg']['max_in_pause_stach']), 200)
        self.assertEqual(int(config['explorer_arg']['max_step']), 50000)
        self.assertEqual(int(config['explorer_arg']['max_end_state']), 600)
        self.assertEqual(int(config['explorer_arg']['max_simul_state']), 10)
        self.assertEqual(int(config['explorer_arg']['loop_counter_concrete']), 10240)
        self.assertEqual(int(config['explorer_arg']['timeout']), 1000)
        self.assertEqual(config['explorer_arg'].getboolean('eval_time'), False)

        # Reset default_config
        with open(sys.argv[1], 'w') as configfile:
            with open('configs/default_config.ini', "r") as default_config:
                default_settings = default_config.read()
                configfile.write(default_settings)


    def test_isomorphism_scdg(self):
        refactS_folder = "test_data/train_150_refactS/"
        old_version_folder = "test_data/train_150_prod/"
        pypy_version = "test_data/train_150_pypy3/"

        family_names = []
        for f in os.listdir(refactS_folder)[:]:
            if os.path.isdir(os.path.join(refactS_folder, f)):
                family_names.append(f)

        # For old version vs refactS (python3)
        for family in family_names:
            for binary_folder in os.listdir(os.path.join(refactS_folder, family)):
                refactS_binary_graph_path = os.path.join(os.path.join(refactS_folder, family), binary_folder)
                csv_path_refactS = os.path.join(refactS_folder, "train_150_refactS.csv")
                old_version_folder_graph_path = os.path.join(os.path.join(old_version_folder, family), binary_folder)
                csv_path_old_version = os.path.join(old_version_folder,"stats_train_prod_naw_mapping.csv")

                print(f"Family : {family} binary : {binary_folder}")
                result = compare_graphs(refactS_binary_graph_path, old_version_folder_graph_path, csv_path_refactS, csv_path_old_version, 150, prod=True)
                self.assertEqual(result, True)

        # For pypy3 version vs refactS (python3)
        for family in family_names:
            for binary_folder in os.listdir(os.path.join(refactS_folder, family)):
                refactS_binary_graph_path = os.path.join(os.path.join(refactS_folder, family), binary_folder)
                csv_path_refactS = os.path.join(refactS_folder, "train_150_refactS.csv")
                pypy3_folder_graph_path = os.path.join(os.path.join(pypy_version, family), binary_folder)
                csv_path_pypy3_version = os.path.join(pypy_version,"train_150_pypy3.csv")

                print(f"Family : {family} binary : {binary_folder}")
                result = compare_graphs(refactS_binary_graph_path, pypy3_folder_graph_path, csv_path_refactS, csv_path_pypy3_version, 150, prod=False)
                self.assertEqual(result, True)

def compare_graphs(graph1_path, graph2_path, csv_path1, csv_path2, exploration_timeout, prod=False):
    if prod:
        g2_path = graph2_path + "/" + os.path.basename(graph2_path) + ".gv"
    else :
        g2_path = graph2_path + "/final_SCDG.gv"
    # Convert DOT representations to networkx DiGraph objects
    g1 = nx.drawing.nx_agraph.read_dot(graph1_path + "/final_SCDG.gv")
    g2 = nx.drawing.nx_agraph.read_dot(g2_path)
    # Check for isomorphism (structural equivalence)
    isomorphic = nx.is_isomorphic(g1, g2)
    if isomorphic:
        print("The graphs are isomorphic")
        return True
    else:
        # Checking that the binary has been explored completely, 
        # if not it is impossible to tell if the difference is due to how far the program went or to the correctness of it.
        dataset1 = pd.read_csv(csv_path1, delimiter=";")
        dataset1 = pd.DataFrame(dataset1)
        dataset1 = dataset1[["filename", "exploration time"]]
        binary_name1 = os.path.basename(graph1_path)
        binary_data1 = dataset1.loc[dataset1['filename'] == binary_name1]

        dataset2 = pd.read_csv(csv_path2, delimiter=";")
        dataset2 = pd.DataFrame(dataset2)
        dataset2 = dataset2[["filename", "exploration time"]]
        binary_name2 = os.path.basename(graph2_path)
        binary_data2 = dataset2.loc[dataset2['filename'] == binary_name2]
 
        if (binary_data1.iloc[0]['exploration time'] >= exploration_timeout or binary_data2.iloc[0]['exploration time'] >= exploration_timeout):
            print("One or the two versions could not explore the binary entirely, impossible to compare the graphs")
            print("The binary has been ignored for the test")
            return True
        return False


if __name__ == "__main__":
    unittest.main(argv=['first-arg-is-ignored'], exit=False)