import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
import argparse
import sys


class ArgumentParserSCDG:
    # TODO customize for other tools
    def __init__(self):
        self.parser = argparse.ArgumentParser(description="SCDG module arguments")
        #self.parser._optionals.title = "SCDG module arguments"

        self.group_expl = self.parser.add_mutually_exclusive_group() # required=True
        self.group_expl.title = 'expl_method'
        self.group_expl.add_argument(
            "--DFS",
            help="Depth First Search",
            action="store_true",

        )
        self.group_expl.add_argument(
            "--BFS",
            help="Breadth First Search",
            action="store_true",

        )
        self.group_expl.add_argument(
            "--CDFS",
            help="Custom Depth First Search (Default)",
            action="store_true",

        )
        self.group_expl.add_argument(
            "--CBFS",
            help="Custom Breadth First Search",
            action="store_true",

        )

        self.group_output = self.parser.add_mutually_exclusive_group() # required=True
        self.group_output.title = 'graph_output'
        self.group_output.add_argument(
            "--gs",
            help=".GS format",
            action="store_true",

        )
        self.group_output.add_argument(
            "--json",
            help=".JSON format",
            action="store_true",

        )

        self.group_unpacked = self.parser.add_mutually_exclusive_group() # required=True
        self.group_unpacked.title = 'packing_type'
        self.group_unpacked.add_argument(
            "--symbion",
            help="Concolic unpacking method (linux | windows [in progress])",
            action="store_true",

        )
        self.group_unpacked.add_argument(
            "--unipacker",
            help="Emulation unpacking method (windows only)",
            action="store_true",

        )

        self.group_logs = self.parser.add_mutually_exclusive_group() # required=True
        self.group_logs.title = 'log_level_sema'
        self.group_logs.add_argument(
            "--INFO",
            help="Info, warning and error logs",
            action="store_true",

        )
        self.group_logs.add_argument(
            "--DEBUG",
            help="All logs and debug logs",
            action="store_true",

        )
        self.group_logs.add_argument(
            "--WARNING",
            help="Only Warning and error logs",
            action="store_true",

        )
        self.group_logs.add_argument(
            "--ERROR",
            help="no log",
            action="store_true",

        )

        self.group_packed = self.parser.add_argument_group('Packed malware')
        self.group_packed.add_argument(
            "--is_packed",
            help="Is the binary packed ? (default : False)",
            action="store_true",

        )
        self.group_packed.add_argument(
            "--concrete_target_is_local",
            action="store_true",
            help="Use a local GDB server instead of using cuckoo (default : False)",

        )

        self.group_expl_param = self.parser.add_argument_group('SCDG exploration techniques parameters')
        self.group_expl_param.add_argument(
            "--jump_it",
            help="Number of iteration allowed for a symbolic loop (default : 3) ",
            default=3,
            type=int,
        )
        self.group_expl_param.add_argument(
            "--max_in_pause_stach",
            help="Number of states allowed in pause stash (default : 200)",
            default=200,
            type=int,
        )
        self.group_expl_param.add_argument(
            "--max_step",
            help="Maximum number of steps allowed for a state (default : 50 000)",
            default=50000,
            type=int,
        )
        self.group_expl_param.add_argument(
            "--max_end_state",
            help="Number of deadended state required to stop (default : 600)",
            default=600,
            type=int,
        )
        self.group_expl_param.add_argument(
            "--max_simul_state",
            help="Number of simultaneous states we explore with simulation manager (default : 5)",
            default=5,
            type=int,
        )

        self.group_bin = self.parser.add_argument_group('Binary parameters')
        self.group_bin.add_argument(
            "--n_args",
            help="Number of symbolic arguments given to the binary (default : 0)",
            default=1,
            type=int,
        )
        self.group_bin.add_argument(
            "--loop_counter_concrete",
            help="How many times a loop can loop (default : 10240)",
            default=10240,
            type=int,
        )

        self.group_rats= self.parser.add_argument_group('RATs custom parameters')
        self.group_rats.add_argument(
            "--count_block_enable",
            help="Count block (default : False)",
            action="store_true",

        )
        self.group_rats.add_argument(
            "--sim_file",
            help="Create SimFile with binary  TODO (default : False)",
            action="store_true",

        )
        self.group_rats.add_argument(
            "--plugin_track_command",
            help="Track command loop of RATs  (default : False)",
            action="store_true",

        )
        self.group_rats.add_argument(
            "--plugin_ioc_report",
            help="produces and IoC report  (default : False)",
            action="store_true",

        )
        self.group_rats.add_argument(
            "--plugin_hooks",
            help="activates the hooks for time-consuming functions  (default : False)",
            action="store_true",

        )

        self.group_scdg = self.parser.add_argument_group('SCDG creation parameter')
        self.group_scdg.add_argument(
            "--min_size",
            help="Minimum size required for a trace to be used in SCDG (default : 3)",
            default=3,
            type=int,
        )
        self.group_scdg.add_argument(
            "--disjoint_union",
            help="Do we merge traces or use disjoint union ? (default : merge)",
            action="store_true",

        )
        self.group_scdg.add_argument(
            "--not_comp_args",
            help="Do we compare arguments to add new nodes when building graph ? (default : comparison enabled)",
            action="store_true",

        )
        self.group_scdg.add_argument(
            "--three_edges",
            help="Do we use the three-edges strategy ? (default : False)",
            action="store_true",

        )
        self.group_scdg.add_argument(
            "--not_ignore_zero",
            help="Do we ignore zero when building graph ? (default : Discard zero)",
            action="store_true",

        )
        self.group_scdg.add_argument(
            "--keep_inter_SCDG",
            help="keep intermediate SCDG in file  (default : False)",
            action="store_true",

        )
        self.group_scdg.add_argument(
            "--eval_time",
            help="Keep intermediate SCDG in file  (default : False)",
            action="store_true",

        )

        self.groupt = self.parser.add_argument_group('Thread parameter')
        self.groupt.add_argument(
            "--pre_run_thread",
            help="TODO (default : False)",
            action="store_true",
        )
        self.groupt.add_argument(
            "--runtime_run_thread",
            help="TODO (default : False)",
            action="store_true",
        )
        self.groupt.add_argument(
            "--post_run_thread",
            help="TODO (default : False)",
            action="store_true",
        )

        self.group = self.parser.add_argument_group('Global parameter')
        self.group.add_argument(
            "--wait_scdg",
            help="Does the classifier wait for the result of the SCDG or not (default = False)",
            action="store_true",
        )
        self.group.add_argument(
            "--approximate",
            help="Symbolic approximation (default : False)",
            action="store_true",
        )
        self.group.add_argument(
            "--fast_main",
            help="Jump directly to the main method of the binary",
            action="store_true",
        )
        self.group.add_argument(
            "--timeout",
            help="Timeout in seconds before ending extraction (default : 1000)",
            default=1000,
            type=int,
        )
        self.group.add_argument(
            "--string_resolve",
            help="Do we try to resolv references of string (default : False)",
            action="store_true",

        )
        self.group.add_argument(
            "exp_dir",
            help=" Name of the output directory",
            default = "Test",

        )

        self.group.add_argument(
            "--print_syscall",
            help="Verbose output indicating syscalls  (default : False)",
            action="store_true",

        )

        self.group.add_argument(
            "--family",
            help="family of the malware (default : Unknown)",
            default="Unknown",

        )
        self.group.add_argument("binary_path",
                help="Name of the binary to analyze",
                )

    def parse_arguments(self, allow_unk = False, args_list=None):
        args = None
        if not allow_unk:
            args = self.parser.parse_args(args_list)
        else:
            args, unknown = self.parser.parse_known_args(args_list)

        return args
