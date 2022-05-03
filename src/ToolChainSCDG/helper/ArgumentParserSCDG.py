import argparse
import sys

from matplotlib.pyplot import title


class ArgumentParserSCDG:
    # TODO customize for other tools
    def __init__(self, tool_scdg):
        self.parser = argparse.ArgumentParser(description="SCDG module arguments")
        #self.parser._optionals.title = "SCDG module arguments"
        self.group = self.parser.add_argument_group('SCDG module arguments')
        self.group.add_argument(
            "--method",
            help="Method used for the analysis among (DFS,BFS,CBFS) (default : DFS)",
        )
        self.group.add_argument(
            "--n_args",
            help="Number of symbolic arguments given to the binary (default : 0)",
            default=0,
            type=int,
        )
        self.group.add_argument(
            "--timeout",
            help="Timeout in seconds before ending extraction (default : 600)",
            default=600,
            type=int,
        )
        self.group.add_argument(
            "--symb_loop",
            help="Number of iteration allowed for a symbolic loop (default : 3) ",
            default=3,
            type=int,
        )
        self.group.add_argument(
            "--conc_loop",
            help="Number of symbolic arguments given to the binary (default : 1024)",
            default=1024,
            type=int,
        )
        self.group.add_argument(
            "--simul_state",
            help="Number of simultaneous states we explore with simulation manager (default : 5)",
            default=5,
            type=int,
        )
        self.group.add_argument(
            "--limit_pause",
            help="Number of states allowed in pause stash (default : 200)",
            default=200,
            type=int,
        )
        self.group.add_argument(
            "--max_step",
            help="Maximum number of steps allowed for a state (default : 50 000)",
            default=50000,
            type=int,
        )
        self.group.add_argument(
            "--max_deadend",
            help="Number of deadended state required to stop (default : 600)",
            default=600,
            type=int,
        )
        self.group.add_argument(
            "--min_size",
            help="Minimum size required for a trace to be used in SCDG (default : 3)",
            default=3,
            type=int,
        )
        self.group.add_argument(
            "--not_resolv_string",
            help="Do we try to resolv references of string (default : False)",
            action="store_true",
        )
        self.group.add_argument(
            "--disjoint_union",
            help="Do we merge traces or use disjoint union ? (default : merge)",
            action="store_true",
        )
        self.group.add_argument(
            "--not_comp_args",
            help="Do we compare arguments to add new nodes when building graph ? (default : comparison enabled)",
            action="store_true",
        )
        self.group.add_argument(
            "--not_ignore_zero",
            help="Do we ignore zero when building graph ? (default : Discard zero)",
            action="store_true",
        )
        self.group.add_argument(
            "--dir",
            help=" Directory to save outputs graph for gspan  (default : output/)",
        )
        self.group.add_argument(
            "--exp_dir",
            help=" Directory to save SCDG extracted (default : output/save-SCDG/)",
            default="output/save-SCDG/",
        )
        self.group.add_argument(
            "--discard_SCDG",
            help="Do not keep intermediate SCDG in file  (default : True)",
            action="store_false",
        )
        self.group.add_argument(
            "--eval_time",
            help="Keep intermediate SCDG in file  (default : False)",
            action="store_true",
        )
        self.group.add_argument(
            "--verbose_scdg",
            help="Verbose output during calls extraction  (default : False)",
            action="store_true",
        )
        self.group.add_argument(
            "--debug_error",
            help="Debug error states (default : False)",
            action="store_true",
        )
        self.group.add_argument(
            "--format_out",
            help="Format to save graph output : gs or json (Default: gs)",
            default="gs",
        )
        self.group.add_argument(
            "--packed",
            help="Is the binary packed ? (default : False)",
            action="store_true",
        )
        self.group.add_argument(
            "--unpack_method",
            help="unpack with Symbion (linux only | todo) or with unipacker (windows only) [symbion|unipacker]\nTrue if --packed is set with symbion as default",
        )
        self.group.add_argument(
            "--concrete_target_is_local",
            action="store_true",
            help="Use a local GDB server instead of using cuckoo (default : False)",
        )
        self.group.add_argument(
            "--familly",
            help="Familly of the malware (default : unknown)",
        )
        self.group.add_argument(
            "--memory_limit",
            help="Skip binary experiment when memory > 90% (default : False)",
            action="store_true",
        )
        self.group.add_argument("binary", 
                help="Name of the binary to analyze")

    
        self.tool_scdg = tool_scdg

    def update_tool(self,args):
        inputs = args.binary
        if not self.tool_scdg.print_on:
            self.tool_scdg.print_on = args.verbose
        self.tool_scdg.debug_error = args.debug_error
        if args.method:
            expl_method = args.method.upper()
            if expl_method not in ["BFS", "DFS", "CDFS", "CBFS"]:
                self.tool_scdg.log.info("Method of exploration not recognized")
                self.tool_scdg.log.info("Changed to default DFS")
                expl_method = "DFS"
        else:
            expl_method = "DFS"

        familly = "unknown"
        if args.familly:
            familly = args.familly
        args.exp_dir = args.exp_dir + familly + "/"

        if args.timeout:
            self.tool_scdg.timeout = args.timeout
        if args.symb_loop:
            self.tool_scdg.jump_it = args.symb_loop
        if args.conc_loop:
            self.tool_scdg.loop_counter_concrete = args.conc_loop
        if args.eval_time:
            self.tool_scdg.eval_time = True

        self.tool_scdg.max_simul_state = args.simul_state
        sys.setrecursionlimit(2000)
        self.tool_scdg.string_resolv = not args.not_resolv_string
        if args.limit_pause:
            self.tool_scdg.max_in_pause_stach = args.limit_pause
        if args.max_step:
            self.tool_scdg.max_step = args.max_step
        if args.max_deadend:
            self.tool_scdg.max_end_state = args.max_deadend
        
        self.tool_scdg.is_packed = args.packed
        if self.tool_scdg.is_packed:
            self.tool_scdg.unpack_mode = "symbion"

        if args.concrete_target_is_local:
            self.tool_scdg.concrete_target_is_local = True
        if args.unpack_method:
            mode = args.unpack_method
            if mode in ["unipacker", "symbion"]:
                self.tool_scdg.log.info("Unpack with %s",mode)
                self.tool_scdg.unpack_mode = mode
                self.tool_scdg.is_packed = True
            else:
                #TODO
                pass

        self.tool_scdg.inputs = inputs
        self.tool_scdg.expl_method = expl_method
        self.tool_scdg.familly = familly
        self.tool_scdg.memory_limit = args.memory_limit # Add custom value

    def parse_arguments(self, allow_unk = False):
        args = None
        if not allow_unk:
            args = self.parser.parse_args()
        else:
            args, unknown = self.parser.parse_known_args()

        return args
