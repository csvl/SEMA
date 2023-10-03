import argparse
import sys


class ArgumentParserSCDG:
    # TODO customize for other tools
    def __init__(self, tool_scdg):
        self.parser = argparse.ArgumentParser(description="SCDG module arguments")
        #self.parser._optionals.title = "SCDG module arguments"
        
        self.group_expl = self.parser.add_mutually_exclusive_group() # required=True
        self.group_expl.title = 'SCDG exploration techniques used'
        self.group_expl.add_argument(
            "--DFS",
            help="TODO",
            action="store_true",
            
        )
        self.group_expl.add_argument(
            "--BFS",
            help="TODO",
            action="store_true",
            
        )
        self.group_expl.add_argument(
            "--CDFS",
            help="TODO",
            action="store_true",
            
        )
        self.group_expl.add_argument(
            "--ThreadCDFS",
            help="TODO",
            action="store_true",
            
        )
        self.group_expl.add_argument(
            "--CBFS",
            help="TODO",
            action="store_true",
            
        )
        self.group_expl.add_argument(
            "--DBFS",
            help="TODO",
            action="store_true",
            
        )
        self.group_expl.add_argument(
            "--SDFS",
            help="TODO",
            action="store_true",
            
        )
        self.group_expl.add_argument(
            "--SCDFS",
            help="TODO",
            action="store_true",
            
        )
        
        self.group_output = self.parser.add_mutually_exclusive_group() # required=True
        self.group_output.title = 'Format to save graph output'
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
        self.group_unpacked.title = 'Unpacking method (iff --packed)'
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
        
        self.group_packed = self.parser.add_argument_group('Packed malware')
        self.group_packed.add_argument(
            "--packed",
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
            "--symb_loop",
            help="Number of iteration allowed for a symbolic loop (default : 3) ",
            default=3,
            type=int,
        )
        self.group_expl_param.add_argument(
            "--limit_pause",
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
            "--max_deadend",
            help="Number of deadended state required to stop (default : 600)",
            default=600,
            type=int,
        )
        self.group_expl_param.add_argument(
            "--simul_state",
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
            "--conc_loop",
            help="Number of symbolic arguments given to the binary (default : 1024)",
            default=10240,
            type=int,
        )
        
        self.group_rats= self.parser.add_argument_group('RATs custom parameters')
        self.group_rats.add_argument(
            "--count_block",
            help="Count block (default : False)",
            action="store_true",
            
        )
        self.group_rats.add_argument(
            "--sim_file",
            help="Create SimFile with binary  TODO (default : False)",
            action="store_true",
            
        )
        self.group_rats.add_argument(
            "--track_command",
            help="Track command loop of RATs  (default : False)",
            action="store_true",
   
        )
        self.group_rats.add_argument(
            "--ioc_report",
            help="produces and IoC report  (default : False)",
            action="store_true",
   
        )
        self.group_rats.add_argument(
            "--hooks",
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
        # self.group_scdg.add_argument(
        #     "--dir",
        #     help=" Directory to save outputs graph for gspan  (default : output/runs/<exp_run>)",
        #     default="database/SCDG/runs/",
        # )
        self.group_scdg.add_argument(
            "--discard_SCDG",
            help="Do not keep intermediate SCDG in file  (default : False)",
            action="store_false",
            
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
            "--approximate",
            help="Symbolic approximation (default : False)",
            action="store_true",
        )     
        self.group.add_argument(
            "--timeout",
            help="Timeout in seconds before ending extraction (default : 200)",
            default=1000,
            type=int,
        )     
        self.group.add_argument(
            "--not_resolv_string",
            help="Do we try to resolv references of string (default : False)",
            action="store_true",
            
        )
        self.group.add_argument(
            "exp_dir",
            help=" Name of the output directory", 

        )
        self.group.add_argument(
            "--memory_limit",
            help="Skip binary experiment when memory > 90%% (default : False)",
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
            "--family",
            help="family of the malware (default : unknown)",
            
        )
        self.group.add_argument("binary", 
                help="Name of the binary to analyze",
                )
        self.group.add_argument(
            "--sthread",
            help="Number of thread used (default: 1)",
            type=int,
            default=1,
        )
    
        self.tool_scdg = tool_scdg

    def update_tool(self,args):
        inputs = args.binary
        if not self.tool_scdg.print_on:
            self.tool_scdg.print_on = args.verbose
        self.tool_scdg.debug_error = args.debug_error
        expl_method = "DFS"   if args.DFS else \
                     ("BFS"   if args.BFS \
                else ("CDFS"  if args.CDFS \
                else ("DBFS"  if args.DBFS \
                else ("SDFS"  if args.SDFS \
                else ("SCDFS" if args.SCDFS \
                else ("ThreadCDFS" if args.ThreadCDFS \
                else  "CBFS"))))))

        family = "unknown"
        if args.family:
            family = args.family
        args.exp_dir = args.exp_dir + "/" + family

        if args.timeout:
            self.tool_scdg.timeout = args.timeout
        if args.symb_loop:
            self.tool_scdg.jump_it = args.symb_loop
        if args.conc_loop:
            self.tool_scdg.loop_counter_concrete = args.conc_loop
        if args.eval_time:
            self.tool_scdg.eval_time = True

        self.tool_scdg.max_simul_state = args.simul_state

        self.tool_scdg.string_resolv = not args.not_resolv_string
        if args.limit_pause:
            self.tool_scdg.max_in_pause_stach = args.limit_pause
        if args.max_step:
            self.tool_scdg.max_step = args.max_step
        if args.max_deadend:
            self.tool_scdg.max_end_state = args.max_deadend
        
        self.tool_scdg.is_packed = args.packed

        if args.concrete_target_is_local:
            self.tool_scdg.concrete_target_is_local = True
        
        if self.tool_scdg.is_packed:
            if args.unipacker:
                mode = "unipacker"
                self.tool_scdg.log.info("Unpack with %s",mode)
                self.tool_scdg.unpack_mode = mode
            elif args.symbion:
                mode = "symbion"
                self.tool_scdg.log.info("Unpack with %s",mode)
                self.tool_scdg.unpack_mode = mode

        self.tool_scdg.inputs = inputs
        self.tool_scdg.expl_method = expl_method
        self.tool_scdg.family = family
        self.tool_scdg.memory_limit = args.memory_limit # Add custom value

    def parse_arguments(self, allow_unk = False, args_list=None):
        args = None
        if not allow_unk:
            args = self.parser.parse_args(args_list)
        else:
            args, unknown = self.parser.parse_known_args(args_list)

        return args
