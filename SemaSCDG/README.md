This repository contains a first version of a SCDG extractor.
During symbolic analysis of a binary, all system calls and their arguments found are recorded. After some stop conditions for symbolic analysis, a graph is build as follow : Nodes are systems Calls recorded, edges show that some arguments are shared between calls.

### How to use ?
First run the SCDG container:
```bash
make run-scdg-service
```

Inside the container you can use :
```bash
python3 SemaSCDG.py EXP_OUTPUT_DIR_NAME BINARY_NAME

usage: SemaSCDG.py [--DFS | --BFS | --CDFS | --CBFS | --ThreadCDFS | --DBFS | --SDFS | --SCDFS] [--gs | --json] [--symbion | --unipacker] [--packed] [--concrete_target_is_local] [--symb_loop SYMB_LOOP]
                              [--limit_pause LIMIT_PAUSE] [--max_step MAX_STEP] [--max_deadend MAX_DEADEND] [--simul_state SIMUL_STATE] [--n_args N_ARGS] [--conc_loop CONC_LOOP]
                              [--count_block] [--sim_file] [--track_command] [--ioc_report] [--hooks]
                              [--min_size MIN_SIZE] [--disjoint_union] [--not_comp_args] [--three_edges] [--not_ignore_zero] [--keep_inter_SCDG] [--eval_time]
                              [--pre_run_thread] [--runtime_run_thread] [--post_run_thread]
                              [--approximate] [--timeout TIMEOUT] [--not_resolv_string] [--memory_limit] [--verbose_scdg] [--debug_error] [--family FAMILY] [--sthread STHREAD]
                              exp_dir
                              binary

SCDG module arguments

optional arguments:
  help                  show this help message and exit
  --DFS                 TODO
  --BFS                 TODO
  --CDFS                TODO
  --CBFS                TODO
  --ThreadCDFS          TODO
  --DBFS                TODO
  --SDFS                TODO
  --SCDFS               TODO
  --gs                  .GS format
  --json                .JSON format
  --symbion             Concolic unpacking method (linux | windows [in progress])
  --unipacker           Emulation unpacking method (windows only)

Packed malware:
  --packed              Is the binary packed ? (default : False)
  --concrete_target_is_local
                        Use a local GDB server instead of using cuckoo (default : False)

SCDG exploration techniques parameters:
  --symb_loop SYMB_LOOP
                        Number of iteration allowed for a symbolic loop (default : 3)
  --limit_pause LIMIT_PAUSE
                        Number of states allowed in pause stash (default : 200)
  --max_step MAX_STEP   Maximum number of steps allowed for a state (default : 50 000)
  --max_deadend MAX_DEADEND
                        Number of deadended state required to stop (default : 600)
  --simul_state SIMUL_STATE
                        Number of simultaneous states we explore with simulation manager (default : 5)

Binary parameters:
  --n_args N_ARGS       Number of symbolic arguments given to the binary (default : 0)
  --conc_loop CONC_LOOP
                        TODO (default : 1024)
  --count_block         TODO
  --sim_file            TODO
  --track_command       TODO
  --ioc_report          TODO
  --hooks               TODO

SCDG creation parameter:
  --min_size MIN_SIZE   Minimum size required for a trace to be used in SCDG (default : 3)
  --disjoint_union      Do we merge traces or use disjoint union ? (default : merge)
  --not_comp_args       Do we compare arguments to add new nodes when building graph ? (default : comparison enabled)
  --three_edges         Do we use the three-edges strategy ? (default : False)
  --not_ignore_zero     Do we ignore zero when building graph ? (default : Discard zero)
  --keep_inter_SCDG     Keep intermediate SCDG in file (default : False)
  --eval_time           TODO

Thread parameters :
  --pre_run_thread      TODO
  --runtime_run_thread  TODO
  --post_run_thread     TDOD

Global parameter:
  --approximate         TODO
  --timeout TIMEOUT     Timeout in seconds before ending extraction (default : 600)
  --not_resolv_string   Do we try to resolv references of string (default : False)
  --memory_limit        Skip binary experiment when memory > 90% (default : False)
  --verbose_scdg        Verbose output during calls extraction (default : False)
  --debug_error         Debug error states (default : False)
  --family FAMILY       Family of the malware (default : unknown)
  exp_dir EXP_DIR       Directory to save SCDG extracted (default : database/SCDG/runs/Test)
  binary                Name of the binary to analyze
```

Program will output a graph in `.gs` format that could be exploited by `gspan`.

You also have a script `MergeGspan.py` which could merge all `.gs` from a directory into only one file.

Password for Examples archive is "infected". Warning : it contains real samples of malwares.

#### Example

```bash
python3 SemaSCDG.py --verbose_scdg 01 database/Binaries/malware-win/small_train/upatre/00a8c63b42803a887b12865ba5f388bf
```

```bash
python3 SemaSCDG.py --verbose_scdg 01 database/Binaries/malware-win/small_train/
```

## Managing your runs

If you want to remove all the runs you have made :
```bash
make clean-scdg-runs
```

If you want to save some runs into the saved_runs file:
```bash
make save-scdg-runs                   #If you want to save all runs
make save-scdg-runs ARGS=DIR_NAME     #If you want to save only a specific run
```

If you want to erase all saved runs :
```bash
make clean-scdg-saved-runs
```