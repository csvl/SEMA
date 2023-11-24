This repository contains a first version of a SCDG extractor.
During symbolic analysis of a binary, all system calls and their arguments found are recorded. After some stop conditions for symbolic analysis, a graph is build as follow : Nodes are systems Calls recorded, edges show that some arguments are shared between calls.

### How to use ?
First run the SCDG container:
```bash
make run-scdg-service
```

Inside the container just run  :
```bash
python3 SemaSCDG.py
```

The parameters are put in a configuration file : "config.ini"
Feel free to modify it to run different experiments. To restore the default values do :
```bash
python3 restore_defaults.py
```
The default parameters are stored in the file "default_config.ini"

**The binary path has to be a relative path to a binary beeing into the *database* directory**

### Parameters description
SCDG module arguments

```
expl_method:
  DFS                 TODO
  BFS                 TODO
  CDFS                TODO
  CBFS                TODO (default)
  DBFS                TODO
  SDFS                TODO
  SCDFS               TODO

graph_output:
  gs                  .GS format
  json                .JSON format

packing_type:
  symbion             Concolic unpacking method (linux | windows [in progress])
  unipacker           Emulation unpacking method (windows only)

SCDG exploration techniques parameters:
  jump_it              Number of iteration allowed for a symbolic loop (default : 3)
  max_in_pause_stach   Number of states allowed in pause stash (default : 200)
  max_step             Maximum number of steps allowed for a state (default : 50 000)
  max_end_state        Number of deadended state required to stop (default : 600)
  max_simul_state      Number of simultaneous states we explore with simulation manager (default : 5)

Binary parameters:
  n_args                  Number of symbolic arguments given to the binary (default : 0)
  loop_counter_concrete   TODO (default : 10240)
  count_block_enable      TODO
  sim_file                TODO
  track_command           TODO
  ioc_report              TODO
  hooks_enable            TODO
  entry_addr              Entry address of the binary

SCDG creation parameter:
  min_size             Minimum size required for a trace to be used in SCDG (default : 3)
  disjoint_union       Do we merge traces or use disjoint union ? (default : merge)
  not_comp_args        Do we compare arguments to add new nodes when building graph ? (default : comparison enabled)
  three_edges          Do we use the three-edges strategy ? (default : False)
  not_ignore_zero      Do we ignore zero when building graph ? (default : Discard zero)
  keep_inter_SCDG      Keep intermediate SCDG in file (default : False)
  eval_time            TODO

Global parameter:
  concrete_target_is_local      Use a local GDB server instead of using cuckoo (default : False)
  print_syscall        print the syscall found
  print_address        print the address
  csv_file             save the stats into a csv file
  plugin_enable        enable the plugins set to true in the config.ini file
  approximate          TODO
  is_packed            Is the binary packed ? (default : False)
  timeout              Timeout in seconds before ending extraction (default : 600)
  string_resolve       Do we try to resolv references of string (default : False)
  memory_limit         Skip binary experiment when memory > 90% (default : False)
  verbose              Verbose output during calls extraction (default : False)
  family               Family of the malware (default : Unknown)
  exp_dir              Directory to save SCDG extracted (default : Default)
  binary_path          Name of the binary to analyze
```

Program will output a graph in `.gs` format that could be exploited by `gspan`.

You also have a script `MergeGspan.py` which could merge all `.gs` from a directory into only one file.

Password for Examples archive is "infected". Warning : it contains real samples of malwares.


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