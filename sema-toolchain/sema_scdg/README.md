:page_with_curl: System Call Dependy Graph extractor (`SemaSCDG`)
====

This repository contains a first version of a SCDG extractor.
During symbolic analysis of a binary, all system calls and their arguments found are recorded. After some stop conditions for symbolic analysis, a graph is build as follow : Nodes are systems Calls recorded, edges show that some arguments are shared between calls.

### How to use ?
First run the SCDG container with volumes like this :
```bash
docker run --rm --name="sema-scdg" -v ${PWD}/OutputFolder:/sema-scdg/application/database/SCDG -v ${PWD}/ConfigFolder:/sema-scdg/application/configs -v ${PWD}/InputFolder:/sema-scdg/application/database/Binaries -p 5001:5001 -it sema-scdg bash
```
In this command:

- The first volume corresponds to the output folder where the results will be put.
- The second volume corresponds to the folder containing the configuration files that will be passed to the docker.
- The third matches the folder containing the binaries that are going to be passed to the container.

Example taking the files already provided, being inside the sema-toolchain folder, run :
```bash
docker run --rm --name="sema-scdg" -v ${PWD}/database/SCDG:/sema-scdg/application/database/SCDG -v ${PWD}/sema_scdg/application/configs:/sema-scdg/application/configs -v ${PWD}/database/Binaries:/sema-scdg/application/database/Binaries -p 5001:5001 -it sema-scdg bash
```

If you want to be able to modify the code when the container is running, use
```bash
docker run --rm --name="sema-scdg" -v ${PWD}/database:/sema-scdg/application/database -v ${PWD}/sema_scdg/application:/sema-scdg/application -p 5001:5001 -it sema-scdg bash
```

To run experiments, run inside the container :
```bash
python3 SemaSCDG.py configs/config.ini
```
Or if you want to use pypy3:
```bash
pypy3 SemaSCDG.py configs/config.ini
```

#### Configuration files

The parameters are put in a configuration file : `configs/config.ini`. Feel free to modify it or create new configuration files to run different experiments.

The output of the SCDG are put into `database/SCDG/runs/` by default. If you are not using volumes and want to save some runs from the container to your host machine, use :
```bash
make save-scdg-runs ARGS=PATH
```

#### Parameters description
SCDG module arguments

```
expl_method:
  DFS                 Depth First Search
  BFS                 Breadth First Search
  CDFS                Coverage Depth-First Search Strategy (Default)
  CBFS                Coverage Breadth First Search

graph_output:
  gs                  .GS format
  json                .JSON format
  EMPTY               if left empty then build on all available format

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
  loop_counter_concrete   How many times a loop can loop (default : 10240)
  count_block_enable      Enable the count of visited blocks and instructions
  sim_file                Create SimFile
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
  print_syscall                 Print the syscall found
  csv_file                      Name of the csv to save the experiment data
  plugin_enable                 Enable the plugins set to true in the config.ini file
  approximate                   Symbolic approximation
  is_packed                     Is the binary packed ? (default : False, not yet supported)
  timeout                       Timeout in seconds before ending extraction (default : 600)
  string_resolve                Do we try to resolv references of string (default : True)
  log_level_sema                Level of log of sema, can be INFO, DEBUG, WARNING, ERROR (default : INFO)
  log_level_angr                Level of log of angr, can be INFO, DEBUG, WARNING, ERROR (default : ERROR)
  log_level_claripy             Level of log of claripy, can be INFO, DEBUG, WARNING, ERROR (default : ERROR)
  family                        Family of the malware (default : Unknown)
  exp_dir                       Name of the directory to save SCDG extracted (default : Default)
  binary_path                   Relative path to the binary or directory (has to be in the database folder)
  fast_main                     Jump directly into the main function

Plugins:
  plugin_env_var          Enable the env_var plugin
  plugin_locale_info      Enable the locale_info plugin
  plugin_resources        Enable the resources plugin
  plugin_widechar         Enable the widechar plugin
  plugin_registry        Enable the registry plugin
  plugin_atom             Enable the atom plugin
  plugin_thread           Enable the thread plugin
  plugin_track_command    Enable the track_command plugin
  plugin_ioc_report       Enable the ioc_report plugin
  plugin_hooks            Enable the hooks plugin
```

**The binary path has to be a relative path to a binary beeing into the `database` directory**

To know the details of the angr options see [Angr documentation](https://docs.angr.io/en/latest/appendix/options.html)

You also have a script `MergeGspan.py` in `sema_scdg/application/helper` which could merge all `.gs` from a directory into only one file.

#### Run multiple experiments automatically

If you wish to run multiple experiments with different configuration files, the script `multiple_experiments.sh` is available and can be used inside the scdg container:
```bash
# To show usage
./multiple_experiments.sh -h

# Run example
./multiple_experiments.sh -m python3 -c configs/config1 configs/config2
```

#### Tests

To run the test, inside the docker container :
```bash
python3 scdg_tests.py test_data/config_test.ini
```

#### Tutorial

There is a jupyter notebook providing a tutorial on how to use the scdg. To launch it, inside the docker, run
```bash
jupyter notebook --ip=0.0.0.0 --port=5001 --no-browser --allow-root --IdentityProvider.token=''
```
and visit `http://127.0.0.1:5001/tree` on your browser. Go to `/Tutorial` and open the jupyter notebook.
