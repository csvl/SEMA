# :skull_and_crossbones: SEMA :skull_and_crossbones: - ToolChain using Symbolic Execution for Malware Analysis. 

```
  ██████ ▓█████  ███▄ ▄███▓ ▄▄▄      
▒██    ▒ ▓█   ▀ ▓██▒▀█▀ ██▒▒████▄    
░ ▓██▄   ▒███   ▓██    ▓██░▒██  ▀█▄  
  ▒   ██▒▒▓█  ▄ ▒██    ▒██ ░██▄▄▄▄██ 
▒██████▒▒░▒████▒▒██▒   ░██▒ ▓█   ▓██▒
▒ ▒▓▒ ▒ ░░░ ▒░ ░░ ▒░   ░  ░ ▒▒   ▓▒█░
░ ░▒  ░ ░ ░ ░  ░░  ░      ░  ▒   ▒▒ ░
░  ░  ░     ░   ░      ░     ░   ▒   
      ░     ░  ░       ░         ░  ░
                                     
```
                                                                                                               
                                   
# :books:  Documentation

1. [ Architecture ](#arch)
    1. [ Toolchain architecture ](#arch_std)

2. [ Installation ](#install)

3. [ SEMA ](#tc)
    1. [ `SemaSCDG` ](#tcscdg)

4. [Quick Start Demos](#)
    1. [ `Extract SCDGs from binaries` ](https://github.com/csvl/SEMA-ToolChain/blob/production/Tutorial/Notebook/SEMA-SCDG%20Demo.ipynb)

5. [ Credentials ](#credit)

:page_with_curl: Architecture
====
<a name="arch"></a>

### Toolchain architecture
<a name="arch_std"></a>


##### Main depencies: 

    * Python 3.8 (angr)

    * KVM/QEMU

    * Celery

##### Interesting links

* https://angr.io/

* https://bazaar.abuse.ch/

:page_with_curl: Installation
====
<a name="install"></a>

Tested on Ubuntu 18 LTS. Checkout Makefile and install.sh for more details.

**Recommanded installation:**

```bash
git clone https://github.com/Manon-Oreins/SEMA-ToolChain.git;
# Full installation (ubuntu)
make build-toolchain;
```

## Installation details (optional)

#### Pip

To run this SCDG extractor you first need to install pip.

##### Debian (and Debian-based)
To install pip on debian-based systems:
```bash
sudo apt update;
sudo apt-get install python3-pip xterm;
```

##### Arch (and Arch-based)
To install pip on arch-based systems:
```bash
sudo pacman -Sy python-pip xterm;
```

#### Python virtual environment

For `angr`, it is recommended to use the python virtual environment. 

```bash
python3 -m venv penv;
```

This create a virtual envirnment called `penv`. 
Then, you can run your virtual environment with:

```bash
source penv/bin/activate;
```

##### For extracting test database

```bash
cd databases/Binaries; bash extract_deploy_db.sh
```

##### For code cleaning

For dev (code cleaning):
```bash
cd databases/Binaries; bash compress_db.sh 
#To zip back the test database
make clean-scdg-empty-directory
#To remove all directory created by the docker files that are empty

```

:page_with_curl: `SEMA - ToolChain`
====
<a name="tc"></a>

Our toolchain is represented in the next figure  and works as follow. A collection of labelled binaries of different malwares families is collected and used as the input of the toolchain. **Angr**, a framework for symbolic execution, is used to execute symbolically binaries and extract execution traces. For this purpose, different heuristics have been developped to optimize symbolic execution. Several execution traces (i.e : API calls used and their arguments) corresponding to one binary are extracted with Angr and gather together thanks to several graph heuristics to construct a SCDG. These resulting SCDGs are then used as input to graph mining to extract common graph between SCDG of the same family and create a signature. Finally when a new sample has to be classified, its SCDG is build and compared with SCDG of known families (thanks to a simple similarity metric).


### How to use ?

First launch the containers : 
```bash
make run-toolchain
```

Then visit 127.0.0.1:5000 on your browser


:page_with_curl: System Call Dependency Graphs extractor (`SemaSCDG`)
====
<a name="tcscdg"></a>

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

## Shut down

To leave the toolchain just press Ctrl+C then use

```bash
make stop-all-containers
```

To stop all docker containers.

If you want to remove all images :

```bash
docker rmi sema-web-app
docker rmi sema-scdg
```

:page_with_curl: Credentials
====
<a name="credit"></a>

Main authors of the projects:

* **Charles-Henry Bertrand Van Ouytsel** (UCLouvain)

* **Christophe Crochet** (UCLouvain)

* **Khanh Huu The Dam** (UCLouvain)

* **Oreins Manon** (UCLouvain)

Under the supervision and with the support of **Fabrizio Biondi** (Avast) 

Under the supervision and with the support of our professor **Axel Legay** (UCLouvain) (:heart:)
