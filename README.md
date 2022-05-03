# :skull_and_crossbones: SEMA :skull_and_crossbones: - ToolChain using Symbolic Execution for Malware Analysis. 
# :books:  Documentation

1. [ Architecture ](#arch)
    1. [ Toolchain architecture ](#arch_std)
    2. [ Federated learning architecture ](#arch_fl)

2. [ Installation ](#install)

3. [ SEMA ](#tc)
    1. [ `ToolChainSCDG` ](#tcscdg)
    2. [ `ToolChainClassifier`](#tcc)
    3. [ `ToolChainFL`](#tcfl)

4. [ Credentials ](#credit)

:page_with_curl: Architecture
====
<a name="arch"></a>

### Toolchain architecture
<a name="arch_std"></a>

![GitHub Logo](/doc/SEMA_illustration.png)

### Federated learning architecture
<a name="arch_fl"></a>

![GitHub Logo](/doc/SEMA-FL.png)

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

Tested on Ubuntu 18 LTS.

**General installation:**

```bash
# WARNING: slow since one submodule contains preconfigure VMs
git clone --recurse-submodules https://github.com/csvl/SEMA-ToolChain.git;
# Full installation (ubuntu)
cd SEMA-ToolChain/; source install.sh;
```

Optionals arguments are available for `install.sh`:

* `--no_malware_db` : Unzip malware's DB (default : True)
* `--vms_dl` : Download preconfigured cuckoo VMs (default : False)
* `--vms_install` : Unzip downloaded VMs for cuckoo, `vms_dl` must be true (default : False)
* `--pypy` : Install also with `pypy3` compiler (default : False)
* `--pytorch_cuda` : Install also CUDA core enable with `pytorch` (default : False)

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

##### For testing: `hypothesis`

For the testing environment, we use [`hypothesis`](https://hypothesis.readthedocs.io/en/latest/quickstart.html#installing) framework 
This can be done by using the command :
```bash
pip3 install pytest hypothesis;
```

###### Usage 

```bash
python3 -m pytest test/HypothesisExamples.py;
```

##### For extracting test database

```bash
cd src/databases; bash extract_deploy_db.sh
```

##### For code cleaning

For dev (code cleaning):
```bash
# PEP 8 compliant opinionated formatter with its own style
pip3 install git+git://github.com/psf/black; 
cd src/
black --exclude .submodules .;
# Removes unused imports and unused variables from Python code
pip3 install --upgrade autoflake; 
autoflake --in-place --remove-unused-variables --remove-all-unused-imports  --recursive  --exclude submodules ToolChainWorker.py;
```

#### PyPy interpreter 

In order to be faster, you should install `pypy` python interpreter. You can add `--pypy` to `install.sh` but some installation error are still possible. The following command are not enough to fully build the project with pypy3 that is why we recommend to use `install.sh --pypy`. Still some package problems.

Note: `Pytorch` not working with `pypy`.

PyPy3.7:

* Linux x86 64 bit: 
    ```bash
    sudo apt-get update
    sudo apt-get install libc6 
    sudo add-apt-repository ppa:pypy/ppa
    sudo apt update
    sudo apt install pypy3 pypy3-dev
    sudo apt-get install libatlas-base-dev

    pypy3 -m ensurepip
    pypy3 -m pip install --upgrade pip testresources setuptools wheel
    pypy3 -m pip install numpy pybind11 avatar2 yara yara-python
    pypy3 -m pip install  . 

    # TODO (hack)
    cd /tmp/ 
    pypy3 -m pip install yara yara-python -t .
    sudo mkdir /usr/lib/pypy3/lib
    sudo cp usr/lib/pypy3/lib/libyara.so /usr/lib/pypy3/lib/libyara.so
    ```

Then in order to used it, replace the `python3` command by `pypy3`command.

:page_with_curl: `SEMA - ToolChain`
====
<a name="tc"></a>

Our toolchain is represented in the next figure  and works as follow. A collection of labelled binaries of different malwares families is collected and used as the input of the toolchain. **Angr**, a framework for symbolic execution, is used to execute symbolically binaries and extract execution traces. For this purpose, different heuristics have been developped to optimize symbolic execution. Several execution traces (i.e : API calls used and their arguments) corresponding to one binary are extracted with Angr and gather together thanks to several graph heuristics to construct a SCDG. These resulting SCDGs are then used as input to graph mining to extract common graph between SCDG of the same family and create a signature. Finally when a new sample has to be classified, its SCDG is build and compared with SCDG of known families (thanks to a simple similarity metric).


### How to use ?
Just run the script : 
```bash
pypy3 ToolChain.py FOLDER_OF_BINARIES FOLDER_OF_SIGNATURE

python3 ToolChain.py FOLDER_OF_BINARIES FOLDER_OF_SIGNATURE
```
* `FOLDER` : Folder containing binaries to classify, these binaries must be ordered by familly (default : `databases/malware-win/train`)

#### Example

```bash
# For folder of malware 
# Deep learning not supported with pypy3 (--classifier dl)
pypy3 ToolChain.py  --memory_limit --method CDFS --train --verbose_scdg --verbose_classifier databases/malware-win/train/ output/save-SCDG/

# (virtual env/penv)
python3 ToolChain.py --memory_limit --method CDFS --train --verbose_scdg --verbose_classifier databases/malware-win/train/ output/save-SCDG/
```

:page_with_curl: System Call Dependency Graphs extractor (`ToolChainSCDG`)
====
<a name="tcscdg"></a>

This repository contains a first version of a SCDG extractor.
During symbolic analysis of a binary, all system calls and their arguments found are recorded. After some stop conditions for symbolic analysis, a graph is build as follow : Nodes are systems Calls recorded, edges show that some arguments are shared between calls.

### How to use ?
Just run the script : 
```bash
pypy3 ToolChainSCDG.py BINARY_NAME

python3 ToolChainSCDG.py BINARY_NAME
```
For syscall extraction, different optionals arguments are available :

* `method` : Method used for the analysis among (DFS,BFS,CBFS,CDFS) (default : DFS)
* `n_args` : Number of symbolic arguments given to the binary (default : 0)
* `timeout` : Timeout in seconds before ending extraction (default : 600)
* `symb_loop` : Number of iteration allowed for a symbolic loop (default : 3)
* `conc_loop` : Number of symbolic arguments given to the binary (default : 1024)
* `simul_state` : Number of simultaneous states we explore with simulation manager (default : 5)
* `limit_pause` : Number of states allowed in pause stash (default : 200)
* `max_step` : Maximum number of steps allowed for a state (default : 50 000)
* `max_deadend` : Number of deadended state required to stop (default : 600)
* `resolv_string` : Do we try to resolv references of string (default : True)
* `familly` : Familly of the malware. if a folder instead of a binary is given, then the familly are associated to the subfolder containing the binaries.  ? (default : unknown)
* `memory_limit` : Skip binary experiment when memory > 90% (default : False)

For the graph building, options are : 

* `min_size` : Minimum size required for a trace to be used in SCDG (default : 3)
* `merge_call` : Do we merge traces or use disjoint union ? (default : True = merge)
* `comp_args` : Do we compare arguments to add new nodes when building graph ? (default : True)
* `ignore_zero` : Do we ignore zero when building graph ? (default : True)

You could also specify a directory (already created) to save outputs with option `-dir`.

Program will output a graph in `.gs` format that could be exploited by `gspan`.

You also have a script `merge_gspan.py` which could merge all `.gs` from a directory into only one file.

Password for Examples archive is "infected". Warning : it contains real samples of malwares.

#### Example

```bash
# +- 447 sec <SimulationManager with 61 deadended>
pypy3 ToolChainSCDG/ToolChainSCDG.py --method DFS --verbose_scdg databases/malware-win/train/nitol/00b2f45c7befbced2efaeb92a725bb3d  

# +- 512 sec <SimulationManager with 61 deadended>
# (virtual env/penv)
python3 ToolChainSCDG/ToolChainSCDG.py --method DFS --verbose_scdg databases/malware-win/train/nitol/00b2f45c7befbced2efaeb92a725bb3d 
```

```bash
# timeout (+- 607 sec) 
# <SimulationManager with 6 active, 168 deadended, 61 pause, 100 ExcessLoop> + 109 SCDG
pypy3 ToolChainSCDG/ToolChainSCDG.py --method DFS --verbose_scdg databases/malware-win/train/RedLineStealer/0f1153b16dce8a116e175a92d04d463ecc113b79cf1a5991462a320924e0e2df 

# timeout (611 sec) 
# <SimulationManager with 5 active, 69 deadended, 63 pause, 100 ExcessLoop> + 53 SCDG
# (virtual env/penv)
python3 ToolChainSCDG/ToolChainSCDG.py --method DFS --verbose_scdg databases/malware-win/train/RedLineStealer/0f1153b16dce8a116e175a92d04d463ecc113b79cf1a5991462a320924e0e2df 
```

:page_with_curl: Model & Classification extractor (`ToolChainClassifier`)
====
<a name="tcc"></a>

When a new sample has to be evaluated, its SCDG is first build as described previously. Then, `gspan` is applied to extract the biggest common subgraph and a similarity score is evaluated to decide if the graph is considered as part of the family or not.

The similarity score `S` between graph `G'` and `G''` is computed as follow:

![GitHub Logo](/doc/tex2img.png)

Since `G''` is a subgraph of `G'`, this is calculating how much `G'` appears in `G''`.

Another classifier we use is the Support Vector Machine (`SVM`) with INRIA graph kernel or the Weisfeiler-Lehman extension graph kernel.

### How to use ?

Just run the script : 
```bash
python3 ToolChainClassifier.py FOLDER/FILE
```
* `FOLDER` : Folder containing binaries to classify, these binaries must be ordered by familly (default : `output/save-SCDG/`)
* `train` :  Launch training process, else classify/detect new sample with previously computed model (default : False)
* `mode`: `detection` = binary decision cleanware vs malware | `classification` = malware family (default: classification) 
* `classifier` : Classifier used [gspan,inria,wl,dl] (default : wl)
* `threshold` : Threshold used for the classifier [0..1] (default : 0.45)
* `support` : Support used for the gspan classifier [0..1] (default : 0.75)
* `ctimeout` : Timeout for gspan classifier (default : 3sec)
* `biggest_subgraph` : Biggest subgraph used with gspan (default : 5)
* `nthread` : Number of thread used (default : max)
* `families`: Families considered
* `epoch` : Only for deep learning model: number of epoch (default : 5)

Experiments purpose arguments:
* `sepoch` : Only for deep learning model: starting epoch (default : 1)
* `data_scale` : Only for deep learning model: data scale value (default: 0.9)
* `vector_size` : Only for deep learning model: Size of the vector used (default: 4)
* `batch_size` : Only for deep learning model: batch size for the model(default: 1)



#### Example

This will train models for input dataset

```bash
# Note: Deep learning model not supported by pypy --classifier dl
pypy3 ToolChainClassifier/ToolChainClassifier.py --train output/save-SCDG/

python3 ToolChainClassifier/ToolChainClassifier.py --train output/save-SCDG/
```

This will classify input dataset based on previously computed models

```bash
pypy3 ToolChainClassifier/ToolChainClassifier.py output/test-set/

python3 ToolChainClassifier/ToolChainClassifier.py  output/test-set/
```


:page_with_curl: Federated Learning for collaborative works (`ToolChainFL`)
====
<a name="tcfl"></a>

Only support deep learning models for now.

### How to use ?

On each client you should run:
```bash
bash run_worker --hostname=<name>
```

Then run the script on the master node: 
```bash
pypy3 ToolChainFL.py --hostnames <listname> BINARY_NAME

python3 ToolChainFL.py --hostnames <listname> BINARY_NAME
```
* `run_name` :  Name for the experiments (default : "")
* `nrounds` :  Number of rounds for training (default : 5)
* `demonstration` :  If set, use specific dataset for each client (up to 3) to simulate different dataset in clients, else use the same input folder dataset for all clients (default : False)
* `no_scdg_create` :  Skip SCDGs create phase (default: False)
* `hostnames` : Hostnames for celery clients
* `smodel` : Only for deep learning model: Share model type, 1 partly aggregation (client do not have necessary the same family samples) and 0 fully aggregation (default: 0)

Experiments purpose arguments:
* `sround` :  Restart from sround (default : 0)
* `nparts` :  Number of partitions (default : 3)
* `FLRtrain` :  FL train rotate (default : False)

You can use any arguments of the toolchain in addition.

#### Example

On each client + master you should run:
```bash
(screen) bash run_worker.sh --hostname=host1 # client 1 = master node
(screen) bash run_worker.sh --hostname=host2 # client 2
(screen) bash run_worker.sh --hostname=host2 # client 3
```

Then on the master node:

```bash
bash setup_network.sh
(screen) python3 ToolChainFL.py --memory_limit --demonstration --timeout 100 --method CDFS --classifier dl --smodel 1 --hostnames host1 host2 host3 --verbose_scdg databases/malware-win/small_train/ output/save-SCDG/


(screen) python3 ToolChainFL.py --memory_limit --demonstration --timeout 100 --method CDFS --classifier gspan --hostnames host1 host2 host3 --verbose_scdg databases/malware-win/small_train/ output/save-SCDG/
```

#### Managing SSH sessions

**Source**: https://unix.stackexchange.com/questions/479/keep-processes-running-after-ssh-session-disconnects

```bash
sudo apt-get install screen
```

To list detached programs
```bash
screen -list
```
To disconnect (but leave the session running) Hit `Ctrl + A` and then `Ctrl + D` in immediate succession. You will see the message [detached]

To reconnect to an already running session

```bash
screen -r
```

To reconnect to an existing session, or create a new one if none exists

```bash
screen -D -r
```

To create a new window inside of a running screen session Hit `Ctrl + A` and then `C` in immediate succession. You will see a new prompt.

To switch from one screen window to another Hit `Ctrl + A` and then `Ctrl + A` in immediate succession.

To list open screen windows Hit `Ctrl + A` and then `W` in immediate succession

:page_with_curl: Credentials
====
<a name="credit"></a>

Main authors of the projects:

* **Charles-Henry Bertrand Van Ouytsel** (UCLouvain)

* **Christophe Crochet** (UCLouvain)

* **Khanh Huu The Dam** (UCLouvain)

Under the supervision and with the support of **Fabrizio Biondi** (Avast) 

Under the supervision and with the support of our professor **Axel Legay** (UCLouvain) (:heart:)
