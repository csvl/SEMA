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
    2. [ Federated learning architecture ](#arch_fl)

2. [ Installation ](#install)

3. [ SEMA ](#tc)
    1. [ `SemaSCDG` ](#tcscdg)
    2. [ `SemaClassifier`](#tcc)
    3. [ `SemaFL`](#tcfl)

4. [Quick Start Demos](#)
    1. [ `Extract SCDGs from binaries` ](https://github.com/csvl/SEMA-ToolChain/blob/production/Tutorial/Notebook/SEMA-SCDG%20Demo.ipynb)
    2. [ `SVM and gSpan Classifiers`](https://github.com/csvl/SEMA-ToolChain/blob/production/Tutorial/Notebook/SEMA-Classifier.ipynb)
    3. [ `Deep learning Classifier`](https://github.com/csvl/SEMA-ToolChain/blob/production/Tutorial/Notebook/Deep%20Learning%20Model%20Demo.ipynb)
    4. [ `Federated learning demo`](https://github.com/csvl/SEMA-ToolChain/blob/production/Tutorial/Notebook/SEMA%20Federated%20Learning%20.ipynb)

5. [ Credentials ](#credit)

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

Tested on Ubuntu 18 LTS. Checkout Makefile and install.sh for more details.

**Recommanded installation:**

```bash
# WARNING: slow since one submodule contains preconfigure VMs
git clone --recurse-submodules https://github.com/csvl/SEMA-ToolChain.git;
# Full installation (ubuntu)
make install-docker;
# TODO link with VM on host
```

**Classical installation:**

```bash
# WARNING: slow since one submodule contains preconfigure VMs
git clone --recurse-submodules https://github.com/csvl/SEMA-ToolChain.git;
# Full installation (ubuntu)
cd SEMA-ToolChain/; source install.sh;
ARGS=<> make install-baremetal;

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
pypy3 Sema.py FOLDER_OF_BINARIES FOLDER_OF_SIGNATURE

python3 Sema.py FOLDER_OF_BINARIES FOLDER_OF_SIGNATURE
```
* `FOLDER` : Folder containing binaries to classify, these binaries must be ordered by familly (default : `databases/malware-win/train`)

#### Example

```bash
# For folder of malware 
# Deep learning not supported with pypy3 (--classifier dl)
pypy3 Sema.py  --memory_limit --CDFS --train --verbose_scdg --verbose_classifier databases/malware-win/train/ output/save-SCDG/

# (virtual env/penv)
python3 Sema.py --memory_limit --CDFS --train --verbose_scdg --verbose_classifier databases/malware-win/train/ output/save-SCDG/
```

:page_with_curl: System Call Dependency Graphs extractor (`SemaSCDG`)
====
<a name="tcscdg"></a>

This repository contains a first version of a SCDG extractor.
During symbolic analysis of a binary, all system calls and their arguments found are recorded. After some stop conditions for symbolic analysis, a graph is build as follow : Nodes are systems Calls recorded, edges show that some arguments are shared between calls.

### How to use ?
Just run the script : 
```bash
pypy3 src/SemaSCDG/SemaSCDG.py BINARY_NAME

python3 src/SemaSCDG/SemaSCDG.py BINARY_NAME

usage: update_readme_usage.py [--DFS | --BFS | --CDFS | --CBFS] [--gs | --json] [--symbion | --unipacker] [--packed] [--concrete_target_is_local] [--symb_loop SYMB_LOOP]
                              [--limit_pause LIMIT_PAUSE] [--max_step MAX_STEP] [--max_deadend MAX_DEADEND] [--simul_state SIMUL_STATE] [--n_args N_ARGS] [--conc_loop CONC_LOOP]
                              [--min_size MIN_SIZE] [--disjoint_union] [--not_comp_args] [--three_edges] [--not_ignore_zero] [--dir DIR] [--discard_SCDG] [--eval_time]
                              [--timeout TIMEOUT] [--not_resolv_string] [--exp_dir EXP_DIR] [--memory_limit] [--verbose_scdg] [--debug_error] [--familly FAMILLY]
                              binary

SCDG module arguments

optional arguments:
  help                  show this help message and exit
  --DFS                 TODO
  --BFS                 TODO
  --CDFS                TODO
  --CBFS                TODO
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
                        Number of symbolic arguments given to the binary (default : 1024)

SCDG creation parameter:
  --min_size MIN_SIZE   Minimum size required for a trace to be used in SCDG (default : 3)
  --disjoint_union      Do we merge traces or use disjoint union ? (default : merge)
  --not_comp_args       Do we compare arguments to add new nodes when building graph ? (default : comparison enabled)
  --three_edges         Do we use the three-edges strategy ? (default : False)
  --not_ignore_zero     Do we ignore zero when building graph ? (default : Discard zero)
  --dir DIR             Directory to save outputs graph for gspan (default : output/)
  --discard_SCDG        Do not keep intermediate SCDG in file (default : True)
  --eval_time           Keep intermediate SCDG in file (default : False)

Global parameter:
  --timeout TIMEOUT     Timeout in seconds before ending extraction (default : 600)
  --not_resolv_string   Do we try to resolv references of string (default : False)
  --exp_dir EXP_DIR     Directory to save SCDG extracted (default : output/save-SCDG/)
  --memory_limit        Skip binary experiment when memory > 90% (default : False)
  --verbose_scdg        Verbose output during calls extraction (default : False)
  --debug_error         Debug error states (default : False)
  --familly FAMILLY     Familly of the malware (default : unknown)
  binary                Name of the binary to analyze

```

Program will output a graph in `.gs` format that could be exploited by `gspan`.

You also have a script `merge_gspan.py` which could merge all `.gs` from a directory into only one file.

Password for Examples archive is "infected". Warning : it contains real samples of malwares.

#### Example

```bash
# +- 447 sec <SimulationManager with 61 deadended>
pypy3 src/SemaSCDG/SemaSCDG.py --DFS --verbose_scdg databases/malware-win/train/nitol/00b2f45c7befbced2efaeb92a725bb3d  

# +- 512 sec <SimulationManager with 61 deadended>
# (virtual env/penv)
python3 src/SemaSCDG/SemaSCDG.py --DFS --verbose_scdg databases/malware-win/train/nitol/00b2f45c7befbced2efaeb92a725bb3d 
```

```bash
# timeout (+- 607 sec) 
# <SimulationManager with 6 active, 168 deadended, 61 pause, 100 ExcessLoop> + 109 SCDG
pypy3 src/SemaSCDG/SemaSCDG.py --DFS --verbose_scdg databases/malware-win/train/RedLineStealer/0f1153b16dce8a116e175a92d04d463ecc113b79cf1a5991462a320924e0e2df 

# timeout (611 sec) 
# <SimulationManager with 5 active, 69 deadended, 63 pause, 100 ExcessLoop> + 53 SCDG
# (virtual env/penv)
python3 src/SemaSCDG/SemaSCDG.py --DFS --verbose_scdg databases/malware-win/train/RedLineStealer/0f1153b16dce8a116e175a92d04d463ecc113b79cf1a5991462a320924e0e2df 
```

:page_with_curl: Model & Classification extractor (`SemaClassifier`)
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
python3 SemaClassifier/SemaClassifier.py FOLDER/FILE

usage: update_readme_usage.py [-h] [--threshold THRESHOLD] [--biggest_subgraph BIGGEST_SUBGRAPH] [--support SUPPORT] [--ctimeout CTIMEOUT] [--epoch EPOCH] [--sepoch SEPOCH]
                              [--data_scale DATA_SCALE] [--vector_size VECTOR_SIZE] [--batch_size BATCH_SIZE] (--classification | --detection) (--wl | --inria | --dl | --gspan)
                              [--bancteian] [--delf] [--FeakerStealer] [--gandcrab] [--ircbot] [--lamer] [--nitol] [--RedLineStealer] [--sfone] [--sillyp2p] [--simbot]
                              [--Sodinokibi] [--sytro] [--upatre] [--wabot] [--RemcosRAT] [--verbose_classifier] [--train] [--nthread NTHREAD]
                              binaries

Classification module arguments

optional arguments:
  -h, --help            show this help message and exit
  --classification      By malware family
  --detection           Cleanware vs Malware
  --wl                  TODO
  --inria               TODO
  --dl                  TODO
  --gspan               TODOe

Global classifiers parameters:
  --threshold THRESHOLD
                        Threshold used for the classifier [0..1] (default : 0.45)

Gspan options:
  --biggest_subgraph BIGGEST_SUBGRAPH
                        Biggest subgraph consider for Gspan (default: 5)
  --support SUPPORT     Support used for the gpsan classifier [0..1] (default : 0.75)
  --ctimeout CTIMEOUT   Timeout for gspan classifier (default : 3sec)

Deep Learning options:
  --epoch EPOCH         Only for deep learning model: number of epoch (default: 5) Always 1 for FL model
  --sepoch SEPOCH       Only for deep learning model: starting epoch (default: 1)
  --data_scale DATA_SCALE
                        Only for deep learning model: data scale value (default: 0.9)
  --vector_size VECTOR_SIZE
                        Only for deep learning model: Size of the vector used (default: 4)
  --batch_size BATCH_SIZE
                        Only for deep learning model: Batch size for the model (default: 1)

Malware familly:
  --bancteian
  --delf
  --FeakerStealer
  --gandcrab
  --ircbot
  --lamer
  --nitol
  --RedLineStealer
  --sfone
  --sillyp2p
  --simbot
  --Sodinokibi
  --sytro
  --upatre
  --wabot
  --RemcosRAT

Global parameter:
  --verbose_classifier  Verbose output during train/classification (default : False)
  --train               Launch training process, else classify/detect new sample with previously computed model
  --nthread NTHREAD     Number of thread used (default: max)
  binaries              Name of the folder containing binary'signatures to analyze (Default: output/save-SCDG/, only that for ToolChain)

```

#### Example

This will train models for input dataset

```bash
# Note: Deep learning model not supported by pypy --classifier dl
pypy3 SemaClassifier/SemaClassifier.py --train output/save-SCDG/

python3 SemaClassifier/SemaClassifier.py --train output/save-SCDG/
```

This will classify input dataset based on previously computed models

```bash
pypy3 SemaClassifier/SemaClassifier.py output/test-set/

python3 SemaClassifier/SemaClassifier.py  output/test-set/
```


:page_with_curl: Federated Learning for collaborative works (`SemaFL`)
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
pypy3 SemaFL.py --hostnames <listname> BINARY_NAME

python3 SemaFL.py --hostnames <listname> BINARY_NAME
```
* `run_name` :  Name for the experiments (default : "")
* `nrounds` :  Number of rounds for training (default : 5)
* `demonstration` :  If set, use specific dataset for each client (up to 3) to simulate different dataset in clients, else use the same input folder dataset for all clients (default : False)
* `no_scdg_create` :  Skip SCDGs create phase (default: False)
* `hostnames` : Hostnames for celery clients
* `smodel` : Only for deep learning model: Share model type, 1 partly aggregation (client do not have necessary the same family samples) and 0 fully aggregation (default: 0)
* `classification` : Enable the pre-train classifier

Experiments purpose arguments:
* `sround` :  Restart from sround (default : 0)
* `nparts` :  Number of partitions (default : 3)

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
(screen) python3 SemaFL.py --memory_limit --demonstration --timeout 100 --method CDFS --classifier dl --smodel 1 --hostnames host1 host2 host3 --verbose_scdg databases/malware-win/small_train/ output/save-SCDG/


(screen) python3 SemaFL.py --memory_limit --demonstration --timeout 100 --method CDFS --classifier gspan --hostnames host1 host2 host3 --verbose_scdg databases/malware-win/small_train/ output/save-SCDG/
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

If you use SEMA or data from this repo for your research please take a look at the following papers:

```
@inproceedings{bertrand2022tool,
  title={Tool Paper-SEMA: Symbolic Execution Toolchain for Malware Analysis},
  author={Bertrand Van Ouytsel, Charles-Henry and Crochet, Christophe and Dam, Khanh Huu The and Legay, Axel},
  booktitle={International Conference on Risks and Security of Internet and Systems},
  pages={62--68},
  year={2022},
  organization={Springer}
}



@InProceedings{10.1007/978-3-031-22295-5_16,
author="Bertrand Van Ouytsel, Charles-Henry
and Legay, Axel",
editor="Reiser, Hans P.
and Kyas, Marcel",
title="Malware Analysis with Symbolic Execution and Graph Kernel",
booktitle="Secure IT Systems",
year="2022",
publisher="Springer International Publishing",
address="Cham",
pages="292--310",
}



@inproceedings{10.1145/3538969.3538996,
author = {Bertrand Van Ouytsel, Charles-Henry and Dam, Khanh Huu The and Legay, Axel},
title = {Symbolic Analysis Meets Federated Learning to Enhance Malware Identifier},
year = {2022},
isbn = {9781450396707},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3538969.3538996},
doi = {10.1145/3538969.3538996},
articleno = {150},
numpages = {10},
keywords = {Symbolic Analysis, Malware Detection, Data Privacy, Federated Learning},
location = {Vienna, Austria},
series = {ARES '22}
}

```
