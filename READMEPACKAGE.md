#  SEMA  - ToolChain using Symbolic Execution for Malware Analysis. 
#  Documentation

1. [ Installation ]
2. [ SEMA ]
    1. [ `ToolChainSCDG` ]
    2. [ `ToolChainClassifier`]
    3. [ `ToolChainFL`]

Installation
====

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

#### Generate executable

https://pyinstaller.readthedocs.io/en/stable/requirements.html

TODO

```bash
pyinstaller -F -w --path="src/:penv/lib/python3.8/site-packages" --onefile src/ToolChain.py
```

#### Generate package

https://test.pypi.org/account/register/

```bash
python3 -m pip install --upgrade build
python3 -m build
twine upload --repository testpypi dist/*
```

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

#### Pip packages 
Once pip is installed and in your virtual environment, use it to install the following packages:

* `graphviz`
* `monkeyhex`
* `angr`
* `researchpy`

This can be done by using the command :
```bash
pip3 install graphviz monkeyhex angr researchpy;
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

 `SEMA - ToolChain`
====

Our toolchain is represented in the next figure  and works as follow. A collection of labelled binaries of different malwares families is collected and used as the input of the toolchain. **Angr**, a framework for symbolic execution, is used to execute symbolically binaries and extract execution traces. For this purpose, different heuristics have been developped to optimize symbolic execution. Several execution traces (i.e : API calls used and their arguments) corresponding to one binary are extracted with Angr and gather together thanks to several graph heuristics to construct a SCDG. These resulting SCDGs are then used as input to graph mining to extract common graph between SCDG of the same family and create a signature. Finally when a new sample has to be classified, its SCDG is build and compared with SCDG of known families (thanks to a simple similarity metric).


### How to use ?
Just run the script : 
```bash
pypy3 ToolChain.py FOLDER

python3 ToolChain.py FOLDER
```
* `FOLDER` : Folder containing binaries to classify, these binaries must be ordered by familly (default : `databases/malware-inputs/Sample_paper`)

#### Example

```bash
# For folder of malware 
# Deep learning not supported with pypy3 (--classifier dl)
pypy3 ToolChain.py  --method CDFS --verbose databases/malware-inputs/Sample_paper/

# (virtual env/penv)
python3 ToolChain.py  --method CDFS --verbose databases/malware-inputs/Sample_paper/
```

 System Call Dependency Graphs extractor (`ToolChainSCDG`)
====

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
pypy3 ToolChainSCDG/ToolChainSCDG.py --method DFS --verbose databases/malware-inputs/Sample_paper/nitol/00b2f45c7befbced2efaeb92a725bb3d  

# +- 512 sec <SimulationManager with 61 deadended>
# (virtual env/penv)
python3 ToolChainSCDG/ToolChainSCDG.py --method DFS --verbose databases/malware-inputs/Sample_paper/nitol/00b2f45c7befbced2efaeb92a725bb3d 
```

```bash
# timeout (+- 607 sec) 
# <SimulationManager with 6 active, 168 deadended, 61 pause, 100 ExcessLoop> + 109 SCDG
pypy3 ToolChainSCDG/ToolChainSCDG.py --method DFS --verbose databases/malware-inputs/Sample_paper/RedLineStealer/0f1153b16dce8a116e175a92d04d463ecc113b79cf1a5991462a320924e0e2df 

# timeout (611 sec) 
# <SimulationManager with 5 active, 69 deadended, 63 pause, 100 ExcessLoop> + 53 SCDG
# (virtual env/penv)
python3 ToolChainSCDG/ToolChainSCDG.py --method DFS --verbose databases/malware-inputs/Sample_paper/RedLineStealer/0f1153b16dce8a116e175a92d04d463ecc113b79cf1a5991462a320924e0e2df 
```

 Model & Classification extractor (`ToolChainClassifier`)
====

When a new sample has to be evaluated, its SCDG is first build as described previously. Then, `gspan` is applied to extract the biggest common subgraph and a similarity score is evaluated to decide if the graph is considered as part of the family or not.

Since `G''` is a subgraph of `G'`, this is calculating how much `G'` appears in `G''`.

Another classifier we use is the Support Vector Machine (`SVM`) with INRIA graph kernel or the Weisfeiler-Lehman extension graph kernel.


### How to use ?

Just run the script : 
```bash
python3 ToolChainClassifier.py FOLDER
```
* `FOLDER` : Folder containing binaries to classify, these binaries must be ordered by familly (default : `output/save-SCDG/`)
* `mode`: `detection` = binary decision cleanware vs malware OR `classification` = malware family (default: classification) 
* `classifier` : Classifier used [gspan,inria,wl,dl] (default : wl)
* `threshold` : Threshold used for the classifier [0..1] (default : 0.45)
* `support` : Support used for the gspan classifier [0..1] (default : 0.75)
* `ctimeout` : Timeout for gspan classifier (default : 3sec)
* `biggest_subgraph` : Biggest subgraph used with gspan (default : 5)
* `nthread` : Number of thread used (default : max)
* `families`: Families considered (default : ['bancteian','delf','FeakerStealer','gandcrab','ircbot','lamer','nitol','RedLineStealer','sfone','sillyp2p','simbot','Sodinokibi','sytro','upatre','wabot','RemcosRAT'])"
* `epoch` : Only for deep learning model: number of epoch (default : 5)
* `data_scale` : Only for deep learning model: data scale value (default: 0.9)
* `vector_size` : Only for deep learning model: Size of the vector used (default: 4)
* `batch_size` : Only for deep learning model: batch size for the model(default: 1)



#### Example

```bash
# Note: Deep learning model not supported by pypy --classifier dl
pypy3 ToolChainClassifier/ToolChainClassifier.py output/test_classifier_CDFS/

python3 ToolChainClassifier/ToolChainClassifier.py output/test_classifier_CDFS/
```


Federated Learning for collaborative works (`ToolChainFL`)
====

TODO

### How to use ?
Just run the script : 
```bash
pypy3 ToolChainFL/ToolChainFL.py BINARY_NAME

python3 ToolChainFL/ToolChainFL.py BINARY_NAME
```

#### Example

```bash
pypy3 ToolChainFL/ToolChainFL.py 

python3 ToolChainFL/ToolChainFL.py 
```