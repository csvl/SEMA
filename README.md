# :skull_and_crossbones: SEMA :skull_and_crossbones:

## ToolChain using Symbolic Execution for Malware Analysis.

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

[![Documentation Built by gendocs](https://img.shields.io/badge/docs%20by-gendocs-blue.svg)](https://gendocs.readthedocs.io/en/latest/)
[![.github/workflows/.pre-commit-config.yaml](https://github.com/csvl/SEMA-ToolChain/actions/workflows/.pre-commit-config.yaml/badge.svg)](https://github.com/csvl/SEMA-ToolChain/actions/workflows/.pre-commit-config.yaml)
[![CodeQL](https://github.com/csvl/SEMA-ToolChain/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/csvl/SEMA-ToolChain/actions/workflows/github-code-scanning/codeql)
[![Documentation Generation](https://github.com/csvl/SEMA-ToolChain/actions/workflows/pr-generate-docs.yaml/badge.svg)](https://github.com/csvl/SEMA-ToolChain/actions/workflows/pr-generate-docs.yaml)
[![pages-build-deployment](https://github.com/csvl/SEMA-ToolChain/actions/workflows/pages/pages-build-deployment/badge.svg)](https://github.com/csvl/SEMA-ToolChain/actions/workflows/pages/pages-build-deployment)
[![Python application](https://github.com/csvl/SEMA-ToolChain/actions/workflows/python-app.yml/badge.svg)](https://github.com/csvl/SEMA-ToolChain/actions/workflows/python-app.yml)


![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54) ![Docker](https://img.shields.io/badge/docker-%230db7ed.svg?style=for-the-badge&logo=docker&logoColor=white)  ![Debian](https://img.shields.io/badge/Debian-D70A53?style=for-the-badge&logo=debian&logoColor=white)

### Toolchain architecture
<a name="toolchain-architecture"></a>

Our toolchain is represented in the following figure and works as follows:

- A collection of labelled binaries from different malware families is collected and used as the input of the toolchain.
- **Angr**, a framework for symbolic execution, is used to execute binaries symbolically and extract execution traces. For this purpose, different heuristics have been developed to optimize symbolic execution.
- Several execution traces (i.e., API calls used and their arguments) corresponding to one binary are extracted with Angr and gathered together using several graph heuristics to construct a SCDG.
- These resulting SCDGs are then used as input to graph mining to extract common graphs between SCDGs of the same family and create a signature.
- Finally, when a new sample has to be classified, its SCDG is built and compared with SCDGs of known families using a simple similarity metric.

![Toolchain Illustration](./doc/images/SEMA_illustration.png)

This repository contains a first version of a SCDG extractor. During the symbolic analysis of a binary, all system calls and their arguments found are recorded. After some stop conditions for symbolic analysis, a graph is built as follows: Nodes are system calls recorded, edges show that some arguments are shared between calls.

When a new sample has to be evaluated, its SCDG is first built as described previously. Then, `gspan` is applied to extract the biggest common subgraph and a similarity score is evaluated to decide if the graph is considered as part of the family or not. The similarity score `S` between graph `G'` and `G''` is computed as follows:
Since `G''` is a subgraph of `G'`, this is calculating how much `G'` appears in `G''`.
Another classifier we use is the Support Vector Machine (`SVM`) with INRIA graph kernel or the Weisfeiler-Lehman extension graph kernel.

A web application is available and is called SemaWebApp. It allows to manage the launch of experiments on SemaSCDG and/or SemaClassifier.

### Pre-commit

This repository uses pre-commit to ensure that the code is formatted correctly and that the code is clean. To install pre-commit, run the following command:

```bash
python3 -m pip install pre-commit
pre-commit install
```

### Documentation

* Complete README of the entire toolchain : ![Sema README](./doc/README.md)

* SCDG README : ![SCDG README](./sema_toolchain/sema_scdg/README.md)

* Classifier README : ![Classifier README](./sema_toolchain/sema_classifier/README.md)

* Web app README : ![Web app README](./sema_toolchain/sema_web_app/README.md)

* A Makefile is provided to ease the usage of the toolchain, run ```make help``` for more information about the available commands

### Credentials

Main authors of the projects:

* **Charles-Henry Bertrand Van Ouytsel** (UCLouvain)

* **Christophe Crochet** (UCLouvain)

* **Khanh Huu The Dam** (UCLouvain)

* **Oreins Manon** (UCLouvain)

Under the supervision and with the support of **Fabrizio Biondi** (Avast)

Under the supervision and with the support of our professor **Axel Legay** (UCLouvain) (:heart:)

### Linked papers

* [Analysis and classification of malware based on symbolic execution and machine learning](https://dial.uclouvain.be/pr/boreal/object/boreal:285757)

* [Tool Paper - SEMA: Symbolic Execution Toolchain for Malware Analysis](https://doi.org/10.1007/978-3-031-31108-6\_5)

* [On Exploiting Symbolic Execution to Improve the Analysis of RAT Samples with angr](https://dial.uclouvain.be/pr/boreal/object/boreal%3A280744/datastream/PDF_01/view)
