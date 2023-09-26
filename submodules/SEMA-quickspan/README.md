***quickSpan***
==============

**quickSpan**
very fast parallel implementation for gSpan algorithm in data mining with many tunable options for different domains

## Features

***quickSpan*** has gained 35x speedup in comparison to [Yan's](https://www.cs.ucsb.edu/~xyan/software/gSpan.htm) original implementation with multi-threading, even 1-6 times faster with a single thread. It also reduces more than 100 folds memory usage, which make it feasible to be adopted on personal computers.  

***quickSpan*** is ***fast***:

1. Adopt task parallel programming.
2. Incorporate **C++11** hastable and hashset.
3. Use contiguous memory storage.
4. Use partial pruning.

***quickSpan*** is ***memory efficient***:

1. Incorporate **C++11** emplace_back method.
2. Reconstruct a graph with frequent edges and nodes before mining.
3. Reuse memory to store temporal data.

***quickSpan*** is ***correct***:

1. We ran experiment for `extern/data/Compound_422` and `extern/data/Chemical_340` with minimal support from 0.1 to 0.9, and the results are exactly the same as Yan's gSpan-64. 

## Install

### Prerequisites

- *g++* or *icc* with **C++11** support.
- *glog*: `sudo apt-get install libgoogle-glog-*` or install from [source](https://github.com/google/glog).
- *gflags*: `sudo apt-get install libgflags-*` or install from [source](https://github.com/gflags/gflags).
- *cmake*: `sudo apt-get install cmake` or install from [source](https://cmake.org/).
- *openmp* environment.

### Steps

    mkdir build && cd build
    cmake ..
    make
    
## Usage

Run an example:

    ./build/gspan -input_file extern/data/gs/Chemical_340 -support 0.2 
    
Arguments help:

    ./build/gspan -help

Multi-thread support:

Using the option:
    -threads N
to run with N threads.

Alternatively by environment variable:
    export OMP_NUM_THREADS=<hardware core num for recommendation>

Memory safety limits:

    export OCLENI_MALLOC_MODE=1
    export OCLENI_MAX_MEMORY=<maximum memory for quickspan to use in KB>


## Docker

The project features a Dockerfile allowing the construction of a docker image to be used in the unlikely event that the code does not compile on your machine. You need to have docker up and running on your machine to use this approach.

### Building the image

The standard docker command works:
```bash
docker build -t quickspan .
```

### Using the image

Let's assume that you have your data in /path/to/data (and want to write your results there).
For testing, you can the full path to the external/data folder of this repository.
First start the docker:
```bash
docker run -u `id -u`:`id -g` -v /path/to/data:/data -it quickspan
```
You will be shown a bash prompt.
Within that prompt, you can use gspan on your data that you will find in /data.
For instance you can type:
```bash
cd /data/
gspan -input_file Chemical_340 -pattern -support 0.5 -output_file Chemical_340_subgraph.gs
```

## Experiments

### Platform

All experiments were run on a server with two 14-core processors running at 2GHz, allowing up to 56 parallel threads, and with 128 GB of RAM.

### Results

The comparison runs over the accompanying data sets sourced from various academic works. The implementations below are:
 * gBolt	- original gBolt implementation
 * GLP		- Graph Learning Package/mathlab library
 * quickSpan	- the implementation here
 * quiskSpan1	- implementation here with "-threads 1" for single threading forced
 * SFS		- the implementation used by the following two papers:
    - B. Bringmann, A. Zimmermann, L. D. Raedt, and S. Nijssen. Don't be afraid of simpler patterns. In PKDD, pages 55-66, 2006.
    - B. Bringmann and S. Nijssen. What is frequent in a single graph? In PAKDD, pages 858-863, 2008.

In the following table, :hourglass: denotes a timeout and :boom: denotes a crash.

|Data set name            |Support         |gBolt   |GLP          |quickSpan      |quickSpan1      |SFS        |
|-------------------------|----------------|--------|-------------|---------------|----------------|-----------|
|BrainNet ADHD            |0.10            |0.27    |1.77         |0.11           |0.13            |:hourglass:|   
|                         |0.15            |0.27    |0.14         |0.10           |0.03            |:hourglass:|
|                         |0.20            |0.28    |0.07         |0.08           |0.02            |:hourglass:|
|                         |0.50            |0.13    |0.07         |0.07           |0.02            |:hourglass:|
|        Hyper/Impulsive  |0.10            |14.12   |:hourglass:  |11.48          |117.54          |:hourglass:|
|                         |0.15            |0.67    |54.06        |0.67           |1.44            |:hourglass:|
|                         |0.20            |0.39    |2.47         |0.19           |0.44            |:hourglass:|
|                         |0.50            |0.19    |0.11         |0.07           |0.06            |:hourglass:|
|        Gender           |0.10            |0.34    |11.16        |0.16           |0.52            |:hourglass:|
|                         |0.15            |0.30    |1.35         |0.10           |0.12            |:hourglass:|
|                         |0.20            |0.30    |0.10         |0.11           |0.05            |:hourglass:|
|                         |0.50            |0.16    |0.05         |0.08           |0.03            |:hourglass:|
|Chemical 340             |0.10            |0.37    |1.06         |0.18           |0.21            |0.23       |
|                         |0.15            |0.34    |0.68         |0.14           |0.12            |0.14       |
|                         |0.20            |0.39    |0.37         |0.13           |0.09            |0.13       |
|                         |0.50            |0.28    |0.18         |0.10           |0.06            |0.06       |
|Mutagen                  |0.10            |0.40    |0.70         |0.23           |0.28            |:hourglass:|
|                         |0.15            |0.40    |0.40         |0.16           |0.24            |:hourglass:|
|                         |0.20            |0.37    |0.32         |0.15           |0.19            |:hourglass:|
|                         |0.50            |0.22    |0.13         |0.12           |0.15            |:hourglass:|
|NCI     AIDS             |0.10            |5.73    |90.96        |5.75           |15.15           |:hourglass:|
|                         |0.15            |5.21    |48.11        |5.36           |11.39           |:hourglass:|
|                         |0.20            |4.84    |34.45        |4.78           |9.75            |:hourglass:|
|                         |0.50            |4.19    |4.33         |4.19           |5.16            |:hourglass:|
|        AIDS Active      |0.10            |0.59    |18.62        |0.36           |1.20            |2.53       |
|                         |0.15            |0.45    |4.70         |0.28           |0.58            |0.96       |
|                         |0.20            |0.43    |1.52         |0.25           |0.26            |0.53       |
|                         |0.50            |0.32    |0.29         |0.18           |0.11            |0.12       |
|        AIDS + Cancer    |0.10            |3.34    |57.28        |3.32           |8.37            |:hourglass:|
|                         |0.15            |3.10    |29.51        |3.05           |6.32            |:hourglass:|
|                         |0.20            |2.80    |20.66        |2.86           |5.26            |:hourglass:|
|                         |0.50            |2.55    |6.78         |2.47           |3.13            |:hourglass:|
|        Cancer           |0.10            |19.05   |363.91       |20.44          |89.04           |:hourglass:|
|                         |0.15            |15.11   |170.93       |15.50          |51.63           |:hourglass:|
|                         |0.20            |13.60   |108.72       |14.04          |38.19           |:hourglass:|
|                         |0.50            |10.42   |29.90        |10.77          |14.99           |:hourglass:|
|Social  DBLP             |0.10            |0.84    |1.51         |0.80           |0.77            |:hourglass:|
|                         |0.15            |0.84    |1.48         |0.85           |0.78            |:hourglass:|
|                         |0.20            |0.85    |1.51         |0.82           |0.75            |:hourglass:|
|                         |0.50            |0.82    |1.50         |0.89           |0.75            |:hourglass:|
|        Twitter          |0.10            |1.61    |3.01         |1.61           |1.62            |:hourglass:|
|                         |0.15            |1.66    |3.06         |1.61           |1.52            |:hourglass:|
|                         |0.20            |1.63    |3.06         |1.60           |1.49            |:hourglass:|
|                         |0.50            |1.70    |3.04         |1.78           |1.48            |:hourglass:|
|Pathological 2           |1.00            |:boom:  |:boom:       |84.54(24.16)   |81.21(23.38)    |:hourglass:|
|Pathological 20          |0.10            |:boom:  |:boom:       |86.51(291.51)  |86.11(289.36)   |:hourglass:|
|                         |0.15            |:boom:  |:boom:       |88.98(291.98)  |84.91(288.22)   |:hourglass:|
|                         |0.20            |:boom:  |:boom:       |88.08(293.15)  |85.86(288.75)   |:hourglass:|
|                         |0.50            |:boom:  |:boom:       |87.22(292.51)  |86.58(289.31)   |:hourglass:|
|                         |1.00            |:boom:  |:hourglass:  |88.11(292.68)  |84.24(295.06)   |:hourglass:|


