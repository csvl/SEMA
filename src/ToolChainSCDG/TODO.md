# SCDGs TODO

* debug_error angr better integration

* hdf5 file compact data utils.py dam

* Enable automatic connection to VM (netplwiz)

* claripy redo like before (opti)

    * uninstall claripy by angr take modif version of CH

* Improve angr to support Symbion at lastest version (TOCHECK)

* Unpacking module A

    1. Detect if binary is packed or not => OK
     
    2. Concolic execution until we reach the unpacked state +- ok

    3. Get the address to jump for classical search, then Sigmion angr

    4. start normal analysis

* Unpacking module B

    * emulation with unicorn

* multithread version (1 thread per file ?) 

    * +++ need to reduce memory used

    * Now usually one core is used at 100%

* Memory leaks: Memory profiling clean integration ?

    * https://pypi.org/project/memory-profiler/

    * tracemalloc

    * https://github.com/angr/angr/issues/2222

* Check heap config 

    * WARNING | 2022-04-01 13:46:06,112 | angr.state_plugins.heap.heap_base | Allocation request of 4294967264 bytes exceeded maximum of 128 bytes; allocating 4294967264 bytes

* "Unable to concretize address for store with the provided strategies.

    * https://github.com/angr/angr-doc/issues/108