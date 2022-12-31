# SCDGs TODO

* gandcrab/00bf3cd055521cde6ab164438d629bae infinite loop GetFileSize

* Netwire infinite loop GetFileSize

* allow escaping infinite loop due to bad sim proc

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

*  Sodinokibi/9c7a33d57688c7a82516a378cf014acadf68e39d0b13063f75c108dc2a40587d

INFO    | 2022-04-08 10:38:14,935 | CustomSimProcedure | Syscall found:  GetProcessHeap[]
WARNING | 2022-04-08 10:38:15,036 | ToolChainExplorerCDFS | ERROR IN STEP() - YOU ARE NOT SUPPOSED TO BE THERE !
WARNING | 2022-04-08 10:38:15,036 | ToolChainExplorerCDFS | 'NoneType' object has no attribute 'get_data_size'
--- Logging error ---
Traceback (most recent call last):
  File "/home/fluser/SEMA-ToolChain/src/ToolChainSCDG/explorer/ToolChainExplorerCDFS.py", line 46, in step
    simgr = simgr.step(stash=stash, **kwargs)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/misc/hookset.py", line 80, in __call__
    return self.func(*args, **kwargs)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/sim_manager.py", line 346, in step
    successors = self.step_state(state, successor_func=successor_func, **run_args)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/sim_manager.py", line 383, in step_state
    successors = self.successors(state, successor_func=successor_func, **run_args)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/sim_manager.py", line 422, in successors
    return self._project.factory.successors(state, **run_args)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/factory.py", line 60, in successors
    return self.default_engine.process(*args, **kwargs)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/engines/vex/light/slicing.py", line 19, in process
    return super().process(*args, **kwargs)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/engines/engine.py", line 149, in process
    self.process_successors(self.successors, **kwargs)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/engines/failure.py", line 21, in process_successors
    return super().process_successors(successors, **kwargs)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/engines/syscall.py", line 18, in process_successors
    return super().process_successors(successors, **kwargs)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/engines/hook.py", line 61, in process_successors
    return self.process_procedure(state, successors, procedure, **kwargs)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/engines/procedure.py", line 37, in process_procedure
    inst = procedure.execute(state, successors, ret_to=ret_to)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/sim_procedure.py", line 226, in execute
    r = getattr(inst, inst.run_func)(*sim_args, **inst.kwargs)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/procedures/win32/heap.py", line 23, in run
    self.state.heap.chunk_from_mem(addr).get_data_size()
AttributeError: 'NoneType' object has no attribute 'get_data_size'

16% (5 of 30) |########################                                                                                                                            | Elapsed Time: 0:53:35 ETA:   4:28:12INFO - 2022-04-08 14:28:36,019 - ToolChainSCDG - Namespace(binary='databases/malware-win/Sample_paper/', conc_loop=1024, concrete_target_is_local=False, debug_error=False, dir=None, discard_SCDG=True, disjoint_union=False, eval_time=False, exp_dir='output/save-SCDG/sfone/', familly=None, format_out='gs', hostnames=None, limit_pause=200, max_deadend=600, max_step=50000, method='CDFS', min_size=3, n_args=0, not_comp_args=False, not_ignore_zero=False, not_resolv_string=False, packed=False, simul_state=5, symb_loop=3, timeout=600, unpack_method=None, verbose=True)
INFO - 2022-04-08 14:28:36,025 - ToolChainSCDG - 
---------------------------------------------------------------
--- Building SCDG of sfone/01769a23486387b4510093a885339d23 ---
---------------------------------------------------------------
Traceback (most recent call last):
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/cle/memory.py", line 95, in pack
    start, backer = next(self.backers(addr))
StopIteration

During handling of the above exception, another exception occurred:

Traceback (most recent call last):
  File "ToolChainSCDG/ToolChainSCDG.py", line 598, in <module>
    main()
  File "ToolChainSCDG/ToolChainSCDG.py", line 581, in main
    toolc.build_scdg(args, file, expl_method,folder.split("/")[-1])
  File "ToolChainSCDG/ToolChainSCDG.py", line 191, in build_scdg
    proj = angr.Project(
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/angr/project.py", line 131, in __init__
    self.loader = cle.Loader(self.filename, concrete_target=concrete_target, **load_options)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/cle/loader.py", line 133, in __init__
    self.initial_load_objects = self._internal_load(main_binary, *preload_libs, *force_load_libs, preloading=(main_binary, *preload_libs))
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/cle/loader.py", line 775, in _internal_load
    obj.relocate()
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/cle/backends/__init__.py", line 326, in relocate
    reloc.relocate()
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/cle/backends/pe/relocation/pereloc.py", line 44, in relocate
    super().relocate()
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/cle/backends/relocation.py", line 118, in relocate
    self.owner.memory.pack_word(self.dest_addr, self.value)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/cle/memory.py", line 122, in pack_word
    return self.pack(addr, self._arch.struct_fmt(size=size, signed=signed, endness=endness), data)
  File "/home/fluser/SEMA-ToolChain/penv/lib/python3.8/site-packages/cle/memory.py", line 97, in pack
    raise KeyError(addr)
KeyError: 91804


* To test a055ffa93a97e641838d9fe11093f8e4 -> delf

* Take Windows and Linux cleanware samples 

* Implemente detection part of each classifier