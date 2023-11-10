#!/usr/bin/env python3
import monkeyhex  # this will format numerical results in hexadecimal
import logging
from collections import deque
import sys
from SemaExplorer import SemaExplorer
import concurrent.futures
from angr.engines.engine import TLSMixin
from angr.misc.ux import once

class SemaThreadCDFS(SemaExplorer):
    def __init__(
        self,
        simgr,
        exp_dir,
        nameFileShort,
        scdg_graph,
        call_sim,
        threads=8
        #local_stash='local_thread'
    ):
        super(SemaThreadCDFS,self).__init__(
            simgr,
            exp_dir,
            nameFileShort,
            scdg_graph,
            call_sim
        )
        
        self.threads = threads
        self.queued = set()
        self.tasks = set()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
        #self.local_stash = local_stash
        
        self.new_addr_stash = "new_addr"
        self.log = logging.getLogger("SemaThreadCDFS")
        self.log.setLevel("INFO")

    def setup(self, simgr):
        super().setup(simgr)
        self.pause_stash = deque()
        # The stash where states leading to new instruction addresses (not yet explored) of the binary are kept. 
        # If CDFS or CBFS are not used, this stash merges with the pause stash.
        if self.new_addr_stash not in simgr.stashes:
            simgr.stashes[self.new_addr_stash] = []

    def inner_step(self, state, simgr, **kwargs):
        #error_list = []
        #simgr.step(stash=self.local_stash, error_list=error_list, **kwargs)
        new_simgr = self.thread_work(simgr, **kwargs)
        return state, new_simgr

    def successors(self, simgr, state, engine=None, **kwargs):
        engine = engine or self.project.factory.default_engine
        if not isinstance(engine, TLSMixin) and once("tls_engine"):
            self.log.error("Using Threading exploration technique but your engine is not thread-safe.")
            self.log.error("Do you want to add the TLSMixin to your engine?")
        return simgr.successors(state, engine=engine, **kwargs)

   # Prioritize state with new addr by replace state in active stash by state in new addr stash
    def new_addr_priority(self, simgr):
        if len(simgr.stashes["new_addr"]) > 0:
            count = min(len(simgr.active), len(simgr.stashes["new_addr"]))
            while count > 0:
                self.pause_stash.append(simgr.active.pop())
                count = count - 1
        while (len(simgr.stashes["new_addr"]) > 0 and len(simgr.active) < self.max_simul_state):
            simgr.active.append(simgr.stashes["new_addr"].pop())
            self.log.info("Hey new addr !")
        while len(simgr.active) < self.max_simul_state and len(self.pause_stash) > 0:
            simgr.active.append(self.pause_stash.pop())

    def manage_stashes(self, simgr):
        # Put new addr state in active stash to treat them first
        self.new_addr_priority(simgr)
        
        # If limit of simultaneous state is not reached and we have some states available in pause stash
        if len(simgr.stashes["pause"]) > 0 and len(simgr.active) < self.max_simul_state:
            moves = min(
                self.max_simul_state - len(simgr.active),
                len(simgr.stashes["pause"]),
            )
            for m in range(moves):
                self.take_longuest(simgr, "pause")

        for vis in simgr.active:
            self.dict_addr_vis.add(str(super().check_constraint(vis, vis.history.jump_target)))

        for s in simgr.stashes["new_addr"]:
            vis_addr = str(self.check_constraint(s, s.history.jump_target))
            id_to_stash = []
            if vis_addr in self.dict_addr_vis:
                self.log.info("YOU ARE NOT SUPPOSED TO BE THERE !!!!!!")
                id_to_stash.append(s.globals["id"])
            simgr.move(
                from_stash="new_addr",
                to_stash="temp",
                filter_func=lambda s: s.globals["id"] in id_to_stash,
            )
            moves = len(simgr.stashes["temp"])
            for i in range(moves):
                self.pause_stash.append(simgr.stashes["temp"].pop())

        super().manage_stashes(simgr)  

    def thread_work(self, simgr, **kwargs):
        try:
            simgr = simgr.step(stash="active", **kwargs)
        except Exception as inst:
            self.log.warning(inst)  # __str__ allows args to be printed directly,
            exc_type, exc_obj, exc_tb = sys.exc_info()
            # fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.log.warning(exc_type)
            self.log.warning(exc_obj,exc_type)
            raise Exception("ERROR IN STEP() - YOU ARE NOT SUPPOSED TO BE THERE !")
        return simgr

    def step(self, simgr, stash="active", error_list=None, target_stash=None, **kwargs):
        try:
            target_stash = target_stash or stash
            self.log.info("Thread-stepping %s of %s", stash, simgr)

            for state in simgr.stashes[stash]:
                if state in self.queued:
                    continue

                # construct new simgr with new lists
                # this means that threads won't trample each other's hook stacks
                # but can still negotiate over shared resources
                tsimgr = simgr.copy()
                tsimgr._create_integral_stashes()
                tsimgr.active.append(state)
                self.tasks.add(self.executor.submit(self.inner_step, state, tsimgr, target_stash=target_stash, **kwargs))
                self.queued.add(state)

            timeout = None
            while True:
                done, self.tasks = concurrent.futures.wait(
                    self.tasks,
                    timeout=timeout,
                    return_when=concurrent.futures.FIRST_COMPLETED
                )
                if not done:
                    break

                for done_future in done:
                    done_future: concurrent.futures.Future
                    state, tsimgr = done_future.result()
                    simgr.absorb(tsimgr)
                    #simgr.errored.extend(error_list)
                    simgr.stashes[stash].remove(state)
                    self.queued.remove(state)
                timeout = 0
                
        except Exception as inst:
            #self.log.warning("ERROR IN STEP() - YOU ARE NOT SUPPOSED TO BE THERE !")
            # self.log.warning(type(inst))    # the exception instance
            self.log.warning(inst)  # __str__ allows args to be printed directly,
            exc_type, exc_obj, exc_tb = sys.exc_info()
            # fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.log.warning(exc_type)
            self.log.warning(exc_tb)
           # exit(-1)
            raise Exception("ERROR IN STEP() - YOU ARE NOT SUPPOSED TO BE THERE !")

        self.build_snapshot(simgr)

        if self.verbose and (len(self.fork_stack) > 0 or len(simgr.deadended) > self.deadended):
            self.log.info("A new block of execution have been executed with changes in sim_manager.")
            self.log.info("Currently, simulation manager is :\n" + str(simgr))
            self.log.info("pause stash len :" + str(len(self.pause_stash)))

        if self.verbose and len(self.fork_stack) > 0:
            self.log.info("fork_stack : " + str(len(self.fork_stack)) + " " + hex(simgr.active[0].addr) + " || " + hex(simgr.active[1].addr))
        
        # We detect fork for a state
        self.manage_fork(simgr)  

        for s in simgr.active:
            vis_addr = str(self.check_constraint(s, s.history.jump_target))
            id_to_stash = []
            if vis_addr not in self.dict_addr_vis:
                id_to_stash.append(s.globals["id"])
            simgr.move(
                from_stash="active",
                to_stash="new_addr",
                filter_func=lambda s: s.globals["id"] in id_to_stash,
            )

        self.manage_stashes(simgr)

        # If states end with errors, it is often worth investigating. Set DEBUG_ERROR to live debug
        # TODO : add a log file if debug error is not activated
        self.manage_error(simgr)

        self.time_evaluation(simgr)
        return simgr
