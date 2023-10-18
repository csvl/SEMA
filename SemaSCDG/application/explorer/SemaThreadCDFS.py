#!/usr/bin/env python3
import monkeyhex  # this will format numerical results in hexadecimal
import logging
from collections import deque
import sys
from SemaExplorer import SemaExplorer
from angr.exploration_techniques.threading import Threading
import concurrent.futures
from angr.engines.engine import TLSMixin
from angr.misc.ux import once

class SemaThreadCDFS(SemaExplorer):
    def __init__(
        self,
        simgr,
        max_length,
        exp_dir,
        nameFileShort,
        worker,
        threads=8,
        local_stash='local_thread'
    ):
        super(SemaThreadCDFS,self).__init__(
            simgr,
            max_length,
            exp_dir,
            nameFileShort,
            worker.scdg,
            worker.call_sim,
            worker.eval_time,
            worker.timeout,
            worker.max_end_state,
            worker.max_step,
            worker.timeout_tab,
            worker.jump_it,
            worker.loop_counter_concrete,
            worker.jump_dict,
            worker.jump_concrete_dict,
            worker.max_simul_state,
            worker.max_in_pause_stach,
            worker.verbose,
            worker.print_sm_step,
            worker.print_syscall,
            worker.debug_error,
        )
        
        self.threads = threads
        self.queued = set()
        self.tasks = set()
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=threads)
        self.local_stash = local_stash
        
        self.pause_stash = deque()
        self.log = logging.getLogger("SemaThreadCDFS")
        self.log.setLevel("INFO")

    # NOOB -> use threads arg on sim_manager
    def inner_step(self, state, simgr, **kwargs):
        error_list = []
        simgr.step(stash=self.local_stash, error_list=error_list, **kwargs)
        return state, error_list, simgr

    def successors(self, simgr, state, engine=None, **kwargs):
        engine = engine or self.project.factory.default_engine
        if not isinstance(engine, TLSMixin) and once("tls_engine"):
            self.log.error("Using Threading exploration technique but your engine is not thread-safe.")
            self.log.error("Do you want to add the TLSMixin to your engine?")
        return simgr.successors(state, engine=engine, **kwargs)

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
                tsimgr._stashes = {self.local_stash: [state]}
                tsimgr._errored = []
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
                    state, error_list, tsimgr = done_future.result()
                    simgr.absorb(tsimgr)
                    simgr.errored.extend(error_list)
                    simgr.stashes[stash].remove(state)
                    self.queued.remove(state)
                timeout = 0
                
        except Exception as inst:
            self.log.warning("ERROR IN STEP() - YOU ARE NOT SUPPOSED TO BE THERE !")
            # self.log.warning(type(inst))    # the exception instance
            self.log.warning(inst)  # __str__ allows args to be printed directly,
            exc_type, exc_obj, exc_tb = sys.exc_info()
            # fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.log.warning(exc_type)
            self.log.warning(exc_tb)
           # exit(-1)
            #raise Exception("ERROR IN STEP() - YOU ARE NOT SUPPOSED TO BE THERE !")

        super().build_snapshot(simgr)

        if self.print_sm_step and (
            len(self.fork_stack) > 0 or len(simgr.deadended) > self.deadended
        ):
            self.log.info(
                "A new block of execution have been executed with changes in sim_manager."
            )
            self.log.info("Currently, simulation manager is :\n" + str(simgr))
            self.log.info("pause stash len :" + str(len(self.pause_stash)))

        if self.print_sm_step and len(self.fork_stack) > 0:
            self.log.info("fork_stack : " + str(len(self.fork_stack)))

        # if self.print_sm_step:
        #    self.log.info("len(self.loopBreak_stack) : " + str(len(self.loopBreak_stack)))
        #    self.log.info("state.globals['n_steps'] : " + str(state.globals['n_steps']))

        # We detect fork for a state
        super().manage_fork(simgr)

        # Remove state which performed more jump than the limit allowed
        super().remove_exceeded_jump(simgr)

        # Manage ended state
        super().manage_deadended(simgr)

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

        super().mv_bad_active(simgr)
        # import pdb; pdb.set_trace()

        if len(simgr.active) > self.max_simul_state:
            excess = len(simgr.active) - self.max_simul_state
            while excess > 0:
                self.pause_stash.append(simgr.active.pop())
                excess = excess - 1
        if len(simgr.stashes["new_addr"]) > 0:
            count = min(len(simgr.active), len(simgr.stashes["new_addr"]))
            while count > 0:
                self.pause_stash.append(simgr.active.pop())
                count = count - 1
        while (
            len(simgr.stashes["new_addr"]) > 0
            and len(simgr.active) < self.max_simul_state
        ):
            simgr.active.append(simgr.stashes["new_addr"].pop())
            #self.log.info("Hey new addr !")
        while len(simgr.active) < self.max_simul_state and len(self.pause_stash) > 0:
            simgr.active.append(self.pause_stash.pop())

        # If limit of simultaneous state is not reached and we have some states available in pause stash
        if len(simgr.stashes["pause"]) > 0 and len(simgr.active) < self.max_simul_state:
            moves = min(
                self.max_simul_state - len(simgr.active),
                len(simgr.stashes["pause"]),
            )
            for m in range(moves):
                super().take_longuest(simgr, "pause")

        super().manage_pause(simgr)

        super().drop_excessed_loop(simgr)

        # If states end with errors, it is often worth investigating. Set DEBUG_ERROR to live debug
        # TODO : add a log file if debug error is not activated
        super().manage_error(simgr)

        super().manage_unconstrained(simgr)

        for vis in simgr.active:
            self.dict_addr_vis[
                str(super().check_constraint(vis, vis.history.jump_target))
            ] = 1

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

        super().excessed_step_to_active(simgr)

        super().excessed_loop_to_active(simgr)

        super().time_evaluation(simgr)

        return simgr
