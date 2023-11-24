#!/usr/bin/env python3
import monkeyhex  # this will format numerical results in hexadecimal
import logging
from collections import deque
from SemaExplorer import SemaExplorer
import sys


class SemaExplorerCBFS(SemaExplorer):
    def __init__(
        self,
        simgr,
        exp_dir,
        nameFileShort,
        scdg_graph,
        call_sim
    ):
        super(SemaExplorerCBFS, self).__init__(
            simgr,
            exp_dir,
            nameFileShort,
            scdg_graph,
            call_sim
        )
        self.log = logging.getLogger("SemaExplorerCBFS")
        self.log.setLevel("INFO")

        self.new_addr_stash = "new_addr"

    def setup(self, simgr):
        super().setup(simgr)
        self.pause_stash = deque()
        if self.new_addr_stash not in simgr.stashes:
            simgr.stashes[self.new_addr_stash] = []

    def new_addr_priority(self, simgr):
        while simgr.active:
            self.pause_stash.append(simgr.active.pop())
            
        while (
            len(simgr.stashes["new_addr"]) > 0
            and len(simgr.active) < self.max_simul_state
        ):
            simgr.active.append(simgr.stashes["new_addr"].pop())
            self.log.info("Hey new addr !")
        while len(simgr.active) < self.max_simul_state and len(self.pause_stash) > 0:
            simgr.active.append(self.pause_stash.popleft())
    
    def manage_stashes(self, simgr):
        for s in simgr.active:
            vis_addr = str(self.check_constraint(s, s.history.jump_target))
            id_to_stash = []
            if vis_addr not in self.dict_addr_vis:
                self.dict_addr_vis.add(vis_addr)
                id_to_stash.append(s.globals["id"])
            simgr.move(
                from_stash="active",
                to_stash="new_addr",
                filter_func=lambda s: s.globals["id"] in id_to_stash,
            )
            if s.addr < s.project.loader.main_object.min_addr: # s.addr > s.project.loader.main_object.max_addr or 
                self.timeout = 0 # TODO

        self.new_addr_priority(simgr)

        # If limit of simultaneous state is not reached and we have some states available in pause stash
        if len(simgr.stashes["pause"]) > 0 and len(simgr.active) < self.max_simul_state:
            moves = min(
                self.max_simul_state - len(simgr.active),
                len(simgr.stashes["pause"]),
            )
            for m in range(moves):
                super().take_smallest(simgr, "pause")

        super().manage_pause(simgr)

        super().drop_excessed_loop(simgr)

        # If states end with errors, it is often worth investigating. Set DEBUG_ERROR to live debug
        # TODO : add a log file if debug error is not activated
        super().manage_error(simgr)

        super().manage_unconstrained(simgr)

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

        super().excessed_step_to_active(simgr)

        super().excessed_loop_to_active(simgr)
    
    def step(self, simgr, stash="active", **kwargs):
        try:
            simgr = simgr.step(stash=stash, **kwargs)
        except Exception as inst:
            self.log.warning("ERROR IN STEP() - YOU ARE NOT SUPPOSED TO BE THERE !")
            self.log.warning(inst)  # __str__ allows args to be printed directly,
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.log.warning(exc_type, exc_obj)
            raise Exception("ERROR IN STEP() - YOU ARE NOT SUPPOSED TO BE THERE !")

        super().build_snapshot(simgr)

        if self.verbose and (len(self.fork_stack) > 0 or len(simgr.deadended) > self.deadended):
            self.log.info("A new block of execution have been executed with changes in sim_manager.\n")
            self.log.info("Currently, simulation manager is :\n" + str(simgr))
            self.log.info("pause stash len :" + str(len(self.pause_stash)))

        if self.verbose and len(self.fork_stack) > 0:
            self.log.info("fork_stack : " + str(len(self.fork_stack)))

        # We detect fork for a state
        super().manage_fork(simgr)

        self.manage_stashes(simgr)

        super().time_evaluation(simgr)

        return simgr
