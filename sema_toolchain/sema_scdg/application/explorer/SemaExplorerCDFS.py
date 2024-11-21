
#!/usr/bin/env python3
import os
import sys



import monkeyhex  # this will format numerical results in hexadecimal
import logging
from collections import deque
import sys, os
from explorer.SemaExplorer import SemaExplorer
import traceback

try:
    log_level = os.environ["LOG_LEVEL"]
    log = logging.getLogger("SemaExplorerCDFS")
    log.setLevel(log_level)
except Exception as e:
    print("Error while setting up logger in SemaExplorerCDFS")
    
class SemaExplorerCDFS(SemaExplorer):
    def __init__(
        self,
        simgr,
        exp_dir,
        nameFileShort,
        scdg_graph,
        call_sim
    ):
        super(SemaExplorerCDFS, self).__init__(
            simgr,
            exp_dir,
            nameFileShort,
            scdg_graph,
            call_sim
        )
        self.new_addr_stash = "new_addr"
        self.config_logger()

    def config_logger(self):
        self.log_level = log_level
        self.log = log

    def setup(self, simgr):
        super().setup(simgr)
        self.pause_stash = deque()
        # The stash where states leading to new instruction addresses (not yet explored) of the binary are kept.
        if self.new_addr_stash not in simgr.stashes:
            simgr.stashes[self.new_addr_stash] = []

    def step(self, simgr, stash="active", **kwargs):
        try:
            simgr = simgr.step(stash=stash, **kwargs)
        except Exception:
            traceback.print_exc()
            raise Exception("ERROR IN STEP() - YOU ARE NOT SUPPOSED TO BE THERE !")

        super().build_snapshot(simgr)

        if  (len(self.fork_stack) > 0 or len(simgr.deadended) > self.deadended):
            self.log.info("A new block of execution have been executed with changes in sim_manager.")
            self.log.info("Currently, simulation manager is :\n" + str(simgr))
            self.log.info("pause stash len :" + str(len(self.pause_stash)))

        if len(self.fork_stack) > 0:
            self.log.info("fork_stack : " + str(len(self.fork_stack)) + " " + hex(simgr.active[0].addr) + " || " + hex(simgr.active[1].addr))

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
        while (len(simgr.stashes["new_addr"]) > 0 and len(simgr.active) < self.max_simul_state):
            simgr.active.append(simgr.stashes["new_addr"].pop())
            self.log.info("Hey new addr !")
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

        super().drop_excessed_loop(simgr)

        # If states end with errors, it is often worth investigating. Set DEBUG_ERROR to live debug
        # TODO : add a log file if debug error is not activated
        super().manage_error(simgr)

        super().manage_unconstrained(simgr)

        for vis in simgr.active:
            self.dict_addr_vis.add(
                str(super().check_constraint(vis, vis.history.jump_target))
            )

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
