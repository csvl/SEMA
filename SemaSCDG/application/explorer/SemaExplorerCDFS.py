#!/usr/bin/env python3
import monkeyhex  # this will format numerical results in hexadecimal
import logging
from collections import deque
import sys
from SemaExplorer import SemaExplorer


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
        self.log = logging.getLogger("SemaExplorerCDFS")
        self.log.setLevel("INFO")

        self.new_addr_stash = "new_addr"

    def setup(self, simgr):
        super().setup(simgr)
        self.pause_stash = deque()
        # The stash where states leading to new instruction addresses (not yet explored) of the binary are kept. 
        if self.new_addr_stash not in simgr.stashes:
            simgr.stashes[self.new_addr_stash] = []

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
    
    def step(self, simgr, stash="active", **kwargs):
        try:
            simgr = simgr.step(stash=stash, **kwargs)
        except Exception as inst:
            self.log.warning(inst)  # __str__ allows args to be printed directly,
            exc_type, exc_obj, exc_tb = sys.exc_info()
            # fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.log.warning(exc_type)
            self.log.warning(exc_obj,exc_type)
            #exit(-1)
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

        self.manage_stashes(simgr)

        # If states end with errors, it is often worth investigating. Set DEBUG_ERROR to live debug
        # TODO : add a log file if debug error is not activated
        self.manage_error(simgr)

        self.time_evaluation(simgr)

        return simgr
