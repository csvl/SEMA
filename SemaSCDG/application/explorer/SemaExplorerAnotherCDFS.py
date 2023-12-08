#!/usr/bin/env python3
import monkeyhex  # this will format numerical results in hexadecimal
import logging
import sys
from collections import deque
from SemaExplorer import SemaExplorer


class SemaExplorerAnotherCDFS(SemaExplorer):
    def __init__(
       self,
        simgr,
        exp_dir,
        nameFileShort,
        scdg_graph,
        call_sim,
        log_level
    ):
        super(SemaExplorerAnotherCDFS, self).__init__(
           simgr,
            exp_dir,
            nameFileShort,
            scdg_graph,
            call_sim
        )

        self.log_level = log_level
        self.config_logger()
        self.flag = False
        self.nberror = 0
        self.new_addr_stash = "new_addr"
        self.config_logger()
    
    def config_logger(self):
        self.log = logging.getLogger("SemaExplorerAnotherCDFS")
        self.log.setLevel(self.log_level)
        
    def setup(self, simgr):
        super().setup(simgr)
        self.pause_stash = deque()
        simgr.active[0].globals["n_forks"] = 0
        if self.new_addr_stash not in simgr.stashes:
            simgr.stashes[self.new_addr_stash] = []
    
    def filter(self, simgr, state, **kwargs):
        if self.flag:
            if state.addr not in self.dict_addr_vis:
                self.dict_addr_vis.add(state.addr)
                return "new_addr"       
        super().filter(simgr, state, **kwargs)

    def manage_stashes(self, simgr):
        super().manage_pause(simgr)

        super().drop_excessed_loop(simgr)

        super().manage_error(simgr)

        super().manage_unconstrained(simgr)

        if self.flag or len(simgr.active) == 0:
            while simgr.active:
                simgr.stashes["pause"].append(simgr.active.pop(0))
            while len(simgr.stashes["new_addr"]) > 0 and len(simgr.active) < self.max_simul_state:
                s = simgr.stashes["new_addr"].pop()
                print("this is new   " + hex(s.addr))
                simgr.active.append(s)
            while len(simgr.stashes["pause"]) > 0 and len(simgr.active) < self.max_simul_state:
                super().take_longuest(simgr, "pause")
            self.log.info("Currently, simulation manager is :")
            self.log.info(str(simgr))
            self.flag = False

        super().excessed_step_to_active(simgr)

        super().excessed_loop_to_active(simgr)
    
    def step(self, simgr, stash="active", **kwargs):
        try:
            simgr = simgr.step(stash=stash, **kwargs)
        except Exception as inst:
            self.log.warning("ERROR IN STEP() - YOU ARE NOT SUPPOSED TO BE THERE !")
            # self.log.warning(type(inst))    # the exception instance
            self.log.warning(inst)  # __str__ allows args to be printed directly,
            exc_type, exc_obj, exc_tb = sys.exc_info()
            # fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.log.warning(exc_type, exc_obj)
            exit(-1)
            
        super().build_snapshot(simgr)

        if len(self.fork_stack) > 0 or len(simgr.deadended) > self.deadended or len(simgr.errored) > self.nberror:
            self.nberror = len(simgr.errored)
            self.flag = True

        # We detect fork for a state
        self.manage_fork(simgr)
        
        if len(simgr.active) > 1 and self.flag:
            l1 = simgr.active[0].solver.constraints
            l2 = simgr.active[1].solver.constraints
            simgr.active[0].globals["n_forks"] +=1
            simgr.active[1].globals["n_forks"] +=1
            ll1 = []
            for i in l1:
                ll1.append(repr(i))
            ll2 = []
            for i in l2:
                ll2.append(repr(i))
            l3 = [value for value in ll1 if value not in ll2]
            simgr.active[0].globals["condition"] = l3
            l4 = [value for value in ll2 if value not in ll1]
            simgr.active[1].globals["condition"] = l4

        self.manage_stashes(simgr)

        self.time_evaluation(simgr)

        return simgr

