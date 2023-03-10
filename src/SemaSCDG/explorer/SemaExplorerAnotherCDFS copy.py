#!/usr/bin/env python3
import monkeyhex  # this will format numerical results in hexadecimal
import logging
import sys
from collections import deque
from .SemaExplorer import SemaExplorer


class SemaExplorerAnotherCDFS(SemaExplorer):
    def __init__(
        self,
        simgr,
        max_length,
        exp_dir,
        nameFileShort,
        worker,
    ):
        super(SemaExplorerAnotherCDFS, self).__init__(
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
            worker.print_on,
            worker.print_sm_step,
            worker.print_syscall,
            worker.debug_error,
        )
        self.pause_stash = deque()
        self.log = logging.getLogger("ToolChainExplorerAnotherCDFS")
        self.log.setLevel("INFO")
        self.flag = False
        self.nberror = 0
        
    def step_state(self, simgr, state, **kwargs):
        # print(state)
        # print(simgr)
        
        super().build_snapshot(simgr)

        if self.print_sm_step and (
            len(self.fork_stack) > 0 or len(simgr.deadended) > self.deadended
        ):
            self.log.info(
                "A new block of execution have been executed with changes in sim_manager."
            )
            self.log.info("Currently, simulation manager is :")
            self.log.info(str(simgr))
            self.log.info("pause stash len :" + str(len(self.pause_stash)))
            self.flag = True
            
        if self.print_sm_step and len(self.fork_stack) > 0:
            self.log.info("fork_stack : " + str(len(self.fork_stack)))
            
        if len(simgr.errored) > self.nberror:
            self.nberror = len(simgr.errored)
            self.flag = True

        # We detect fork for a state
        super().manage_fork(simgr)

        # Remove state which performed more jump than the limit allowed
        super().remove_exceeded_jump(simgr)

        # Manage ended state
        super().manage_deadended(simgr)

        if self.flag:
            id_to_stash = []
            for s in simgr.active:
                vis_addr = s.addr
                if vis_addr not in self.dict_addr_vis:
                    self.dict_addr_vis[vis_addr] = 1
                    id_to_stash.append(s.globals["id"])
            simgr.move(
                from_stash="active",
                to_stash="new_addr",
                filter_func=lambda s: s.globals["id"] in id_to_stash,
            )
                
        for s in simgr.active:
            vis_addr = s.addr
            id_to_stash = []
            if vis_addr not in self.dict_addr_vis:
                self.dict_addr_vis[vis_addr] = 1
            if s.globals["n_calls_recv"] < 0:
                s.globals["n_calls_recv"] = len(self.scdg[s.globals["id"]])-1
            if s.globals["n_calls_send"] < 0:
                s.globals["n_calls_send"] = len(self.scdg[s.globals["id"]])-1

        super().mv_bad_active(simgr)

        super().manage_pause(simgr)

        super().drop_excessed_loop(simgr)

        super().manage_error(simgr)

        super().manage_unconstrained(simgr)

        # if self.flag:
        #     while simgr.active:
        #         simgr.stashes["pause"].append(simgr.active.pop())
        #     while len(simgr.stashes["new_addr"]) > 0 and len(simgr.active) < self.max_simul_state:
        #         s = simgr.stashes["new_addr"].pop()
        #         print("this is new   " + hex(s.addr))
        #         simgr.active.append(s)
        #     while len(simgr.stashes["pause"]) > 0 and len(simgr.active) < self.max_simul_state:
        #         super().take_longuest(simgr, "pause")
        #     self.flag = False

        super().excessed_step_to_active(simgr)

        super().excessed_loop_to_active(simgr)

        super().time_evaluation(simgr)
        
        # print(simgr.stash)
        # print(simgr.active)
        #print(simgr.step_state(state, **kwargs))
        
        return simgr.step_state(state, **kwargs)
        #return simgr.stashes

        
    def step(self, simgr, stash="active", **kwargs):
        try:
            simgr = simgr.step(stash=stash, **kwargs)
        except Exception as inst:
            self.log.warning("ERROR IN STEP() - YOU ARE NOT SUPPOSED TO BE THERE !")
            # self.log.warning(type(inst))    # the exception instance
            self.log.warning(inst)  # __str__ allows args to be printed directly,
            exc_type, exc_obj, exc_tb = sys.exc_info()
            # fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.log.warning(exc_type)
            self.log.warning(exc_obj,exc_type)
            exit(-1)
            
        if self.flag:
            while simgr.active:
                simgr.stashes["pause"].append(simgr.active.pop())
            while len(simgr.stashes["new_addr"]) > 0 and len(simgr.active) < self.max_simul_state:
                s = simgr.stashes["new_addr"].pop()
                print("this is new   " + hex(s.addr))
                simgr.active.append(s)
            while len(simgr.stashes["pause"]) > 0 and len(simgr.active) < self.max_simul_state:
                super().take_longuest(simgr, "pause")
            self.flag = False

        return simgr
