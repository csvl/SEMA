#!/usr/bin/env python3
import monkeyhex  # this will format numerical results in hexadecimal
import logging
import sys
from SemaExplorer import SemaExplorer


class SemaExplorerChooseDFS(SemaExplorer):
    def __init__(
        self,
        simgr,
        max_length,
        exp_dir,
        nameFileShort,
        worker
    ):
        super(SemaExplorerChooseDFS, self).__init__(
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
        self.log = logging.getLogger("SemaExplorerDFS")
        self.log.setLevel("INFO")
        
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

        if self.print_sm_step and (
            len(self.fork_stack) > 0 or len(simgr.deadended) > self.deadended
        ):
            self.log.info(
                "A new block of execution have been executed with changes in sim_manager."
            )
            self.log.info("Currently, simulation manager is :\n" + str(simgr))
            self.log.info("pause stash len :" + str(len(simgr.stashes["pause"])))

        if self.print_sm_step and len(self.fork_stack) > 0:
            self.log.info("fork_stack : " + str(len(self.fork_stack)) + " " + hex(simgr.active[0].addr) + " " + hex(simgr.active[1].addr))
            
        # We detect fork for a state
        super().manage_fork(simgr)
 
        simgr.move(
            from_stash="active",
            to_stash="deadend",
            filter_func=lambda s: s.addr == 0xdeadbeef,
        )
        
        # Command loop -> not loop over the same command forever
        #super().remove_loop(simgr)
        
        # Remove state which performed more jump than the limit allowed
        super().remove_exceeded_jump(simgr)

        # Manage ended state
        super().manage_deadended(simgr)
        
        super().mv_bad_active(simgr)

        # If limit of simultaneous state is not reached and we have some states available in pause stash
        if len(simgr.active) > 1:
            print(simgr.active[0])
            l1 = simgr.active[0].solver.constraints
            l2 = simgr.active[1].solver.constraints
            ll1 = []
            for i in l1:
                ll1.append(repr(i))
            ll2 = []
            for i in l2:
                ll2.append(repr(i))
            l3 = [value for value in ll1 if value not in ll2]
            print(l3)
            print(simgr.active[1])
            l4 = [value for value in ll2 if value not in ll1]
            print(l4)
            x = input()
            if x == "" or int(x) == 1:
                simgr.stashes["pause"].append(simgr.active[1])
                simgr.active.remove(simgr.active[1])
            else:
                simgr.stashes["pause"].append(simgr.active[0])
                simgr.active.remove(simgr.active[0])
            
        if len(simgr.active) == 0 and len(simgr.stashes["pause"]) > 0:
            simgr.active.append(simgr.stashes["pause"].pop())
            
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

        super().excessed_step_to_active(simgr)

        super().excessed_loop_to_active(simgr)

        super().time_evaluation(simgr)
       
        return simgr
