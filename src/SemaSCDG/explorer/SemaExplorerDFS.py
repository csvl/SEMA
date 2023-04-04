#!/usr/bin/env python3
import monkeyhex  # this will format numerical results in hexadecimal
import logging
import sys
from .SemaExplorer import SemaExplorer


class SemaExplorerDFS(SemaExplorer):
    def __init__(
        self,
        simgr,
        max_length,
        exp_dir,
        nameFileShort,
        worker
    ):
        super(SemaExplorerDFS, self).__init__(
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

        # Command loop -> not loop over the same command forever
        #super().remove_loop(simgr)
        
        # Remove state which performed more jump than the limit allowed
        super().remove_exceeded_jump(simgr)

        # Manage ended state
        super().manage_deadended(simgr)
        
        super().mv_bad_active(simgr)

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

        super().excessed_step_to_active(simgr)

        super().excessed_loop_to_active(simgr)

        super().time_evaluation(simgr)
       
        return simgr
