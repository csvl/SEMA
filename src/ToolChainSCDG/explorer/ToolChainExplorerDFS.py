#!/usr/bin/env python3
import logging
import sys
from .ToolChainExplorer import ToolChainExplorer


class ToolChainExplorerDFS(ToolChainExplorer):
    def __init__(
        self,
        simgr,
        max_length,
        exp_dir,
        nameFileShort,
        worker,
    ):
        super(ToolChainExplorerDFS, self).__init__(
            simgr,
            max_length,
            exp_dir,
            nameFileShort,
            worker
        )
        self.log = logging.getLogger("ToolChainExplorerDFS")
        self.log.setLevel("INFO")

    def __take_longuest(self, simgr, source_stash):
        """
        Take a state of source_stash with longuest amount of steps and append it to active stash
        @pre : source_stash exists
        """
        id_to_move = 0
        max_step = 0
        if len(simgr.stashes[source_stash]) > 0:
            id_to_move = simgr.stashes[source_stash][0].globals["id"]
            max_step = simgr.stashes[source_stash][0].globals["n_steps"]
        else:
            return

        for s in simgr.stashes[source_stash]:
            if s.globals["n_steps"] > max_step:
                id_to_move = s.globals["id"]
                max_step = s.globals["n_steps"]

        simgr.move(source_stash, "active", lambda s: s.globals["id"] == id_to_move)

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
            self.log.info("pause stash len :" + str(len(self.pause_stash)))

        if self.print_sm_step and len(self.fork_stack) > 0:
            self.log.info("fork_stack : " + str(len(self.fork_stack)))

        # if self.print_sm_step:
        #    self.log.info("len(self.loopBreak_stack) : " + str(len(self.loopBreak_stack)))
        #    self.log.info("state.globals['n_steps'] : " + str(state.globals['n_steps']))

        # self.log.warning("STEP")

        # We detect fork for a state
        super().manage_fork(simgr)

        # Remove state which performed more jump than the limit allowed
        super().remove_exceeded_jump(simgr)

        # Manage ended state
        super().manage_deadended(simgr)

        super().mv_bad_active(simgr)
        # import pdb; pdb.set_trace()

        # If limit of simultaneous state is not reached and we have some states available in pause stash
        if len(simgr.stashes["pause"]) > 0 and len(simgr.active) < self.max_simul_state:
            moves = min(
                self.max_simul_state - len(simgr.active),
                len(simgr.stashes["pause"]),
            )
            for m in range(moves):
                self.__take_longuest(simgr, "pause")

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
