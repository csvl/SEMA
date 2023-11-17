#!/usr/bin/env python3
import time as timer
import sys
#import monkeyhex  # this will format numerical results in hexadecimal
import logging
from collections import deque
import angr
import psutil
import claripy
import configparser

config = configparser.ConfigParser()
config.read('config.ini')

# import sim_procedure.dll_table as dll
# from sim_procedure.SimProceduresLoader import SimProcedures
from angr.exploration_techniques import ExplorationTechnique

# from sim_procedure.simprocedures import *
# from sim_procedure.CustomSimProcedureWindows import custom_simproc_windows

class SemaExplorer(ExplorationTechnique):
    """
    TODO
    """

    def __init__(
        self,
        simgr,
        exp_dir,
        nameFileShort,
        scdg_graph,
        call_sim
    ):
        super(SemaExplorer, self).__init__()

        self.start_time = timer.time()

        self.memory_limit = config['explorer_arg'].getboolean('memory_limit')
        self.verbose = config['explorer_arg'].getboolean('verbose')
        self.eval_time = config['explorer_arg'].getboolean('eval_time')
        #self._max_length = int(config['explorer_arg']['max_length'])
        self.timeout = int(config['explorer_arg']['timeout'])
        self.max_end_state = int(config['explorer_arg']['max_end_state'])
        self.max_step = int(config['explorer_arg']['max_step'])
        self.jump_it = int(config['explorer_arg']['jump_it'])
        self.loop_counter_concrete = int(config['explorer_arg']['loop_counter_concrete'])
        self.max_simul_state = int(config['explorer_arg']['max_simul_state'])
        self.max_in_pause_stach = int(config['explorer_arg']['max_in_pause_stach'])
        self.timeout_tab = config['explorer_arg']['timeout_tab']
        
        self.log = logging.getLogger("SemaExplorer")
        self.log.setLevel("INFO")

        self.errored = 0
        self.unconstrained = 0
        self.deadended = 0
        self.active = 1
        self.id = 0
        self.snapshot_state = {}
        self.fork_stack = deque()
        self.loopBreak_stack = deque()

        self.excessLoop_stash = "ExcessLoop"
        self.excessStep_stash = "ExcessStep"
        self.deadbeef_stash = "deadbeef"
        self.lost_stash = "lost"

        self.jump_dict = {}
        self.jump_concrete_dict = {}
        self.jump_dict[0] = {}
        self.jump_concrete_dict[0] = {}

        self.exp_dir = exp_dir
        self.nameFileShort = nameFileShort
        self.time_id = 0

        self.scdg_graph = scdg_graph
        self.call_sim = call_sim
        
        self.scdg_fin = []
        self.dict_addr_vis = set()

    def setup(self, simgr):
        #TODO : split in specific observer what is needed

        # The stash where states which exceed the threshold related to loops are moved. If new states are needed and there is no state available in pause
        # or ExcessStep stash, states in this stash are used to resume exploration (their loop counter are put back to zero).
        if self.excessLoop_stash not in simgr.stashes:
            simgr.stashes[self.excessLoop_stash] = []

        # The stash where states exceeding the threshold related to number of steps are moved. If new states are needed and there is no state available
        # in pause stash, states in this stash are used to resume exploration (their step counter are put back to zero).
        if self.excessStep_stash not in simgr.stashes:
            simgr.stashes[self.excessStep_stash] = []

        if self.deadbeef_stash not in simgr.stashes:
            simgr.stashes[self.deadbeef_stash] = []

        if self.lost_stash not in simgr.stashes:
            simgr.stashes[self.lost_stash] = []

        simgr.active[0].globals["id"] = 0
        simgr.active[0].globals["JumpExcedeed"] = False
        simgr.active[0].globals["n_steps"] = 0
        simgr.active[0].globals["loaded_libs"] = {}
        simgr.active[0].globals["addr_call"] = []
        simgr.active[0].globals["loop"] = 0
        simgr.active[0].globals["files"] = {}
        # simgr.active[0].globals["crypt_algo"] = 0
        # simgr.active[0].globals["crypt_result"] = 0
        # simgr.active[0].globals["n_buffer"] = 0
        # simgr.active[0].globals["n_calls"] = 0
        # simgr.active[0].globals["recv"] = 0
        # simgr.active[0].globals["rsrc"] = 0
        # simgr.active[0].globals["resources"] = {}
        # simgr.active[0].globals["df"] = 0
        # simgr.active[0].globals["n_calls_recv"] = 0
        # simgr.active[0].globals["n_calls_send"] = 0
        # simgr.active[0].globals["n_buffer_send"] = 0
        # simgr.active[0].globals["buffer_send"] = []
        simgr.active[0].globals["FindFirstFile"] = 0
        # simgr.active[0].globals["FindNextFile"] = 0
        # simgr.active[0].globals["GetMessageA"] = 0
        # simgr.active[0].globals["GetLastError"] = claripy.BVS("last_error", 32)
        # simgr.active[0].globals["HeapSize"] = {}
        # simgr.active[0].globals["files_fd"] = {}
        # simgr.active[0].globals["create_thread_address"] = []
        # simgr.active[0].globals["is_thread"] = False
        # simgr.active[0].globals["allow_web_interaction"] = False

    def check_constraint(self, state, value):
        try:
            val = state.solver.eval_one(value)
            is_sao = hasattr(val, "to_claripy")
            if is_sao:
                val = val.to_claripy()

        except Exception as e:
            if self.verbose:
                self.log.info("Symbolic value encountered !")
                print(e)
            return value
        return val

    def take_smallest(self, simgr, source_stash):
        """
        Take a state of source_stash with smallest amount of steps and append it to active stash
        @pre : source_stash exists
        """
        id_to_move = 0
        min_step = 2000
        if len(simgr.stashes[source_stash]) > 0:
            id_to_move = simgr.stashes[source_stash][0].globals["id"]
            min_step = simgr.stashes[source_stash][0].globals["n_steps"]
        else:
            return

        for s in simgr.stashes[source_stash]:
            if s.globals["n_steps"] < min_step or (
                str(self.check_constraint(s, s.history.jump_target))
                not in self.dict_addr_vis
                and s.globals["n_steps"] <= min_step
            ):
                id_to_move = s.globals["id"]
                min_step = s.globals["n_steps"]

        simgr.move(source_stash, "active", lambda s: s.globals["id"] == id_to_move)

    def take_longuest(self, simgr, source_stash):
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

    # Return True if a loop without symbolic variable takes too much time
    def check_bad_active(self, state):
        test = str(state.history.jump_target) + "-" + str(state.history.jump_source)
        #backwards = state.solver.eval(state.history.jump_target) - state.solver.eval(state.history.jump_source) < 0

        if test in self.jump_concrete_dict[state.globals["id"]]:
            self.jump_concrete_dict[state.globals["id"]][test] += 1
        else:
            state.globals["previous_regs"] = state.regs
            self.jump_concrete_dict[state.globals["id"]][test] = 1

        if (self.jump_concrete_dict[state.globals["id"]][test] > self.loop_counter_concrete):
            self.jump_concrete_dict[state.globals["id"]][test] = 0
            return True
        return False

    def __update_id_stash(self, simgr, id, new_id):
        """
        Inspect active stash
        Update two ids that are the same to new_id
        Return states have this initial id
        """
        found = False
        was_excess = False
        first_state = None
        for state in simgr.active:
            if state.globals["id"] == id:
                # Case 1 : First state of stash could be a JumpExcedeed, second is not
                if found and not state.globals["JumpExcedeed"]:
                    if was_excess:
                        state.globals["id"] = new_id
                        return first_state, state
                    return state, first_state
                # Case 2 : First state of stash could not be a JumpExcedeed, second is !
                elif found and state.globals["JumpExcedeed"]:
                    return state, first_state
                # Case 3 : First state of stash IS a jumpExcedeed !
                elif not found and state.globals["JumpExcedeed"]:
                    found = True
                    was_excess = True
                    first_state = state
                # Case 4 : First state of stash IS NOT a jumpExcedeed !
                else:
                    found = True
                    state.globals["id"] = new_id
                    first_state = state
        # Was a 'fake' fork
        first_state.globals["id"] = id

    def build_snapshot(self, simgr):
        self.snapshot_state.clear()
        for state in simgr.active:
            if state.globals["id"] in self.snapshot_state:
                self.fork_stack.append(state.globals["id"])
                self.snapshot_state[state.globals["id"]] += 1
            else:
                self.snapshot_state[state.globals["id"]] = 1
            state.globals["n_steps"] += 1

    def manage_unconstrained(self, simgr):
        if len(simgr.unconstrained) > self.unconstrained:
            new_unconstrained = len(simgr.unconstrained) - self.unconstrained
            for i in range(new_unconstrained):
                id_cur = simgr.unconstrained[-1].globals["id"]
                self.log.info("End of the trace number " + str(id_cur) + " unconstrained")
            self.unconstrained = len(simgr.unconstrained)
            
    def manage_error(self, simgr):
        if len(simgr.errored) > self.errored:
            new_errors = len(simgr.errored) - self.errored
            for i in range(new_errors):
                id_cur = simgr.errored[-i - 1].state.globals["id"]
                self.log.info("End of the trace number " + str(id_cur) + " with errors")
                self.log.info(simgr.errored[-i - 1].state)
                self.log.info(simgr.errored[-i - 1].error)
            self.errored = len(simgr.errored)

    def drop_excessed_loop(self, simgr):
        excess_loop = len(simgr.stashes["ExcessLoop"]) - (self.max_in_pause_stach / 5)
        excess_loop = int(excess_loop)  # TODO chris check where we round (up-down)
        if excess_loop > 0:
            id_to_stash = []
            state_to_stash = simgr.stashes["ExcessLoop"][-excess_loop:]
            for t in state_to_stash:
                id_to_stash.append(t.globals["id"])
            simgr.drop(filter_func=lambda s: s.globals["id"] in id_to_stash, stash="ExcessLoop")

    def excessed_step_to_active(self, simgr):
        if len(simgr.active) == 0 and len(simgr.stashes["ExcessStep"]) > 0:
            moves = min(len(simgr.stashes["ExcessStep"]), self.max_simul_state)
            id_move = []
            for i in range(moves):
                state = simgr.stashes["ExcessStep"][i]
                self.id = state.globals["id"]
                id_move.append(self.id)
                state.globals["n_steps"] = 0
            simgr.move(
                from_stash="ExcessStep",
                to_stash="active",
                filter_func=lambda s: s.globals["id"] in id_move,
            )

    def excessed_loop_to_active(self, simgr):
        if len(simgr.active) == 0 and len(simgr.stashes["ExcessLoop"]) > 0:
            moves = min(len(simgr.stashes["ExcessLoop"]), self.max_simul_state)
            id_move = []
            for i in range(moves):
                state = simgr.stashes["ExcessLoop"][i]
                self.id = state.globals["id"]
                id_move.append(self.id)
                state.globals["JumpExcedeed"] = False
                self.jump_dict[self.id].clear()
                self.jump_concrete_dict[self.id].clear()
                self.loopBreak_stack.remove(state)
            simgr.move(
                from_stash="ExcessLoop",
                to_stash="active",
                filter_func=lambda s: s.globals["id"] in id_move,
            )

    # If there is too much states in pause stash, discard some of them
    def manage_pause(self, simgr):
        excess_pause = len(simgr.stashes["pause"]) - self.max_in_pause_stach
        if excess_pause > 0:
            id_to_stash = []
            state_to_stash = simgr.pause[-excess_pause:]
            for t in state_to_stash:
                id_to_stash.append(t.globals["id"])
            simgr.drop(filter_func=lambda s: s.globals["id"] in id_to_stash, stash="pause")

    def time_evaluation(self, simgr):
        ######################################
        #######     Timeout reached ?  #######
        ######################################
        if self.eval_time:
            for new in ["deadended", "active", "errored", "Excessloop", "ExcessStep", "unconstrained"]:
                for state in simgr.stashes[new]:
                    if new == "errored":
                        state = state.state
                    self.scdg_graph[state.globals["id"]][0]["ret"] = new
                    self.scdg_fin.append(self.scdg_graph[state.globals["id"]])

            if self.time_id >= len(self.timeout_tab):
                self.log.info("All timeouts were tested !")
            else:
                with open(
                    self.exp_dir
                    + self.nameFileShort
                    + "_SCDG_"
                    + str(self.timeout_tab[self.time_id])
                    + ".txt",
                    "w",
                ) as save_SCDG:
                    for s in self.scdg_fin:
                        save_SCDG.write(str(s) + "\n")
                self.scdg_fin.clear()
                self.time_id = self.time_id + 1

    def check_fork_split(self, prev_id, found_jmp_table, state):
        if found_jmp_table and prev_id == state.globals["id"]:
            self.snapshot_state[prev_id] = self.snapshot_state[prev_id] - 1
        else:
            concrete_targ = (
                str(state.history.jump_target)
                + "-"
                + str(state.history.jump_source)
            )
            if (concrete_targ not in self.jump_dict[state.globals["id"]]):
                self.jump_dict[state.globals["id"]][concrete_targ] = 1
            else:
                self.jump_dict[state.globals["id"]][concrete_targ] += 1
                if (self.jump_dict[state.globals["id"]][concrete_targ] >= self.jump_it):
                    state.globals["JumpExcedeed"] = True
                    self.loopBreak_stack.append(state)

    def manage_fork(self, simgr):
        if len(self.fork_stack) > 0:
            for i in range(len(self.fork_stack)):
                prev_id = self.fork_stack.pop()
                self.id = self.id + 1  # id for the new state

                # TODO true and false branch ? is it an IF statement here ?
                state_fork1, state_fork2 = self.__update_id_stash(simgr, prev_id, self.id)
                # Check if there is a jump table ('fork implying more than two states')
                found_jmp_table = self.snapshot_state[prev_id] > 1

                if (state_fork1 and state_fork2 and state_fork1.globals["id"] != state_fork2.globals["id"]):
                    if state_fork2.globals["id"] != self.id:
                        self.log.warning("Something bad happend after update_id_stash, ids are messed up")

                    self.scdg_graph.append(self.scdg_graph[prev_id].copy())
                    self.scdg_graph[-1][0] = self.scdg_graph[prev_id][0].copy()

                    self.jump_dict[self.id] = self.jump_dict[prev_id].copy()
                    self.jump_concrete_dict[self.id] = self.jump_concrete_dict[prev_id].copy()

                    # Manage jump of first state
                    self.check_fork_split(prev_id, found_jmp_table, state_fork2)

                    # Manage jump of second state
                    self.check_fork_split(prev_id, found_jmp_table, state_fork1)
                else:
                    self.id = self.id - 1

    def filter(self, simgr, state, **kwargs) :
        # Manage lost state
        if state.addr < simgr._project.loader.main_object.mapped_base :
            return "lost"
        
        # Manage end thread state
        if state.addr == 0xdeadbeef:
            return "deadbeef"
        
        if state in self.loopBreak_stack:
            self.log.info("A state has been discarded because of jump")
            self.log.info(state.addr)
            return "ExcessLoop"
        
        if self.check_bad_active(state):
            self.log.info("A state has been discarded because of simple loop")
            return "ExcessLoop"
        
        if state.globals["n_steps"] % 1000 == 0:
            self.log.debug("n_steps = " + str(state.globals["n_steps"]))

        if state.globals["n_steps"] > self.max_step:
            state.history.trim()
            self.log.info("A state has been discarded because of max_step reached")
            return "ExcessStep"
            
        # TODO check seems new
        if state.globals["loop"] > 3:
            self.log.info("A state has been discarded because of 1 loop reached")
            return "ExcessLoop"
        
        # If too many states are explored simulateously, put state into pause stash
        if len(simgr.active) > self.max_simul_state:
            return "pause"

        else :
            return simgr.filter(state, **kwargs)
            

    def manage_stashes(self, simgr):
        # If there is too much states in pause stash, discard some of them
        self.manage_pause(simgr)

        # If there is too much states in ExcessLoop stash, drop some of them
        self.drop_excessed_loop(simgr)

        # Log information about the unconstrained stash
        self.manage_unconstrained(simgr)

        # Take back state from ExcessStep stash if active stash is empty
        self.excessed_step_to_active(simgr)

        # Take back state from ExcessLoop stash if active stash is empty
        self.excessed_loop_to_active(simgr)


    def complete(self, simgr):
        self.deadended = len(simgr.deadended)
        elapsed_time = timer.time() - self.start_time
        if elapsed_time > self.timeout:
            self.log.info("Timeout expired for simulation !")
        if not (len(simgr.active) > 0 and self.deadended < self.max_end_state):
            self.log.info("len(simgr.active) <= 0 or deadended >= self.max_end_state)")
        if True:
            vmem = psutil.virtual_memory()
            if vmem.percent > 97:
                # TODO return in logs file the malware hash
                self.log.info("Memory limit reach")
                return True
        return elapsed_time > self.timeout or (
            len(simgr.active) <= 0 or self.deadended >= self.max_end_state
        )
