#!/usr/bin/env python3
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

import time as timer
#import monkeyhex  # this will format numerical results in hexadecimal
import logging
from collections import deque
import angr, claripy
import psutil
import configparser
import sys
import os
import json

from angr.exploration_techniques import ExplorationTechnique

try:
    config = configparser.ConfigParser()
    config.read(sys.argv[1])

    log = logging.getLogger("SemaExplorer")
    log_level = os.environ["LOG_LEVEL"]
    log.setLevel(log_level)
except Exception as e:
    print("Error in SemaExplorer.py")
    print(e)

class SemaExplorer(ExplorationTechnique):
    """
    Manages the exploration of states during symbolic execution.

    This class defines methods for setting up exploration parameters, filtering states based on various criteria, and managing the exploration process, including handling timeouts and memory limits.
    """

    def __init__(self, simgr, exp_dir, nameFileShort, scdg_graph, call_sim):
        """
        Initializes the SemaExplorer for symbolic execution exploration.

        This class sets up parameters and data structures for symbolic execution exploration, including timeout, maximum steps, and state management.
        """
        super(SemaExplorer, self).__init__()

        self.log = log
        self.log_level = log_level

        self.start_time = timer.time()

        self.eval_time = config['explorer_arg'].getboolean('eval_time')
        #self._max_length = int(config['explorer_arg']['max_length'])
        self.timeout = int(config['explorer_arg']['timeout'])
        self.max_end_state = int(config['explorer_arg']['max_end_state'])
        self.max_step = int(config['explorer_arg']['max_step'])
        self.jump_it = int(config['explorer_arg']['jump_it'])
        self.loop_counter_concrete = int(config['explorer_arg']['loop_counter_concrete'])
        self.max_simul_state = int(config['explorer_arg']['max_simul_state'])
        self.max_in_pause_stach = int(config['explorer_arg']['max_in_pause_stach'])
        self.timeout_tab = json.loads(config['explorer_arg']['timeout_tab'])

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
        """
        Sets up the exploration parameters and state management for symbolic execution.

        This function initializes various global variables and stashes in the symbolic execution manager to manage states during exploration.
        """
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
        simgr.active[0].globals["is_thread"] = False
        simgr.active[0].globals["crypt_algo"] = 0
        simgr.active[0].globals["crypt_result"] = 0
        simgr.active[0].globals["n_buffer"] = 0
        simgr.active[0].globals["n_calls"] = 0
        simgr.active[0].globals["recv"] = 0
        simgr.active[0].globals["rsrc"] = 0
        simgr.active[0].globals["resources"] = {}
        simgr.active[0].globals["df"] = 0
        simgr.active[0].globals["n_calls_recv"] = 0
        simgr.active[0].globals["n_calls_send"] = 0
        simgr.active[0].globals["n_buffer_send"] = 0
        simgr.active[0].globals["buffer_send"] = []
        simgr.active[0].globals["FindFirstFile"] = 0
        simgr.active[0].globals["FindNextFile"] = 0
        simgr.active[0].globals["GetMessageA"] = 0
        simgr.active[0].globals["GetLastError"] = claripy.BVS("last_error", 32)
        simgr.active[0].globals["HeapSize"] = {}
        simgr.active[0].globals["files_fd"] = {}
        simgr.active[0].globals["create_thread_address"] = []
        simgr.active[0].globals["allow_web_interaction"] = False

    def filter(self, simgr, state, **kwargs):
        """
        Filters states during symbolic execution exploration.

        This function determines the appropriate stash for a state based on various criteria such as address, loop counters, step counts, and specific conditions, managing state transitions during exploration.
        Each time a new state is created, this function checks where the state has to go. Put the state in active stash by default
        """
        if state.addr < simgr._project.loader.main_object.mapped_base :
            return "lost"

        # Manage end thread state
        if state.addr == 0xdeadbeef:
            return "deadbeef"

        # If too many states are explored simulateously, put state into pause stash
        if len(simgr.active) > self.max_simul_state:
            return "pause"

        # if Execute too many times a simple loop
        test = f"{str(state.history.jump_target)}-{str(state.history.jump_source)}"
        if test in self.jump_concrete_dict[state.globals["id"]]:
            self.jump_concrete_dict[state.globals["id"]][test] += 1
        else:
            state.globals["previous_regs"] = state.regs
            self.jump_concrete_dict[state.globals["id"]][test] = 1

        if (self.jump_concrete_dict[state.globals["id"]][test] > self.loop_counter_concrete):
            self.jump_concrete_dict[state.globals["id"]][test] = 0
            return "ExcessLoop"

        # If execute too many steps
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

        return simgr.filter(state, **kwargs)

    def check_constraint(self, state, value):
        """
        Checks and evaluates constraints on a state.

        This function evaluates a constraint value in the context of a state, handling symbolic values and exceptions, and returning the evaluated value.
        """
        try:
            val = state.solver.eval_one(value)
            if hasattr(val, "to_claripy"):
                val = val.to_claripy()

        except Exception as e:
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
        if len(simgr.stashes[source_stash]) <= 0:
            return

        id_to_move = simgr.stashes[source_stash][0].globals["id"]
        min_step = simgr.stashes[source_stash][0].globals["n_steps"]
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
        if len(simgr.stashes[source_stash]) <= 0:
            return

        id_to_move = simgr.stashes[source_stash][0].globals["id"]
        max_step = simgr.stashes[source_stash][0].globals["n_steps"]
        for s in simgr.stashes[source_stash]:
            if s.globals["n_steps"] > max_step:
                id_to_move = s.globals["id"]
                max_step = s.globals["n_steps"]

        simgr.move(source_stash, "active", lambda s: s.globals["id"] == id_to_move)

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
                elif found:
                    return state, first_state
                # Case 3 : First state of stash IS a jumpExcedeed !
                elif state.globals["JumpExcedeed"]:
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

    def step(self, simgr, stash="active", **kwargs):
        raise NotImplementedError()

    def build_snapshot(self, simgr):
        """
        Builds a snapshot of the current state during symbolic execution.

        This function clears the existing snapshot state, updates the state information, and increments the step count for each active state in the symbolic execution manager.
        """
        self.snapshot_state.clear()
        for state in simgr.active:
            if state.globals["id"] in self.snapshot_state:
                self.fork_stack.append(state.globals["id"])
                self.snapshot_state[state.globals["id"]] += 1
            else:
                self.snapshot_state[state.globals["id"]] = 1
            state.globals["n_steps"] += 1

    def manage_unconstrained(self, simgr):
        """
        Manages unconstrained states during symbolic execution.

        This function tracks and logs the unconstrained states in the symbolic execution manager, providing information about the end of each unconstrained trace.
        """
        if len(simgr.unconstrained) > self.unconstrained:
            new_unconstrained = len(simgr.unconstrained) - self.unconstrained
            for _ in range(new_unconstrained):
                id_cur = simgr.unconstrained[-1].globals["id"]
                self.log.info(f"End of the trace number {str(id_cur)} unconstrained")
            self.unconstrained = len(simgr.unconstrained)

    def manage_error(self, simgr):
        """
        Manages and logs errors encountered during symbolic execution.

        This function compares the number of errors in the symbolic execution manager with the stored count of errors, logs information about each new error, and updates the error count.
        """
        if len(simgr.errored) > self.errored:
            new_errors = len(simgr.errored) - self.errored
            for i in range(new_errors):
                id_cur = simgr.errored[-i - 1].state.globals["id"]
                self.log.info(f"End of the trace number {str(id_cur)} with errors")
                self.log.info(simgr.errored[-i - 1].state)
                self.log.info(simgr.errored[-i - 1].error)
            self.errored = len(simgr.errored)

    def drop_excessed_loop(self, simgr):
        """
        Drops excessed loop states from the symbolic execution manager.

        This function calculates the number of excess loop states to drop based on a threshold, selects the states to drop from the "ExcessLoop" stash, and removes them from the symbolic execution manager.
        """
        excess_loop = len(simgr.stashes["ExcessLoop"]) - (self.max_in_pause_stach / 5)
        excess_loop = int(excess_loop)  # TODO chris check where we round (up-down)
        if excess_loop > 0:
            state_to_stash = simgr.stashes["ExcessLoop"][-excess_loop:]
            id_to_stash = [t.globals["id"] for t in state_to_stash]
            simgr.drop(filter_func=lambda s: s.globals["id"] in id_to_stash, stash="ExcessLoop")

    def excessed_step_to_active(self, simgr):
        """
        Moves excessed step states to the active stash for further exploration.

        This function transfers states from the "ExcessStep" stash to the active stash if the active stash is empty and there are states in the "ExcessStep" stash, resetting the step count for the moved states.
        """
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
        """
        Moves excessed loop states to the active stash for further exploration and manages the number of states in the pause stash.

        This function transfers states from the "ExcessLoop" stash to the active stash if the active stash is empty and there are states in the "ExcessLoop" stash, resetting certain state attributes. It also checks and discards excess states from the pause stash if the number of states exceeds a specified threshold.
        """
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
            simgr.move(
                from_stash="ExcessLoop",
                to_stash="active",
                filter_func=lambda s: s.globals["id"] in id_move,
            )

        # If there is too much states in pause stash, discard some of them
        excess_pause = len(simgr.stashes["pause"]) - self.max_in_pause_stach
        if excess_pause > 0:
            state_to_stash = simgr.pause[-excess_pause:]
            id_to_stash = [t.globals["id"] for t in state_to_stash]
            simgr.drop(
                filter_func=lambda s: s.globals["id"] in id_to_stash, stash="pause"
            )

    def remove_exceeded_jump(self, simgr):
        """
        Removes states with exceeded jumps from the active stash.

        This function checks for states in the loopBreak_stack indicating exceeded jumps, logs information about the discarded states, and moves these states from the active stash to the "ExcessLoop" stash based on the guilty state ID.
        """
        if len(self.loopBreak_stack) > 0:
            for i in range(len(self.loopBreak_stack)):
                self.log.info("A state has been discarded because of jump")
                guilty_state_id, addr = self.loopBreak_stack.pop()
                self.log.info(hex(addr))
                simgr.move(
                    "active", "ExcessLoop", lambda s: s.globals["id"] == guilty_state_id
                )

    def time_evaluation(self, simgr):
        """
        Evaluates states based on time constraints during symbolic execution.

        This function processes states based on time evaluation criteria, updating the state information in the SCFG graph and saving the results to files if the time evaluation conditions are met.
        """
        if not self.eval_time:
            return
        for new in ["deadended", "active", "errored", "Excessloop", "ExcessStep", "unconstrained"]:
            for state in simgr.stashes[new]:
                if new == "errored":
                    state = state.state
                self.scdg_graph[state.globals["id"]][0]["ret"] = new
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])

        if self.time_id >= len(self.timeout_tab):
            self.log.info("All timeouts were tested !")
        else:
            with open(self.exp_dir + self.nameFileShort + "_SCDG_" + str(self.timeout_tab[self.time_id]) + ".txt","w",) as save_SCDG:
                for s in self.scdg_fin:
                    save_SCDG.write(str(s) + "\n")
            self.scdg_fin.clear()
            self.time_id = self.time_id + 1

    def manage_deadended(self, simgr):
        """
        Manages states that have reached a dead-ended state during symbolic execution.

        This function tracks and updates the count of dead-ended states in the symbolic execution manager, ensuring proper management of these states.
        """
        if len(simgr.deadended) > self.deadended:
            to_clean = len(simgr.deadended) - self.deadended
            for i in range(to_clean):
                simgr.deadended[-i - 1].globals["id"]
            self.deadended = len(simgr.deadended)

    def check_fork_split(self, prev_id, found_jmp_table, state):
        """
        Checks and manages fork splits during symbolic execution.

        This function evaluates the fork split conditions based on the previous state ID, jump table presence, and concrete targets, updating state attributes and managing exceeded jumps by adding states to the loopBreak_stack.
        """
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
                    self.loopBreak_stack.append((state.globals["id"],state.scratch.ins_addr,))

    def manage_fork(self, simgr):
        """
        Manages forked states during symbolic execution.

        This function processes and updates forked states, handling the creation of new states, managing state IDs, and checking for jump tables to handle forked states appropriately.
        """
        if len(self.fork_stack) <= 0:
            return
        for _ in range(len(self.fork_stack)):
            prev_id = self.fork_stack.pop()
            self.id = self.id + 1  # id for the new state

            # TODO true and false branch ? is it an IF statement here ?
            state_fork1, state_fork2 = self.__update_id_stash(simgr, prev_id, self.id)
            if (state_fork1 and state_fork2 and state_fork1.globals["id"] != state_fork2.globals["id"]):
                if state_fork2.globals["id"] != self.id:
                    self.log.warning("Something bad happend after update_id_stash, ids are messed up")

                self.scdg_graph.append(self.scdg_graph[prev_id].copy())
                self.scdg_graph[-1][0] = self.scdg_graph[prev_id][0].copy()

                self.jump_dict[self.id] = self.jump_dict[prev_id].copy()
                self.jump_concrete_dict[self.id] = self.jump_concrete_dict[prev_id].copy()

                # Check if there is a jump table ('fork implying more than two states')
                found_jmp_table = self.snapshot_state[prev_id] > 1

                # Manage jump of first state
                self.check_fork_split(prev_id, found_jmp_table, state_fork2)

                # Manage jump of second state
                self.check_fork_split(prev_id, found_jmp_table, state_fork1)
            else:
                self.id = self.id - 1

    def complete(self, simgr):
        """
        Checks if the symbolic execution is finished by checking the timeout value, the number of state in the active stash and the number of state in the deadended stash
        """
        self.deadended = len(simgr.deadended)
        elapsed_time = timer.time() - self.start_time
        if elapsed_time > self.timeout:
            self.log.info("Timeout expired for simulation !")
        if len(simgr.active) <= 0 or self.deadended >= self.max_end_state:
            self.log.info("len(simgr.active) <= 0 or deadended >= self.max_end_state)")
        vmem = psutil.virtual_memory()
        if vmem.percent > 97:
            # TODO return in logs file the malware hash
            self.log.info("Memory limit reach")
            return True
        return elapsed_time > self.timeout or (
            len(simgr.active) <= 0 or self.deadended >= self.max_end_state
        )
