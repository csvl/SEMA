#!/usr/bin/env python3
import time as timer
import sys
import logging
from collections import deque
from angr.exploration_techniques import ExplorationTechnique
import psutil

class ToolChainExplorer(ExplorationTechnique):
    """
    TODO
    """

    def __init__(
        self,
        simgr,
        max_length,
        exp_dir,
        nameFileShort,
        worker
    ):
        #TODO refactor
        super(ToolChainExplorer, self).__init__()
        self._max_length = max_length
        self.worker = worker
        self.timeout = worker.timeout
        self.jump_it = worker.jump_it
        self.timeout_tab = worker.timeout_tab

        self.start_time = timer.time()
        self.log = logging.getLogger("ToolChainExplorer")
        self.log.setLevel("INFO")

        self.max_end_state = worker.max_end_state
        self.errored = 0
        self.unconstrained = 0
        self.deadended = 0
        self.active = 1
        self.id = 0
        self.snapshot_state = {}
        self.fork_stack = deque()
        self.pause_stash = simgr.stashes["pause"]
        self.exp_dir = exp_dir
        self.nameFileShort = nameFileShort
        self.eval_time = worker.eval_time
        self.time_id = 0
        self.print_sm_step = True

        self.loopBreak_stack = deque()
        self.jump_concrete_dict = worker.jump_concrete_dict
        self.jump_dict = worker.jump_dict
        self.jump_dict[0] = {}
        self.jump_concrete_dict[0] = {}
        self.loop_counter_concrete = worker.loop_counter_concrete
        self.max_step = worker.max_step
        self.max_simul_state = worker.max_simul_state
        self.max_in_pause_stach = worker.max_in_pause_stach

        self.scdg = worker.scdg
        self.scdg_fin = [] # TODO from main 
        self.dict_addr_vis = {}

        self.print_on = worker.print_on
        self.print_sm_step = worker.print_sm_step
        self.print_syscall = worker.print_syscall
        self.debug_error = worker.debug_error

        self.loopBreak_stack = deque()

        self.call_sim = worker.call_sim

        self.expl_method = "DFS"
        self.memory_limit = worker.memory_limit

    def _filter(self, s):
        return True  

    def check_constraint(self, state, value):
        try:
            val = state.solver.eval_one(value)
            is_sao = hasattr(val, "to_claripy")
            if is_sao:
                val = val.to_claripy()

        except Exception:
            if self.print_on:
                self.log.info("Symbolic value encountered !")
            return value
        return val

    def __proper_formating(self, state, value):
        """
        Take a state and a value (argument/return value) and return an appropriate reprensentation to use in SCDG.
        """
        if hasattr(value, "to_claripy"):
            value = value.to_claripy()

        if hasattr(value, "symbolic") and value.symbolic and hasattr(value, "name"):
            # self.log.info("case 1 formating")
            return value.name
        elif (
            hasattr(value, "symbolic") and value.symbolic and len(value.variables) == 1
        ):
            # import pdb; pdb.set_trace()
            # self.log.info("case 2 formating")
            # self.log.info(value.variables)

            return list(value.variables)[0]
        elif hasattr(value, "symbolic") and value.symbolic:
            # self.log.info('case 3 : multiple variables involved')
            # TODO improve this
            ret = "_".join(list(value.variables))

            return ret
        else:
            # self.log.info("case 4 formating")
            try:
                val = state.solver.eval_one(value)
                return val
            except:
                return value

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

    def __take_custom(self, simgr, source_stash, moves):
        """
        Take a state of source_stash with smallest amount of steps and append it to active stash
        @pre : source_stash exists
        """
        id_to_move = 0
        if len(simgr.stashes[source_stash]) == 0:
            return

        for s in simgr.stashes[source_stash]:
            if (
                str(self.check_constraint(s, s.history.jump_target))
                not in self.dict_addr_vis
            ):
                id_to_move = s.globals["id"]
                simgr.move(
                    source_stash, "active", lambda s: s.globals["id"] == id_to_move
                )
                # self.log.info('optimization for exploration used')
                return
        self.take_smallest(simgr, source_stash)

    def __take_custom_deep(self, simgr, source_stash):
        id_to_move = 0
        if len(simgr.stashes[source_stash]) == 0:
            return

        for s in simgr.stashes[source_stash]:
            if (
                str(self.check_constraint(s, s.history.jump_target))
                not in self.dict_addr_vis
            ):
                id_to_move = s.globals["id"]
                simgr.move(
                    source_stash, "active", lambda s: s.globals["id"] == id_to_move
                )
                # self.log.info('optimization for exploration used')
                return
        self.take_longuest(simgr, source_stash)

    def __change_main_state(self, simgr, source_stash):
        """
        Take a state of source_stash and append it to active stash
        @pre : source_stash exists
        """
        if len(simgr.stashes[source_stash]) > 0:
            simgr.stashes["active"].append(simgr.stashes[source_stash].pop())

    def mv_bad_active(self, simgr):
        """
        Take simulation manager and discard states that :
         - Exceed max number of step
         - Execute too many times a simple loop
        """
        # Discard Loop without symbolic variable which takes too much time
        for state in simgr.active:
            test = str(state.history.jump_target) + "-" + str(state.history.jump_source)
            if test in self.jump_concrete_dict[state.globals["id"]]:
                self.jump_concrete_dict[state.globals["id"]][test] += 1
            else:
                self.jump_concrete_dict[state.globals["id"]][test] = 1

            if (
                self.jump_concrete_dict[state.globals["id"]][test]
                > self.loop_counter_concrete
            ):
                # import pdb; pdb.set_trace()
                # state.history.trim()
                simgr.move(
                    from_stash="active",
                    to_stash="ExcessLoop",
                    filter_func=lambda s: s.globals["id"] == state.globals["id"],
                )

                self.log.info("A state has been discarded because of simple loop")

            if state.globals["n_steps"] % 1000 == 0:
                self.log.debug("n_steps = " + str(state.globals["n_steps"]))

            if state.globals["n_steps"] > self.max_step:
                # import pdb; pdb.set_trace()
                state.history.trim()
                simgr.move(
                    from_stash="active",
                    to_stash="ExcessStep",
                    filter_func=lambda s: s.globals["id"] == state.globals["id"],
                )
                self.log.info("A state has been discarded because of max_step reached")

    def __mv_new_addr_state(self, simgr):
        """
        Check new_addr stash and update it correctly
        """
        for s in simgr.stashes["new_addr"]:
            if (
                str(self.check_constraint(s, s.history.jump_target))
                in self.dict_addr_vis
            ):
                id_to_move = s.globals["id"]
                simgr.move("new_addr", "pause", lambda s: s.globals["id"] == id_to_move)
                # self.log.info('optimization for exploration used')
                return

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

    # Break at specific instruction and open debug mode.
    def __debug_instr(self, state):
        if state.inspect.instruction == int(
            "0x0040123f", 16
        ) or state.inspect.instruction == int("0x0040126e", 16):
            self.log.info("Debug function\n\n")
            self.log.info(hex(state.inspect.instruction))
            import pdb
            pdb.set_trace()

    def __debug_read(self, state):
        if state.solver.eval(state.inspect.mem_read_address) == int("0xf404120", 16):
            self.log.info("Read function\n\n")
            self.log.info(state.inspect.mem_read_address)
            import pdb
            pdb.set_trace()

    def __debug_write(self, state):
        if state.solver.eval(state.inspect.mem_write_address) == int("0xf404120", 16):
            self.log.info("Write function\n\n")
            self.log.info(state.inspect.mem_write_address)
            import pdb

            pdb.set_trace()

    def __add_addr_call(self, state):
        test = state.globals["addr_call"] + [state.scratch.ins_addr]
        state.globals["addr_call"] = test

    def __rm_addr_call(self, state):
        calls = state.globals["addr_call"]
        if len(calls) > 1:
            state.globals["addr_call"] = calls[1:]

    def step(self, simgr, stash="active", **kwargs):
        pass

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
                self.log.info(
                    "End of the trace number " + str(id_cur) + " unconstrained"
                )
            self.unconstrained = len(simgr.unconstrained)

    def manage_error(self, simgr):
        if len(simgr.errored) > self.errored:
            new_errors = len(simgr.errored) - self.errored
            self.log.info(simgr.errored)
            for i in range(new_errors):
                id_cur = simgr.errored[-i - 1].state.globals["id"]
                self.log.info("End of the trace number " + str(id_cur) + " with errors")
                simgr.errored[-i - 1]
                if self.debug_error:
                    # import pdb
                    # pdb.set_trace()
                    # last_error.debug()
                    pass
            self.errored = len(simgr.errored)

    def drop_excessed_loop(self, simgr):
        excess_loop = len(simgr.stashes["ExcessLoop"]) - (self.max_in_pause_stach / 5)
        excess_loop = int(excess_loop)  # TODO chris check how we round (up-down)
        if excess_loop > 0:
            id_to_stash = []
            # print(excess_loop)
            state_to_stash = simgr.stashes["ExcessLoop"][-excess_loop:]
            for t in state_to_stash:
                id_to_stash.append(t.globals["id"])
            simgr.drop(
                filter_func=lambda s: s.globals["id"] in id_to_stash, stash="ExcessLoop"
            )

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
            simgr.move(
                from_stash="ExcessLoop",
                to_stash="active",
                filter_func=lambda s: s.globals["id"] in id_move,
            )

    def manage_pause(self, simgr):
        # If too many states are explored simulateously, move some of them to pause stash.
        if len(simgr.active) > self.max_simul_state:
            excess = len(simgr.active) - self.max_simul_state
            state_to_stash = simgr.active[-excess:]
            id_to_stash = []
            for t in state_to_stash:
                id_to_stash.append(t.globals["id"])
            simgr.move(
                from_stash="active",
                to_stash="pause",
                filter_func=lambda s: s.globals["id"] in id_to_stash,
            )

            # If there is too much states in pause stash, discard some of them
        excess_pause = len(simgr.stashes["pause"]) - self.max_in_pause_stach
        if excess_pause > 0:
            id_to_stash = []
            state_to_stash = simgr.pause[-excess_pause:]
            for t in state_to_stash:
                id_to_stash.append(t.globals["id"])
            simgr.drop(
                filter_func=lambda s: s.globals["id"] in id_to_stash, stash="pause"
            )

    def remove_exceeded_jump(self, simgr):
        if len(self.loopBreak_stack) > 0:
            # if PRINT_ON :
            #    self.log.info('Length of LoopBreaker Stack at this step: '+  str(len(self.loopBreak_stack)))
            for i in range(len(self.loopBreak_stack)):
                guilty_state_id, addr = self.loopBreak_stack.pop()
                simgr.move(
                    "active", "ExcessLoop", lambda s: s.globals["id"] == guilty_state_id
                )

    def time_evaluation(self, simgr):
        ######################################
        #######     Timeout reached ?  #######
        ######################################
        if self.eval_time:
            new = "deadendend"
            for stateDead in simgr.deadended:
                self.scdg[stateDead.globals["id"]][0]["ret"] = new
                self.scdg_fin.append(self.scdg[stateDead.globals["id"]])
            new = "active"
            for state in simgr.active:
                self.scdg[state.globals["id"]][0]["ret"] = new
                self.scdg_fin.append(self.scdg[state.globals["id"]])
            new = "errored"
            for error in simgr.errored:
                state = error.state
                self.scdg[state.globals["id"]][0]["ret"] = new
                self.scdg_fin.append(self.scdg[state.globals["id"]])
            new = "ExcessLoop"
            for state in simgr.stashes["ExcessLoop"]:
                self.scdg[state.globals["id"]][0]["ret"] = new
                self.scdg_fin.append(self.scdg[state.globals["id"]])
            new = "ExcessStep"
            for state in simgr.stashes["ExcessStep"]:
                self.scdg[state.globals["id"]][0]["ret"] = new
                self.scdg_fin.append(self.scdg[state.globals["id"]])
            new = "unconstrained"
            for state in simgr.unconstrained:
                self.scdg[state.globals["id"]][0]["ret"] = new
                self.scdg_fin.append(self.scdg[state.globals["id"]])

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
            if self.time_id >= len(self.timeout_tab):
                self.log.info("All timeouts were tested !\n\n\n")
        else:
            pass

    def manage_deadended(self, simgr):
        if len(simgr.deadended) > self.deadended:
            to_clean = len(simgr.deadended) - self.deadended
            for i in range(to_clean):
                simgr.deadended[-i - 1].globals["id"]
                # if PRINT_ON:
                #    self.log.info("End of the trace number "+str(id_cur))
            self.deadended = len(simgr.deadended)

    def manage_fork(self, simgr):
        if len(self.fork_stack) > 0:
            for i in range(len(self.fork_stack)):
                prev_id = self.fork_stack.pop()
                self.id = self.id + 1  # id for the new state

                # TODO true and false branch ? is it an IF statement here ?
                state_fork1, state_fork2 = self.__update_id_stash(
                    simgr, prev_id, self.id
                )
                # Check if there is a jump table ('fork implying more than two states')
                found_jmp_table = self.snapshot_state[prev_id] > 1

                if (
                    state_fork1
                    and state_fork2
                    and state_fork1.globals["id"] != state_fork2.globals["id"]
                ):
                    if state_fork2.globals["id"] != self.id:
                        self.log.warning(
                            "Something bad happend after update_id_stash, ids are messed up"
                        )
                        sys.exit(0)

                    self.scdg.append(self.scdg[prev_id].copy())
                    self.scdg[-1][0] = self.scdg[prev_id][0].copy()

                    self.jump_dict[self.id] = self.jump_dict[prev_id].copy()
                    self.jump_concrete_dict[self.id] = self.jump_concrete_dict[
                        prev_id
                    ].copy()

                    # Manage jump of first state
                    if found_jmp_table and prev_id == state_fork2.globals["id"]:
                        self.snapshot_state[prev_id] = self.snapshot_state[prev_id] - 1
                    else:
                        concrete_targ = (
                            str(state_fork2.history.jump_target)
                            + "-"
                            + str(state_fork2.history.jump_source)
                        )
                        if (
                            concrete_targ
                            not in self.jump_dict[state_fork2.globals["id"]]
                        ):
                            self.jump_dict[state_fork2.globals["id"]][concrete_targ] = 1
                        else:
                            self.jump_dict[state_fork2.globals["id"]][
                                concrete_targ
                            ] += 1
                            if (
                                self.jump_dict[state_fork2.globals["id"]][concrete_targ]
                                >= self.jump_it
                            ):
                                state_fork2.globals["JumpExcedeed"] = True
                                # new_state.history.trim()
                                self.loopBreak_stack.append(
                                    (
                                        state_fork2.globals["id"],
                                        state_fork2.scratch.ins_addr,
                                    )
                                )
                        # Manage jump of second state
                    if found_jmp_table and prev_id == state_fork1.globals["id"]:
                        self.snapshot_state[prev_id] = self.snapshot_state[prev_id] - 1
                    else:
                        concrete_targ = (
                            str(state_fork1.history.jump_target)
                            + "-"
                            + str(state_fork1.history.jump_source)
                        )

                        if (
                            concrete_targ
                            not in self.jump_dict[state_fork1.globals["id"]]
                        ):
                            self.jump_dict[state_fork1.globals["id"]][concrete_targ] = 1
                        else:
                            self.jump_dict[state_fork1.globals["id"]][
                                concrete_targ
                            ] += 1
                            if (
                                self.jump_dict[state_fork1.globals["id"]][concrete_targ]
                                >= self.jump_it
                            ):
                                state_fork1.globals["JumpExcedeed"] = True
                                # state1.history.trim()
                                self.loopBreak_stack.append(
                                    (
                                        state_fork1.globals["id"],
                                        state_fork1.scratch.ins_addr,
                                    )
                                )
                else:
                    self.id = self.id - 1

    def complete(self, simgr):
        elapsed_time = timer.time() - self.start_time

        if elapsed_time > self.timeout:
            self.log.info("Timeout expired for simulation !")

        if not (len(simgr.active) > 0 and self.deadended < self.max_end_state):
            self.log.info("sm.active.len > 0 and deadended < max_end_state")
        
        if self.memory_limit:
            vmem = psutil.virtual_memory()
            if vmem.percent > 90:
                # TODO return in logs file the malware hash
                self.log.info("Memory limit reach")
                return True

        return elapsed_time > self.timeout or (
            len(simgr.active) <= 0 or self.deadended >= self.max_end_state
        )
