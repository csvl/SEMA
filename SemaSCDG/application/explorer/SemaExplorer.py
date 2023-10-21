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

# (1) TODO manon: better integration with angr
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

        #TODO Christophe : check config files -> good ? 
        self.memory_limit = config['explorer_arg'].getboolean('memory_limit')
        self.verbose = config['explorer_arg'].getboolean('verbose')
        self.eval_time = config['explorer_arg'].getboolean('eval_time')
        self.runtime_run_thread = config['explorer_arg'].getboolean('runtime_run_thread')
        #self._max_length = int(config['explorer_arg']['max_length'])
        self.timeout = int(config['explorer_arg']['timeout'])
        self.max_end_state = int(config['explorer_arg']['max_end_state'])
        self.max_step = int(config['explorer_arg']['max_step'])
        self.jump_it = int(config['explorer_arg']['jump_it'])
        self.loop_counter_concrete = int(config['explorer_arg']['loop_counter_concrete'])
        self.max_simul_state = int(config['explorer_arg']['max_simul_state'])
        self.max_in_pause_stach = int(config['explorer_arg']['max_in_pause_stach'])
        self.timeout_tab = config['explorer_arg']['timeout_tab']
        self.start_time = timer.time()
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

        self.pause_stash = "pause"
        self.new_addr_stash = "new_addr"
        self.excessLoop_stash = "ExcessLoop"
        self.excessStep_stash = "ExcessStep"
        self.deadbeef_stash = "deadbeef"
        self.lost_stash = "lost"

        self.exp_dir = exp_dir
        self.nameFileShort = nameFileShort
        self.time_id = 0

        self.scdg_graph = scdg_graph
        self.call_sim = call_sim
        
        self.jump_dict = {}
        self.jump_concrete_dict = {}
        self.jump_dict[0] = {}
        self.jump_concrete_dict[0] = {}
        
        self.scdg_fin = []
        self.dict_addr_vis = {}
        

    def setup(self, simgr):
        # The stash where states are moved to wait
        # until some space becomes available in Active stash.
        # The size of the space in this stash is a parameter of
        # the toolchain. If new states appear and there is no
        # space available in the Pause stash, some states are
        # dropped.
        if self.pause_stash not in simgr.stashes:
            simgr.stashes[self.pause_stash] = []

        # The stash where states leading to new
        # instruction addresses (not yet explored) of the binary
        # are kept. If CDFS or CBFS are not used, this stash
        # merges with the pause stash.
        if self.new_addr_stash not in simgr.stashes:
            simgr.stashes[self.new_addr_stash] = []


        # The stash where states which exceed the
        # threshold related to loops are moved. If new states
        # are needed and there is no state available in pause
        # or ExcessStep stash, states in this stash are used to
        # resume exploration (their loop counter are put back
        # to zero).
        if self.excessLoop_stash not in simgr.stashes:
            simgr.stashes[self.excessLoop_stash] = []

        # The stash where states exceeding the
        # threshold related to number of steps are moved. If
        # new states are needed and there is no state available
        # in pause stash, states in this stash are used to resume
        # exploration (their step counter are put back to zero).
        if self.excessStep_stash not in simgr.stashes:
            simgr.stashes[self.excessStep_stash] = []

        if self.deadbeef_stash not in simgr.stashes:
            simgr.stashes[self.deadbeef_stash] = []

        if self.lost_stash not in simgr.stashes:
            simgr.stashes[self.lost_stash] = []

        simgr.active[0].globals["id"] = 0
        simgr.active[0].globals["JumpExcedeed"] = False
        simgr.active[0].globals["JumpTable"] = {}
        simgr.active[0].globals["n_steps"] = 0
        simgr.active[0].globals["n_forks"] = 0
        simgr.active[0].globals["last_instr"] = 0
        simgr.active[0].globals["counter_instr"] = 0
        simgr.active[0].globals["loaded_libs"] = {}
        simgr.active[0].globals["addr_call"] = []
        simgr.active[0].globals["loop"] = 0
        simgr.active[0].globals["crypt_algo"] = 0
        simgr.active[0].globals["crypt_result"] = 0
        simgr.active[0].globals["n_buffer"] = 0
        simgr.active[0].globals["n_calls"] = 0
        simgr.active[0].globals["recv"] = 0
        simgr.active[0].globals["rsrc"] = 0
        simgr.active[0].globals["resources"] = {}
        simgr.active[0].globals["df"] = 0
        simgr.active[0].globals["files"] = {}
        simgr.active[0].globals["n_calls_recv"] = 0
        simgr.active[0].globals["n_calls_send"] = 0
        simgr.active[0].globals["n_buffer_send"] = 0
        simgr.active[0].globals["buffer_send"] = []
        simgr.active[0].globals["files"] = {}
        simgr.active[0].globals["FindFirstFile"] = 0
        simgr.active[0].globals["FindNextFile"] = 0
        simgr.active[0].globals["GetMessageA"] = 0
        simgr.active[0].globals["GetLastError"] = claripy.BVS("last_error", 32)
        simgr.active[0].globals["HeapSize"] = {}
        simgr.active[0].globals["CreateThread"] = 0
        simgr.active[0].globals["CreateRemoteThread"] = 0
        simgr.active[0].globals["condition"] = ""
        simgr.active[0].globals["files_fd"] = {}
        simgr.active[0].globals["create_thread_address"] = []
        simgr.active[0].globals["is_thread"] = False
        simgr.active[0].globals["recv"] = 0
        simgr.active[0].globals["allow_web_interaction"] = False
        if self.runtime_run_thread:
            simgr.active[0].globals["is_thread"] = True

    def _filter(self, s):
        return True  # s.history.block_count > self._max_length

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

    def mv_bad_active(self, simgr):
        """
        Take simulation manager and discard states that :
         - Exceed max number of step
         - Execute too many times a simple loop
        """
        # Discard Loop without symbolic variable which takes too much time
        for state in simgr.active:
            test = str(state.history.jump_target) + "-" + str(state.history.jump_source)
           
            #backwards = state.solver.eval(state.history.jump_target) - state.solver.eval(state.history.jump_source) < 0
            if test in self.jump_concrete_dict[state.globals["id"]]:
                self.jump_concrete_dict[state.globals["id"]][test] += 1
            else:
                state.globals["previous_regs"] = state.regs
                self.jump_concrete_dict[state.globals["id"]][test] = 1

            if (
                self.jump_concrete_dict[state.globals["id"]][test]
                > self.loop_counter_concrete
            ):
                # import pdb; pdb.set_trace()
                # state.history.trim()
                self.jump_concrete_dict[state.globals["id"]][test] = 0
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
                
            # TODO check seems new
            if state.globals["loop"] > 3:
                simgr.move(
                    from_stash="active",
                    to_stash="ExcessLoop",
                    filter_func=lambda s: s.globals["id"] == state.globals["id"],
                )
                self.log.info("A state has been discarded because of 1 loop reached")

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

    def step(self, simgr, stash="active", **kwargs):
        raise NotImplementedError()

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
            
    def manage_lost(self, simgr):
        simgr.move(
            from_stash="active",
            to_stash="lost" ,#"lost", deadended
            filter_func=lambda s: s.addr < simgr._project.loader.main_object.mapped_base,
        )
        
    def manage_end_thread(self, simgr):
        simgr.move(
            from_stash="active",
            to_stash="deadbeef",
            filter_func=lambda s: s.addr == 0xdeadbeef,
        )
        
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
            for i in range(len(self.loopBreak_stack)):
                self.log.info("A state has been discarded because of jump")
                guilty_state_id, addr = self.loopBreak_stack.pop()
                self.log.info(hex(addr))
                simgr.move(
                    "active", "ExcessLoop", lambda s: s.globals["id"] == guilty_state_id
                )

    def time_evaluation(self, simgr):
        ######################################
        #######     Timeout reached ?  #######
        ######################################
        if self.eval_time:
            new = "deadended"
            for stateDead in simgr.deadended:
                self.scdg_graph[stateDead.globals["id"]][0]["ret"] = new
                self.scdg_fin.append(self.scdg_graph[stateDead.globals["id"]])
            new = "active"
            for state in simgr.active:
                self.scdg_graph[state.globals["id"]][0]["ret"] = new
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])
            new = "errored"
            for error in simgr.errored:
                state = error.state
                self.scdg_graph[state.globals["id"]][0]["ret"] = new
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])
            new = "ExcessLoop"
            for state in simgr.stashes["ExcessLoop"]:
                self.scdg_graph[state.globals["id"]][0]["ret"] = new
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])
            new = "ExcessStep"
            for state in simgr.stashes["ExcessStep"]:
                self.scdg_graph[state.globals["id"]][0]["ret"] = new
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])
            new = "unconstrained"
            for state in simgr.unconstrained:
                self.scdg_graph[state.globals["id"]][0]["ret"] = new
                self.scdg_fin.append(self.scdg_graph[state.globals["id"]])

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

    def manage_deadended(self, simgr):
        if len(simgr.deadended) > self.deadended:
            to_clean = len(simgr.deadended) - self.deadended
            for i in range(to_clean):
                simgr.deadended[-i - 1].globals["id"]
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
                        #sys.exit(0)

                    self.scdg_graph.append(self.scdg_graph[prev_id].copy())
                    self.scdg_graph[-1][0] = self.scdg_graph[prev_id][0].copy()

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
