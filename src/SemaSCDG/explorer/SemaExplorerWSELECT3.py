import logging
from numpy import random
from collections import defaultdict, deque
import sys

# from angr.exploration_techniques import ExplorationTechnique
from .SemaExplorer import SemaExplorer

l = logging.getLogger('syml')

syscalls_hunters = ['RegCreateKeyExA', 'RegCreateKeyExW', 'RegSetValueExA', 'RegSetValueExW', 'RegCreateKeyA', 'RegCreateKeyW', 'RegDeleteKeyA', 'RegDeleteKeyW', 'RegCloseKey', 'CreateToolhelp32Snapshot', 'CreateProcessA', 'CreateThread', 'CreateFileA', 'CreateFileW', 'OpenFile', 'DeleteFileA', 'DeleteFileW', 'OpenProcess', 'CreateRemoteThread', 'CreateRemoteThreadEx', 'WriteProcessMemory', 'ReadProcessMemory', 'NtOpenFile', 'NtCreateFile', 'NtRenameKey', 'WinExec', 'LookupPrivilegeValueA', 'LookupPrivilegeValueW', 'ExitWindowsEx', 'SetWindowsHookExA', 'SetWindowsHookExW', 'CallNextHookEx', 'UnhookWindowsHookEx', 'GetAsyncKeyState', 'GetKeyState', 'GetKeyboardState', 'CryptBinaryToStringW', 'CreateEventA', 'CreateEventW', 'CreateEventExA', 'CryptDecrypt', 'CryptEncrypt', 'CryptDecryptMessage', 'CryptEncryptMessage', 'socket', 'send', 'recv', 'listen', 'connect', 'bind', 'gethostbyname', 'gethostbyaddr', 'URLDownloadToFile', 'HttpOpenRequestA', 'HttpOpenRequestW', 'HttpSendRequestA', 'HttpSendRequestW', 'InternetConnectA', 'InternetConnectW', 'InternetCrackUrlA', 'InternetCrackUrlW', 'InternetOpenA', 'InternetOpenW', 'InternetOpenUrlA', 'InternetOpenUrlW', 'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'OutputDebugStringA', 'OutputDebugStringW', 'SecureZeroMemory', 'memcpy', 'wmemcpy', 'memcpy', 'wmemcpy', 'VirtualProtect', 'VirtualProtectEx', 'VirtualAlloc', 'VirtualAllocEx', 'VirtualQuery', 'VirtualQueryEx', 'LoadLibraryA', 'LoadLibraryW', 'LoadLibraryExA', 'LoadLibraryExW']

class SemaExplorerWSELECT3(SemaExplorer):
    """
    Stochastic Search.
    Will only keep one path active at a time, any others will be discarded.
    Before each pass through, weights are randomly assigned to each basic block.
    These weights form a probability distribution for determining which state remains after splits.
    When we run out of active paths to step, we start again from the start state.
    """

    def __init__(
        self,
        simgr,
        max_length,
        exp_dir,
        nameFileShort,
        worker
        # restart_prob=0.0001
    ):
        """
        :param start_state:  The initial state from which exploration stems.
        :param restart_prob: The probability of randomly restarting the search (default 0.0001).
        """
        super(SemaExplorerWSELECT3, self).__init__(
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
        self.start_state = simgr.one_active
        # self.restart_prob = restart_prob
        self._random = random.RandomState()
        # self.seed = 42
        # self._random.seed(self.seed)
        self.affinity = {}
        self.pause_stash = deque()
        # self.reset_stash = deque()
        self.log = logging.getLogger("SemaExplorerWSELECT3")
        self.log.setLevel("INFO")
        self.last_scdg = defaultdict(int)
        # self.discovery_counter = 0

    def step(self, simgr, stash='active', **kwargs):
        try:
            simgr = simgr.step(stash=stash, **kwargs)
        except Exception as inst:
            self.log.warning(inst)  # __str__ allows args to be printed directly,
            exc_type, exc_obj, exc_tb = sys.exc_info()
            # fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            self.log.warning(exc_type)
            self.log.warning(exc_obj,exc_type)
            #exit(-1)
            #raise Exception("ERROR IN STEP() - YOU ARE NOT SUPPOSED TO BE THERE !")

        super().build_snapshot(simgr)

        if self.print_sm_step and (
            len(self.fork_stack) > 0 or len(simgr.deadended) > self.deadended
        ):
            self.log.info(
                "A new block of execution have been executed with changes in sim_manager.\n"
            )
            self.log.info("Currently, simulation manager is :\n" + str(simgr))
            self.log.info("pause stash len :" + str(len(self.pause_stash)))

        if self.print_sm_step and len(self.fork_stack) > 0:
            self.log.info("fork_stack : " + str(len(self.fork_stack)) + " " + hex(simgr.active[0].addr) + " || " + hex(simgr.active[1].addr))

        # We detect fork for a state
        super().manage_fork(simgr)

        simgr.move(
            from_stash="active",
            to_stash="deadend",
            filter_func=lambda s: s.addr == 0xdeadbeef,
        )

        # Remove state which performed more jump than the limit allowed
        super().remove_exceeded_jump(simgr)

        super().manage_end_thread(simgr)
        
        super().manage_lost(simgr)

        # Manage ended state
        super().manage_deadended(simgr)

        for s in simgr.active:
            vis_addr = str(self.check_constraint(s, s.history.jump_target))
            id_to_stash = []
            if vis_addr not in self.dict_addr_vis:
                id_to_stash.append(s.globals["id"])
                simgr.stashes["covered_blocks"].append(s)
                simgr.stashes["new_addr"].append(s)

        super().mv_bad_active(simgr)
      
        def count_syscall(state):
            # return len(set([e["name"] for e in self.scdg[state.globals["id"]]]))/1000
            # sys_calls = set([e["name"] for e in self.scdg[state.globals["id"]]])
            sys_calls = [e["name"] for e in self.scdg[state.globals["id"]]]
            counter = 0
            for s in simgr.stashes["new_addr"]:
                if s.globals["id"] == state.globals["id"]:
                    counter += 2
                    break
            for c in sys_calls:
                if c in syscalls_hunters:
                    counter += 2
                else:
                    counter += 1
            return counter/1000
            
        def weighted_pick(states, n=1):
                """
                param states: Diverging states.
                """
                # import pdb; pdb.set_trace()
                if len(states) == 1:
                    return states

                for s in states:
                    # if s.globals["id"] not in self.affinity:
                    self.affinity[s.globals["id"]] = count_syscall(s)
                weights = []
                population = []
                for _, e in enumerate(states):
                    population.append(e)
                    # weights.append(self.affinity[e.globals["id"]])
                # import pdb; pdb.set_trace()
                # total_weight = sum(weights)
                # norm_weights = [w/total_weight for w in weights]
                if n > len(population):
                    n = len(population)
                # import pdb; pdb.set_trace()
                sorted_list = sorted(population, key=lambda x: self.affinity[x.globals["id"]], reverse=True)
                picked = sorted_list[:n]
                return picked

        if not simgr.active:
            if len(simgr.stashes["pause"]) > 0:
                the_chosen_ones = weighted_pick(simgr.stashes["pause"], self.max_simul_state) # Pick randomly states from pause stash
                simgr.move(
                    from_stash="pause",
                    to_stash="active",
                    filter_func=lambda s: s.globals["id"] in [elem.globals["id"] for elem in the_chosen_ones]
                )

        if (len(simgr.active) > self.max_simul_state
            # If limit of simultaneous state is exceeded
            or (len(simgr.stashes["pause"]) > 0 and len(simgr.active) < self.max_simul_state)):
            # If limit of simultaneous state is not reached and we have some states available in pause stash
            
            # import pdb; pdb.set_trace()
            simgr.move( # Move all state to pause stash
                from_stash="active",
                to_stash="pause",
                filter_func=lambda s: True
            )
            the_chosen_ones = weighted_pick(simgr.stashes["pause"], self.max_simul_state) # Pick randomly states from pause stash
            simgr.move(
                from_stash="pause",
                to_stash="active",
                filter_func=lambda s: s.globals["id"] in [elem.globals["id"] for elem in the_chosen_ones]
            )

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

        super().excessed_step_to_active(simgr)

        super().excessed_loop_to_active(simgr)

        super().time_evaluation(simgr)
        
        return simgr