#!/usr/bin/env python3
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))


class PluginCommands:
    def __init__(self):
        pass

    def merge(self,calls,new_calls):
        for call in new_calls:
            if call not in calls:
                calls.append(call)
        return calls

    def track(self, simgr,scdg,exp_dir):
        not_interesting = ["CopyHook","HeapAlloc","HeapFree","GetProcessHeap","UserHook","VirtualFree","HeapReAlloc","VirtualAlloc","lstrlenA","lstrlenW","strlen","lstrcpyA","lstrcpyW","strncpy","lstrcatA","lstrcatW","lstrcmpA","lstrcmpW","strcmp","strncmp","wsprintfA","wsprintfW"]
        buffers = {}
        for state in simgr.deadended + simgr.stashes["pause"]:
            for key, symbol in state.solver.get_variables("buffer"):
                buf = hex(state.solver.eval(symbol))
                if buf != "0x0":
                    calls = []
                    flag = False
                    for dic in scdg[state.globals["id"]]:
                        if dic["name"] == "recv":
                            flag = True
                        if flag and dic["name"] not in not_interesting:
                            calls.append(dic["name"])
                    if buf not in buffers:
                        buffers[buf] = calls
                    else:
                        buffers[buf] = self.merge(buffers[buf],calls)

        f = open(exp_dir + "commands.log", 'w')
        for i in buffers:
            f.write("* " + i + '\n')
            for j in buffers[i]:
                f.write('        - ' + j + '\n')
