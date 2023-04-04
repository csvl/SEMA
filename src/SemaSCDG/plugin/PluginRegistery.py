import angr


class PluginRegistery(angr.SimStatePlugin):
    def __init__(self):
        super(PluginRegistery, self).__init__()
        self.last_error = 0
        self.registery_block = 0
        self.registery = {}
        self.stop_flag = False

    def setup_plugin(self):
        # For locale info mainly
        self.registery_block = self.state.heap.malloc(32767) 
        for i in range(32767):
            c = self.state.solver.BVS("c_registery_block{}".format(i), 8)
            self.state.memory.store(self.registery_block + i, c)

    # TODO improve
    def ending_state(self, simgr):
        total_registery = {}
        for sstate in simgr.deadended + simgr.active + simgr.stashes["pause"]:
            for key in sstate.plugin_registery.registery.keys():
                if key not in total_registery:
                    total_registery[key] = []
                    if sstate.plugin_registery.registery[key] not in total_registery[key]:
                        total_registery[key].append(sstate.plugin_registery.registery[key])
                else:
                    if sstate.plugin_registery.registery[key] not in total_registery[key]:
                        total_registery[key].append(sstate.plugin_registery.registery[key])
        return total_registery
    
    @angr.SimStatePlugin.memo
    def copy(self, memo):
        p = PluginRegistery()
        p.last_error = self.last_error
        p.registery_block = self.registery_block
        p.registery = self.registery.copy()
        p.stop_flag = self.stop_flag
        return p
