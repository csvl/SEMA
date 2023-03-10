import angr


class PluginResources(angr.SimStatePlugin):
    def __init__(self):
        super(PluginResources, self).__init__()
        self.last_error = 0
        self.res_block = 0
        self.resources = {}
        self.stop_flag = False
       
    def setup_plugin(self):
        # For locale info mainly
        self.res_block = self.state.heap.malloc(32767) 
        for i in range(32767):
            c = self.state.solver.BVS("c_res_block{}".format(i), 8)
            self.state.memory.store(self.res_block + i, c)

    # TODO improve
    def ending_state(self, simgr):
        total_res = {}
        for sstate in simgr.deadended + simgr.active + simgr.stashes["pause"]:
            for key in sstate.plugin_resources.resources.keys():
                if key not in total_res:
                    total_res[key] = []
                    if sstate.plugin_resources.resources[key] not in total_res[key]:
                        total_res[key].append(sstate.plugin_resources.resources[key])
                else:
                    if sstate.plugin_resources.resources[key] not in total_res[key]:
                        total_res[key].append(sstate.plugin_resources.resources[key])
        return total_res
    
    @angr.SimStatePlugin.memo
    def copy(self, memo):
        p = PluginResources()
        p.last_error = self.last_error
        p.res_block = self.res_block
        p.resources = self.resources.copy()
        p.stop_flag = self.stop_flag
        return p
