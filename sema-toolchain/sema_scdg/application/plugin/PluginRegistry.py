import angr


class PluginRegistry(angr.SimStatePlugin):
    def __init__(self):
        super(PluginRegistry, self).__init__()
        self.last_error = 0
        self.registry_block = 0
        self.registry = {}
        self.stop_flag = False

    def setup_plugin(self):
        # For locale info mainly
        self.registry_block = self.state.heap.malloc(32767)
        for i in range(32767):
            c = self.state.solver.BVS("c_registry_block{}".format(i), 8)
            self.state.memory.store(self.registry_block + i, c)

    # TODO improve
    def ending_state(self, simgr):
        total_registry = {}
        for sstate in simgr.deadended + simgr.active + simgr.stashes["pause"]:
            for key in sstate.plugin_registry.registry.keys():
                if key not in total_registry:
                    total_registry[key] = []
                    if sstate.plugin_registry.registry[key] not in total_registry[key]:
                        total_registry[key].append(sstate.plugin_registry.registry[key])
                else:
                    if sstate.plugin_registry.registry[key] not in total_registry[key]:
                        total_registry[key].append(sstate.plugin_registry.registry[key])
        return total_registry

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        p = PluginRegistry()
        p.last_error = self.last_error
        p.registry_block = self.registry_block
        p.registry = self.registry.copy()
        p.stop_flag = self.stop_flag
        return p
