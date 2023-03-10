import angr


class PluginLocaleInfo(angr.SimStatePlugin):
    def __init__(self):
        super(PluginLocaleInfo, self).__init__()
        self.last_error = 0
        self.locale_info_block = 0
        self.locale_info = {}
        self.stop_flag = False
        
    def setup_plugin(self):
        # For locale info mainly
        self.locale_info_block = self.state.heap.malloc(32767) 
        for i in range(32767):
            c = self.state.solver.BVS("c_locale_info_block{}".format(i), 8)
            self.state.memory.store(self.locale_info_block + i, c)

    # TODO improve
    def ending_state(self, simgr):
        total_locale = {}
        for sstate in simgr.deadended + simgr.active + simgr.stashes["pause"]:
            for key in sstate.plugin_locale_info.locale_info.keys():
                if key not in total_locale:
                    total_locale[key] = []
                    if sstate.plugin_locale_info.locale_info[key] not in total_locale[key]:
                        total_locale[key].append(sstate.plugin_locale_info.locale_info[key])
                else:
                    if sstate.plugin_locale_info.locale_info[key] not in total_locale[key]:
                        total_locale[key].append(sstate.plugin_locale_info.locale_info[key])
        return total_locale
    
    @angr.SimStatePlugin.memo
    def copy(self, memo):
        p = PluginLocaleInfo()
        p.last_error = self.last_error
        p.locale_info_block = self.locale_info_block
        p.locale_info = self.locale_info.copy()
        p.stop_flag = self.stop_flag
        return p
