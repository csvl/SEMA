import angr


class PluginResources(angr.SimStatePlugin):
    def __init__(self):
        super(PluginResources, self).__init__()
        self.last_error = 0
        self.res_block = 0
        self.resources = {}
        self.stop_flag = False
        self.dict_calls = {}
        self.expl_method = "BFS"

    def update_dic(self, call_name):
        if call_name in self.dict_calls:
            if self.dict_calls[call_name] > 5:
                self.stop_flag = True
                self.dict_calls[call_name] = 0
            else:
                self.dict_calls[call_name] = self.dict_calls[call_name] + 1
        else:
            self.dict_calls[call_name] = 1

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        p = PluginResources()
        p.last_error = self.last_error
        p.res_block = self.res_block
        p.resources = self.resources.copy()
        p.stop_flag = self.stop_flag
        p.dict_calls = self.dict_calls.copy()
        return p
