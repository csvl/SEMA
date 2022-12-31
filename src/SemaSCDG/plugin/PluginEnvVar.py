import angr


class PluginEnvVar(angr.SimStatePlugin):
    def __init__(self):
        super(PluginEnvVar, self).__init__()
        self.last_error = 0
        self.env_block = 0
        self.env_var = {}
        self.stop_flag = False
        self.dict_calls = {}

    def update_dic(self, call_name):
        if call_name in self.dict_call:
            if self.dict_call[call_name] > 5:
                self.stop_flag = True
                self.dict_call[call_name] = 0
            else:
                self.dict_call[call_name] = self.dict_call[call_name] + 1
        else:
            self.dict_call[call_name] = 1

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        p = PluginEnvVar()
        p.last_error = self.last_error
        p.env_block = self.env_block
        p.env_var = self.env_var.copy()
        p.stop_flag = self.stop_flag
        p.dict_calls = self.dict_calls.copy()
        return p
