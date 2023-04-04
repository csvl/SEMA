import angr


class PluginWideChar(angr.SimStatePlugin):
    def __init__(self):
        super(PluginWideChar, self).__init__()
        self.last_error = 0
        self.widechar_address = []
        self.stop_flag = False

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        p = PluginWideChar()
        p.last_error = self.last_error
        p.widechar_address = self.widechar_address.copy()
        p.stop_flag = self.stop_flag
        return p
