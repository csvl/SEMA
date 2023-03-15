import angr


class PluginEnvVar(angr.SimStatePlugin):
    def __init__(self):
        super(PluginEnvVar, self).__init__()
        self.last_error = 0
        self.env_block = 0
        self.env_blockw = 0
        self.env_var = {}
        self.wenv_var = {}
        self.env_var_requested = {}
        self.wenv_var_requested = {}
        self.stop_flag = False
        self.dict_calls = {}
        self.expl_method = "BFS"
        
        self.windows_env_vars = {
            "ALLUSERSPROFILE": "C:\\ProgramData\\",
            "APPDATA": "C:\\Users\\ElNiak\\AppData\\Roaming\\",
            "CommonProgramFiles": "C:\\Program Files\\Common Files\\",
            "COMPUTERNAME": "ElNiak",
            "COMSPEC": "C:\\Windows\\system32\\cmd.exe",
            "DRIVERDATA": "C:\\Windows\\System32\\Drivers\\DriverData\\",
            "HOMEDRIVE": "C:",
            "HOMEPATH": "C:\\Users\\ElNiak\\",
            "LOCALAPPDATA": "C:\\Users\\ElNiak\\AppData\\Local\\",
            "LOGONSERVER": "\\\\[DomainControllerName]",
            "NUMBER_OF_PROCESSORS": "8",
            "OS": "Windows_NT",
            "Path": "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem;C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\",
            "PATHEXT": ".COM;.EXE;.BAT;.CMD;.VBS;.VBgetenvE;.JS;.JSE;.WSF;.WSH;.MSC",
            "PROCESSOR_ARCHITECTURE": "AMD64",
            "PROCESSOR_IDENTIFIER": "Intel64 Family 6 Model 58 Stepping 9, GenuineIntel",
            "PROCESSOR_LEVEL": "6",
            "PROCESSOR_REVISION": "3a09",
            "ProgramData": "C:\\ProgramData\\",
            "ProgramFiles": "C:\\Program Files\\",
            "ProgramFiles(x86)": "C:\\Program Files (x86)",
            "ProgramW6432": "C:\\Program Files",
            "PSModulePath": "C:\\Windows\\system32\\WindowsPowerShell\\v1.0\\Modules\\",
            "PUBLIC": "C:\\Users\\Public\\",
            "SystemDrive": "C:\\",
            "SystemRoot": "C:\\Windows\\",
            "TEMP": "C:\\Users\\ElNiak\\AppData\\Local\\Temp\\",
            "TMP": "C:\\Users\\ElNiak\\AppData\\Local\\Temp\\",
            "USERPROFILE": "C:\\Users\\ElNiak\\",
            "windir": "C:\\Windows",
            
            "QT_NO_CPU_FEATURE":"", # rdrand
            "UNICODEMAP_JP":"unicode-ascii",
            "QT_LOGGING_TO_CONSOLE":"0",
            "QT_LOGGING_RULES": "", #"*.debug=false;", qml=false
            "QT_LOGGING_CONF":"", # qt-log.conf
            "LANG":"en_GB.UTF-8",
            "QT_NO_DEBUG_OUTPUT":"1",
            "QT_ASSUME_STDERR_HAS_CONSOLE":"0",
            "QT_HASH_SEED":"0",
            "QT_FORCE_STDERR_LOGGING":"0",
            "QT_USE_NATIVE_WINDOWS":"1",
            "QT_LOGGING_DEBUG":"0",
            "QT_DEBUG_PLUGINS":"0",
            "QT_STYLE_OVERRIDE":"0",
            "QT_EXCLUDE_GENERIC_BEARER":"0",
            "QT_PLUGIN_PATH":"C:\\Users\\ElNiak\\QTPlugin\\",
            "QT_MESSAGE_PATTERN": "", #"[%{time yyyyMMdd h:mm:ss.zzz t} %{if-debug}D%{endif}%{if-info}I%{endif}%{if-warning}W%{endif}%{if-critical}C%{endif}%{if-fatal}F%{endif}] %{file}:%{line} - %{message}\0\0"
        }
        
    def setup_plugin(self, expl_method):
        self.env_block = self.state.heap.malloc(32767) 
        for i in range(32767):
            c = self.state.solver.BVS("c_env_block{}".format(i), 8)
            self.state.memory.store(self.env_block + i, c)
            
        env_var_str = b""
        env_var_wstr = b""
        for env_var in self.windows_env_vars.keys():
            env_var_val = (env_var + "=")
            env_var_val += (self.windows_env_vars[env_var] + "\x00\x00")
            env_var_str += env_var_val.encode("utf-8")
            env_var_wstr += env_var_val.encode("utf-16-le")
            self.env_var[env_var.upper()] = self.windows_env_vars[env_var]
            # wenv_var_val = (env_var + "=")
            # wenv_var_val += (windows_env_vars[env_var] + "\x00\x00")
            #wenv_var_str += wenv_var_val.encode("utf-16-le")
            self.wenv_var[env_var.upper()] = self.windows_env_vars[env_var].encode("utf-16-le")
        
        env_var_bv = self.state.solver.BVV(env_var_str)
        self.state.memory.store(self.env_block, env_var_bv)
        env_var_wbv = self.state.solver.BVV(env_var_wstr)
        self.state.memory.store(self.env_block, env_var_wbv)
        self.expl_method = expl_method
            
    def update_dic(self, call_name):
        if call_name in self.dict_calls:
            if self.dict_calls[call_name] > 5:
                self.stop_flag = True
                self.dict_calls[call_name] = 0
            else:
                self.dict_calls[call_name] = self.dict_calls[call_name] + 1
        else:
            self.dict_calls[call_name] = 1
    
    # TODO improve
    def ending_state(self, simgr):
        total_env_var = {}
        for sstate in simgr.deadended + simgr.active + simgr.stashes["pause"]:
            for key in sstate.plugin_env_var.env_var_requested.keys():
                if key not in total_env_var:
                    total_env_var[key] = []
                    if sstate.plugin_env_var.env_var_requested[key] not in total_env_var[key]:
                        total_env_var[key].append(str(sstate.plugin_env_var.env_var_requested[key]))
                else:
                    if sstate.plugin_env_var.env_var_requested[key] not in total_env_var[key]:
                        total_env_var[key].append(str(sstate.plugin_env_var.env_var_requested[key]))
        for key in sstate.plugin_env_var.wenv_var_requested.keys():
                if key not in total_env_var:
                    total_env_var[key] = []
                    if sstate.plugin_env_var.wenv_var_requested[key] not in total_env_var[key]:
                        total_env_var[key].append(str(sstate.plugin_env_var.wenv_var_requested[key]))
                else:
                    if sstate.plugin_env_var.wenv_var_requested[key] not in total_env_var[key]:
                        total_env_var[key].append(str(sstate.plugin_env_var.wenv_var_requested[key]))
        return total_env_var
    
    @angr.SimStatePlugin.memo
    def copy(self, memo):
        p = PluginEnvVar()
        p.last_error = self.last_error
        p.env_block = self.env_block
        p.env_blockw = self.env_blockw
        p.env_var = self.env_var.copy()
        p.wenv_var = self.wenv_var.copy()
        p.stop_flag = self.stop_flag
        p.dict_calls = self.dict_calls.copy()
        p.env_var_requested = self.env_var_requested.copy()
        p.wenv_var_requested = self.wenv_var_requested.copy()
        return p
