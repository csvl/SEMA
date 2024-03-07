class PluginIoC:
    def __init__(self):
        pass
    
    def build_ioc(self,scdg,exp_dir):
        funcs = {
                "strings": ["lstrlenA","lstrlenW","strlen","lstrcpyA","lstrcpyW","strncpy","lstrcatA","lstrcatW","lstrcmpA","lstrcmpW","strcmp","strncmp"],
                "format": ["wsprintfA","wsprintfW","MultiByteToWideChar","WideCharToMultiByte"],
                "regs" :  
                    ["RegCreateKeyExA","RegCreateKeyExW","RegCreateKeyA","RegCreateKeyW","RegSetValueExA","RegSetValueExW","RegSetValueA","RegSetValueW","RegQueryValueExW","RegQueryValueExA","RegQueryValueA","RegQueryValueW","RegOpenKeyA","RegOpenKeyW","RegOpenKeyExA","RegOpenKeyExW","RegDeleteKeyW","RegDeleteKeyA","RegGetValueA","RegGetValueW",],
                "files" : 
                    ["CreateFileA","CreateFileW","GetModuleFileNameA","GetModuleFileNameW","GetTempPathA","GetTempPathW","FindFirstFileW","FindFirstFileA","WriteFile","ReadFile","CopyFile"],
                "dir" :
                    ["CreateDirectoryA","CreateDirectoryW","SHGetFolderPathW","SHGetFolderPathA","GetWindowsDirectoryW","GetWindowsDirectoryA","SHGetSpecialFolderPathW","SHGetSpecialFolderPathA"],
                "network" : 
                    ["getaddrinfo","gethostbyname","inet_addr","NetLocalGroupAddMembers","socket","bind","listen","accept","connect","recv","shutdown","WSAStratup","WSACleanup","send"],
                "cmd" : 
                    ["ShellExecuteW","ShellExecuteA","ShellExecuteExW","ShellExecuteExA","WinExec"],
                "thread" : 
                    ["ResumeThread","NtResumeThread","CreateThread","GetThreadContext","SetThreadContext"],
                "process" : 
                    ["CreateProcessA","CreateProcessW","ReadProcessMemory","NtWriteVirtualMemory","CreateRemoteThread","NtUnmapViewOfSection","WriteProcessMemory","VirtualAllocEx","ZwUnmapViewOfSection"],
                "other" : ["CreateEventA","CreateEventW","FindResourceW","FindResourceA","LookupAccountSidW","LookupAccountSidA","ExpandEnvironmentStringsW","GetDriveTypeW","GetDriveTypeA","URLDownloadToFileW","URLDownloadToFileA","GetLogicalDriveStringsW","GetLogicalDriveStringsA"],
                "lib" : 
                    ["LoadLibraryA","LoadLibraryW","GetModuleHandleA","GetModuleHandleW"],
                "proc" : 
                    ["GetProcAddress"],
                "services" :
                    ["OpenSCManager","CreateService","StartServiceCtrlDispatcher"],
                "crypt" :
                    ["CryptAcquireContext","CryptGenKey","CryptDeriveKey","CryptDecrypt","CryptReleaseContext"],
                "anti" :
                    ["IsDebuggerPresent","GetSystemInfo","GlobalMemoryStatusEx","GetVersion","CreateToolhelp32Snapshot"]
        }
        
        f = open(exp_dir + "IoC_report.txt", 'w')
        for func in funcs:
            strings = {""}
            f.write("\n #################################################################################### \n")
            f.write(func + "\n")
            for i in scdg:
                for call in i:
                    if call["name"] in funcs[func]:
                        string = call["name"] + " ( "
                        for arg in call["args"]:
                            if isinstance(arg,str): #and arg[-2:] != "32" and "_" not in arg and arg != "":
                                string = string + " " + arg + ","
                        string = string + "\x08" + " ) \n"
                        if string not in strings:
                            f.write(string)
                            strings.add(string)
        f.close()
        
