import angr
import claripy
from angr.sim_type import SimType

class GetStartupInfoA(angr.SimProcedure):
    #NO_RET = True
    def run(self, lpStartupInfo):
        # Get pointer to STARTUPINFO struct
        #startupinfo_ptr = self.state.mem[self.state.mem[lpStartupInfo].int.resolved].int.resolved
        
        # Get default structure values
        # startupinfo = angr.SIM_PROCEDURES['libc']['__ctype_b_loc']().get_startupinfo_dict()
        startupinfo = {
            "cb": [68,"dword"],
            "lpReserved": ["","LPSTR"],
            "lpDesktop":[ "winsta0\\default","LPSTR"],
            "lpTitle": ["","LPSTR"],
            "dwX": [0,"dword"],
            "dwY": [0,"dword"],
            "dwXSize": [0,"dword"],
            "dwYSize": [0,"dword"],
            "dwXCountChars": [0,"dword"],
            "dwYCountChars": [0,"dword"],
            "dwFillAttribute": [0,"dword"],
            "dwFlags": [0,"dword"],
            "wShowWindow": [1,"word"],
            "cbReserved2": [0,"word"],
            "lpReserved2": [0,"LPBYTE"],
            "hStdInput": [self.state.solver.BVS(
                            "hStdInputHandle_{}".format(self.display_name), self.arch.bits
                          ),"HANDLE"],
            "hStdOutput": [self.state.solver.BVS(
                            "hStdOutputHandle_{}".format(self.display_name), self.arch.bits
                         ),"HANDLE"],
            "hStdError": [self.state.solver.BVS(
                            "hStdErrorHandle_{}".format(self.display_name), self.arch.bits
                            ),"HANDLE"]
        }
        
        # Update the structure values with information about the current process
        # startupinfo['dwX'][0] = self.state.posix.get_fd(1).pos
        # startupinfo['dwY'][0] = self.state.posix.get_fd(2).pos
        startupinfo['dwFillAttribute'][0] = 0x7
        
        # Write the updated structure values to memory
        offset = 0
        bits = 32 if self.state.arch.bits == 32 else 64 # TODO
        for key, value in startupinfo.items():
            if startupinfo[key][1] == "dword":
                sz = int(bits / 8)
            elif startupinfo[key][1] == "word":
                sz = int(bits / 2 / 8)
            elif startupinfo[key][1] == "LPSTR":
                sz = len(startupinfo[key][0])
            elif startupinfo[key][1] == "LPBYTE":
                sz = int(bits / 8)
            elif startupinfo[key][1] == "HANDLE":
                sz = int(bits / 8)
            print(sz)
            print(startupinfo[key])
            self.state.memory.store(lpStartupInfo + offset, startupinfo[key][0], size=sz)
            offset += sz

        return None
