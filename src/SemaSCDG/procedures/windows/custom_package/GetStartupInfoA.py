import angr
import claripy
from angr.sim_type import SimType
import logging

lw = logging.getLogger("CustomSimProcedureWindows")

# typedef struct _STARTUPINFOA {
#   DWORD  cb;
#   LPSTR  lpReserved;
#   LPSTR  lpDesktop;
#   LPSTR  lpTitle;
#   DWORD  dwX;
#   DWORD  dwY;
#   DWORD  dwXSize;
#   DWORD  dwYSize;
#   DWORD  dwXCountChars;
#   DWORD  dwYCountChars;
#   DWORD  dwFillAttribute;
#   DWORD  dwFlags;
#   WORD   wShowWindow;
#   WORD   cbReserved2;
#   LPBYTE lpReserved2;
#   HANDLE hStdInput;
#   HANDLE hStdOutput;
#   HANDLE hStdError;
# } STARTUPINFOA, *LPSTARTUPINFOA;

class GetStartupInfoA(angr.SimProcedure):
    #NO_RET = True
    def run(self, lpStartupInfo):
        # Get pointer to STARTUPINFO struct
        #startupinfo_ptr = self.state.mem[self.state.mem[lpStartupInfo].int.resolved].int.resolved
        
        # Get default structure values
        # startupinfo = angr.SIM_PROCEDURES['libc']['__ctype_b_loc']().get_startupinfo_dict()
        startupinfo = {
            "cb": [
                            68
                          ,"dword"],
            "lpReserved": ["","LPSTR"],
            "lpDesktop":[ "winsta0\\default","LPSTR"],
            "lpTitle": ["","LPSTR"],
            "dwX": [self.state.solver.BVS(
                            "dwX{}".format(self.display_name), 32
                          ),"dword"],
            "dwY": [self.state.solver.BVS(
                            "dwY{}".format(self.display_name), 32
                          ),"dword"],
            "dwXSize": [self.state.solver.BVS(
                            "dwXSize{}".format(self.display_name), 32
                          ),"dword"],
            "dwYSize": [self.state.solver.BVS(
                            "dwYSize{}".format(self.display_name), 32
                          ),"dword"],
            "dwXCountChars": [self.state.solver.BVS(
                            "dwXCountChars{}".format(self.display_name), 32
                          ),"dword"],
            "dwYCountChars": [self.state.solver.BVS(
                            "dwYCountChars{}".format(self.display_name), 32
                          ),"dword"],
            "dwFillAttribute": [self.state.solver.BVS(
                            "dwFillAttribute{}".format(self.display_name), 32
                          ),"dword"],
            "dwFlags": [self.state.solver.BVS(
                            "dwFlags{}".format(self.display_name), 32
                          ),"dword"],
            "wShowWindow": [self.state.solver.BVS(
                            "wShowWindow{}".format(self.display_name), 16
                          ),"word"],
            "cbReserved2": [self.state.solver.BVS(
                            "cbReserved2{}".format(self.display_name), 16
                          ),"word"],
            "lpReserved2": [self.state.solver.BVS(
                            "lpReserved2{}".format(self.display_name), self.arch.bits
                          ),"LPBYTE"],
            "hStdInput": [self.state.solver.BVS(
                            "hStdInput{}".format(self.display_name), self.arch.bits
                          ),"HANDLE"],
            "hStdOutput": [self.state.solver.BVS(
                            "hStdOutput{}".format(self.display_name), self.arch.bits
                         ),"HANDLE"],
            "hStdError": [self.state.solver.BVS(
                            "hStdError{}".format(self.display_name), self.arch.bits
                            ),"HANDLE"]
        }
        
        # Update the structure values with information about the current process
        # startupinfo['dwX'][0] = self.state.posix.get_fd(1).pos
        # startupinfo['dwY'][0] = self.state.posix.get_fd(2).pos
        # startupinfo['dwFillAttribute'][0] = 0x7
        
        # Write the updated structure values to memory
        offset = 0
        bits = 32 if self.state.arch.bits == 32 else 64 # TODO
        sz = 0
        for key, value in startupinfo.items():
            if startupinfo[key][1] == "dword":
                sz = 4
            elif startupinfo[key][1] == "word":
                sz = 2
            elif startupinfo[key][1] == "LPSTR":
                sz = len(startupinfo[key][0])#int(bits/8)
                #self.state.mem[lpStartupInfo + offset] = startupinfo[key][0]
                #len(startupinfo[key][0])
            elif startupinfo[key][1] == "LPBYTE":
                sz = int(bits/8)
            elif startupinfo[key][1] == "HANDLE":
                sz = int(bits/8)
            lw.info(sz)
            lw.info(startupinfo[key])
            #if not startupinfo[key][1] == "LPSTR":
            self.state.memory.store(lpStartupInfo + offset, startupinfo[key][0], size=sz)
            offset += sz

        return None
