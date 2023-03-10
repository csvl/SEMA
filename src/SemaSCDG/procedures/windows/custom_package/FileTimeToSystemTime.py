import angr
from angr.sim_type import SimStruct
import time
import datetime

class FileTimeToSystemTime(angr.SimProcedure):
    systemtime = None
    systemtime_ptr = None
    def run(self, lpFileTime, lpSystemTime):
        # filetime_ptr = self.state.mem[lpFileTime].int.resolved
        #systemtime_ptr = self.state.mem[lpSystemTime].int.resolved

        # Extract the low and high 32-bit words from the filetime
        # low_dword = self.state.mem[filetime_ptr].int.resolved
        # high_dword = self.state.mem[filetime_ptr + 4].int.resolved

        # Convert the filetime to seconds since January 1, 1601 (UTC)
        # filetime_seconds = (high_dword << 32) + low_dword
        # filetime_seconds -= 11644473600  # seconds between 1601 and 1970

        # # Convert the filetime to a UNIX timestamp
        # unix_timestamp = filetime_seconds * 10000000

        # Convert the UNIX timestamp to a system time struct
        # systemtime = SimStruct(
        #     self.state.arch,
        #     self.state.solver.BVV(unix_timestamp, self.state.arch.bits),
        #     self.state.solver.BVV(0, self.state.arch.bits),
        # )

        #typedef struct _SYSTEMTIME {
        # WORD wYear; //1601 through 30827.
        # WORD wMonth; //1 -> 12
        # WORD wDayOfWeek; // 0 -> 6
        # WORD wDay;
        # WORD wHour;
        # WORD wMinute;
        # WORD wSecond;
        # WORD wMilliseconds;
        # } SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;
                
        # Write the system time struct to the given pointer
        # dyear = self.state.solver.BVS("wYear{}".format(self.display_name),self.state.arch.bits)
        # self.state.solver.add(dyear >= 1601)
        # self.state.solver.add(dyear < 30827)
        # self.state.memory.store(lpSystemTime, dyear, endness=self.state.arch.memory_endness)
        # dmonth = self.state.solver.BVS("dmonth{}".format(self.display_name),self.state.arch.bits)
        # self.state.solver.add(dmonth >= 1)
        # self.state.solver.add(dmonth <= 12)
        # self.state.memory.store(lpSystemTime+2, dmonth, endness=self.state.arch.memory_endness)
        # wDayOfWeek = self.state.solver.BVS("wDayOfWeek{}".format(self.display_name),self.state.arch.bits)
        # self.state.solver.add(wDayOfWeek >= 0)
        # self.state.solver.add(wDayOfWeek <= 6)
        # self.state.memory.store(lpSystemTime+4, wDayOfWeek, endness=self.state.arch.memory_endness)
        # wDay = self.state.solver.BVS("wDay{}".format(self.display_name),self.state.arch.bits)
        # self.state.solver.add(wDay >= 1)
        # self.state.solver.add(wDay <= 31)
        # self.state.memory.store(lpSystemTime+6, wDay, endness=self.state.arch.memory_endness)
        # wHour = self.state.solver.BVS("wHour{}".format(self.display_name),self.state.arch.bits)
        # self.state.solver.add(wHour >= 0)
        # self.state.solver.add(wHour <= 23)
        # self.state.memory.store(lpSystemTime+8, wHour, endness=self.state.arch.memory_endness)
        # wMinute = self.state.solver.BVS("wMinute{}".format(self.display_name),self.state.arch.bits)
        # self.state.solver.add(wMinute >= 0)
        # self.state.solver.add(wMinute <= 59)
        # self.state.memory.store(lpSystemTime+10, wMinute, endness=self.state.arch.memory_endness)
        # wSecond = self.state.solver.BVS("wSecond{}".format(self.display_name),self.state.arch.bits)
        # self.state.solver.add(wSecond >= 0)
        # self.state.solver.add(wSecond <= 59)
        # self.state.memory.store(lpSystemTime+12, wSecond, endness=self.state.arch.memory_endness)
        # wMilliseconds = self.state.solver.BVS("wMilliseconds{}".format(self.display_name),self.state.arch.bits)
        # self.state.solver.add(wMilliseconds >= 1)
        # self.state.solver.add(wMilliseconds <= 999)
        # self.state.memory.store(lpSystemTime+14, wMilliseconds, endness=self.state.arch.memory_endness)
        
        self.systemtime_ptr =  self.state.mem[lpSystemTime].int.resolved #lpSystemTime
        self.instrument()

        # Return success
        return 0x1 #self.state.solver.BVV(1, self.state.arch.bits)
    
    def instrument(self):
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            self.fill_from_systemtime(time.time())
        else:
            self.fill_symbolic()

    def fill_symbolic(self):
        # self.systemtime = # int(ts * 1000 * 1000 / 100)
                    # convert to microseconds, convert to nanoseconds, convert to 100ns intervals
        dyear = self.state.solver.BVS("wYear{}".format(self.display_name),16)
        self.state.solver.add(dyear >= 1601)
        self.state.solver.add(dyear < 30827)
        #self.state.memory.store(lpSystemTime, dyear, endness=self.state.arch.memory_endness)
        self.state.mem[self.systemtime_ptr].word = dyear
        dmonth = self.state.solver.BVS("dmonth{}".format(self.display_name),16)
        self.state.solver.add(dmonth >= 1)
        self.state.solver.add(dmonth <= 12)
        #self.state.memory.store(lpSystemTime+2, dmonth, endness=self.state.arch.memory_endness)
        self.state.mem[self.systemtime_ptr+2].word = dmonth
        wDayOfWeek = self.state.solver.BVS("wDayOfWeek{}".format(self.display_name),16)
        self.state.solver.add(wDayOfWeek >= 0)
        self.state.solver.add(wDayOfWeek <= 6)
        #self.state.memory.store(lpSystemTime+4, wDayOfWeek, endness=self.state.arch.memory_endness)
        self.state.mem[self.systemtime_ptr+4].word = wDayOfWeek
        wDay = self.state.solver.BVS("wDay{}".format(self.display_name),16)
        self.state.solver.add(wDay >= 1)
        self.state.solver.add(wDay <= 31)
        #self.state.memory.store(lpSystemTime+6, wDay, endness=self.state.arch.memory_endness)
        self.state.mem[self.systemtime_ptr+6].word = wDay
        wHour = self.state.solver.BVS("wHour{}".format(self.display_name),16)
        self.state.solver.add(wHour >= 0)
        self.state.solver.add(wHour <= 23)
        #self.state.memory.store(lpSystemTime+8, wHour, endness=self.state.arch.memory_endness)
        self.state.mem[self.systemtime_ptr+8].word = wHour
        wMinute = self.state.solver.BVS("wMinute{}".format(self.display_name),16)
        self.state.solver.add(wMinute >= 0)
        self.state.solver.add(wMinute <= 59)
        # self.state.memory.store(lpSystemTime+10, wMinute, endness=self.state.arch.memory_endness)
        self.state.mem[self.systemtime_ptr+10].word = wMinute
        wSecond = self.state.solver.BVS("wSecond{}".format(self.display_name),16)
        self.state.solver.add(wSecond >= 0)
        self.state.solver.add(wSecond <= 59)
        # self.state.memory.store(lpSystemTime+12, wSecond, endness=self.state.arch.memory_endness)
        self.state.mem[self.systemtime_ptr+12].word = wSecond
        wMilliseconds = self.state.solver.BVS("wMilliseconds{}".format(self.display_name),16)
        self.state.solver.add(wMilliseconds >= 1)
        self.state.solver.add(wMilliseconds <= 999)
        self.state.mem[self.systemtime_ptr+12].word = wMilliseconds
        # self.state.memory.store(lpSystemTime+14, wMilliseconds, endness=self.state.arch.memory_endness)

    def fill_from_systemtime(self, ts):
        self.systemtime = self.state.solver.BVS('FileTimeToSystemTime', 64, key=('api', 'FileTimeToSystemTime'))