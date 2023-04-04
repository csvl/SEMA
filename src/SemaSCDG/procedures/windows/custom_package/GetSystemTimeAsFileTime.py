import angr
import time
import datetime
# from angr.sim_type import SimStruct

# class GetSystemTimeAsFileTime(angr.SimProcedure):
#     def run(self, lpSystemTimeAsFileTime):
#         # systemtime_ptr = self.state.mem[lpSystemTimeAsFileTime].int.resolved

#         # # Convert the UNIX timestamp to a system time struct
#         # filetime = SimStruct(
#         #     self.state.arch,
#         #     self.state.solver.BVS("dwLowDateTime{}".format(self.display_name), 32),
#         #     self.state.solver.BVS("dwHighDateTime{}".format(self.display_name), 32),
#         # )

#         # Write the system time struct to the given pointer
#         #self.state.memory.store(lpSystemTimeAsFileTime, filetime, endness=self.state.arch.memory_endness)
#         dwLowDateTime = self.state.solver.BVS("dwLowDateTime{}".format(self.display_name),self.state.arch.bits)
#         # self.state.solver.add(dwLowDateTime >= 1601)
#         # self.state.solver.add(dwLowDateTime < 30827)
#         self.state.memory.store(lpSystemTimeAsFileTime, dwLowDateTime, endness=self.state.arch.memory_endness)
#         dwHighDateTime = self.state.solver.BVS("dwHighDateTime{}".format(self.display_name),self.state.arch.bits)
#         # self.state.solver.add(dwHighDateTime >= 1)
#         # self.state.solver.add(dwHighDateTime <= 12)
#         self.state.memory.store(lpSystemTimeAsFileTime+4, dwHighDateTime, endness=self.state.arch.memory_endness)
        
#         # Return success
#         return

class GetSystemTimeAsFileTime(angr.SimProcedure):
    timestamp = None
    def run(self, outptr):
        self.instrument()
        self.state.mem[outptr].qword = self.timestamp

    def instrument(self):
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            self.fill_from_timestamp(time.time())
        else:
            self.fill_symbolic()

    def fill_from_timestamp(self, ts):
        self.timestamp = int(ts * 1000 * 1000 / 100)
                    # convert to microseconds, convert to nanoseconds, convert to 100ns intervals

    def fill_symbolic(self):
        self.timestamp = self.state.solver.BVS('SystemTimeAsFileTime', 64, key=('api', 'SystemTimeAsFileTime'))

