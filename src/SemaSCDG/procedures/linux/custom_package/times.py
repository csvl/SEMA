import angr
import time


class times(angr.SimProcedure):
    def run(self, pointer):
        # note : clock_t --> unsigned long
        angr.sim_type.register_types(
            angr.sim_type.parse_types(
                """
                struct tms {
                    long tms_utime;  /* user time */
                    long tms_stime;  /* system time */
                    long tms_cutime; /* user time of children */
                    long tms_cstime; /* system time of children */
                };
                """
            )
        )
        # TODO : Better feeding + long instead of int
        # import pdb; pdb.set_trace()
        self.state.mem[pointer].struct.tms.tms_utime = int(time.process_time())
        self.state.mem[pointer].struct.tms.tms_stime = int(time.process_time() + 1)
        self.state.mem[pointer].struct.tms.tms_cutime = int(time.process_time())
        self.state.mem[pointer].struct.tms.tms_cstime = int(time.process_time() + 1)
        return int(time.perf_counter() * 1000) # python <3.8 time.clock()
