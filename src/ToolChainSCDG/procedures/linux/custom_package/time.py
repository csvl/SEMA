import angr
import time as timer

# https://docs.python.org/3/library/time.html
class time(angr.SimProcedure):
    KEY = "sys_last_time"

    @property
    def last_time(self):
        return self.state.globals.get(self.KEY, None)

    @last_time.setter
    def last_time(self, v):
        self.state.globals[self.KEY] = v

    def run(self, pointer):

        result = int(timer.time())
        return result
