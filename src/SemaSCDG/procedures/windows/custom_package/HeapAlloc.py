import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")

class HeapAlloc(angr.SimProcedure):
    def run(self, HeapHandle, Flags, Size): #pylint:disable=arguments-differ, unused-argument
        addr = self.state.heap._malloc(Size)

        # conditionally zero the allocated memory
        if self.state.solver.solution(Flags & 8, 8):
            if isinstance(self.state.heap, angr.SimHeapPTMalloc):
                # allocated size might be greater than requested
                data_size = self.state.solver.eval_one(
                    self.state.heap.chunk_from_mem(addr).get_data_size()
                )
            else:
                data_size = self.state.heap._conc_alloc_size(Size)
            data = self.state.solver.BVV(0, data_size * 8)
            self.state.memory.store(addr, data, size=data_size, condition=Flags & 8 == 8)
        return addr
