import logging
import angr
lw = logging.getLogger("CustomSimProcedureWindows")

class CreateSemaphoreW(angr.SimProcedure):

    def run(
        self,
        lpSemaphoreAttributes,
        lInitialCount,
        lMaximumCount,
        lpName
    ):
        handle = self.state.solver.BVS("retval_{}".format(self.display_name), self.arch.bits)
        self.state.solver.add(handle != 0)
        return handle

# import angr

# class CreateSemaphoreWSimProcedure(angr.SimProcedure):
#     def run(self, lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName):
#         # For simplicity, we assume that lpSemaphoreAttributes and lpName are NULL.
#         # We only focus on the semaphore object creation.

#         # Retrieve the process object
#         process = self.state.project.loader.main_object

#         # Create a new semaphore object
#         semaphore_id = process.seg_alloc(0, 0x10)  # Allocate memory for the semaphore object
#         semaphore_size = process.arch.bytes
#         self.state.memory.store(semaphore_id, self.state.solver.BVV(0, semaphore_size))  # Initialize the semaphore value to 0

#         # Record the semaphore object information in the state
#         self.state.globals['semaphore_objects'] = self.state.globals.get('semaphore_objects', {})
#         semaphore_handle = len(self.state.globals['semaphore_objects']) + 1
#         self.state.globals['semaphore_objects'][semaphore_handle] = semaphore_id

#         # Return the semaphore handle as the function result
#         return semaphore_handle
