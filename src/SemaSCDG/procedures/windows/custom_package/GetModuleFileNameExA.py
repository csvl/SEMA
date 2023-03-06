import logging
import angr

# from ...CustomSimProcedure import *
# from ...linux.CustomSimProcedureLinux import *
lw = logging.getLogger("CustomSimProcedureWindows")


class GetModuleFileNameExA(angr.SimProcedure):
    def getFakeName(self, size):
        # import pdb; pdb.set_trace()
        name = self.state.project.filename.split("/")[-1]
        path = (name[: size - 1] + "\0").encode("utf-8")  # truncate if too long
        return path

    def decodeString(self, ptr):
        lib = self.state.mem[ptr].string.concrete
        if not isinstance(lib, str):
            lib = lib.decode("utf-8") # TODO 
        return lib

    def run(self, hProcess, hModule, lpFilename, nSize):
        self.state.project
        size = self.state.solver.eval(nSize)

        # if NULL, retrieve path of exe of current process
        # We create a fake one
        if self.state.solver.is_true(hModule == 0):
            path_rough = self.getFakeName(size)
            lw.info("GetModuleFileNameExA: " + str(path_rough))
            path = self.state.solver.BVV(path_rough)
            self.state.memory.store(
                lpFilename, path
            )  # ,endness=self.arch.memory_endness)
            # self.state.memory.store(size_buf,self.state.solver.BVV(len(path), self.arch.bits),endness= self.arch.memory_endness)
            return len(path_rough) - 1
        else:
            module_name = self.decodeString(hModule)
            lw.info("GetModuleFileNameExA: " + str(module_name))
            # import pdb; pdb.set_trace()
            path = self.state.solver.BVV(module_name)
            self.state.memory.store(
                lpFilename, path, endness=self.arch.memory_endness
            )
            # self.state.memory.store(buf_filename,self.state.solver.BVS("filename_{}".format(self.display_name), size*8))
            return len(module_name)
        # ret_expr = self.state.solver.BVS("retval_{}".format(self.display_name),self.arch.bits)
        # self.state.add_constraints(ret_expr <= size_buf)
        return ret_expr
