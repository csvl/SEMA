import angr
import logging

lw = logging.getLogger("CustomSimProcedureLinux")
logging.getLogger("CustomSimProcedureLinux").setLevel("INFO")

# class readdir(angr.SimProcedure):
#     # pylint: disable=arguments-differ
#     def run(self,dirp):
#         lw.info(self.cc)
#         return 0

# import angr
from collections import namedtuple

# import logging

# l = logging.getLogger(name=__name__)

Dirent = namedtuple("dirent", ("d_ino", "d_off", "d_reclen", "d_type", "d_name"))


class readdir(angr.SimProcedure):
    struct = None
    condition = None
    out_of_files = False

    def run(self, dirp):  # pylint: disable=arguments-differ
        # TODO: make sure argument is actually a DIR struct
        if self.state.arch.name != "AMD64":
            lw.error("readdir SimProcedure is only implemented for AMD64")
            return 0

        self._build_amd64()
        self.instrument()
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
        pointer = self.inline_call(malloc, 19 + 256).ret_expr
        self._store_amd64(pointer)
        print("*"*250)
        return pointer if not self.out_of_files else 0 # TODO: self.state.solver.If(self.condition, pointer, 0)

    def instrument(self, dirp):
        """
        Override this function to instrument the SimProcedure.

        The two useful variables you can override are self.struct, a named tuple of all the struct
        fields, and self.condition, the condition for whether the function succeeds.
        """
        if dirp.eof():
            self.out_of_files = True
            return
        if dirp.tell() == 0:
            dirp.seek(offset=275) # size of 1 dirent struct i hope
        
        self.struct.d_ino, readsize = dirp.read_data(8) # 8bytes i hope
        self.struct.d_off, readsize = dirp.read_data(8)
        self.struct.d_reclen, readsize = dirp.read_data(2)
        self.struct.d_type, readsize = dirp.read_data(1)
        self.struct.d_name, readsize = dirp.read_data(256)

    def _build_amd64(self):
        self.struct = Dirent(
            self.state.solver.BVV(0, 64),  # d_ino
            self.state.solver.BVV(0, 64),  # d_off
            self.state.solver.BVS("d_reclen", 16, key=("api", "readdir", "d_reclen")),  # d_reclen
            self.state.solver.BVS("d_type", 8, key=("api", "readdir", "d_type")),  # d_type
            self.state.solver.BVS("d_name", 255 * 8, key=("api", "readdir", "d_name")),
        )  # d_name
        self.condition = self.state.solver.BoolS("readdir_cond")  # TODO: variable key

    def _store_amd64(self, ptr):
        def stores(offset, val):
            return self.state.memory.store(ptr + offset, val, endness="Iend_BE")

        def storei(offset, val):
            return self.state.memory.store(ptr + offset, val, endness="Iend_LE")

        storei(0, self.struct.d_ino)
        storei(8, self.struct.d_off)
        storei(16, self.struct.d_reclen)
        storei(18, self.struct.d_type)
        stores(19, self.struct.d_name)
        stores(19 + 255, self.state.solver.BVV(0, 8))