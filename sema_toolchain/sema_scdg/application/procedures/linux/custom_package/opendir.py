import os
import sys
import angr
import logging
from collections import namedtuple
from .open import open  # if needed


try:
    lw = logging.getLogger("CustomSimProcedureLinux")
    lw.setLevel(os.environ["LOG_LEVEL"])
except Exception as e:
    print(e)

# This is the structure used by _build_amd64/_store_amd64 (used by readdir).
from collections import namedtuple

Dirent = namedtuple("dirent", ("d_ino", "d_off", "d_reclen", "d_type", "d_name"))


class opendir(angr.SimProcedure):
    struct = None
    condition = None

    def run(self, dirp):  # pylint: disable=arguments-differ
        # TODO: make sure argument is actually a DIR struct
        if self.state.arch.name != "AMD64":
            lw.error("readdir SimProcedure is only implemented for AMD64")
            return 0

        if dirp.symbolic:
            lw.debug("dirp is symbolic")
            lw.debug(dirp)
            self._build_amd64()
            self.instrument()
            malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
            pointer = self.inline_call(malloc, 19 + 256).ret_expr
            self._store_amd64(pointer)
        else:
            lw.debug("dirp is concrete")
            lw.debug(dirp)
            folder_name = self.state.mem[dirp].string.concrete
            if hasattr(folder_name, "decode"):
                folder_name = folder_name.decode("utf-8")
            lw.debug(folder_name)
            lw.debug(self.state.plugin_linux_fs.folder_address)
            if folder_name in self.state.plugin_linux_fs.folder_address.keys() and \
                    self.state.plugin_linux_fs.folder_address[folder_name] != None:
                pointer = self.state.plugin_linux_fs.folder_address[folder_name]
            else:
                self.state.plugin_linux_fs.add_folder(folder_name)
                pointer = self.state.plugin_linux_fs.folder_address[folder_name]

        return pointer  # self.state.solver.If(self.condition, pointer, 0)

    def instrument(self):
        """
        Override this function to instrument the SimProcedure.

        The two useful variables you can override are self.struct, a named tuple of all the struct
        fields, and self.condition, the condition for whether the function succeeds.
        """
        pass

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