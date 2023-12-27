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
        lw.info("*"*200)
        simdp = self.state.posix.get_fd(fd=dirp)
        lw.info(f'reading directory: {simdp.file.name}')

        # TODO: make sure argument is actually a DIR struct
        if self.state.arch.name != "AMD64":
            lw.error("readdir SimProcedure is only implemented for AMD64")
            return 0

        self._build_amd64()
        self.instrument(dirp)
        malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
        pointer = self.inline_call(malloc, 19 + 256).ret_expr
        self._store_amd64(pointer)
        if self.out_of_files:
            lw.info('returned nullptr')
        else:
            lw.info('returned dirent ptr: '+str(hex(pointer)))
        lw.info("*"*250)
        return 0 if self.out_of_files else pointer #if not self.out_of_files else 0 # TODO: self.state.solver.If(self.condition, pointer, 0)

    def instrument(self, dirp):
"""
      if dirp.symbolic:
            lw.info("dirp is symbolic")
            lw.info(dirp)
            self._build_amd64()
            self.instrument()
            malloc = angr.SIM_PROCEDURES["libc"]["malloc"]
            pointer = self.inline_call(malloc, 19 + 256).ret_expr
            self._store_amd64(pointer)
        else:
            lw.info("dirp is concrete")
            lw.info(dirp)
            folder_name  = self.state.plugin_linux_fs.folder_address_to_name[self.state.solver.eval(dirp)]
            lw.info(folder_name)
            
            splitted_path = folder_name.split("/")
            if splitted_path[-1] == "":
                splitted_path.pop()
            current_folder = self.state.plugin_linux_fs.linux_folders
            current_folder_file = self.state.plugin_linux_fs.linux_files
            current_file_per_folder = self.state.plugin_linux_fs.current_file_per_folder
            pointer = 0
            used_part = ""
            for part in splitted_path:
                if part != "":
                    used_part = "/" + part 
                    lw.info("Part: " + used_part)
                    if used_part in current_folder.keys():
                        lw.info("Part in current_folder.keys()")
                        # lw.info(current_file_per_folder)
                        # lw.info(current_folder)
                        # lw.info(current_folder_file)
                        current_folder = current_folder[used_part]
                        current_file_per_folder = current_file_per_folder[1][used_part]
                        current_folder_file = current_folder_file[used_part]
                        # files = current_folder_file[used_part]["files"]
                        # current_file_index = current_file_per_folder[0]
                    else:
                        lw.info("Part not in current_folder.keys()")
                        current_folder[used_part] = {}
                        current_file_per_folder[1][used_part] = [0, {}]
                        current_folder_file[used_part] = {"files": []}
                        
                    #if part == splitted_path[-1]:
                    # current_file_index = current_file_per_folder[0]
                    # files = current_folder_file[part]["files"]
                    
            #TODO should give dirent of folder too
            lw.info("current_folder")
            # lw.info(current_folder_file)
            # lw.info(current_file_per_folder)
            files = current_folder_file["files"]
            current_file_index = current_file_per_folder[0]
            for file in files:
                if not file[0]:
                    pointer = self.state.plugin_linux_fs.file_address["/".join(splitted_path) + file[1]]
                    lw.info("Found file")
                    lw.info("/".join(splitted_path) + file[1])
                    file[0] = True
                    break
                
            # current_file_index = self.state.plugin_linux_fs.current_file_per_folder[folder_name]
            lw.info(current_file_index)
            # if folder_name in self.state.plugin_linux_fs.linux_files.keys():
            #     if current_file_index < len(self.state.plugin_linux_fs.linux_files[folder_name]):
            #         pointer = self.state.plugin_linux_fs.linux_files[folder_name][current_file_index]
            #     else:
            #         pointer = None
            # else: #  TODO
            #     pointer = None
            
            lw.info(pointer)
            
        print(self.state.solver.eval(self.state.memory.load(pointer+18, 1)))
           
        return pointer #self.state.solver.If(self.condition, pointer, 0)

    def instrument(self):
"""
        """
        Override this function to instrument the SimProcedure.

        The two useful variables you can override are self.struct, a named tuple of all the struct
        fields, and self.condition, the condition for whether the function succeeds.
        """

        lw.info('is dirp symbolic: ' + str( dirp.symbolic))
        simdp = self.state.posix.get_fd(fd=dirp)
        lw.info('starting fp position: ' + str(self.state.solver.eval(simdp.tell(), cast_to=int)))

        if self.state.solver.is_true(simdp.eof()):
            self.out_of_files = True
            return
        
        if self.state.solver.is_true(simdp.tell() == 0):
            simdp.seek(offset=275) # size of 1 dirent struct i hope
        
        d_ino, readsize = simdp.read_data(8) # 8 bytes i hope
        d_off, readsize = simdp.read_data(8)
        d_reclen, readsize = simdp.read_data(2)
        d_type, readsize = simdp.read_data(1)
        d_name, readsize = simdp.read_data(256)

        self.struct = Dirent(d_ino, d_off, d_reclen, d_type, d_name)

        lw.info('filename: '+ str(self.state.solver.eval(self.struct.d_name, cast_to=bytes)))


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