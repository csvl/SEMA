import angr

class DeleteFileW(angr.SimProcedure):
    def run(self, file_path_ptr):
        return 0x1