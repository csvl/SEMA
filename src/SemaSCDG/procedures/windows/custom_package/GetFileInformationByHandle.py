import angr
import claripy

class GetFileInformationByHandle(angr.SimProcedure):
    def run(self, hFile, lpFileInformation):
        # Not implemented, just return success
        file_attributes = 0

            #if os.path.isfile(path):
        file_attributes |= 0x00000020  # FILE_ATTRIBUTE_ARCHIVE

        # if os.path.isdir(path):
            #     file_attributes |= 0x00000010  # FILE_ATTRIBUTE_DIRECTORY

            # if os.access(path, os.R_OK):
            #     file_attributes |= 0x00000001  # FILE_ATTRIBUTE_READONLY

            # Write the file attributes to the output buffer
        self.state.memory.store(lpFileInformation, file_attributes.to_bytes(int(self.arch.bits/8), byteorder='little'))
        return 0x1
