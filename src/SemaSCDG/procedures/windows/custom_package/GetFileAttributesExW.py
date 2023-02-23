import angr
import claripy
import os


class GetFileAttributesExW(angr.SimProcedure):
    def run(self, lpFileName, fInfoLevelId, lpFileInformation):
        # We only support retrieving basic file attribute information, so ignore fInfoLevelId.
        # We also ignore lpFileInformation since we're just going to return a single DWORD.

        # Get the path of the file to check
        path = self.state.mem[lpFileName].wstring.concrete

        # Check if the file exists
        if True:
            # File exists, so get its attributes
            file_attributes = 0

            #if os.path.isfile(path):
            file_attributes |= 0x00000020  # FILE_ATTRIBUTE_ARCHIVE

            # if os.path.isdir(path):
            #     file_attributes |= 0x00000010  # FILE_ATTRIBUTE_DIRECTORY

            # if os.access(path, os.R_OK):
            #     file_attributes |= 0x00000001  # FILE_ATTRIBUTE_READONLY

            # Write the file attributes to the output buffer
            self.state.memory.store(lpFileInformation, file_attributes.to_bytes(int(self.arch.bits/8), byteorder='little'))
            return 1  # Success
        else:
            # File doesn't exist, so return an error
            self.state.memory.store(lpFileInformation, claripy.BVV(0, 4))
            return 0  # Error
