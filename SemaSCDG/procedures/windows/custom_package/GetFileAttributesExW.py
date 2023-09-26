import angr
import claripy
import os

import time
import datetime

class GetFileAttributesExW(angr.SimProcedure):
    def run(self, lpFileName, fInfoLevelId, lpFileInformation):
        # We only support retrieving basic file attribute information, so ignore fInfoLevelId.
        # We also ignore lpFileInformation since we're just going to return a single DWORD.

        # Get the path of the file to check
        path = self.state.mem[lpFileName].wstring.concrete
        
        lpFileInformation_addr = self.state.mem[lpFileInformation].int.concrete

        # Check if the file exists
        if True:
            # File exists, so get its attributes
            file_attributes = 0

            #if os.path.isfile(path):
            # file_attributes |= 0x00000020  # FILE_ATTRIBUTE_ARCHIVE
            
            file_attributes |= 0x00000080  # FILE_ATTRIBUTE_NORMAL 

            # if os.path.isdir(path):
            #     file_attributes |= 0x00000010  # FILE_ATTRIBUTE_DIRECTORY

            # if os.access(path, os.R_OK):
            #     file_attributes |= 0x00000001  # FILE_ATTRIBUTE_READONLY

            # Write the file attributes to the output buffer
            
            # typedef struct _FILE_BASIC_INFO {
            # LARGE_INTEGER CreationTime;
            # LARGE_INTEGER LastAccessTime;
            # LARGE_INTEGER LastWriteTime;
            # LARGE_INTEGER ChangeTime;
            # DWORD         FileAttributes;
            # } FILE_BASIC_INFO, *PFILE_BASIC_INFO;
            
            _FILE_BASIC_INFO = {
                'CreationTime': self.state.solver.BVS("CreationTime{}".format(self.display_name),64), # 0xFEEF04BD,
                'LastAccessTime': self.state.solver.BVS("LastAccessTime{}".format(self.display_name),64), # 0x00010000,
                'LastWriteTime': self.state.solver.BVS("LastWriteTime{}".format(self.display_name),64), # 0x00030001,
                'ChangeTime': self.state.solver.BVS("ChangeTime{}".format(self.display_name),64), #  0x00040001,
                'FileAttributes': self.state.solver.BVS("FileAttributes{}".format(self.display_name),32) # 0x00030002,
            }
            
            # _FILE_BASIC_INFO = {
            #     'CreationTime': int(time.time() * 1000 * 1000 / 100), # 0xFEEF04BD,
            #     'LastAccessTime': int(time.time() * 1000 * 1000 / 100), # 0x00010000,
            #     'LastWriteTime': int(time.time() * 1000 * 1000 / 100), # 0x00030001,
            #     'ChangeTime': int(time.time() * 1000 * 1000 / 100), #  0x00040001,
            #     'FileAttributes': self.state.solver.BVS("FileAttributes{}".format(self.display_name),32) # 0x00030002,
            # }
            
            self.state.solver.add(_FILE_BASIC_INFO['CreationTime'] >= 1601)
            self.state.solver.add(_FILE_BASIC_INFO['CreationTime'] < 30827)
            
            self.state.solver.add(_FILE_BASIC_INFO['LastAccessTime'] >= 1601)
            self.state.solver.add(_FILE_BASIC_INFO['LastAccessTime'] < 30827)
            
            self.state.solver.add(_FILE_BASIC_INFO['LastWriteTime'] >= 1601)
            self.state.solver.add(_FILE_BASIC_INFO['LastWriteTime'] < 30827)
            
            self.state.solver.add(_FILE_BASIC_INFO['ChangeTime'] >= 1601)
            self.state.solver.add(_FILE_BASIC_INFO['ChangeTime'] < 30827)
            
            self.state.solver.add(_FILE_BASIC_INFO['CreationTime']  <= _FILE_BASIC_INFO['LastAccessTime'])
            self.state.solver.add(_FILE_BASIC_INFO['LastWriteTime'] <= _FILE_BASIC_INFO['LastAccessTime'])
            self.state.solver.add(_FILE_BASIC_INFO['ChangeTime']    <= _FILE_BASIC_INFO['LastWriteTime'])
            
            self.state.mem[lpFileInformation_addr].qword    = _FILE_BASIC_INFO['CreationTime']
            self.state.mem[lpFileInformation_addr+8].qword  = _FILE_BASIC_INFO['LastAccessTime']
            self.state.mem[lpFileInformation_addr+16].qword = _FILE_BASIC_INFO['LastWriteTime']
            self.state.mem[lpFileInformation_addr+24].qword = _FILE_BASIC_INFO['ChangeTime']
            file_attributes = 0
            file_attributes = 0x00000080  # FILE_ATTRIBUTE_NORMAL 
            self.state.mem[lpFileInformation_addr+32].dword =  _FILE_BASIC_INFO['FileAttributes'] # file_attributes #.to_bytes(int(self.arch.bits/8), byteorder='little')
            #self.state.mem[lpFileInformation_addr+32].dword = _FILE_BASIC_INFO['FileAttributes']
            #self.state.memory.store(lpFileInformation, file_attributes.to_bytes(int(self.arch.bits/8), byteorder='little'))
            return 1  # Success
        else:
            # File doesn't exist, so return an error
            self.state.memory.store(lpFileInformation, claripy.BVV(0, 4))
            return 0  # Error
