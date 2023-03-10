import angr
import claripy
import time 

class GetFileInformationByHandle(angr.SimProcedure):
    timestamp = None
    
    def run(self, hFile, lpFileInformation):
        # Not implemented, just return success
        # self.state.memory.store(lpFileInformation, file_attributes.to_bytes(int(self.arch.bits/8), byteorder='little'))

        file_attributes = 0
        self.instrument()
        
        # typedef struct _BY_HANDLE_FILE_INFORMATION {
        # DWORD    dwFileAttributes;
        # FILETIME ftCreationTime;
            # typedef struct _FILETIME {
            # DWORD dwLowDateTime;
            # DWORD dwHighDateTime;
            # } FILETIME, *PFILETIME, *LPFILETIME;
        # FILETIME ftLastAccessTime;
        # FILETIME ftLastWriteTime;
        # DWORD    dwVolumeSerialNumber;
        # DWORD    nFileSizeHigh;
        # DWORD    nFileSizeLow;
        # DWORD    nNumberOfLinks;
        # DWORD    nFileIndexHigh;
        # DWORD    nFileIndexLow;
        # } BY_HANDLE_FILE_INFORMATION, *PBY_HANDLE_FILE_INFORMATION, *LPBY_HANDLE_FILE_INFORMATION;

        #if os.path.isfile(path):
        #file_attributes |= 0x00000020  # FILE_ATTRIBUTE_ARCHIVE
        
        file_attributes = 0x00000080  # FILE_ATTRIBUTE_NORMAL 

        # if os.path.isdir(path):
        # file_attributes |= 0x00000010  # FILE_ATTRIBUTE_DIRECTORY

            # if os.access(path, os.R_OK):
            #     file_attributes |= 0x00000001  # FILE_ATTRIBUTE_READONLY

            # Write the file attributes to the output buffer
        self.fileinfo_ptr =  self.state.mem[lpFileInformation].int.resolved #lpSystemTime
            
        self.state.mem[self.fileinfo_ptr].dword = self.state.solver.BVS("dwFileAttributes{}".format(self.display_name),32) # file_attributes #.to_bytes(int(self.arch.bits/8), byteorder='little')
        
        ftCreationTime = self.state.solver.BVS("ftCreationTime{}".format(self.display_name),32*2)
        self.state.solver.add(ftCreationTime >= 1601)
        self.state.solver.add(ftCreationTime < 30827)
        
        ftLastAccessTime = self.state.solver.BVS("ftLastAccessTime{}".format(self.display_name),32*2)
        self.state.solver.add(ftLastAccessTime >= 1601)
        self.state.solver.add(ftLastAccessTime < 30827)
        
        ftLastWriteTime = self.state.solver.BVS("ftLastWriteTime{}".format(self.display_name),32*2)
        self.state.solver.add(ftLastWriteTime >= 1601)
        self.state.solver.add(ftLastWriteTime < 30827)
        
        self.state.solver.add(ftCreationTime <= ftLastAccessTime)
        self.state.solver.add(ftLastWriteTime <= ftLastAccessTime)
        
        self.state.mem[self.fileinfo_ptr+4].qword  = ftCreationTime # int(time.time() * 1000 * 1000 / 100) # 
        self.state.mem[self.fileinfo_ptr+12].qword = ftLastAccessTime # int(time.time() * 1000 * 1000 / 100) #
        self.state.mem[self.fileinfo_ptr+20].qword = ftLastWriteTime # = int(time.time() * 1000 * 1000 / 100) #
        
        
        dwVolumeSerialNumber = self.state.solver.BVS("dwVolumeSerialNumber{}".format(self.display_name),32)
        self.state.mem[self.fileinfo_ptr+28].dword = dwVolumeSerialNumber
        
        nFileSizeHigh = self.state.solver.BVS("nFileSizeHigh{}".format(self.display_name),32)
        self.state.mem[self.fileinfo_ptr+32].dword = nFileSizeHigh
        
        nFileSizeLow = self.state.solver.BVS("nFileSizeLow{}".format(self.display_name),32)
        self.state.mem[self.fileinfo_ptr+36].dword = nFileSizeLow
        
        nNumberOfLinks = self.state.solver.BVS("nNumberOfLinks{}".format(self.display_name),32)
        self.state.mem[self.fileinfo_ptr+40].dword = nNumberOfLinks
        
        nFileIndexHigh = self.state.solver.BVS("nFileIndexHigh{}".format(self.display_name),32)
        self.state.mem[self.fileinfo_ptr+44].dword = nFileIndexHigh
        
        nFileIndexLow = self.state.solver.BVS("nFileIndexLow{}".format(self.display_name),32)
        self.state.mem[self.fileinfo_ptr+48].dword = nFileIndexLow
        
        return 0x1
    
    def instrument(self):
        if angr.options.USE_SYSTEM_TIMES in self.state.options:
            self.fill_from_timestamp(time.time())
        else:
            self.fill_symbolic()

    def fill_from_timestamp(self, ts):
        self.timestamp = int(ts * 1000 * 1000 / 100)
                    # convert to microseconds, convert to nanoseconds, convert to 100ns intervals

    def fill_symbolic(self):
        self.timestamp = self.state.solver.BVS('SystemTimeAsFileTime', 64, key=('api', 'SystemTimeAsFileTime'))
