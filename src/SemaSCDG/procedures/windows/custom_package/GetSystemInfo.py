import logging
import angr
import struct

lw = logging.getLogger("CustomSimProcedureWindows")

class GetSystemInfo(angr.SimProcedure):
    def run(self, system_info_ptr):
        # Specify the SYSTEM_INFO structure values
        processor_architecture      = 0x8664 # value for x64 architecture
        page_size                   = 0x1000 # 4 KB page size
        minimum_application_address = 0x1000000 # 16 MB
        maximum_application_address = 0x7fffffff # 2 GB
        active_processor_mask       = 0xffffffff # all processors active
        number_of_processors        = 4 # example value
        processor_type              = 0x5658 # example value
        allocation_granularity      = 0x10000 # 64 KB
        reserved                    = 0 # reserved field
        
        # Pack the SYSTEM_INFO structure values into a bytearray
        system_info = struct.pack("<HHIIIII",
                                  processor_architecture,
                                  reserved,
                                  page_size,
                                  minimum_application_address,
                                  maximum_application_address,
                                  active_processor_mask,
                                  number_of_processors)
        system_info += struct.pack("<II", processor_type, allocation_granularity)
        
        # Write the SYSTEM_INFO structure values to the specified memory location
        self.state.memory.store(system_info_ptr, system_info)
        return 1 # returns a non-zero value to indicate success