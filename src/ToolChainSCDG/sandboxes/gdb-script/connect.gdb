# http://sourceware.org/gdb/wiki/FAQ: to disable the
# "---Type <return> to continue, or q <return> to quit---"
# in batch mode:
# https://sourceware.org/gdb/wiki/BuildingCrossGDBandGDBserver


#set sysroot remote:/


#file /home/crochetch/Documents/Projects/MalwareAnalysis/SEMA-ToolChain-packing/src/submodules/binaries/tests/x86/windows/packed_pe32.exe

#set debug remote on

target extended-remote 192.168.122.8:9876 

remote put /home/crochetch/Documents/Projects/MalwareAnalysis/SEMA-ToolChain-packing/src/submodules/binaries/tests/x86/windows/packed_pe32.exe C:\\Users\\user\\Desktop\\packed_pe32.exe

set remote exec-file C:\\Users\\user\\Desktop\\packed_pe32.exe

#quit
# cont