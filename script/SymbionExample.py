import subprocess
import os
import nose
import avatar2 as avatar2
import sys
                                                       
import angr
import claripy
from angr_targets import AvatarGDBConcreteTarget


## OEP : 0x400b95

# https://angr.io/blog/angr_symbion/
# https://issueexplorer.com/issue/angr/angr/2858


GDB_SERVER_IP = '127.0.0.1'
GDB_SERVER_PORT = 9876

# First set everything up
# binary_x64 = os.path.join(os.path.dirname(os.path.realpath(__file__)),
#                                           os.path.join('..', 'binaries',
#                                           'tests','x86_64',
#                                           'packed_elf64'))

binary_x64 = "/home/crochetch/Documents/SEMA-ToolChain/src/submodules/binaries/tests/x86_64/packed_elf64"

# Spawning of the gdbserver analysis environment
print("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary_x64))
subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,binary_x64),
                  stdout=subprocess.PIPE,
                  stderr=subprocess.PIPE,
                  shell=True)

# Instantiation of the AvatarGDBConcreteTarget
avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86_64,
                                     GDB_SERVER_IP, GDB_SERVER_PORT)                                                                        
#sys.exit()
# Creation of the project with the new attributes 'concrete_target'
p = angr.Project(binary_x64, concrete_target=avatar_gdb,
                             use_sim_procedures=True)

entry_state = p.factory.entry_state()
entry_state.options.add(angr.options.SYMBION_SYNC_CLE)
entry_state.options.add(angr.options.SYMBION_KEEP_STUBS_ON_SYNC)

simgr = p.factory.simgr(entry_state)

## Now, let's the binary unpack itself
simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x85b853]))
exploration = simgr.run()

new_concrete_state = exploration.stashes['found'][0]

# Hit the new stub 4 times before having our unpacked code at 0x400cd6
for i in range(0,4):
    simgr = p.factory.simgr(new_concrete_state)
    simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x85b853]))
    exploration = simgr.run()
    new_concrete_state = exploration.stashes['found'][0]

## Reaching the first decision point
simgr = p.factory.simgr(new_concrete_state)
simgr.use_technique(angr.exploration_techniques.Symbion(find=[0x400cd6]))
exploration = simgr.run()
new_concrete_state = exploration.stashes['found'][0]
print("[1]exploration: " + str(exploration))

# Declaring a symbolic buffer
arg0 = claripy.BVS('arg0', 8*32)

# The address of the symbolic buffer would be the one of the
# hardcoded malware configuration
symbolic_buffer_address = new_concrete_state.regs.rbp-0xc0

concrete_memory_2 = new_concrete_state.memory.load(symbolic_buffer_address, 36)
assert(not concrete_memory_2.symbolic)

# Setting the symbolic buffer in memory!
new_concrete_state.memory.store(symbolic_buffer_address, arg0)

# We should read symbolic data from the page now
symbolic_memory = new_concrete_state.memory.load(symbolic_buffer_address, 36)
assert(symbolic_memory.symbolic)

simgr = p.factory.simgr(new_concrete_state)

# https://angr.io/img/symbion_ex1.png
DROP_STAGE2_V2 = 0x400d99
DROP_STAGE2_V1 = 0x400d6a
VENV_DETECTED = 0x400da5
FAKE_CC = 0x400db9
BINARY_EXECUTION_END = 0x400dcd 

find_addr=DROP_STAGE2_V2
avoid_addrs=[DROP_STAGE2_V1, VENV_DETECTED, FAKE_CC]

print("[2]Symbolically executing binary to find dropping of second stage " +
       "[ address:  " + hex(DROP_STAGE2_V2) + " ]")

# # Symbolically explore the malware to find a specific behavior by avoiding
# # evasive behaviors

# exploration = simgr.explore(find=[DROP_STAGE2_V2], avoid=[DROP_STAGE2_V1,
#                                                         VENV_DETECTED, FAKE_CC ])

simgr.use_technique(angr.exploration_techniques.DFS())
simgr.use_technique(angr.exploration_techniques.Explorer(find=find_addr, avoid=avoid_addrs))

new_concrete_state.globals["hit_malloc_sim_proc"] = False
new_concrete_state.globals["hit_memcpy_sim_proc"] = False

def check_hooked_simproc(state):
    sim_proc_name = state.inspect.simprocedure_name
    if sim_proc_name == "malloc":
        state.globals["hit_malloc_sim_proc"] = True
    elif sim_proc_name == "memcpy":
        state.globals["hit_memcpy_sim_proc"] = True

new_concrete_state.inspect.b('simprocedure', action=check_hooked_simproc)

exploration = simgr.explore()

print("[2]exploration: " + str(exploration))

# for angr buggy version
#print("simgr.errored[0].debug() %s", simgr.errored[0].debug())
#print("simgr.errored[0].reraise() \n %s", simgr.errored[0].reraise())

# Get our synchronized state back!
new_symbolic_state = simgr.stashes['found'][0]

print("[3]Executing binary concretely with solution found until the end " +hex(BINARY_EXECUTION_END))

simgr = p.factory.simgr(new_symbolic_state)

# Concretizing the solution to reach the interesting behavior in the memory
# of the concrete process and resume until the end of the execution.
simgr.use_technique(angr.exploration_techniques.Symbion(find=[BINARY_EXECUTION_END],
                              memory_concretize = [(symbolic_buffer_address,arg0)],
                              register_concretize =[]))
                              
exploration = simgr.run()
new_concrete_state = exploration.stashes['found'][0]