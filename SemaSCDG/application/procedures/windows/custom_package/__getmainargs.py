import angr
import logging
import claripy
import struct

lw = logging.getLogger("CustomSimProcedureWindows")

# class __getmainargs(angr.SimProcedure):
#     def run(self, argc, argv, env, do_wildcard, start_info):
#         # Obtain a handle to the current process
#         lw.info("kaka")
#         # # malloc memory for argc and store the argument count in it
#         # argc_mem = self.state.heap.malloc(4) 
#         # #self.state.solver.add(argc == 5)
#         # self.state.memory.store(argc_mem, argc, endness=self.arch.memory_endness)
#         # #self.state.mem[argc].store(argc, endness=self.arch.memory_endness)
        
        
        
#         # # malloc memory for argv and store the argument values in it
#         # argv_mem = self.state.heap.malloc(4 * argc)
#         # for i, arg in enumerate(argv):
#         #     arg_mem = self.state.heap.malloc(len(arg) + 1)
#         #     self.state.memory.store(arg_mem,arg)
#         #     self.state.memory.store(arg_mem+len(arg),0)
#         #     self.state.memory.store(argv_mem + i * 4, arg_mem) # :argv_mem + (i + 1) * 4
        
#         # # malloc memory for env and store the environment variables in it
#         # env_mem = self.state.heap.malloc(4 * len(env))
#         # for i, e in enumerate(env):
#         #     env_var_mem = self.state.heap.malloc(len(e) + 1)
#         #     self.state.memory.store(env_var_mem, e)
#         #     self.state.memory.store(env_var_mem+len(e),0)
#         #     self.state.memory.store(env_mem + i * 4, env_var_mem) # :env_mem + (i + 1) * 4
        
#         # Return the value indicating success
#         # argc = self.state.se.BVV(0, self.state.arch.bits)
#         # argv = self.state.se.BVV(0, self.state.arch.bits)
#         # envp = self.state.se.BVV(0, self.state.arch.bits)

#         # # Add the values to the return tuple
#         # self.return_expr = argc, argv, envp

#         # return self.return_expr
#         return 0

class __getmainargs(angr.SimProcedure):
    #pylint:disable=arguments-differ,unused-argument

    def run(self, argc_p, argv_ppp, env_ppp, dowildcard, startupinfo_p):
        if any(map(self.state.solver.symbolic, [argc_p, argv_ppp, env_ppp])):
            raise angr.errors.SimProcedureError("__getmainargs cannot handle symbolic pointers")
        
        lw.info("argc_p: " + str(argc_p))
        lw.info("argv_ppp: " + str(argv_ppp))
        lw.info("env_ppp: " + str(env_ppp))
        lw.info("self.state.posix.argc: " + str(self.state.posix.argc))
        lw.info("self.state.posix.argv: " + str(self.state.posix.argv))
        lw.info("self.state.posix.environ: " + str(self.state.posix.environ))

        self.state.memory.store(argc_p, self.state.posix.argc, endness=self.state.arch.memory_endness)
        self.state.memory.store(argv_ppp, self.state.posix.argv, endness=self.state.arch.memory_endness)
        self.state.memory.store(env_ppp, self.state.posix.environ, endness=self.state.arch.memory_endness)

        #return 0
        #self.state.regs.al = 0
        return self.state.solver.BVV(0,self.state.arch.bits) # self.state.regs.al # self.state.solver.BVV(0,8) # AL:1 bytes

# class __getmainargs(angr.SIM_PROCEDURES['win32']['__getmainargs']):
#     # Override the run method to create a custom sim procedure

#     def run(self, argc_ptr, argv_ptr_ptr, env_ptr_ptr, do_wildcard, startup_info_ptr):
#         # Get the state and the memory model
#         state = self.state
#         mem = state.memory

#         # Define symbolic variables for argc, argv, and env
#         argc = claripy.BVS('argc', 32)
#         argv_ptr = claripy.BVS('argv_ptr', 32)
#         env_ptr = claripy.BVS('env_ptr', 32)

#         # Allocate memory for storing the command-line arguments and environment variables
#         argc_val = argc.zero_extend(32 - argc.size())
#         argv_val = mem.allocate(4)
#         env_val = mem.allocate(4)

#         # Get the command-line arguments from the state
#         arg_list = state.args[1:]

#         # Convert the arguments to the appropriate format (e.g., UTF-8)
#         argv = [mem.allocate(len(arg)) for arg in arg_list]
#         for i, arg in enumerate(arg_list):
#             mem.store(argv[i], arg.encode('utf-8'))

#         # Pack the pointers to argc and argv and store them in the memory
#         argc_packed = struct.pack('<I', argc_val)
#         argv_packed = struct.pack('<I', argv_val)
#         mem.store(argc_ptr, argc_packed)
#         mem.store(argv_ptr_ptr, argv_packed)

#         # Update the values of argc and argv to point to the allocated memory
#         mem.store(argv_val, struct.pack('<I', len(arg_list)))
#         mem.store(argv_ptr, argv[0])
#         mem.store(env_ptr_ptr, struct.pack('<I', env_val))

#         # Return to the normal control flow of the program
#         return (argc_val, argv_val, env_val)
    
    