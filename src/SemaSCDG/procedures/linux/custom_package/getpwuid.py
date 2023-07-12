import angr
import logging

lw = logging.getLogger("CustomSimProcedureLinux")
logging.getLogger("CustomSimProcedureLinux").setLevel("INFO")


class getpwuid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self, uid):
        lw.info(self.cc)
        """_summary_
        struct passwd {
            char *pw_name;
            char *pw_passwd;
            uid_t pw_uid;       # using unsigned int instead
            gid_t pw_gid;       # using unsigned int instead
            char *pw_gecos;
            char *pw_dir;
            char *pw_shell;
        }; 
        """

        passwd_struct_def = (
            "struct passwd {"
                "char *pw_name;"
                "char *pw_passwd;"
                "unsigned int pw_uid;"       # using unsigned int instead
                "unsigned int pw_gid;"       # using unsigned int instead
                "char *pw_gecos;"
                "char *pw_dir;"
                "char *pw_shell;"
            "}"
        )

        # adding username, pw_name
        pw_name_val = b"user\0"
        pw_name_ptr = self.state.heap.malloc(len(pw_name_val))
        self.state.memory.store(
            pw_name_ptr, 
            self.state.solver.BVV(pw_name_val, len(pw_name_val) * 8)
        )

        # adding home directory, pw_dir
        pw_dir_val = b"/home/user\0"
        pw_dir_ptr = self.state.heap.malloc(len(pw_dir_val))
        self.state.memory.store(
            pw_dir_ptr, 
            self.state.solver.BVV(pw_dir_val, len(pw_dir_val) * 8)
        )

        passwd_struct_SimType = angr.types.parse_type(passwd_struct_def).with_arch(self.state.arch)
        angr.types.register_types(passwd_struct_SimType)
        passwd_struct_size_bytes = int(passwd_struct_SimType.size // 8)
        passwd_struct_ptr = self.state.heap.malloc(passwd_struct_size_bytes)

        # write values to memory
        self.state.mem[passwd_struct_ptr].struct.passwd.pw_name = pw_name_ptr
        self.state.mem[passwd_struct_ptr].struct.passwd.pw_dir = pw_dir_ptr


        return passwd_struct_ptr
