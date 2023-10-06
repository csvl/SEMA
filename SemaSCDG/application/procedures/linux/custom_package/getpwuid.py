import angr
import logging

lw = logging.getLogger("CustomSimProcedureLinux")
logging.getLogger("CustomSimProcedureLinux").setLevel("INFO")

class getpwuid(angr.SimProcedure):
    # pylint: disable=arguments-differ
    def run(self,uid):
        lw.info(self.cc)
        """_summary_
        struct passwd {
            char *pw_name;
            char *pw_passwd;
            uid_t pw_uid;
            gid_t pw_gid;
            time_t pw_change;
            char *pw_class;
            char *pw_gecos;
            char *pw_dir;
            char *pw_shell;
            time_t pw_expire;
        }; 
        """
        passwd_struc = self.state.solver.BVV(50) # TODO better struct
        ret_len = len(50)
        passwd_struc_ptr = self.state.heap._malloc(ret_len)
        self.state.memory.store(
            passwd_struc_ptr, passwd_struc
        )  # ,endness=self.arch.memory_endness)
        return passwd_struc_ptr
