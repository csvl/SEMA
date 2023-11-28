try:
    import tests.tests.linux.linux_test as linux_test
    from clogging.CustomFormatter import CustomFormatter
except:
    import src.SemaSCDG.tests.tests.linux.linux_test as linux_test
    from src.SemaSCDG.clogging.CustomFormatter import CustomFormatter

import logging
import os 

class SemaTests:
    def __init__(self,scdg_tool,args):
        # TODO maybe recreate a neww tool object each time
        # TODO maybe use its own mapping file
        # TODO tests with different arguments
        # TODO use unittest classes
        self.scdg_tool = scdg_tool
        self.scdg_tool.launch_test = False
        self.args = args
        self.log = logging.getLogger("SemaSCDGTests")
        if args.verbose_scdg:
            #logging.getLogger("SemaSCDG").handlers.clear()
            ch = logging.StreamHandler()
            ch.setLevel(logging.INFO)
            ch.setFormatter(CustomFormatter())
            self.log.addHandler(ch)
            self.log.propagate = False
            logging.getLogger("angr").setLevel("INFO")
            logging.getLogger('claripy').setLevel('INFO')
            self.log.setLevel(logging.INFO)
            
            # ch = logging.StreamHandler()
            # ch.setLevel(logging.INFO)
            # ch.setFormatter(CustomFormatter())
            # self.scdg_tool.log.addHandler(ch)
            # self.scdg_tool.log.propagate = False
            # self.scdg_tool.log.setLevel(logging.INFO)
        else :
            self.log.setLevel(logging.ERROR)
        args.verbose_scdg = False
        
    def start_tests(self):
        self.log.info("Starting running samples:")
        # tested_exploration = ["CBFS"]
        # for explo in tested_exploration:
        #     # TODO use config files
        #     self.log.info("Starting running samples with " + explo + " exploration")
        #     self.scdg_tool.expl_method = explo
        #     self.scdg_tool.max_simul_state = 1
        #     self.scdg_tool.timeout = 300
        #     self.scdg_tool.start_scdg(self.args)
        #     self.args.exp_dir = self.args.exp_dir.replace(str(self.scdg_tool.current_exp_dir),str(self.scdg_tool.current_exp_dir+1))
        #     self.args.dir     = self.args.dir.replace(str(self.scdg_tool.current_exp_dir),str(self.scdg_tool.current_exp_dir+1))
        #     self.scdg_tool.current_exp_dir += 1
        #     # self.scdg_tool.current_exp_dir += 1

        self.log.info("Starting linux tests:")
        # linux_test.start_tests(self.scdg_tool.current_exp_dir)
        os.system("ls -al src/SemaSCDG/tests/tests/linux/")
        self.log.info("python3 src/SemaSCDG/tests/tests/linux/linux_test.py ") #  + str(self.scdg_tool.current_exp_dir-1))
        os.system("python3 src/SemaSCDG/tests/tests/linux/linux_test.py ") #  + str(self.scdg_tool.current_exp_dir-1))
        
        
        