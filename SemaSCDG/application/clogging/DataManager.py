import pandas as pd
import datetime
import json
import logging

from clogging.CustomFormatter import CustomFormatter

class DataManager():
    def __init__(self, log_level):
        self.log_level = log_level
        self.config_logger()
        self.dataframe = None
        self.data = dict()
        self.data["instr_dict"] = {}
        self.data["block_dict"] = {}

    #Set up the logger
    def config_logger(self):
        self.log = logging.getLogger("DataManager")
        ch = logging.StreamHandler()
        ch.setLevel(self.log_level)
        ch.setFormatter(CustomFormatter())
        self.log.addHandler(ch)
        self.log.propagate = False
        self.log.setLevel(self.log_level)

    #Check if the csv file exists, if not, create and return a Dataframe
    def setup_csv(self, csv_file_path):
        try:
            df = pd.read_csv(csv_file_path,sep=";")
            self.log.info(df)
        except:
            df = pd.DataFrame(
                columns=["family",
                            "filename", 
                            "time",
                            "date",
                            "Syscall found", 
                            "EnvVar found",
                            "Locale found",
                            "Resources found",
                            "Registry found",
                            "Address found", 
                            "Libraries",
                            "OS",
                            "CPU architecture",
                            "Entry point",
                            "Min/Max addresses",
                            "Stack executable",
                            "Binary position-independent",
                            "Total number of blocks",
                            "Total number of instr",
                            "Number of blocks visited",
                            "Number of instr visited",
                            ]) # TODO add frame type
        self.dataframe = df
    
    # Save project information into a csv file or append the data to an existing csv file
    def save_to_csv(self, proj, family, call_sim, csv_file_path):
        to_append = pd.DataFrame({"family":family,
                    "filename": self.data["nameFileShort"], 
                    "time": self.data["elapsed_time"],
                    "date":datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    
                    "Syscall found": json.dumps(call_sim.syscall_found),  
                    "EnvVar found": json.dumps(self.data.get("total_env_var", -1)), 
                    "Locale found": json.dumps(self.data.get("total_locale", -1)), 
                    "Resources found": json.dumps(self.data.get("total_res", -1)), 
                    "Registry found": json.dumps(self.data.get("total_registery", -1)), 
                    
                    "Number Address found": 0, 
                    "Number Syscall found": sum(call_sim.syscall_found.values()), 
                    "Libraries":str(proj.loader.requested_names),
                    "OS": proj.loader.main_object.os,
                    "CPU architecture": proj.loader.main_object.arch.name,
                    "Entry point": proj.loader.main_object.entry,
                    "Min/Max addresses": str(proj.loader.main_object.mapped_base) + "/" + str(proj.loader.main_object.max_addr),
                    "Stack executable": proj.loader.main_object.execstack,
                    "Binary position-independent:": proj.loader.main_object.pic,
                    "Total number of different blocks": self.data.get("nbblocks", -1),
                    "Total number of different instr": self.data.get("nbinstr", -1),
                    "Number of different block visited": len(self.data.get("block_dict", {})),
                    "Number of different instruction visited": len(self.data.get("instr_dict", {})),
                    "Number of blocks visited": sum(self.data.get("block_dict", {}).values()),
                    "Number of instr visited": sum(self.data.get("instr_dict", {}).values()),
                }, index=[1])
        df = pd.concat([self.dataframe, to_append], ignore_index=True)
        df.to_csv(csv_file_path, index=False,sep=";")


    # count total number of blocks and instructions
    def count_block(self, proj, main_obj):
        nbinstr = 0
        nbblocks = 0
        vaddr = 0
        memsize = 0
        for sec in main_obj.sections:
            name = sec.name.replace("\x00", "")
            if name == ".text":
                vaddr = sec.vaddr
                memsize = sec.memsize
        i = vaddr
        
        while i < vaddr + memsize:
            block = proj.factory.block(i)
            nbinstr += block.instructions
            nbblocks += 1
            if len(block.bytes) == 0:
                i += 1
                nbblocks -= 1
            else:
                i += len(block.bytes)
        self.data["nbblocks"] = nbblocks
        self.data["nbinstr"] = nbinstr
    
    #Print state address if verbose set to True
    def print_state_address(self, state):
        self.log.debug(hex(state.addr))
                
    # Add the instruction into the instructions set
    def add_instr_addr(self, state):
        self.data["instr_dict"][state.addr] = self.data["instr_dict"].get(state.addr,0) + 1
            
    # Add the block address into the block address set
    def add_block_addr(self, state):
        self.data["block_dict"][state.inspect.address] = self.data["block_dict"].get(state.inspect.address,0) + 1

    # Add information from plugin into the stats Dataframe and print info if verbose
    def get_plugin_data(self, state, simgr, to_store=False):
        if state.has_plugin("plugin_env_var"):
            total_env_var = state.plugin_env_var.ending_state(simgr)
            if to_store:
                self.data["total_env_var"] = total_env_var
            self.log.info("Environment variables:" + str(total_env_var))
        if state.has_plugin("plugin_registery"):
            total_registery = state.plugin_registery.ending_state(simgr)
            if to_store:
                self.data["total_registery"] = total_registery
            self.log.info("Registery variables:" + str(total_registery))
        if state.has_plugin("plugin_locale_info"):
            total_locale = state.plugin_locale_info.ending_state(simgr)
            if to_store:
                self.data["total_locale"] = total_locale
            self.log.info("Locale informations variables:" + str(total_locale))
        if state.has_plugin("plugin_resources"): 
            total_res = state.plugin_resources.ending_state(simgr)
            if to_store:
                self.data["total_res"] = total_res
            self.log.info("Resources variables:" + str(total_res))

    #Log information about instructions and blocks
    def print_block_info(self):
        self.log.info("Total number of blocks: " + str(self.data["nbblocks"]))
        self.log.info("Total number of instr: " + str(self.data["nbinstr"]))
        self.log.info("Number of blocks visited: " + str(sum(self.data["block_dict"].values())))
        self.log.info("Number of instr visited: " + str(sum(self.data["instr_dict"].values())))