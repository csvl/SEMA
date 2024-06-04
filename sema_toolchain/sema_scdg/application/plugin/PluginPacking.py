import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from sandboxes.CuckooInterface import CuckooInterface
import time
import subprocess
import threading
import sys

import avatar2 as avatar2
from unipacker.core import Sample, SimpleClient, UnpackerEngine
from unipacker.utils import RepeatedTimer, InvalidPEFile
#from angr_targets import AvatarGDBConcreteTarget # TODO FIX in submodule

class PluginPacking():

    # TODO : check implementation
    def setup_symbion(nameFile, proj, concrete_target_is_local, call_sim, logger):
        # Getting from a binary file to its representation in a virtual address space
        main_obj = proj.loader.main_object
        os_obj = main_obj.os

        logger.info("OS recognized as : " + str(os_obj))
        logger.info("CPU architecture recognized as : " + str(proj.arch))

        # First set everything up
        GDB_SERVER_IP = '127.0.0.1'
        GDB_SERVER_PORT = 9876

        if not concrete_target_is_local:
            filename = "cuckoo_ubuntu18.04"
            gos = "linux"
            if "win" in os_obj:
                filename = "win10"
                gos = "windows"

            cuckoo = CuckooInterface(name=filename, ossys="linux", guestos=gos, create_vm=False)
            GDB_SERVER_IP = cuckoo.start_sandbox(GDB_SERVER_PORT)
            cuckoo.load_analysis(nameFile)
            remote_binary=cuckoo.start_analysis(nameFile)
            print(GDB_SERVER_IP)
        else:
            # TODO use the one in sandbox
            print("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,nameFile))
            subprocess.Popen("gdbserver %s:%s %s" % (GDB_SERVER_IP,GDB_SERVER_PORT,nameFile),
                                    stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE,
                                    shell=True)
        avatar_gdb = None
        local_ddl_path = call_sim.ddl_loader.calls_dir.replace("calls","windows7_ddls")
        try:
            logger.info("AvatarGDBConcreteTarget("+ GDB_SERVER_IP+","+ str(GDB_SERVER_PORT) +")")
            avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86,
                                                GDB_SERVER_IP, GDB_SERVER_PORT,remote_binary,local_ddl_path)  # TODO modify to send file and update gdbserver conf
        except Exception as e:
            time.sleep(5)
            logger.info("AvatarGDBConcreteTarget failure")
            try:
                avatar_gdb = AvatarGDBConcreteTarget(avatar2.archs.x86.X86, # TODO
                                                GDB_SERVER_IP, GDB_SERVER_PORT,remote_binary,local_ddl_path)
            except Exception as ee:
                exit(-1)

        call_sim.system_call_table = call_sim.ddl_loader.load(proj, False)

        preload = []
        for lib in call_sim.system_call_table:
            for key in call_sim.system_call_table[lib]:
                print(lib)
                preload.append(lib)

        return preload, avatar_gdb

    # TODO : check implementation
    def setup_unipacker(nameFile, nameFileShort, logger):
        try:
            unpacker_heartbeat = RepeatedTimer(120, print, "- still running -", file=sys.stderr)
            event = threading.Event()
            client = SimpleClient(event)
            sample = Sample(nameFile)
            unpacked_file_path = nameFile.replace(nameFileShort,"unpacked_"+nameFileShort)
            engine = UnpackerEngine(sample, unpacked_file_path)
            logger.info("Unpacking process with unipacker")
            engine.register_client(client)
            unpacker_heartbeat.start()
            threading.Thread(target=engine.emu).start()
            event.wait()
            unpacker_heartbeat.stop()
            engine.stop()
            return unpacked_file_path
        except InvalidPEFile as e:
            logger.error("Unexpected usage of unipacker")
            raise e

    # TODO : implement
    def setup_bin_dmp():
        #     main_opt = {'backend': 'blob', "arch":"x86","simos":"windows"}#cle.Blob(nameFile,arch=avatar2.archs.x86.X86,binary_stream=True)
        #     #nameFile = loader
        #     main_opt = {} #0x0005f227 0x400000 0x001191f7
        #     proj = angr.Project(
        #         nameFile,
        #         use_sim_procedures=True,
        #         load_options={
        #             "auto_load_libs": True
        #         },  # ,load_options={"auto_load_libs":False}
        #         support_selfmodifying_code=True if not nameFile.endswith(".dmp") else False,
        #         main_opts=main_opt,
        #         #simos = "windows"if nameFile.endswith(".bin") or nameFile.endswith(".dmp") else None
        #         # arch="",
        #     )
        #     main_obj = proj.loader.main_object
        #     first_sec = False
        #     libs = []
        #     dll = []
        #     for sec in main_obj.sections:
        #         name = sec.name.replace("\x00", "")
        #         if not first_sec:
        #             first_sec = True
        #         else:
        #             if "KERNELBASE.dll" in name:
        #                 name = name.replace("KERNELBASE.dll","KernelBase.dll")
        #             dll.append(name.split("\\")[-1])
        #             print(dll)
        #             libs.append(name.replace("C:\\",self.call_sim.ddl_loader.calls_dir.replace("calls","windows10_ddls/C:/")).replace("\\","/")) # .replace("system","System")
        #             self.log.info(name)
        #             #self.log.info(dump_file["sections"][name])
        #     t_0x0548 = proj.loader.main_object.get_thread_registers_by_id() # 0x1b30 0x0548 0x13c4 0x1ecc 0x760
        #     print(t_0x0548)
        #     print(hex(t_0x0548["eip"]) )
        #     # print(proj.loader.memory[t_0x0548["esp"]])
        #     main_opt = {"entry_point":t_0x0548["eip"]} # "entry_point":t_0x0548["eip"]
        #     print(main_opt)
        #     #exit()
        #     proj = angr.Project(
        #         nameFile,
        #         use_sim_procedures=True, # if not nameFile.endswith(".dmp") else False,
        #         load_options={
        #             "auto_load_libs": True,
        #             "load_debug_info": True,
        #             #"preload_libs": libs,
        #         },  # ,load_options={"auto_load_libs":False}
        #         support_selfmodifying_code=True, #if not nameFile.endswith(".dmp") else False,
        #         main_opts=main_opt,
        #         #simos = "windows"if nameFile.endswith(".bin") or nameFile.endswith(".dmp") else None
        #         # arch="",
        #     )
        #     symbs = proj.loader.symbols
        #     for symb in symbs:
        #         print(symb)
        #     print(symbs)
        #     print(proj.loader.shared_objects)
        #     print(proj.loader.all_objects)
        #     print(proj.loader.requested_names)
        #     print(proj.loader.initial_load_objects)
        #     for register in t_0x0548:
        #         print(register,hex(t_0x0548[register]))
        #     #exit()
        pass
