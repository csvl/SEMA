import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
from SandBoxInterface import SandBoxInterface
from vm.kvm.KVMInterface import KVMInterface
from vm.virtualbox import VirtualBoxInterface
import os
import subprocess
import time
import shlex
# import cuckoo #python 2.7

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))


class CuckooInterface(SandBoxInterface):
    """
    sources: inspired from https://github.com/keithjjones/cuckoo-api/blob/master/CuckooAPI/__init__.py
    """
    def __init__(self, name:str, ossys="linux", guestos="windows", create_vm=True):
        self.vm = None
        self.name = name
        self.guestos = guestos
        self.guest_ip = ""
        self.gdb_port = 0
        self.home_dir = ""
        self.win_name = ""
        self.init_vm(name, ossys, guestos, create_vm)

    def init_vm(self, name, ossys, guestos, create_vm):
        if ossys == "linux":
            import libvirt
            if False:
                conf= ROOT_DIR + "/vm/kvm/config/win7.xml"
                image="/var/lib/libvirt/images/en_windows_7_ultimate_x64_dvd.iso"
                self.win_name="win7"
            else:
                conf= ROOT_DIR + "/vm/kvm/config/win10.xml"
                image="/home/crochetch/Documents/PhD/VMImages/images/Win10_22H2_English_x64.iso" # TODO
                self.win_name="win10"
            conf_vol=ROOT_DIR + "/vm/kvm/config/vol.xml"
            conf_pool= ROOT_DIR + "/vm/kvm/config/pool.xml"
            self.home_dir = "C:\\\\Users\\\\user\\\\Desktop\\\\" # Users\\\\user\\\\Desktop\\\\
            if guestos == "linux":
                conf= ROOT_DIR + "/vm/kvm/config/ub18.xml"
                self.home_dir = "/home/user/"
            self.vm = KVMInterface(name, name+"_filename", config_vol=conf_vol, config_pool=conf_pool,
                                   config=conf, create_vm=create_vm, image=image,
                                   guestos=self.guestos)

        elif ossys == "windows":
            self.vm = VirtualBoxInterface() # TODO

    def udpdate_conf(self):
        file = open(ROOT_DIR + "/.cuckoo/conf/qemu_template.conf",mode='r')
        # read all lines at once
        self.quemu_conf = file.read()
        self.quemu_conf = self.quemu_conf.replace(":ip:",self.guest_ip)
        self.quemu_conf = self.quemu_conf.replace(":image:",self.vm.name)
        self.quemu_conf = self.quemu_conf.replace(":platform:",self.guestos)
        print(self.quemu_conf)
        file.close()
        file = open(ROOT_DIR + "/.cuckoo/conf/qemu.conf",mode='w')
        file.write(self.quemu_conf)
        file.close()

    # TODO change this !!
    def start_sandbox(self, gdb_port):
        self.gdb_port = gdb_port
        try:
            self.vm.start_vm()
            time.sleep(10) # TODO wait for VM to be up
        except Exception as e:
            pass
        if "win" in self.name:
            cmd='for mac in `virsh domiflist ' + self.win_name + ' |grep -o -E "([0-9a-f]{2}:){5}([0-9a-f]{2})"` ; do arp -e |grep $mac  |grep -o -P "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" ; done'
        else:
            cmd='for mac in `virsh domiflist ' + self.name + ' |grep -o -E "([0-9a-f]{2}:){5}([0-9a-f]{2})"` ; do arp -e |grep $mac  |grep -o -P "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" ; done'
        print(cmd)
        args = shlex.split(cmd)
        print(args)
        self.guest_ip = subprocess.run(cmd ,shell=True, executable='/bin/bash', stdout=subprocess.PIPE,encoding="utf-8").stdout
        self.guest_ip = self.guest_ip.replace("\n","")
        print(self.guest_ip)
        self.udpdate_conf()

        return self.guest_ip

    def load_analysis(self,file):
        # TODO pre post, check sandbox started etc
        cmd = "bash " + ROOT_DIR + "/load_analysis_cuckoo.sh " + file
        rc = subprocess.call(cmd,shell=True, executable='/bin/bash')

    def start_analysis(self,file):
        cmd =  "bash " + ROOT_DIR + "/start_analysis_cuckoo.sh "
        rc = subprocess.call(cmd,shell=True, executable='/bin/bash')

        # Note: the following command is now integrated directly in avatar target
        filet = open(ROOT_DIR + "/gdb-script/connect_template.gdb",mode='r')
        gdb_conf = filet.read()
        gdb_conf = gdb_conf.replace(":ip:",self.guest_ip)
        gdb_conf = gdb_conf.replace(":port:",str(self.gdb_port))
        gdb_conf = gdb_conf.replace(":input:",file)
        output = file.split("/")[-1]
        print(output)
        gdb_conf = gdb_conf.replace(":output:", self.home_dir+output)
        print(gdb_conf)
        filet.close()
        filet = open(ROOT_DIR + "/gdb-script/connect.gdb",mode='w')
        filet.write(gdb_conf)
        filet.close()
        print("gdb --batch --command="+ ROOT_DIR + "/gdb-script/connect.gdb")
        #subprocess.call("gdb --batch --command="+ ROOT_DIR + "/gdb-script/connect.gdb",shell=True, executable='/bin/bash')
        return [file,self.home_dir+output]

    def stop_sandbox(self):
        self.vm.stop_vm()

    def get_address(self):
        # TODO
        return 0x85b853
