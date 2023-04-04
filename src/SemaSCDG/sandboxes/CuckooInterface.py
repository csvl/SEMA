from .SandBoxInterface import SandBoxInterface
from .vm.kvm.KVMInterface import KVMInterface
from .vm.virtualbox import VirtualBoxInterface
import os
import subprocess
import time
import shlex
# import cuckoo #python 2.7 

class CuckooInterface(SandBoxInterface):
    """
    sources: inspired from https://github.com/keithjjones/cuckoo-api/blob/master/CuckooAPI/__init__.py
    """
    def __init__(self, name:str, ossys="linux", guestos="windows", create_vm=True):
        self.vm = None
        self.name = name
        self.guestos = guestos
        self.guest_ip = ""
        self.init_vm(name, ossys, guestos, create_vm)

    def init_vm(self, name, ossys, guestos, create_vm):
        if ossys == "linux":
            import libvirt
            conf= os.getcwd() + "/sandboxes/vm/kvm/config/win7.xml"
            conf_vol= os.getcwd() + "/sandboxes/vm/kvm/config/vol.xml"
            conf_pool= os.getcwd() + "/sandboxes/vm/kvm/config/pool.xml"
            if guestos == "linux":
                conf= os.getcwd() + "/sandboxes/vm/kvm/config/ub18.xml"
            self.vm = KVMInterface(name, name+"_filename", config_vol=conf_vol, config_pool=conf_pool, 
                                   config=conf, create_vm=create_vm, image="/var/lib/libvirt/images/en_windows_7_ultimate_x64_dvd.iso")
            
        elif ossys == "windows":
            self.vm = VirtualBoxInterface() # TODO
        
    def udpdate_conf(self):
        file = open("/home/crochetch/Documents/toolchain_malware_analysis/src/sandboxes/.cuckoo/conf/qemu_template.conf",mode='r')
        # read all lines at once
        self.quemu_conf = file.read()
        self.quemu_conf = self.quemu_conf.replace(":ip:",self.guest_ip)
        self.quemu_conf = self.quemu_conf.replace(":image:",self.vm.name)
        self.quemu_conf = self.quemu_conf.replace(":platform:",self.guestos)
        print(self.quemu_conf)
        file.close()
        file = open("/home/crochetch/Documents/toolchain_malware_analysis/src/sandboxes/.cuckoo/conf/qemu.conf",mode='w')
        file.write(self.quemu_conf)
        file.close()

    # TODO change this !!
    def start_sandbox(self):
        try:
            self.vm.start_vm()
            time.sleep(10) # TODO
        except Exception as e:
            pass
        # import libvirt
        # ifaces = self.vm.dom.interfaceAddresses(libvirt.VIR_DOMAIN_INTERFACE_ADDRESSES_SRC_AGENT, 0)
        # print("The interface IP addresses:")
        # for (name, val) in ifaces.iteritems():
        #     if val['addrs']:
        #         for ipaddr in val['addrs']:
        #             if ipaddr['type'] == libvirt.VIR_IP_ADDR_TYPE_IPV4:
        #                 print(ipaddr['addr'] + " VIR_IP_ADDR_TYPE_IPV4")
        #                 self.guest_ip = ipaddr['addr']
        #             elif ipaddr['type'] == libvirt.VIR_IP_ADDR_TYPE_IPV6:
        #                 print(ipaddr['addr'] + " VIR_IP_ADDR_TYPE_IPV6")
        #                 self.guest_ip = ipaddr['addr']
        cmd='for mac in `virsh domiflist ' + self.name + ' |grep -o -E "([0-9a-f]{2}:){5}([0-9a-f]{2})"` ; do arp -e |grep $mac  |grep -o -P "^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}" ; done'
        print(cmd)
        args = shlex.split(cmd)
        print(args)
        #output = subprocess.call(cmd,shell=True, executable='/bin/bash')
        #output = subprocess.check_output(args, shell=True, executable='/bin/bash')
        self.guest_ip = subprocess.run(cmd ,shell=True, executable='/bin/bash', stdout=subprocess.PIPE,encoding="utf-8").stdout
        self.guest_ip = self.guest_ip.replace("\n","")
        #output = subprocess.Popen(args,stdout = subprocess.PIPE,shell=True, executable='/bin/bash',encoding="utf-8").stdout
        #print(output.stdout.decode())
        # print(rc)
        print(self.guest_ip)
        self.udpdate_conf()

    def load_analysis(self,file):
        # TODO pre post, check sandbox started etc
        cmd = "source load_analysis_cuckoo.sh " + file
        rc = subprocess.call(cmd,shell=True, executable='/bin/bash')

    def start_analysis(self):
        cmd = "source start_analysis_cuckoo.sh "
        rc = subprocess.call(cmd,shell=True, executable='/bin/bash')

    def stop_sandbox(self):
        self.vm.stop_vm()

    def get_address(self):
        # TODO
        return 0x85b853


        