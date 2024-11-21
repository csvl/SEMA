import os
import sys


from unix import Local, Remote, UnixError
from unix.linux import Linux
import kvm # hypervisor (https://pypi.org/project/kvm/)
import json
import logging

# import libvirt # VMs manager
import sys
import os
import inspect

# currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
# parentdir = os.path.dirname(currentdir)
# sys.path.insert(0, parentdir)

from VMInterface import VMInterface

"""
TODO volume should be deleted by hand for now
"""
class KVMInterface(VMInterface):
    def __init__(self, name: str, filename:str, config:str, config_vol:str, config_pool:str, image:str,
                 mem_mb=4194304, vcpu=2, capacity = 45, create_vm=False, user="user",password="user",guestos="linux"):

        self.user = user
        self.password = password
        self.filename = '/var/lib/libvirt/save/'+filename+'.img'
        self.name = name
        self.new_name = name
        if not guestos == "linux":
            self.new_name = "win10" #todo
            if False:#TODO
                self.new_name="win7"
        self.mem_mb = mem_mb
        self.image = image
        self.vcpu = vcpu
        self.capacity = capacity
        # Maybe useless
        self.localhost = kvm.Hypervisor(Linux(Local()))

        self.log = logging.getLogger("KVMInterface")
        self.log.setLevel("INFO")
        self.log.info(self.localhost.hypervisor.nodeinfo())

        self.conn = None
        try:
            self.conn = libvirt.open('qemu:///system') #KVM-QEMU
            #slef.conn = libvirt.openAuth('qemu+tcp://localhost/system', auth, 0)
        except libvirt.libvirtError as e:
            self.log.info('libvirt:' + str(e))
            exit(1)

        self.update_global_config(config)

        self.update_pool_config(config_pool)

        self.update_volume_config(config_vol)

        self.dom = None
        if create_vm:
            self.create_vm()

        self.get_vm_infos()

        try:
            self.dom = self.conn.lookupByName(self.new_name)
        except libvirt.libvirtError:
            self.log.info('libvirt: Failed to find the main domain')
            sys.exit(1)

    def request_cred(self,credentials, user_data):
        for credential in credentials:
            if credential[0] == libvirt.VIR_CRED_AUTHNAME:
                credential[4] = self.user
            elif credential[0] == libvirt.VIR_CRED_PASSPHRASE:
                credential[4] = self.password
        return 0

    def update_volume_config(self, config_vol):
        self.xml_vol_config = None
        if config_vol:
            file = open(config_vol,mode='r')
            # read all lines at once
            self.xml_vol_config = file.read()
            self.xml_vol_config = self.xml_vol_config.replace("$name$",self.new_name)
            self.xml_vol_config = self.xml_vol_config.replace("$capacity$",str(self.capacity))
            # close the file
            file.close()
            print(self.xml_vol_config)
            self.log.info(self.xml_vol_config)

    def update_pool_config(self, config_pool):
        self.xml_pool_config = None
        self.pool = None
        if config_pool:
            file = open(config_pool,mode='r')
            # read all lines at once
            self.xml_pool_config = file.read()
            self.xml_pool_config = self.xml_pool_config.replace("$name$",self.new_name)
            # close the file
            file.close()
            print(self.xml_pool_config)
            self.log.info(self.xml_pool_config)

    def update_global_config(self, config):
        if config:
            file = open(config,mode='r')
            # read all lines at once
            self.xml_config = file.read()
            self.xml_config = self.xml_config.replace("$name$",self.new_name)
            self.xml_config = self.xml_config.replace("$mem_mb$",str(self.mem_mb))
            self.xml_config = self.xml_config.replace("$vcpu$",str(self.vcpu))
            self.xml_config = self.xml_config.replace("$image$",self.image)
            # close the file
            file.close()
            print(self.xml_config)
            self.log.info(self.xml_config)
        else:
            self.xml_config = None

    def create_vm(self):
        if self.new_name: # try catch
            try:
                #self.pool = self.conn.storagePoolDefineXML(self.xml_pool_config, 0) # TODO for custom "pool"
                self.pool = self.conn.storagePoolLookupByName("default")
                self.pool.setAutostart(1)
                #self.pool.create()  # TODO for custom "pool"
            except libvirt.libvirtError as e:
                self.log.info(e)

            try:
                self.pool.createXML(self.xml_vol_config, 0)
            except libvirt.libvirtError as e:
                self.log.info(e)

            try:
                self.dom = self.conn.defineXML(self.xml_config)
                self.dom.create()
            except libvirt.libvirtError as e:
                self.log.info(e)
        else:
            self.log.info('libvirt: Failed to create the main domain')
            sys.exit(1)

    def start_vm(self):
        self.dom = self.conn.lookupByName(self.new_name)
        self.dom.create()

    def stop_vm(self):
        self.dom.shutdown()
        self.conn.close()

    def get_vm_infos(self):
        nodeinfo = self.conn.getInfo()
        self.log.info('Model: '+str(nodeinfo[0]))
        self.log.info('Memory size: '+str(nodeinfo[1])+'MB')
        self.log.info('Number of CPUs: '+str(nodeinfo[2]))
        self.log.info('MHz of CPUs: '+str(nodeinfo[3]))
        self.log.info('Number of NUMA nodes: '+str(nodeinfo[4]))
        self.log.info('Number of CPU sockets: '+str(nodeinfo[5]))
        self.log.info('Number of CPU cores per socket: '+str(nodeinfo[6]))
        self.log.info('Number of CPU threads per core: '+str(nodeinfo[7]))
        print('Model: '+str(nodeinfo[0]))
        print('Memory size: '+str(nodeinfo[1])+'MB')
        print('Number of CPUs: '+str(nodeinfo[2]))
        print('MHz of CPUs: '+str(nodeinfo[3]))
        print('Number of NUMA nodes: '+str(nodeinfo[4]))
        print('Number of CPU sockets: '+str(nodeinfo[5]))
        print('Number of CPU cores per socket: '+str(nodeinfo[6]))
        print('Number of CPU threads per core: '+str(nodeinfo[7]))

    def save_vm(self):
        if self.dom.save(self.filename) < 0:
            self.log.info('Unable to save guest to '+self.filename)
        self.log.info('Guest state saved to '+self.filename)

    def pause_vm(self):
        try:
            self.dom.suspend()
        except Exception as e:
            self.log.info('Unable to suspend guest')

    def resume_vm(self):
        try:
            self.dom.resume()
        except Exception as e:
            self.log.info('Unable to resume guest')
