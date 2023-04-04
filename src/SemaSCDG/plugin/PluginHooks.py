#!/usr/bin/env python3
import os
import sys

import claripy
import monkeyhex
import logging

import subprocess
import nose
import avatar2 as avatar2

import angr
import claripy

import zlib 
import binascii
import mmh3
import re
import time

    
class PluginHooks: # TODO replace with classses
    def __init__(self):
        self.hooks = {}
        
        self.general_hooks = {
            "copy": b'\x56\x33\xf6\x39\x74\x24\x08\x76\x0d\x8a\x04\x16\x88\x04\x0e\x46\x3b\x74\x24\x08\x72\xf3\x5e',
            "copy_2":  b'\x55\x8b\xec\x56\x8b\x75\x08\x85\xf6\x74\x11\x57\x8b\xf9\x2b\xfa\x8a\x02\x88\x04\x17\x42\x83\xee\x01\x75\xf5\x5f\x8b\xc1\x5e\x5d',
            "copy_3":  b'\x55\x8b\xec\x83\x7d\x10\x00\x8b\x4d\x08\x56\x8b\xf1\x74\x12\x8b\x55\x0c\x8a\x02\xff\x4d\x10\x88\x01\x41\x42\x83\x7d\x10\x00\x75\xf1\x8b\xc6\x5e\x5d',
        }
        
        self.internal_functions_hooks = {
                # for warzone
                "crc32": b'\x53\x55\x56\x33\xf6\x8b\xda\x8b\xe9\x39\x35\x04\xac\x41\x00\x75\x38\x57\x8b\xfe\xb9\x00\xa8\x41\x00\x6a\x08\x8b\xc7\x5a\xa8\x01\x74\x09\xd1\xe8\x35\x20\x83\xb8\xed\xeb\x02\xd1\xe8\x4a\x75\xee\x89\x01\x47\x83\xc1\x04\x81\xff\x00\x01\x00\x00\x72\xdb\xc7\x05\x04\xac\x41\x00\x01\x00\x00\x00\x5f\x83\xc9\xff\x85\xdb\x74\x1a\x0f\xb6\x04\x2e\x33\xc1\xc1\xe9\x08\x25\xff\x00\x00\x00\x33\x0c\x85\x00\xa8\x41\x00\x46\x3b\xf3\x72\xe6\x5e\xf7\xd1\x5d\x8b\xc1\x5b',
                "murmurhash": b'\x55\x8b\xec\x53\x8b\xda\x8b\xc3\x99\x83\xe2\x03\x56\x57\x8d\x3c\x02\x8b\x55\x08\xc1\xff\x02\x8d\x34\xb9\xf7\xdf\x74\x23\x69\x04\xbe\x51\x2d\x9e\xcc\xc1\xc0\x0f\x69\xc0\x93\x35\x87\x1b\x33\xc2\xc1\xc0\x0d\x6b\xd0\x05\x81\xea\x9c\x94\xab\x19\x83\xc7\x01\x75\xdd\x8b\xc3\x33\xc9\x83\xe0\x03\x83\xe8\x01\x74\x1a\x83\xe8\x01\x74\x0c\x83\xe8\x01\x75\x26\x0f\xb6\x4e\x02\xc1\xe1\x10\x0f\xb6\x46\x01\xc1\xe0\x08\x33\xc8\x0f\xb6\x06\x33\xc1\x69\xc0\x51\x2d\x9e\xcc\xc1\xc0\x0f\x69\xc0\x93\x35\x87\x1b\x33\xd0\x33\xd3\x8b\xc2\xc1\xe8\x10\x33\xc2\x69\xc8\x6b\xca\xeb\x85\x5f\x5e\x5b\x8b\xc1\xc1\xe8\x0d\x33\xc1\x69\xc0\x35\xae\xb2\xc2\x8b\xc8\xc1\xe9\x10\x33\xc8\x8b\x45\x0c\x89\x08\x5d',
                "murmurhash2": b'\x55\x8b\xec\x83\xec\x2c\x8b\x45\x08\x89\x45\xe0\x8b\x45\x0c\x99\x83\xe2\x03\x03\xc2\xc1\xf8\x02\x89\x45\xec\x8b\x45\x10\x89\x45\xf8\xc7\x45\xd8\x51\x2d\x9e\xcc\xc7\x45\xd4\x93\x35\x87\x1b\x8b\x45\xec\x8b\x4d\xe0\x8d\x04\x81\x89\x45\xdc\x8b\x45\xec\xf7\xd8\x89\x45\xf0\xeb\x07\x8b\x45\xf0\x40\x89\x45\xf0\x83\x7d\xf0\x00\x74\x59\xff\x75\xf0\xff\x75\xdc\xe8\x59\x2d\xfe\xff\x59\x59\x89\x45\xf4\x69\x45\xf4\x51\x2d\x9e\xcc\x89\x45\xf4\x6a\x0f\xff\x75\xf4\xe8\x1e\x2d\xfe\xff\x59\x59\x89\x45\xf4\x69\x45\xf4\x93\x35\x87\x1b\x89\x45\xf4\x8b\x45\xf8\x33\x45\xf4\x89\x45\xf8\x6a\x0d\xff\x75\xf8\xe8\xfc\x2c\xfe\xff\x59\x59\x89\x45\xf8\x6b\x45\xf8\x05\x2d\x9c\x94\xab\x19\x89\x45\xf8\xeb\x9a\x8b\x45\xec\x8b\x4d\xe0\x8d\x04\x81\x89\x45\xe4\x83\x65\xfc\x00\x8b\x45\x0c\x83\xe0\x03\x89\x45\xe8\x83\x7d\xe8\x01\x74\x39\x83\x7d\xe8\x02\x74\x1d\x83\x7d\xe8\x03\x74\x02\xeb\x6a\x33\xc0\x40\xd1\xe0\x8b\x4d\xe4\x0f\xb6\x04\x01\xc1\xe0\x10\x33\x45\xfc\x89\x45\xfc\x33\xc0\x40\xc1\xe0\x00\x8b\x4d\xe4\x0f\xb6\x04\x01\xc1\xe0\x08\x33\x45\xfc\x89\x45\xfc\x33\xc0\x40\x6b\xc0\x00\x8b\x4d\xe4\x0f\xb6\x04\x01\x33\x45\xfc\x89\x45\xfc\x69\x45\xfc\x51\x2d\x9e\xcc\x89\x45\xfc\x6a\x0f\xff\x75\xfc\xe8\x6a\x2c\xfe\xff\x59\x59\x89\x45\xfc\x69\x45\xfc\x93\x35\x87\x1b\x89\x45\xfc\x8b\x45\xf8\x33\x45\xfc\x89\x45\xf8\x8b\x45\xf8\x33\x45\x0c\x89\x45\xf8\xff\x75\xf8\xe8\x71\x2c\xfe\xff\x59\x89\x45\xf8\x8b\x45\x14\x8b\x4d\xf8\x89\x08\xc9',
                "findstart": b'\x55\x8b\xec\x83\xec\x14\xc6\x45\xff\x00\xc7\x45\xf4\x90\x1d\x42\x00\xc6\x45\xf8\x4d\xc6\x45\xf9\x5a\xc6\x45\xfa\x90\xc6\x45\xfb\x00\x83\x65\xf0\x00\x0f\xb6\x45\xff\x85\xc0\x75\x42\x6a\x04\xff\x75\xf4\x8d\x45\xf8\x50\xe8\x12\xf5\xfd\xff\x83\xc4\x0c\x89\x45\xec\x83\x7d\xec\x00\x75\x0b\xc6\x45\xff\x01\x8b\x45\xf4\xeb\x21\xeb\x07\x8b\x45\xf4\x48\x89\x45\xf4\x8b\x45\xf0\x40\x89\x45\xf0\x81\x7d\xf0\xe8\x03\x00\x00\x75\x04\x83\x65\xf0\x00\xeb\xb6\x33\xc0\xc9',
                "findstart2": b'\x55\x8b\xec\x51\xb9\x0e\x5c\x41\x00\xc7\x45\xfc\x4d\x5a\x90\x00\x8d\x45\xfc\x8b\x00\x3b\x01\x74\x03\x49\xeb\xf4\x8b\xc1\xc9',
                "findstart3": b'\x55\x8b\xec\x51\x53\x56\xbe\x23\x33\x41\x00\xc7\x45\xfc\x4d\x5a\x90\x00\x33\xdb\x6a\x04\x8d\x45\xfc\x56\x50\xe8\xbd\xdc\xfe\xff\x83\xc4\x0c\x85\xc0\x74\x13\x33\xc9\x8d\x43\x01\x4e\x81\xfb\xe7\x03\x00\x00\x0f\x45\xc8\x8b\xd9\xeb\xda\x8b\xc6\x5e\x5b\xc9',
                "findstart4": b'\x55\x8b\xec\x51\x53\x56\xbe\xa2\x1c\x41\x00\xc7\x45\xfc\x4d\x5a\x90\x00\x33\xdb\x6a\x04\x8d\x45\xfc\x56\x50\xe8\x3e\xf3\xfe\xff\x83\xc4\x0c\x85\xc0\x74\x13\x33\xc9\x8d\x43\x01\x4e\x81\xfb\xe7\x03\x00\x00\x0f\x45\xc8\x8b\xd9\xeb\xda\x8b\xc6\x5e\x5b\xc9',
                "findstart5": b'\x55\x8b\xec\x51\xb9\xe5\x17\x42\x00\xc7\x45\xfc\x4d\x5a\x90\x00\x8d\x45\xfc\x8b\x00\x3b\x01\x74\x03\x49\xeb\xf4\x8b\xc1\xc9',
                # For wabot
                # FUN_004031e8:004031fe(c), FUN_004031e8:0040325a(j), FUN_00403264:00403281(c), FUN_00403264:00403297(c), FUN_004042f4:0040430e(c
                # "weed":b'\x53\x56\x51\x8b\xd8\x8b\x73\x0c\x85\xf6\x75\x04\x33\xc0\xeb\x26\x6a\x00\x8d\x44\x24\x04\x50\x56\x8b\x43\x14\x50\x8b\x03\x50\xe8\x0c\xe8\xff\xff\x85\xc0\x75\x07\xe8\x3b\xe8\xff\xff\xeb\x02\x33\xc0\x33\xd2\x89\x53\x0c\x5a\x5e\x5b\xc3',
                # "weed2": b'\x66\x81\x7e\x04\xb3\xd7',
                # "weed3":b'\xe8\x91\xff\xff\xff',
                # "weed4":b'\xe8\x13\x52\xff\xff\xb8\x44\xff\x40\x00\xe8\x99\x4f\xff\xff\xe8\x2c\x4d\xff\xff\x8b\x15\xf0\xe9\x40\x00\xb8\x44\xff\x40\x00\xe8\x38\x6a\xff\xff\xe8\x9f\x52\xff\xff\xe8\x12\x4d\xff\xff\xb8\x44\xff\x40\x00\xe8\x50\x53\xff\xff\xe8\x03\x4d\xff\xff',
                "weed5":b'\x55\x8b\xec\x83\xc4\xf0\xb8\x0c\xd8\x40\x00\xe8\xcc\x6f\xff\xff\xb8\x20\xd9\x40\x00\xe8\x96\x75\xff\xff\xba\x34\xd9\x40\x00\xb8\x44\xff\x40\x00\xe8\x13\x52\xff\xff\xb8\x44\xff\x40\x00\xe8\x99\x4f\xff\xff\xe8\x2c\x4d\xff\xff\x8b\x15\xf0\xe9\x40\x00\xb8\x44\xff\x40\x00\xe8\x38\x6a\xff\xff\xe8\x9f\x52\xff\xff\xe8\x12\x4d\xff\xff\xb8\x44\xff\x40\x00\xe8\x50\x53\xff\xff\xe8\x03\x4d\xff\xff\xa1\x08\xea\x40\x00\xc7\x00\x01\x00\x00\x00\xa1\x18\xea\x40\x00\xba\x50\xd9\x40\x00\xe8\xed\x64\xff\xff\xa1\x14\xea\x40\x00\x33\xd2\x89\x10\xb9\x68\xd9\x40\x00\xba\x74\xd9\x40\x00\xb8\x80\xd9\x40\x00\xe8\xd8\x83\xff\xff\xa1\x08\xea\x40\x00\x66\x8b\x00',
                # "clear_stack": b'\x68\x57\x6b\x40\x00',
                # SakulaRAT
                "rewriting": b'\x8b\x45\xf8\x8b\x5d\xf0\x39\xd8\x74\x97',
                # AsyncRat
                #"returns": b'\x83\xc4\x34\x5b\x5e\xc3'
                #"TODO": b'\x55\x8b\xec\x83\xc4\xf0\xb8\xf0\x76\x48\x00\xe8\x80\xec\xf7\xff\xa1\x0c\x1e\x49\x00\x8b\x00\xe8\x9c\x66\xfd\xff\x8b\x0d\xa8\x1f\x49\x00\xa1\x0c\x1e\x49\x00\x8b\x00\x8b\x15\x48\x74\x48\x00\xe8\x9c\x66\xfd\xff'#b'\x55\x8b\xec\x83\xc4\xf0\xb8\xf0\x76\x48\x00\xe8\x80\xec\xf7\xff\xa1\x0c\x1e\x49\x00\x8b\x00\xe8\x9c\x66\xfd\xff' 
                
                # MagicRat       b'\x31\xd2\x48\x89\xd0\x48\x87\x01\x48\x85\xc0\x74\x03\x31\xc0\xc3\xf3\x90\x48\x8b\x01\x48\x85\xc0\x74\xf6\xeb\xe6'
                "magicRAT_trap": b'\x31\xd2\x48\x89\xd0\x48\x87\x01\x48\x85\xc0\x74\x03\x31\xc0\xc3\xf3\x90\x48\x8b\x01\x48\x85\xc0\x74\xf6\xeb\xe6',
                "trap":b'\x0f\x29\x02', 
                "trap_2": b'\x0f\x29\x74\x24\x20',
                "trap_3": b'\x0f\x28\x74\x24\x20',
                "force_test":b'\x85\xdb',
                #"sse3_mrat": b'\x45\x85\xc9', 
                "sse3_mrat": b'\x45\x85\xc9\x0f\x84\xf5\x00\x00\x00',
                "cpuid":b'\x0f\xa2',
                "LAB_00cafb11":b'\x48\x8b\x84\x24\xd0\x00\x00\x00\x48\x8b\x48\x08\x48\x85\xc9\x74\x07\x48\x8b\x01\xff\x50\x08\x90',
                "0x701140":b'',
            }
    
    def initialization(self, cont, is_64bits=False):
        pe_header = int.from_bytes(cont[0x3c:0x40],"little")
        if not is_64bits:
            size_of_headers = int.from_bytes(cont[pe_header+0x54:pe_header+0x54+4],"little")
            base_of_code = int.from_bytes(cont[pe_header+0x2c:pe_header+0x2c+4],"little")
            image_base = int.from_bytes(cont[pe_header+0x34:pe_header+0x34+4],"little")
        else: # TODO FIX
            size_of_headers = int.from_bytes(cont[pe_header+0x70:pe_header+0x70+4], "little")
            base_of_code = int.from_bytes(cont[pe_header+0x48:pe_header+0x48+4], "little")
            image_base = int.from_bytes(cont[pe_header+0x38:pe_header+0x38+8], "little")
        total = base_of_code + image_base - size_of_headers
        
        addr_list = [m.start()+total for m in re.finditer(b'\xf3\xab',cont)]
        if(len(addr_list) > 0):
            self.hooks["rep stosd"] = addr_list

        addr_list1 = [m.start()+total for m in re.finditer(b'\xf3\xa5',cont)]
        if(len(addr_list1) > 0):
            self.hooks["rep movsd"] = addr_list1

        addr_list2 = [m.start()+total for m in re.finditer(b'\xf3\xa4',cont)]
        if(len(addr_list2) > 0):
            self.hooks["rep movsb"] = addr_list2

        addr_list3 = [m.start()+total for m in re.finditer(b'\xfd',cont)]
        if(len(addr_list3) > 0):
            self.hooks["std"] = addr_list3

        addr_list4 = [m.start()+total for m in re.finditer(b'\xfc',cont)]
        if(len(addr_list4) > 0):
            self.hooks["cld"] = addr_list4
            
        for fun in self.general_hooks.keys():
            offset = cont.find(self.general_hooks[fun])
            if offset != -1:
                self.hooks[fun] = offset+total
        
        for fun in self.internal_functions_hooks.keys():
            offset = cont.find(self.internal_functions_hooks[fun])
            if offset != -1:
                self.hooks[fun] = offset+total
        
        #self.hooks["cpuid"] = [0x559e37,0x559e27,0x559e68]
        
    def hook(self,state,proj,call_sim):
        if False: # TODO 
            if "std" in self.hooks:
                for addr in self.hooks["std"]:
                    proj.hook(
                        addr,
                        call_sim.custom_simproc_windows["custom_hook"]["StdHook"](plength=1),
                        length=1
                    )          
            if "cld" in self.hooks:
                for addr in self.hooks["cld"]:
                    proj.hook(
                        addr,
                        call_sim.custom_simproc_windows["custom_hook"]["CldHook"](plength=1),
                        length=1
                    )
            if "rep movsd" in self.hooks:
                for addr in self.hooks["rep movsd"]:
                    proj.hook(
                        addr,
                        call_sim.custom_simproc_windows["custom_hook"]["RepMovsdHook"](plength=2),
                        length=2
                    )    
            if "rep movsb" in self.hooks:
                for addr in self.hooks["rep movsb"]:
                    proj.hook(
                        addr,
                        call_sim.custom_simproc_windows["custom_hook"]["RepMovsbHook"](plength=2),
                        length=2
                    )   
           
            if "rep stosd" in self.hooks:
                for addr in self.hooks["rep stosd"]:
                    proj.hook(
                        addr,
                        call_sim.custom_simproc_windows["custom_hook"]["RepStosdHook"](plength=2),
                        length=2
                    )
        
            for addr in self.hooks["cpuid"]:
                proj.hook(
                    addr,
                    call_sim.custom_simproc_windows["custom_hook"]["CPUIDHook"](plength=2),
                    length=2
                ) 
        # TODO change key per class name and add list for multiple hooks                 
        for fun in self.hooks.keys():
            if fun == "copy" or fun == "copy_2":
                proj.hook(
                    self.hooks[fun],
                    call_sim.custom_simproc_windows["custom_hook"]["CopyHook"](plength=len(self.general_hooks[fun])),
                    length=len(self.general_hooks[fun])
                )        
            elif fun == "copy_3":
                proj.hook(
                    self.hooks[fun],
                    call_sim.custom_simproc_windows["custom_hook"]["Copy3Hook"](plength=len(self.general_hooks[fun])),
                    length=len(self.general_hooks[fun])
                )
            elif fun == "murmurhash":
                proj.hook(
                    self.hooks[fun],
                    call_sim.custom_simproc_windows["custom_hook"]["MurmurHashHook"](plength=len(self.internal_functions_hooks[fun])),
                    length=len(self.internal_functions_hooks[fun])
                )        
            elif fun == "murmurhash2":
                proj.hook(
                    self.hooks[fun],
                    call_sim.custom_simproc_windows["custom_hook"]["MurmurHash2Hook"](plength=len(self.internal_functions_hooks[fun])),
                    length=len(self.internal_functions_hooks[fun])
                )               
            elif fun == "crc32":
                proj.hook(
                    self.hooks[fun],
                    call_sim.custom_simproc_windows["custom_hook"]["Crc32Hook"](plength=len(self.internal_functions_hooks[fun])),
                    length=len(self.internal_functions_hooks[fun])
                )  
            elif "findstart" in fun:
                proj.hook(
                    self.hooks[fun],
                    call_sim.custom_simproc_windows["custom_hook"]["FindStartHook"](plength=len(self.internal_functions_hooks[fun])),
                    length=len(self.internal_functions_hooks[fun])
                )  
            elif fun == "weed":
                proj.hook(
                    self.hooks[fun],
                    call_sim.custom_simproc_windows["custom_hook"]["WeedLeafHook"](plength=len(self.internal_functions_hooks[fun])),
                    length=len(self.internal_functions_hooks[fun])
                )  
            elif fun == "weed2":
                proj.hook(
                    self.hooks[fun],
                    call_sim.custom_simproc_windows["custom_hook"]["WeedLeaf2Hook"](plength=len(self.internal_functions_hooks[fun])),
                    length=len(self.internal_functions_hooks[fun])
                )  
            elif fun == "weed3" or fun == "weed4" or fun == "weed5":
                proj.hook(
                    self.hooks[fun],
                    call_sim.custom_simproc_windows["custom_hook"]["WeedLeaf3Hook"](plength=len(self.internal_functions_hooks[fun])),
                    length=len(self.internal_functions_hooks[fun])
                )  
            elif fun == "rewriting":
                proj.hook(
                    self.hooks[fun],
                    call_sim.custom_simproc_windows["custom_hook"]["RewritingHook"](plength=len(self.internal_functions_hooks[fun])),
                    length=len(self.internal_functions_hooks[fun])
                ) 
            elif fun == "clear_stack":
                proj.hook(
                        self.hooks[fun],
                        call_sim.custom_simproc_windows["custom_hook"]["ClearStackHook"](plength=len(self.internal_functions_hooks[fun])),
                        length=len(self.internal_functions_hooks[fun])
                ) 
            elif fun == "magicRAT_trap":
                proj.hook(
                        self.hooks[fun],
                        call_sim.custom_simproc_windows["custom_hook"]["MagicRATTrapHook"](plength=len(self.internal_functions_hooks[fun])),
                        length=len(self.internal_functions_hooks[fun])
                ) 
            elif fun == "trap":
                proj.hook(
                        self.hooks[fun],
                        call_sim.custom_simproc_windows["custom_hook"]["MagicRATTrapHook2"](plength=len(self.internal_functions_hooks[fun])),
                        length=len(self.internal_functions_hooks[fun])
                )   
            elif fun == "trap_2":
                proj.hook(
                        self.hooks[fun],
                        call_sim.custom_simproc_windows["custom_hook"]["MagicRATTrapHook3"](plength=len(self.internal_functions_hooks[fun])),
                        length=len(self.internal_functions_hooks[fun])
                )   
            elif fun == "trap_3":
                proj.hook(
                        self.hooks[fun],
                        call_sim.custom_simproc_windows["custom_hook"]["MagicRATTrapHook4"](plength=len(self.internal_functions_hooks[fun])),
                        length=len(self.internal_functions_hooks[fun])
                )   
            elif fun == "sse3_mrat":
                proj.hook(
                        self.hooks[fun],
                        call_sim.custom_simproc_windows["custom_hook"]["MagicRATSSE3Hook"](plength=len(self.internal_functions_hooks[fun])),
                        length=len(self.internal_functions_hooks[fun])
                ) 
            elif fun == "force_test":
                proj.hook(
                        self.hooks[fun],
                        call_sim.custom_simproc_windows["custom_hook"]["MagicRATForceHook"](plength=len(self.internal_functions_hooks[fun])),
                        length=len(self.internal_functions_hooks[fun])
                ) 
            elif fun == "LAB_00cafb11":
                proj.hook(
                        self.hooks[fun],
                        call_sim.custom_simproc_windows["custom_hook"]["LAB_00cafb11"](plength=len(self.internal_functions_hooks[fun])),
                        length=len(self.internal_functions_hooks[fun])
                ) 
            
            elif fun == "TODO":
                @proj.hook(self.hooks[fun], length=len(self.internal_functions_hooks[fun]))
                def nothing(state):
                    print("TODO")
                    return
