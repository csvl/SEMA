import os
import sys
import random


class PluginCallReplace:


    def __init__(self):
        pass


    def call_replace(self,scdg):
        fields = ['name', 'args', 'addr_func', 'addr', 'ret']
        # call that need to be replaced, add info only on what differ from the replaced call
        to_replace = {
            "is_path": [
                {'name': 'opendir'},
                {'name': 'closedir', 'ret': 0x0}
            ],
            "WannacryHook_Str":[
                {'name': "GetComputerNameW", 'ret': "retval_GetComputerNameW_0_32", 'args':["replace_2147417141",399]},
                {'name': "wcslen", 'ret': 12, 'args': ["replace_2147417141"]},
                {'name': "wcslen", 'ret': 12, 'args': ["replace_2147417141"]},
                {'name': "srand",'ret': 0x0, 'args': []},
                {'name': "rand", 'ret': 0, 'args': []},
                {'name': "rand", 'ret': 0, 'args': []},
            ],
            "WannacryHook2": [
                {'name': "InitializeCriticalSection", 'args':["replace_2147415672"],'ret': 0x0},
                {'name': "InitializeCriticalSection", 'args': ["replace_2147415632"],'ret': 0x0}
            ],
            "WannacryHook3": [
                {'name': "DeleteCriticalSection", 'args':["replace_2147415672"],'ret': 0x0},
                {'name': "DeleteCriticalSection", 'args':["replace_2147415632"],'ret': 0x0},
            ],
            "WannacryHook4": [
                {'name': "strlen", 'args': ["WNcry@2ol7"], "ret": 10},
                {'name': "??2@YAPAXI@Z", 'args': [11], 'ret': "replace_3221324456"},
                {'name': "strcpy", 'args': ["replace_3221324456","WNcry@2ol7"], 'ret': 0x0},
            ],
            "WannacryHook_add_to_file_list":[
                {'name': "operator_new", 'args':[0x4ec]}
            ],
            "WannacryHook_allocate_24":[
                {'name': "operator_new", 'args': [0x18]}
            ],
            "WannacryHook_cleanup":[
                {'name': "operator_delete"}
            ],
            "WannacryHook_cls_100071f8":[
                {'name': "InitializeCriticalSection",'ret': 0x0},
                {'name': "InitializeCriticalSection",'ret': 0x0},
                {'name': "operator_new", 'args': [0x18]}
            ],
            "WannacryHook_free_contexts":[
                {'name': "CryptReleaseContext", 'ret': 0x0},
                {'name': "cryptDestroyKey", 'ret': 0x0},
                {'name': "GlobalFree", 'ret': 0x0},
                {'name': "WaitForSingleObject", 'ret': 0x0},
                {'name': "DeleteCriticalSection", 'ret': 0x0},
                {'name': "wcslen"},
            ]

        }
        for i in scdg:
            for call in i:
                if call["name"] in to_replace.keys():
                    #print("-------------------------")
                    #print(call)
                    for to_add in to_replace[call["name"]]:
                        new_call = {
                            field: to_add[field] if field in to_add else call[field]
                            for field in fields
                        }
                        new_call["addr_func"] = "replace_" + new_call["addr_func"]
                        new_call["addr"] = "replace_" + new_call["addr"]
                        i.append(new_call)
                        #print(new_call)
                    i.remove(call)
