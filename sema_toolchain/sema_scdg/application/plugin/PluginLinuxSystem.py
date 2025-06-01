import angr

from collections import namedtuple

Dirent = namedtuple("dirent", ("d_ino", "d_off", "d_reclen", "d_type", "d_name"))

class PluginLinuxSystem(angr.SimStatePlugin):
    def __init__(self):
        super(PluginLinuxSystem, self).__init__()
        self.last_error = 0
        self.files_block = 0
        self.files = []
        self.files_requested = {}
        self.folder_requested = {}
        self.folder_address = {}
        self.file_address = {}
        self.folder_address_to_name = {}
        self.stop_flag = False
        self.dict_calls = {}
        self.expl_method = "BFS"
        
        self.file_extensions = "doc docx xls" # xlsx ppt pptx pst ost msg eml vsd vsdx txt csv rtf wks wk1"
        self.linux_folders = {
            "/home": {
                "/user": {
                    "/.local": {
                        "/share": {
                            "/Trash": {
                            }
                        }
                    },
                    "/Desktop": {
                    }
                }
            },
            "/media": {
                "/user": {
                }
            }
        } 
        
        
        
        #["/home/user/.local/share/Trash/","/media/user/","/home/user/Desktop/"]  
        self.current_file_per_folder = [0, {
            "/home": [1, {
                "/user": [2, {
                    "/.local": [1, {
                        "/share": [1, {
                            "/Trash": [0, {
                            }]
                        }]
                    }],
                    "/Desktop": [0, {
                    }]
                }]
            }],
            "/media": [1, {
                "/user": [0, {
                }]
            }]
        }]
        
        # {
        #     "/home/user/.local/share/Trash/":0,
        #     "/media/user/":0,            
        #     "/home/user/Desktop/":0
        # }
        
        self.linux_files = {
            "/home": {
                "files": [],
                "/user": {
                    "files": [],
                    "/.local": {
                        "files": [],
                        "/share": {
                            "files": [],
                            "/Trash": {
                                "files": [],
                            }
                        }
                    },
                    "/Desktop": {
                        "files": [],
                    }
                }
            },
            "/media": {
                "files": [],
                "/user": {
                    "files": [],
                }
            }
        } 
        
        # {
        #     "/home/user/.local/share/Trash/":[],
        #     "/media/user/":[],
        #     "/home/user/Desktop/":[]
        # }
        
        # for folder in self.linux_folders:
        #     for extension in self.file_extensions.split(" "):
        #         simfile_name = "file." + extension     
        #         self.linux_files[folder].append(simfile_name)
        
        current_folder_level = list(self.linux_folders.keys())
        current_folder = self.linux_files
        previous_folder = []
        previous_current_file_per_folder = []
        current_file_per_folder = self.current_file_per_folder
        current_path = []
        end_folder = False
        while current_folder_level:
            #print("-------------------------------")
            #print("current_folder_level: ", str(current_folder_level))
            
            folder = current_folder_level.pop()
            #print("folder: ", str(folder))
            
            if end_folder:
                while len(current_path) >= 0:
                    current_path.pop()
                    current_folder = previous_folder.pop()
                    current_file_per_folder = previous_current_file_per_folder.pop()
                    # print(current_folder.keys())
                    if folder in current_folder.keys():
                        break
                        
            current_path.append(folder)
            #print("current_path: ", str(current_path))
                
            new_folder_level = list(current_folder[folder].keys())
            new_folder_level.remove("files")
            
            previous_folder.append(current_folder)
            current_folder   = current_folder[folder]
            
            previous_current_file_per_folder.append(current_file_per_folder)
            current_file_per_folder = current_file_per_folder[1][folder]
            
            #print("current_folder: ", str(current_folder))
            
            if len(new_folder_level) == 0: # reach end of the tree
                # print("We are at the end of the tree")
                for extension in self.file_extensions.split(" "):
                    simfile_name = "/file." + extension     
                    current_folder["files"].append([False, simfile_name]) # False means not read yet
                    current_file_per_folder[0] += 1
                end_folder = True
            else:
                #print("We are not at the end of the tree")
                for new_folder in new_folder_level:
                    current_folder_level.append(new_folder)
                end_folder = False
                
            # current_folder_level.remove(folder)
                
        #print(self.linux_files)
        # exit(0)
            
    def stores(self, offset, val, size):
        return self.state.memory.store(self.files_block + offset, val, size=size, endness="Iend_BE")

    def storei(self, offset, val, size):
        return self.state.memory.store(self.files_block + offset, val, size=size, endness="Iend_LE")            

    def add_folder(self, folder):
        
        splitted_path = folder.split("/")
        current_folder = self.linux_folders
        current_folder_file = self.linux_files
        current_file_per_folder = self.current_file_per_folder
        for part in splitted_path:
            if part in current_folder.keys():
                current_folder = current_folder[part]
                current_file_per_folder = current_file_per_folder[1][part]
                current_folder_file = current_folder_file[part]
            else:
                current_folder[part] = {}
                current_file_per_folder[1][part] = [0, {}]
                current_folder_file[part] = {"files": []}
        
        #self.files_block = self.state.heap.malloc(512) 
        self.folder_address[folder] = self.state.heap.malloc(512) # self.files_block
        # self.current_file_per_folder[folder] = 0
        self.folder_address_to_name[self.folder_address[folder]] = folder
        for i in range(512):
            c = self.state.solver.BVS("c_files_block{}".format(i), 8)
            self.state.memory.store(self.files_block + i, c)
            
        # self.struct = Dirent(
        #     self.state.solver.BVV(0, 64),  # d_ino /* inode number */
        #     self.state.solver.BVV(0, 64),  # d_off /* offset to the next dirent */
        #     self.state.solver.BVS("d_reclen", 16, key=("api", "readdir", "d_reclen")),  # d_reclen /* length of this record */
        #     self.state.solver.BVS("d_type", 8, key=("api", "readdir", "d_type")),  # d_type /* type of file; not supported by all file system types */
        #     self.state.solver.BVS("d_name", 255 * 8, key=("api", "readdir", "d_name")),
        # )  # d_name
        
        # simfile = angr.SimFile(simfile_name, content='wtf why has this been so annoying')
        
                
        d_ino = 0
        d_off = 0
        d_reclen = 8 + 8 + 2 + 1 + len(folder.encode("utf-8"))
            
            
        self.storei(i, d_ino, 8)
        self.storei(i+8, d_off, 8)
        self.storei(i+16, d_reclen, 2)
        self.storei(i+18, 0x4, 1) # Folder
        self.stores(i+18+1, folder.encode("utf-8"), len(folder.encode("utf-8")))
        i = i + 18 + len(folder.encode("utf-8"))
        
    def add_file(self, file):
        self.files_block = self.state.heap.malloc(512) 
        self.file_address[file] = self.files_block # self.state.heap.malloc(512) # self.files_block
        for i in range(512):
            c = self.state.solver.BVS("c_files_block{}".format(i), 8)
            self.state.memory.store(self.files_block + i, c)
                
        d_ino = 0
        d_off = 0
        d_reclen = 8 + 8 + 2 + 1 + len(file.encode("utf-8"))
            
        self.storei(i, d_ino, 8)
        self.storei(i+8, d_off, 8)
        self.storei(i+16, d_reclen, 2)
        self.storei(i+18, 0x8, 1) # File
        self.stores(i+18+1, file.encode("utf-8"), len(file.encode("utf-8")))
        i = i + 18 + len(file.encode("utf-8"))
    
    def setup_plugin(self):
        i = 0
        # for folder in self.linux_folders:
        #     #self.files_block = self.state.heap.malloc(512) 
            # self.folder_address[folder] = self.state.heap.malloc(512) # self.files_block
            # self.folder_address_to_name[self.folder_address[folder]] = folder
            # for i in range(512):
            #     c = self.state.solver.BVS("c_files_block{}".format(i), 8)
            #     self.state.memory.store(self.files_block + i, c)
                
            # d_ino = 0
            # d_off = 0
            # d_reclen = 8 + 8 + 2 + 1 + len(folder.encode("utf-8"))
            
            # self.storei(i, d_ino, 8)
            # self.storei(i+8, d_off, 8)
            # self.storei(i+16, d_reclen, 2)
            # self.storei(i+18, 0x4, 1) # Folder
            # self.stores(i+18 + len(folder.encode("utf-8")), folder.encode("utf-8"), len(folder.encode("utf-8")))
            # i = i + 18 + len(folder.encode("utf-8"))
        
        current_folder_level = list(self.linux_folders.keys())
        current_folder = self.linux_folders
        previous_folder = []
        current_path = []
        end_folder = False
        while current_folder_level:
            print("current_folder_level: ", str(current_folder_level))
            
            folder = current_folder_level.pop()
            print("folder: ", str(folder))
            
            if end_folder:
                while len(current_path) >= 0:
                    current_path.pop()
                    current_folder = previous_folder.pop()
                    print(current_folder.keys())
                    if folder in current_folder.keys():
                        break
            
            current_path.append(folder)
            print("current_path: ", str(current_path))
            self.files_block = self.state.heap.malloc(512)
            self.folder_address["".join(current_path)] = self.files_block # self.state.heap.malloc(512) # self.files_block
            self.folder_address_to_name[self.folder_address["".join(current_path)]] = "".join(current_path)
            for i in range(512):
                c = self.state.solver.BVS("c_files_block{}".format(i), 8)
                self.state.memory.store(self.files_block + i, c)
                
            d_ino = 0
            d_off = 0
            d_reclen = 8 + 8 + 2 + 1 + len(folder.encode("utf-8"))
            i = 0           
            self.storei(i, d_ino, 8)
            self.storei(i+8, d_off, 8)
            self.storei(i+16, d_reclen, 2)
            self.storei(i+18, 0x4, 1) # Folder
            self.stores(i+18+1, folder.encode("utf-8"), len(folder.encode("utf-8")))
            i = 0 # i + 18 + + len(folder.encode("utf-8"))
           
            new_folder_level = list(current_folder[folder].keys())
            
            previous_folder.append(current_folder)
            current_folder   = current_folder[folder]
           
            if len(new_folder_level) == 0: # reach end of the tree
                end_folder = True
            else:
                for new_folder in new_folder_level:
                    current_folder_level.append(new_folder)
                end_folder = False

        
        # for file in self.linux_files:
        #     #self.files_block = self.state.heap.malloc(512) 
            # self.file_address[file] = self.state.heap.malloc(512) # self.files_block
            # for i in range(512):
            #     c = self.state.solver.BVS("c_files_block{}".format(i), 8)
            #     self.state.memory.store(self.files_block + i, c)
                
            # d_ino = 0
            # d_off = 0
            # d_reclen = 8 + 8 + 2 + 1 + len(file.encode("utf-8"))
            
            # self.storei(i, d_ino, 8)
            # self.storei(i+8, d_off, 8)
            # self.storei(i+16, d_reclen, 2)
            # self.storei(i+18, 0x8, 1) # File
            # self.stores(i+18 + len(file.encode("utf-8")), file.encode("utf-8"),len(file.encode("utf-8")))
            # i = i + 18 + len(file.encode("utf-8"))
        print(self.folder_address)
        
        current_folder_level = list(self.linux_folders.keys())
        current_folder = self.linux_files
        previous_folder = []
        current_path = []
        end_folder = False
        
        while current_folder_level:
            print("current_folder_level: ", str(current_folder_level))
            
            folder = current_folder_level.pop()
            print("folder: ", str(folder))
            
            if end_folder:
                while len(current_path) >= 0:
                    current_path.pop()
                    current_folder = previous_folder.pop()
                    print(current_folder.keys())
                    if folder in current_folder.keys():
                        break
            
            current_path.append(folder)
            print("current_path: ", str(current_path))
              
               
            new_folder_level = list(current_folder[folder].keys())
            new_folder_level.remove("files")
            
            # TODO problem current_path
            if len(new_folder_level) == 0: # reach end of the tree
                for file in current_folder[folder]["files"]:
                    print(file)
                    self.files_block = self.state.heap.malloc(512)
                    self.file_address["".join(current_path) + file[1]] = self.files_block # self.state.heap.malloc(512) # self.files_block # TODO add path in key
                    for i in range(512):
                        c = self.state.solver.BVS("c_files_block{}".format(i), 8)
                        self.state.memory.store(self.files_block + i, c)
                    i = 0
                    d_ino = 0
                    d_off = 0
                    d_reclen = 8 + 8 + 2 + 1 + len(file[1].encode("utf-8"))
                    
                    self.storei(i, d_ino, 8)
                    self.storei(i+8, d_off, 8)
                    self.storei(i+16, d_reclen, 2)
                    self.storei(i+18, 0x8, 1) # File
                    self.stores(i+18+1, file[1].encode("utf-8"),len(file[1].encode("utf-8")))
                    i = 0 #i + 18 + 1 + len(file[1].encode("utf-8"))
                end_folder = True
            else:
                for new_folder in new_folder_level:
                    current_folder_level.append(new_folder)
                end_folder = False
            
            previous_folder.append(current_folder)
            current_folder   = current_folder[folder]
            
        print(self.file_address)
        
            
            
    def update_dic(self, call_name):
        if call_name in self.dict_calls:
            if self.dict_calls[call_name] > 5:
                self.stop_flag = True
                self.dict_calls[call_name] = 0
            else:
                self.dict_calls[call_name] = self.dict_calls[call_name] + 1
        else:
            self.dict_calls[call_name] = 1
    
  
    @angr.SimStatePlugin.memo
    def copy(self, memo):
        # TODO for loop on all the attributes
        p = PluginLinuxSystem()
        p.last_error = self.last_error
        p.files_block = self.files_block
        p.file_address = self.file_address.copy()
        p.folder_address = self.folder_address.copy()
        p.folder_requested = self.folder_requested.copy()
        p.files = self.files.copy()
        p.linux_files = self.linux_files.copy()
        p.folder_address_to_name = self.folder_address_to_name.copy()
        p.current_file_per_folder = self.current_file_per_folder.copy()
        p.stop_flag = self.stop_flag
        p.dict_calls = self.dict_calls.copy()
        p.files_requested = self.files_requested.copy()
        return p
    
    def merge(self):
        pass
