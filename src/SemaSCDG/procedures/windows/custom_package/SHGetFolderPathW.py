import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class SHGetFolderPathW(angr.SimProcedure):
    def run(self, hwnd, csidl, hToken, dwFlags, pszPath):
        csidl = self.state.solver.eval(csidl)
        if csidl == 0x00: # CSIDL_DESKTOP
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\Public\\Desktop".encode('utf-16le')))
        elif csidl == 0x01: # CSIDL_INTERNET
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Program Files (x86)\\Internet Explorer\\".encode('utf-16le')))
        elif csidl == 0x02: # CSIDL_PROGRAMS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\Public\\Programs".encode('utf-16le')))
        elif csidl == 0x03: # CSIDL_CONTROLS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Windows\\System32\\control.exe".encode('utf-16le')))
        elif csidl == 0x04: # CSIDL_PRINTERS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Windows\\System32\\spool\\printers".encode('utf-16le')))
        elif csidl == 0x05: # CSIDL_PERSONAL
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\Documents".encode('utf-16le')))
        elif csidl == 0x06: # CSIDL_FAVORITES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\Favorites".encode('utf-16le')))
        elif csidl == 0x07: # CSIDL_STARTUP
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup".encode('utf-16le')))
        elif csidl == 0x08: # CSIDL_RECENT
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Recent".encode('utf-16le')))
        elif csidl == 0x09: # CSIDL_SENDTO
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\SendTo".encode('utf-16le')))
        elif csidl == 0x0A: # CSIDL_BITBUCKET
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\$Recycle.Bin".encode('utf-16le')))
        elif csidl == 0x0B: # CSIDL_STARTMENU
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu".encode('utf-16le')))
        elif csidl == 0x0C: # CSIDL_DESKTOPDIRECTORY
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\Public\\Desktop".encode('utf-16le')))
        elif csidl == 0x0D: # CSIDL_DRIVES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\".encode('utf-16le')))
        elif csidl == 0x0E: # CSIDL_NETWORK
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Windows\\Network Shortcuts".encode('utf-16le')))
        elif csidl == 0x0F: # CSIDL_NETHOOD
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts".encode('utf-16le')))
        elif csidl == 0x10: # CSIDL_FONTS
             self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Windows\\Fonts".encode('utf-16le')))
        elif csidl == 0x11: # CSIDL_TEMPLATES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Templates".encode('utf-16le')))
        elif csidl == 0x12: # CSIDL_COMMON_STARTMENU
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\ProgramData\\Microsoft\\Windows\\Start Menu".encode('utf-16le')))
        elif csidl == 0x13: # CSIDL_COMMON_PROGRAMS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs".encode('utf-16le')))
        elif csidl == 0x14: # CSIDL_COMMON_STARTUP
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp".encode('utf-16le')))
        elif csidl == 0x15: # CSIDL_COMMON_DESKTOPDIRECTORY
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\Public\\Desktop".encode('utf-16le')))
        elif csidl == 0x16: # CSIDL_APPDATA
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming".encode('utf-16le')))
        elif csidl == 0x17: # CSIDL_PRINTHOOD
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts".encode('utf-16le')))
        elif csidl == 0x18: # CSIDL_COMMON_STARTUP
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp".encode('utf-16le')))
        elif csidl == 0x19: # CSIDL_ALTSTARTUP
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp".encode('utf-16le')))
        elif csidl == 0x1A: # CSIDL_COMMON_ALTSTARTUP
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\USERNAME\\AppData\\Roaming".encode('utf-16le')))
        elif csidl == 0x1B: # CSIDL_COMMON_FAVORITES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\Public\\Favorites".encode('utf-16le')))
        elif csidl == 0x1C: # CSIDL_INTERNET_CACHE
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\USERNAME\\AppData\\Local".encode('utf-16le')))
        elif csidl == 0x1D: # CSIDL_COOKIES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Cookies".encode('utf-16le')))
        elif csidl == 0x1E: # CSIDL_HISTORY
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\History".encode('utf-16le')))
        elif csidl == 0x1F: # CSIDL_COMMON_APPDATA
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\ProgramData".encode('utf-16le')))
        elif csidl == 0x23: # CSIDL_ADMINTOOLS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools".encode('utf-16le')))
        elif csidl == 0x24: # CSIDL_RESOURCES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Windows\\".encode('utf-16le')))
        elif csidl == 0x25: # CSIDL_RESOURCES_LOCALIZED
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Windows\\Resources\\%LOCALIZED_RESOURCE_FOLDER%".encode('utf-16le')))
        elif csidl == 0x26: # CSIDL_COMMON_DOCUMENTS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\Public\\Documents".encode('utf-16le')))
        elif csidl == 0x27: # CSIDL_COMMON_ADMINTOOLS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools".encode('utf-16le')))
        elif csidl == 0x28: # CSIDL_ADMINTOOLS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools".encode('utf-16le')))
        elif csidl == 0x2f: # CSIDL_MYPICTURES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\Pictures".encode('utf-16le')))
        else:
            pass
            
        return 0x1
