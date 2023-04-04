import logging
import angr

lw = logging.getLogger("CustomSimProcedureWindows")


class SHGetSpecialFolderPathA(angr.SimProcedure):
    def run(self, hwnd, pszPath, csidl, fCreate):
        csidl = self.state.solver.eval(csidl)
        if csidl == 0x00: # CSIDL_DESKTOP
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\Public\\Desktop"))
        elif csidl == 0x01: # CSIDL_INTERNET
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Program Files (x86)\\Internet Explorer\\"))
        elif csidl == 0x02: # CSIDL_PROGRAMS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\Public\\Programs"))
        elif csidl == 0x03: # CSIDL_CONTROLS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Windows\\System32\\control.exe"))
        elif csidl == 0x04: # CSIDL_PRINTERS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Windows\\System32\\spool\\printers"))
        elif csidl == 0x05: # CSIDL_PERSONAL
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\Documents"))
        elif csidl == 0x06: # CSIDL_FAVORITES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\Favorites"))
        elif csidl == 0x07: # CSIDL_STARTUP
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"))
        elif csidl == 0x08: # CSIDL_RECENT
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Recent"))
        elif csidl == 0x09: # CSIDL_SENDTO
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\SendTo"))
        elif csidl == 0x0A: # CSIDL_BITBUCKET
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\$Recycle.Bin"))
        elif csidl == 0x0B: # CSIDL_STARTMENU
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu"))
        elif csidl == 0x0C: # CSIDL_DESKTOPDIRECTORY
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\Public\\Desktop"))
        elif csidl == 0x0D: # CSIDL_DRIVES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\"))
        elif csidl == 0x0E: # CSIDL_NETWORK
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Windows\\Network Shortcuts"))
        elif csidl == 0x0F: # CSIDL_NETHOOD
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Network Shortcuts"))
        elif csidl == 0x10: # CSIDL_FONTS
             self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Windows\\Fonts"))
        elif csidl == 0x11: # CSIDL_TEMPLATES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Templates"))
        elif csidl == 0x12: # CSIDL_COMMON_STARTMENU
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\ProgramData\\Microsoft\\Windows\\Start Menu"))
        elif csidl == 0x13: # CSIDL_COMMON_PROGRAMS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs"))
        elif csidl == 0x14: # CSIDL_COMMON_STARTUP
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"))
        elif csidl == 0x15: # CSIDL_COMMON_DESKTOPDIRECTORY
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\Public\\Desktop"))
        elif csidl == 0x16: # CSIDL_APPDATA
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming"))
        elif csidl == 0x17: # CSIDL_PRINTHOOD
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Printer Shortcuts"))
        elif csidl == 0x18: # CSIDL_COMMON_STARTUP
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"))
        elif csidl == 0x19: # CSIDL_ALTSTARTUP
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"))
        elif csidl == 0x1A: # CSIDL_APPDATA
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\USERNAME\\AppData\\Roaming"))
        elif csidl == 0x1B: # CSIDL_COMMON_FAVORITES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\Public\\Favorites"))
        elif csidl == 0x1C: # CSIDL_INTERNET_CACHE
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\INetCache"))
        elif csidl == 0x1D: # CSIDL_COOKIES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Cookies"))
        elif csidl == 0x1E: # CSIDL_HISTORY
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\History"))
        elif csidl == 0x1F: # CSIDL_COMMON_APPDATA
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\ProgramData"))
        elif csidl == 0x23: # CSIDL_ADMINTOOLS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools"))
        elif csidl == 0x24: # CSIDL_RESOURCES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Windows\\"))
        elif csidl == 0x25: # CSIDL_RESOURCES_LOCALIZED
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Windows\\Resources\\%LOCALIZED_RESOURCE_FOLDER%"))
        elif csidl == 0x26: # CSIDL_COMMON_DOCUMENTS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\Public\\Documents"))
        elif csidl == 0x27: # CSIDL_COMMON_ADMINTOOLS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools"))
        elif csidl == 0x28: # CSIDL_ADMINTOOLS
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Administrative Tools"))
        elif csidl == 0x2f: # CSIDL_MYPICTURES
            self.state.memory.store(pszPath,self.state.solver.BVV("C:\\Users\\%USERNAME%\\Pictures"))
        else:
            pass
            
        return 0x1
