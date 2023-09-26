import angr
import logging

lw = logging.getLogger("CustomSimProcedureWindows")

class GetLocaleInfoW(angr.SimProcedure):
    def run(self, locale, lctype, lp_lc_data, cch_data):
        response = { # TODO check from ChatGPT + enhance
            0x00000001: "English (United States)\x00", # LOCALE_SENGLANGUAGE
            0x00000002: "United States\x00", # LOCALE_SENGCOUNTRY
            0x00000003: "en-US\x00", # LOCALE_SABBREVLANGNAME
            0x00000007: "09\x00", # LOCALE_IDEFAULTLANGUAGE
            0x00000010: "MM/dd/yyyy\x00", # LOCALE_SSHORTDATE
            0x0000000f: "MM/dd/yyyy\x00", # LOCALE_SSHORTDATE
            0x0000001e: "MM/dd/yyyy\x00", #LOCALE_SLONGDATE
            0x00000029: "AM\x00", # LOCALE_S1159
            0x0000001c: "am\x00",# LOCALE_S1159
            0x0000002A: "PM\x00", # LOCALE_S2359
            0x0000005E: "$\x00", # LOCALE_SCURRENCY
            0x0000007F: ".", # LOCALE_SDECIMAL
            0x00000020: ".", #LOCALE_SDECIMAL
            0x00000087: ",", # LOCALE_STHOUSAND
            0x000000A0: ".", # LOCALE_SNATIVEDIGITS
            0x000000B7: "-", # LOCALE_SMINUSIGN
            0x000000C0: "+", # LOCALE_SPLUSSIGN
            0x000000F5: "1,234.56\x00", # LOCALE_SPOSITIVESIGN
            0x0000004e: "h:mm tt\x00",  # LOCALE_SSHORTTIME
            0x0000004f: "1033\x00",  # LOCALE_IDEFAULTANSICODEPAGE
            0x00000042: "1033\x00",  # LOCALE_IDEFAULTANSICODEPAGE
            0x00000014: "US\x00", # LOCALE_IDEFAULTCOUNTRY
            0x00000043: "840\x00",  # LOCALE_SCOUNTRY
            0x00000019: "2\x00",  # LOCALE_ICURRDIGITS
            0x0000001B: "$\x00",  # LOCALE_ICURRENCY
            0x0000001D: "M/d/yyyy\x00",  # LOCALE_IDATE
            0x00000026: "0\x00",  # LOCALE_IDAYLZERO
            0x00000019: "2\x00",  # LOCALE_ICURRDIGITS
            0x00000005: "840\x00",  # LOCALE_ICOUNTRY
            0x00001009: "1\x00",  # LOCALE_ICALENDARTYPE
            0x00000024: "1\x00",  # LOCALE_ICENTURY
            0x0000100b: "1\x00",  # LOCALE_IOPTIONALCALENDAR
            
            0x00000031: "Monday\x00", # LOCALE_SABBREVDAYNAME1
            0x00000031: "Tuesday\x00", # LOCALE_SABBREVDAYNAME2
            0x00000033: "Wednesday\x00", # LOCALE_SABBREVDAYNAME3
            0x00000034: "Thursday\x00", # LOCALE_SABBREVDAYNAME4
            0x00000035: "Friday\x00", # LOCALE_SABBREVDAYNAME5
            0x00000036: "Saturday\x00", # LOCALE_SABBREVDAYNAME6
            0x00000037: "Sunday\x00", # LOCALE_SABBREVDAYNAME7
             
            #0x00010000: "\x00", # LOCALE_RETURN_NUMBER    = 68
            
            0x00000044: "January\x00", # LOCALE_SABBREVMONTHNAME1    = 68
            0x00000045: "February\x00", # LOCALE_SABBREVMONTHNAME2    = 69
            0x00000046: "March\x00", # LOCALE_SABBREVMONTHNAME3    = 70
            0x00000047: "April\x00", # LOCALE_SABBREVMONTHNAME4    = 71
            0x00000048: "May\x00", # LOCALE_SABBREVMONTHNAME5    = 72
            0x00000049: "June\x00", # LOCALE_SABBREVMONTHNAME6    = 73
            0x00000050: "July\x00", # LOCALE_SABBREVMONTHNAME7    = 74
            0x00000051: "August\x00", # LOCALE_SABBREVMONTHNAME8    = 75
            0x00000052: "September\x00", # LOCALE_SABBREVMONTHNAME9    = 76
            0x00000053: "October\x00", # LOCALE_SABBREVMONTHNAME10   = 77
            0x00000054: "November\x00", # LOCALE_SABBREVMONTHNAME11   = 78
            0x00000055: "December\x00", # LOCALE_SABBREVMONTHNAME12   = 79
            0x00000056: "\x00", # LOCALE_SABBREVMONTHNAME13   = 0x100F
            
            0xFFFFFFFF: "\x00", # LOCALE_ALL
        }
        # TODO some error, shoud init with local directly in plugin
        if self.state.solver.eval(lctype) in response.keys():
            lw.info("GetLocaleInfoW: %s", response[self.state.solver.eval(lctype)])
            # if self.state.solver.eval(lctype) == 0x00010000:
            #     return_int = response[self.state.solver.eval(lctype)] -> TO INT
            return_string = response[self.state.solver.eval(lctype)]
            # Store the return string in the buffer pointed to by `lp_lc_data`
            str_size = len(return_string) + 1  # include the null terminator
            str_size = min(str_size, self.state.solver.eval(cch_data))  # make sure we don't write past the end of the buffer
            self.state.memory.store(lp_lc_data, return_string.encode("utf-16le")[:str_size * 2], endness="little")
            locale_ev = self.state.solver.eval(locale)
            if not locale_ev in self.state.plugin_locale_info.locale_info:
                self.state.plugin_locale_info.locale_info[locale_ev] = (self.state.solver.eval(lctype), return_string, str_size)
            # Return the size of the string, in characters, excluding the null terminator
            return str_size - 1
        else:
            lw.info("Not in response")
            locale_ev = self.state.solver.eval(locale)
            lw.info(hex(locale_ev))
            if locale_ev in self.state.plugin_locale_info.locale_info:
                infotype, lpdata, cchData = self.state.plugin_locale_info.locale_info[locale_ev]
                info_ev = self.state.solver.eval(infotype)
                lctype_ev = self.state.solver.eval(lctype)
                if info_ev == lctype_ev:
                    self.state.memory.store(lp_lc_data, lpdata, endness="little")
                    return cchData
            lw.info("Not in locale_info")
            self.state.plugin_locale_info.locale_info[locale_ev] = (self.state.solver.eval(lctype), self.state.solver.eval(lp_lc_data), self.state.solver.eval(cch_data))
            return 0

        
