import angr

# class GetThreadLocaleW(angr.SimProcedure):
#     def run(self, locale, lctype, lp_lc_data, cch_data):
        
       
#         response = { # TODO check from ChatGPT
#             0x00000001: "English (United States)\x00", # LOCALE_SENGLANGUAGE
#             0x00000002: "United States\x00", # LOCALE_SENGCOUNTRY
#             0x00000003: "en-US\x00", # LOCALE_SABBREVLANGNAME
#             0x00000007: "09\x00", # LOCALE_IDEFAULTLANGUAGE
#             0x00000010: "MM/dd/yyyy\x00", # LOCALE_SSHORTDATE
#             0x00000029: "AM\x00", # LOCALE_S1159
#             0x0000002A: "PM\x00", # LOCALE_S2359
#             0x0000005E: "$\x00", # LOCALE_SCURRENCY
#             0x0000007F: ".", # LOCALE_SDECIMAL
#             0x00000087: ",", # LOCALE_STHOUSAND
#             0x000000A0: ".", # LOCALE_SNATIVEDIGITS
#             0x000000B7: "-", # LOCALE_SMINUSIGN
#             0x000000C0: "+", # LOCALE_SPLUSSIGN
#             0x000000F5: "1,234.56\x00", # LOCALE_SPOSITIVESIGN
#         }
#         # TODO some error, shoud init with local directly in plugin
#         if lctype in response:
#             return_string = response[lctype]
#             # Store the return string in the buffer pointed to by `lp_lc_data`
#             str_size = len(return_string) + 1  # include the null terminator
#             str_size = min(str_size, cch_data)  # make sure we don't write past the end of the buffer
#             self.state.memory.store(lp_lc_data, return_string.encode("utf-16le")[:str_size * 2], endness="little")

#             # Return the size of the string, in characters, excluding the null terminator
#             return str_size - 1
#         else:
#             locale_ev = self.state.solver.eval(locale)
#             if locale_ev in self.state.plugin_locale_info.locale_info:
#                 infotype, lpdata, cchData = self.state.plugin_locale_info.locale_info[locale_ev]
#                 if infotype == lctype:
#                     self.state.memory.store(lp_lc_data, lpdata, endness="little")
#                     return cchData
                
#             return 0

        
