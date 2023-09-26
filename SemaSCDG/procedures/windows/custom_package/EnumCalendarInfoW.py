import angr


class EnumCalendarInfoW(angr.SimProcedure):
    def run(self, lpCalInfoEnumProc,Locale, Calendar,CalType):
        return 0x1
