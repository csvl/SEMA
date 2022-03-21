from hypothesis import given, strategies as st
from toolchain_scdg.src.procedures.linux.custom_package.getgid import getgid
from angr import SimState

def getgid_test():
    """
    DESCRIPTION         
       getgid() returns the real group ID of the calling process.

       getegid() returns the effective group ID of the calling process.
    ERRORS         
       These functions are always successful and never modify errno.
    """
    state = SimState(arch="AMD64", mode="symbolic")
    command = getgid()
    command.state = state.copy()
    assert command.run() == 1000