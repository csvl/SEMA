from hypothesis import given, strategies as st
from toolchain_scdg.src.procedures.linux.custom_package.chdir import chdir
from angr import SimState

@given(st.characters())
def chdir_test(path):
    """
    chdir(path) changes the current working directory of the calling
    process to the directory specified in path.
    On success, zero is returned.  On error, -1 is returned, and
    errno is set to indicate the error.
    """
    state = SimState(arch="AMD64", mode="symbolic")
    command = chdir()
    command.state = state.copy()
    assert command.run(path) == 0