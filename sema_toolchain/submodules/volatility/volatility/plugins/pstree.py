import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))
# Volatility
#
# Authors
# Michael Cohen <scudette@users.sourceforge.net>
#
# This file is part of Volatility.
#
# Volatility is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Volatility is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Volatility.  If not, see <http://www.gnu.org/licenses/>.
#

"""pstree example file"""
from volatility import renderers
from volatility.renderers.basic import Address

import volatility.win32.tasks as tasks
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.cache as cache
import volatility.obj as obj
import volatility.debug as debug

#pylint: disable-msg=C0111

class ProcessAuditVTypes(obj.ProfileModification):
    before = ["WindowsVTypes"]
    conditions = {'os': lambda x: x == 'windows'}
    def modification(self, profile):
        profile.vtypes.update({
            '_SE_AUDIT_PROCESS_CREATION_INFO' : [ 0x4, {
            'ImageFileName' : [ 0x0, ['pointer', ['_OBJECT_NAME_INFORMATION']]],
            }],
            '_OBJECT_NAME_INFORMATION' : [ 0x8, {
            'Name' : [ 0x0, ['_UNICODE_STRING']],
            }]})

class PSTree(common.AbstractWindowsCommand):
    """Print process list as a tree"""

    text_sort_column = "Pid"

    def find_root(self, pid_dict, pid):
        # Prevent circular loops.
        seen = set()

        while pid in pid_dict and pid not in seen:
            seen.add(pid)
            pid = int(pid_dict[pid].InheritedFromUniqueProcessId)

        return pid

    def generator(self, data):
        def draw_branch(level, inherited_from):
            for task in list(data.values()):
                if task.InheritedFromUniqueProcessId == inherited_from:

                    row = [Address(task.obj_offset),
                           str(task.ImageFileName or ''),
                           int(task.UniqueProcessId),
                           int(task.InheritedFromUniqueProcessId),
                           int(task.ActiveThreads),
                           int(task.ObjectTable.HandleCount),
                           str(task.CreateTime)]

                    if self._config.VERBOSE:
                        row += [str(task.SeAuditProcessCreationInfo.ImageFileName.Name or '')]
                        process_params = task.Peb.ProcessParameters
                        if not process_params:
                            row += [str("-"), str("-")]
                        else:
                            row += [str(process_params.CommandLine or ''),
                                    str(process_params.ImagePathName or '')]
                    yield (level, row)

                    try:
                        del data[int(task.UniqueProcessId)]
                    except KeyError:
                        debug.warning("PID {0} PPID {1} has already been seen".format(task.UniqueProcessId,
                                                                                      task.InheritedFromUniqueProcessId))

                    for item in draw_branch(level + 1, task.UniqueProcessId):
                        yield item

        while len(list(data.keys())) > 0:
            keys = list(data.keys())
            root = self.find_root(data, keys[0])
            for item in draw_branch(0, root):
                yield item

    def unified_output(self, data):

        cols = [("Offset", Address),
                ("Name", str),
                ("Pid", int),
                ("PPid", int),
                ("Thds", int),
                ("Hnds", int),
                ("Time", str)]

        if self._config.VERBOSE:
            cols += [("Audit", str),
                     ("Cmd", str),
                     ("Path", str)]

        tg = renderers.TreeGrid(cols, self.generator(data))
        return tg

    def render_text(self, outfd, data):
        self.table_header(outfd,
                         [("Name", "<50"),
                          ("Pid", ">6"),
                          ("PPid", ">6"),
                          ("Thds", ">6"),
                          ("Hnds", ">6"),
                          ("Time", "")])

        def draw_branch(pad, inherited_from):
            for task in list(data.values()):
                if task.InheritedFromUniqueProcessId == inherited_from:

                    first_column = "{0} {1:#x}:{2:20}".format(
                                        "." * pad,
                                        task.obj_offset,
                                        str(task.ImageFileName or '')
                                        )

                    self.table_row(outfd,
                        first_column,
                        task.UniqueProcessId,
                        task.InheritedFromUniqueProcessId,
                        task.ActiveThreads,
                        task.ObjectTable.HandleCount,
                        task.CreateTime)

                    if self._config.VERBOSE:
                        outfd.write("{0}    audit: {1}\n".format(
                                ' ' * pad, str(task.SeAuditProcessCreationInfo.ImageFileName.Name or '')))
                        process_params = task.Peb.ProcessParameters
                        if process_params:
                            outfd.write("{0}    cmd: {1}\n".format(
                                ' ' * pad, str(process_params.CommandLine or '')))
                            outfd.write("{0}    path: {1}\n".format(
                                ' ' * pad, str(process_params.ImagePathName or '')))

                    try:
                        del data[int(task.UniqueProcessId)]
                    except KeyError:
                        debug.warning("PID {0} PPID {1} has already been seen".format(task.UniqueProcessId, task.InheritedFromUniqueProcessId))

                    draw_branch(pad + 1, task.UniqueProcessId)

        while len(list(data.keys())) > 0:
            keys = list(data.keys())
            root = self.find_root(data, keys[0])
            draw_branch(0, root)

    @cache.CacheDecorator(lambda self: "tests/pstree/verbose={0}".format(self._config.VERBOSE))
    def calculate(self):

        ## Load a new address space
        addr_space = utils.load_as(self._config)

        return dict(
                (int(task.UniqueProcessId), task)
                for task in tasks.pslist(addr_space)
                )
