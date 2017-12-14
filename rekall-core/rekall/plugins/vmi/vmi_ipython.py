# rVMI
# Copyright (C) 2017 FireEye, Inc. All Rights Reserved.
#
# Authors:
# Jonas Pfoh     <jonas.pfoh@fireeye.com>
# Sebastian Vogl <sebastian.vogl@fireeye.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation. Version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#


import IPython
from IPython.core.magic import (Magics, magics_class, line_magic,
                                cell_magic, line_cell_magic)
from IPython.core.inputtransformer import StatelessInputTransformer

from rekall import plugin
from utils import Singleton

import json
import re

@magics_class
class QmpMagics(Magics):
    def split_cmd(self,line):
        m = re.search("(.+)\((.*)\)",line)
        if m is None:
            raise RuntimeError("invalid format")

        cmd = m.group(1).strip()
        args = m.group(2).strip()
        if len(args) == 0:
            args = []
        else:
            args = args.split(',')
        return cmd, args

    def get_num(self,x):
        try:
            return int(x)
        except ValueError:
            try:
                return float(x)
            except ValueError:
                return int(x,16)

    def split_arg(self,line):
        m = re.search("(\S+)\s*=\s*('.*?'|\".*?\"|\S+)", line)
        if m is None:
            raise RuntimeError("invalid format")
        key = m.group(1)
        value = m.group(2)
        if((value.startswith("'") and value.endswith("'")) or
           (value.startswith("\"") and value.endswith("\""))):
            value = value.strip("\"'")
        elif value.lower() == "true":
            value = True
        elif value.lower() == "false":
            value = False
        else:
            try:
                value = self.get_num(value)
            except ValueError:
                raise RuntimeError("invalid format")
        return key, value

    @line_magic
    def qmpx(self, line):
        session = self.shell.user_global_ns["session"]
        cmd, args = self.split_cmd(line)
        arg_items = {}
        for item in args:
            key, value = self.split_arg(item)
            if(key in arg_items.keys()):
                raise RuntimeError("duplicate args")
            arg_items[key]=value

        #{ "execute": "eject", "arguments": { "device": "ide1-cd0" } }
        if len(arg_items) > 0:
            qmp_cmd_obj = {"execute":cmd,"arguments":arg_items}
        else:
            qmp_cmd_obj = {"execute":cmd}

        q = session.vmi._qmp
        print(json.dumps(qmp_cmd_obj))
        print(q.cmd_obj(qmp_cmd_obj))

class VmiIPython(object):
    __metaclass__ = Singleton

    def __init__(self, session):
        self._session = session

    @property
    def session(self):
        return self._session

    def apply_transforms(self, line):
        result = line

        # Only apply the transformations im VMI is active
        if not self.session.GetParameter("mode_vmi", default=False):
            return result

        for s in VmiTransform.__subclasses__():
            if s.matches(result):
                result = s.transform(result, self)

        return result

def vmi_keyboard_interrupt_handler(self, etype, value, tb, tb_offset=None):
    return None

@StatelessInputTransformer.wrap
def vmi_input_transformer(line):
    vmi_ip = VmiIPython()
    result = vmi_ip.apply_transforms(line)

    return result

def Init(session):
    shell = IPython.get_ipython()

    if shell:
        VmiIPython(session)
        shell.input_splitter.logical_line_transforms.append(vmi_input_transformer())
        shell.input_transformer_manager.logical_line_transforms.append(vmi_input_transformer())
        shell.register_magics(QmpMagics)

        # Register interrupt handlers
        shell.set_custom_exc((KeyboardInterrupt,), vmi_keyboard_interrupt_handler)


class VmiTransform(object):
    # Regex that will trigger the transformation
    _regex = None

    @classmethod
    def matches(cls, data):
        result = re.search(cls._regex, data)

        if result != None:
            return True
        else:
            return False

    @classmethod
    def transform(cls, data, vmi_ip):
        return data

class VmiRegisterTransform(VmiTransform):
    _regex = r"\$([a-zA-Z0-9]+)(\[(?P<cpu>[0-9]+)\])?(?!\s*=)"

    @classmethod
    def transform(cls, data, vmi_ip):
        cpu_state = vmi_ip.session.vmi.guest_state.get_cpu_state()
        cpu_state_func = vmi_ip.session.vmi.guest_state.get_cpu_state

        result = data
        for match in re.finditer(cls._regex, data):
            if match.group(1) != None and match.group(1) in cpu_state.keys():
                cpu = match.group("cpu") if match.group("cpu") != None else ""
                cpu_replace = ("[" + match.group("cpu") + "]" if match.group("cpu")
                                                                 != None else "")
                result = result.replace("$" + match.group(1) + cpu_replace,
                                        'session.vmi.guest_state.' \
                                        'get_cpu_state(' + cpu + ')["' +
                                        match.group(1) + '"]')

        return result

class VmiRegisterUpdateTransform(VmiTransform):
    _regex = r"\$([a-zA-Z0-9]+)(\s*=\s*)"

    @classmethod
    def transform(cls, data, vmi_ip):
        match = re.match(cls._regex, data)

        if not match:
            return data

        reg = match.group(1)
        value = data[data.find('=') + 1:]

        return 'vm_cpu_state_update("{0}", value={1})'.format(reg, value)

class VmiGdbMemoryTransform(VmiTransform):
    _regex = r"^\s*x/?(?P<length>[0-9]+)?(?P<format>(o|x|d|u|t|f|c|s|i|b|h|w|g)+)?\s*(?P<addr>.+)$"

    @classmethod
    def transform(cls, data, vmi_ip):
        match = re.match(cls._regex, data)
        match = match.groupdict()

        # Disassemble
        if "format" in match and "i" in match["format"]:
            length = 10

            if "length" in match:
                length = match["length"]

            return "dis({0},length={1})".format(match["addr"], length)

        # Else
        args = ""

        if "length" in match:
            args += 'length={0},'.format(match["length"])

        if "format" in match:
            args += 'output_format="{0}",'.format(match["format"])

        args += 'addr={0}'.format(match["addr"])

        return "vm_print_mem({0})".format(args)



