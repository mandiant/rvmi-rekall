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


""" This file contains the core classes used by VMI plugins. """
from rekall_lib import utils
from rekall import addrspace
from rekall import plugin
from rekall.plugins import core
from rekall.plugins.common import address_resolver

import datetime
import subprocess
import socket
import struct
import string
import tempfile

from .callbacks import callbacks_init
from rekall import addrspace

# Called by the VMI interface once a connection is ready
def vmi_init(vmi):
    callbacks_init(vmi)

class GuestState(object):
    def __init__(self,session=None, vmi=None):
        if(session is None):
            raise ValueError("session must be set")
        if(vmi is None):
            raise ValueError("session.vmi must be set")
        self.session = session
        self.vmi = vmi

    @utils.safe_property
    def num_cpus(self):
        num_cpus = self.session.GetParameter("num_cpus",default=None)
        if(num_cpus is None):
            vminfo = self.vmi.get_vminfo()
            num_cpus = vminfo["num_cpus"]
            self.session.SetCache("num_cpus", num_cpus)
        return num_cpus

    @utils.safe_property
    def mem_size(self):
        mem_size = self.session.GetParameter("mem_size",default=None)
        if(mem_size is None):
            vminfo = self.vmi.get_vminfo()
            mem_size = vminfo["mem_info"]["size"]
            self.session.SetCache("mem_size", mem_size)
        return mem_size

    @utils.safe_property
    def mem_filebacked(self):
        mem_filebacked = self.session.GetParameter("mem_filebacked",default=None)
        if(mem_filebacked is None):
            vminfo = self.vmi.get_vminfo()
            mem_filebacked = vminfo["mem_info"]["filebacked"]
            self.session.SetCache("mem_filebacked", mem_filebacked)
        return mem_filebacked

    @utils.safe_property
    def mem_path(self):
        mem_path = self.session.GetParameter("mem_path",default=None)
        if(mem_path is None):
            vminfo = self.vmi.get_vminfo()
            mem_path = vminfo["mem_info"]["path"]
            self.session.SetCache("mem_path", mem_path)
        return mem_path

    def cur_cpl(self,cpu_num):
        cpu_state = self.get_cpu_state(cpu_num)
        return cpu_state["cs"]["selector"] & 0x3

    def get_cpu_state(self,cpu_num=None):
        if cpu_num == None:
            cpu_num = self.session.GetParameter("cur_cpu",default=None)

            if cpu_num == None:
                cpu_num = 0

        cpu_state = self.session.GetParameter("cpu_state",default=None)
        if cpu_state is None:
            cpu_state = [None] * self.vmi.guest_state.num_cpus

        if cpu_state[cpu_num] is None:
            cpu_state[cpu_num] = self.vmi.get_cpu_state(cpu_num)

        self.session.SetCache("cpu_state",cpu_state)
        return cpu_state[cpu_num]

    def set_cpu_state(self,cpu_num=None):
        if cpu_num == None:
            cpu_num = self.session.GetParameter("cur_cpu",default=None)

            if cpu_num == None:
                cpu_num = 0

        state = self.get_cpu_state(cpu_num).copy()
        self.vmi.set_cpu_state(cpu_num, state)

    def process(self, cpu_num=None):
        """ Get the process running on cpu cpu_num. """
        return None

    def cache_period_flush(self,key):
        return True

class VMCommandPlugin(plugin.PhysicalASMixin,
                      plugin.TypedProfileCommand,
                      plugin.Command):
    """ Base class for all VM commands.

        VM commands require mode vmi and a physical address space.
    """

    __abstract = True

    mode = "mode_vmi"

class VMProfileCommandPlugin(VMCommandPlugin, plugin.ProfileCommand):
    """ Base class for all VM commands that require a profile. """

    __abstract = True

class VMContinue(VMCommandPlugin):
    """ Let the execution of the VM continue.

    Execution will continue until the VM is stopped (e.g. by an event),
    the given timeout is met, or the user interrupts execution using
    a KeyboardInterrupt.
    """

    __name = "vm_cont"

    __args = [
        dict(name="timeout", positional=True, type="FloatParser", default=False,
             help="Continue until an event is received or the timeout occurs.")
    ]

    def render(self, renderer):
        self.session.vmi.cont_until_stop(float(self.plugin_args.timeout))

class VMSingleStep(VMCommandPlugin):
    """ Let the execution of the VM continue on a single CPU for a single instruction.

    Execution will continue on a single CPU until the next instruction.
    If the instruction to single step causes an exception or fault, control
    will return before the first instruction of the given handler.
    """

    __name = "vm_ss"

    __args = [
        dict(name="cpu", positional=True, type="IntParser", default=None,
             help="The cpu on which to single step (default: current CPU)")
    ]

    def render(self, renderer):
        self.session.vmi.single_step(cpu_num=self.plugin_args.cpu)
        self.session.vmi.cont_until_stop()

class VMBreakpointSW(VMCommandPlugin):
    """ Set software breakpoint for a specified DTB and GVA.

    A software breakpoint will be set for the specified diretory table base (DTB)
    on the specified guest virtual address (GVA).  If 'global' is True, the breakpoint
    will be set globally
    """

    __name = "vm_breakpoint_add"

    __args = [
        dict(name="dtbs", positional=True, required=True, type="ArrayIntParser",
             help="The directory table base to use for translation when translating the guest virtual address (must be possed as array)"),
        dict(name="gva", positional=True, required=True, type="IntParser",
             help="The guest virtual address on which to set the breakpoint."),
        dict(name="globally", type="BoolParser", default=False,
             help="Set whether the breakpoint is to be global. (default: False)"),
    ]

    def render(self, renderer):
        if getattr(self.plugin_args,"globally"):
            dtb = 0
        else:
            dtb = self.plugin_args.dtbs[0]
        self.session.vmi.breakpoint_sw_add(dtb=dtb,gva=self.plugin_args.gva)
        renderer.format("Successfully set breakpoint on {0}:{1}", dtb, self.plugin_args.gva)

class VMWatchpoint(VMCommandPlugin):
    """ Set watchpoint for a specified DTB and GVA.

    A watchpoint will be set for the specified diretory table base (DTB) on the
    specified guest virtual address (GVA).  If 'global' is True, the watchpoint
    will be set globally
    """

    __name = "vm_watchpoint_add"

    __args = [
        dict(name="dtbs", positional=True, required=True, type="ArrayIntParser",
             help="The directory table base to use for translation when translating the guest virtual address (must be possed as array)"),
        dict(name="gva", positional=True, required=True, type="IntParser",
             help="The guest virtual address on which to set the watchpoint."),
        dict(name="length", positional=True, required=True, type="IntParser",
             help="The length of the watchpoint in bytes (1, 2, 4)."),
        dict(name="type", positional=True, required=True, type="StringParser",
             help="The type of the watchpoint to set (\"watchpoint_read\", \"watchpoint_write\", \"watchpoint_access\")"),
        dict(name="globally", type="BoolParser", default=False,
             help="Set whether the breakpoint is to be global. (default: False)"),
    ]

    def render(self, renderer):
        if getattr(self.plugin_args,"globally"):
            dtb = 0
        else:
            dtb = self.plugin_args.dtbs[0]
        self.session.vmi.watchpoint_add(dtb=dtb,gva=self.plugin_args.gva,
                                        length=self.plugin_args.length,
                                        type=self.plugin_args.type)
        renderer.format("Successfully set {0} watchpoint on {1}:{2}({3})",
                        self.plugin_args.type, dtb, self.plugin_args.gva,
                        self.plugin_args.length)

class DebugList(VMCommandPlugin):
    """ List all debug events currently set.

    List all debug events previously set.  This includes all breakpoints and watchpoints.
    """

    __name = "vm_debug_list"

    def render(self, renderer):
        debug_list = self.session.vmi.debug_list()
        renderer.table_header([
            ("Index", "index", "5"),("Type", "type", "15"),
            ("DTB", "dtb", "18"),("GVA", "gva", "18"),
            ("Length", "length", "6")])

        for debug_entry in debug_list:
            renderer.table_row(debug_entry["index"],debug_entry["type"],
                               hex(debug_entry["dtb"]), "0x{:x}".format(debug_entry["gva"]),
                               debug_entry["length"])

class DebugRemove(VMCommandPlugin):
    """ Remove debug events.

    Remove all specified debug events.  Each event is specified through the index displyed by vm_debug_list
    """

    __name = "vm_debug_remove"

    __args = [
        dict(name="indices", positional=True, required=True, type="ArrayIntParser",
             help="The indices of the debug events to remove."),
    ]

    def render(self, renderer):
        for index in self.plugin_args.indices:
            self.session.vmi.debug_remove(index)
            renderer.format("Successfully removed index {0}",index)

class VMContext(VMCommandPlugin):
    """ Print the current context. """
    __name = "vm_context"

    def render(self, renderer):
        for cpu in range(0, self.session.vmi.guest_state.num_cpus):
            rip = self.session.vmi.guest_state.get_cpu_state(cpu)["rip"]
            renderer.format("CPU {:2d} @ 0x{:016x}\n".format(cpu, rip))

class VMGetCpuState(VMCommandPlugin):
    __name = "vm_cpu_state"

    __args = [
        dict(name="cpu_num", positional=True, type="IntParser", default=0,
             help="The cpu number for which you want state."),
    ]

    def _64b_to_str(self, v):
        return "0x%016x" % v

    def _32b_to_str(self, v):
        return "0x%08x" % v

    def _16b_to_str(self, v):
        return "0x%04x" % v

    def _seg_to_str(self, v):
        return "0x%04x 0x%016x 0x%08x 0x%08x" % (v["selector"], v["base"], v["limit"], v["flags"])

    def _sign_extend(self, v):
        if self.session.profile.metadata("arch") == "AMD64":
            if(v & 0x800000000000):
                return 0xffff000000000000 | v
        return v

    def render(self, renderer):
        rsp = self.session.vmi.guest_state.get_cpu_state(self.plugin_args.cpu_num)
        renderer.format("CPU {0}\n", str(self.plugin_args.cpu_num))
        renderer.table_header([
            ("Key", "key", "5"),("Value", "value", "50"),
            ("Key", "key", "5"),("Value", "value", "50")], suppress_headers=True)

        renderer.table_row("RAX",self._64b_to_str(rsp["rax"]),"RBX",self._64b_to_str(rsp["rbx"]))
        renderer.table_row("RCX",self._64b_to_str(rsp["rcx"]),"RDX",self._64b_to_str(rsp["rdx"]))
        renderer.table_row("RSI",self._64b_to_str(rsp["rsi"]),"RDI",self._64b_to_str(rsp["rdi"]))
        renderer.table_row("RBP",self._64b_to_str(rsp["rbp"]),"RSP",self._64b_to_str(rsp["rsp"]))
        renderer.table_row("R8",self._64b_to_str(rsp["r8"]),"R9",self._64b_to_str(rsp["r9"]))
        renderer.table_row("R10",self._64b_to_str(rsp["r10"]),"R11",self._64b_to_str(rsp["r11"]))
        renderer.table_row("R12",self._64b_to_str(rsp["r12"]),"R13",self._64b_to_str(rsp["r13"]))
        renderer.table_row("R14",self._64b_to_str(rsp["r14"]),"R15",self._64b_to_str(rsp["r15"]))
        renderer.table_row("RIP",self._64b_to_str(rsp["rip"]),"EFL",self._32b_to_str(rsp["eflags"]))
        renderer.table_row("ES",self._seg_to_str(rsp["es"]),"CS",self._seg_to_str(rsp["cs"]))
        renderer.table_row("SS",self._seg_to_str(rsp["ss"]),"DS",self._seg_to_str(rsp["ds"]))
        renderer.table_row("FS",self._seg_to_str(rsp["fs"]),"GS",self._seg_to_str(rsp["gs"]))
        renderer.table_row("LDT",self._seg_to_str(rsp["ldt"]),"TR",self._seg_to_str(rsp["tr"]))
        renderer.table_row("GDT",self._seg_to_str(rsp["gdt"]),"IDT",self._seg_to_str(rsp["idt"]))
        renderer.table_row("CR0",self._64b_to_str(rsp["cr0"]),"CR2",self._64b_to_str(rsp["cr2"]))
        renderer.table_row("CR3",self._64b_to_str(rsp["cr3"]),"CR4",self._64b_to_str(rsp["cr4"]))
        renderer.table_row("DR0",self._64b_to_str(rsp["dr0"]),"DR1",self._64b_to_str(rsp["dr1"]))
        renderer.table_row("DR2",self._64b_to_str(rsp["dr2"]),"DR3",self._64b_to_str(rsp["dr3"]))
        renderer.table_row("DR6",self._64b_to_str(rsp["dr6"]),"DR7",self._64b_to_str(rsp["dr7"]))
        renderer.table_row("EFER",self._64b_to_str(rsp["efer"]),"","")

class VMUpdateCpuState(VMProfileCommandPlugin):
    __name = "vm_cpu_state_update"
    __abstract = False
    interactive = True

    __args = [
        dict(name="cpu_num", positional=False, type="IntParser", default=0,
             help="The cpu number for which you want state."),
        dict(name="register", required=True, positional=True, type="String", default=0,
             help="The register that should be updated."),
        dict(name="value", type="IntParser", default=None,
             help="The new value of the register."),
        dict(name="base", type="IntParser", default=None,
             help="Update the base of a segment register."),
        dict(name="limit", type="IntParser", default=None,
             help="Update the limit of a segment register."),
        dict(name="selector", type="IntParser", default=None,
             help="Update the selector of a segment register."),
        dict(name="flags", type="IntParser", default=None,
             help="Update the flags of a segment register."),
    ]

    def render(self, renderer):
        state = self.session.vmi.guest_state.get_cpu_state(self.plugin_args.cpu_num)

        if not self.plugin_args.register in state:
            raise ValueError("unknown register '{0}'".format(self.plugin_args.register))

        if self.plugin_args.register.lower() in ["es", "cs", "ss", "ds", "fs", "gs",
                                                     "ldt", "gdt", "tr", "idt"]:
            if (self.plugin_args.base == None and
                self.plugin_args.limit == None and
                self.plugin_args.selector == None and
                self.plugin_args.flags == None):
                raise ValueError("Setting a segment requires a base, limit, selector, or flags argument")

            if self.plugin_args.base != None:
                state[self.plugin_args.register]["base"] = self.plugin_args.base

            if self.plugin_args.limit != None:
                state[self.plugin_args.register]["limit"] = self.plugin_args.limit

            if self.plugin_args.selector != None:
                state[self.plugin_args.register]["selector"] = self.plugin_args.selector

            if self.plugin_args.flags != None:
                state[self.plugin_args.register]["flags"] = self.plugin_args.flags
        else:
            if self.plugin_args.value == None:
                raise ValueError("Setting a register requires a value argument")

            state[self.plugin_args.register] = self.plugin_args.value

        self.session.vmi.guest_state.set_cpu_state()
        return "{0} = {1}".format(self.plugin_args.register, state[self.plugin_args.register])

class VMLBR(VMCommandPlugin):
    __name = "vm_lbr"

    __args = [
        dict(name="enable", required=True, positional=False,
             type="Bool", default=False,
             help="Whether to enable or disable the LBR."),
        dict(name="select",
             type="IntParser", default=0,
             help="Value of the MSR_LBR_SELECT register."),
    ]

    def render(self, renderer):
        enable = self.plugin_args.enable
        select = self.plugin_args.select

        result = self.session.vmi.lbr(enable, select)

class VMGetLBR(VMCommandPlugin):
    __name = "vm_get_lbr"

    __args = [
        dict(name="cpu_num",
             type="IntParser", default=None,
             help="The CPU number of which the lbr should be obtained."),
    ]

    def resolve_symbol(self, v):
        resolve = self.session.address_resolver.get_nearest_constant_by_address
        symbol = resolve(v)[1]
        symbol = "".join(symbol)
        symbol = symbol.encode('ascii', 'ignore')

        if symbol == "":
            return "???"
        else:
            return symbol

    def disassemble(self, offset, length=1):
        from rekall.plugins.tools.disassembler import Function

        f = Function(offset=offset,
                     vm=self.session.default_address_space,
                     session=self.session)

        return f.disassemble(instructions=length)

    def pretty_inst(self, offset):
        op_str = self.disassemble(offset, 1).next().op_str

        if op_str == None:
            return ""
        return op_str

    def render(self, renderer):
        if self.plugin_args.cpu_num == None:
            cpu_num = self.session.GetParameter("cur_cpu",default=0)
        else:
            cpu_num = self.plugin_args.cpu_num

        lbr = self.session.vmi.get_lbr(self.plugin_args.cpu_num)

        entries = lbr["entries"]
        tos = lbr["tos"]
        resolve = self.resolve_symbol
        from_symbols = []
        to_symbols = []
        max_sym = 0

        renderer.format("CPU:{:2d}, Entries: {:02d}, " \
                        "Top of Stack (TOS): {:02d}\n".format(cpu_num, entries, tos))
        renderer.format("-------------------------------------------\n")

        for i in range(0, entries):
            cur = (tos - i) % entries
            cur_from = lbr["from"][cur]
            cur_to = lbr["to"][cur]

            if (cur_from & 0xf000000000000000) != 0xf000000000000000:
                if (cur_from & 0x0f00000000000000) == 0x0f00000000000000:
                    cur_from |= 0xf000000000000000
                else:
                    cur_from &= 0x0fffffffffffffff

            _from = resolve(cur_from) + ":" + self.pretty_inst(cur_from)
            from_symbols.append(_from)
            _to = resolve(cur_to)  + ":" + self.pretty_inst(cur_to)
            to_symbols.append(_to)

            if len(_from) > max_sym:
                max_sym = len(_from)
            if len(_to) > max_sym:
                max_sym = len(_to)

        for i in range(0, entries):
            cur = (tos - i) % entries
            cur_from = lbr["from"][cur]
            cur_to = lbr["to"][cur]
            predicted = True

            if (cur_from & 0xf000000000000000) != 0xf000000000000000:
                if (cur_from & 0x0f00000000000000) == 0x0f00000000000000:
                    cur_from |= 0xf000000000000000
                else:
                    cur_from &= 0x0fffffffffffffff
                predicted = False

            renderer.format(("{:5} #{:02d} 0x{:016x} {:" + str(max_sym + 2) + "s} " \
                             "(Predicted: {:s})\n{:5}  {:2} 0x{:016x} "\
                             "{:" + str(max_sym + 2) + "s}\n").format(
                             " TOS " if i == 0 else "", cur,
                            cur_from, "[" + from_symbols[i] + "]",
                            str(predicted), "", "",
                            cur_to, "[" + to_symbols[i] + "]"))

class VMSave(VMCommandPlugin):
    __name = "vm_save"

    __args = [
        dict(name="name", type="String", default=None,
             help="The name that the snapshot will be stored under.")
    ]

    def render(self, renderer):
        self.session.vmi.savevm(None, self.plugin_args.name)

class VMDelete(VMCommandPlugin):
    __name = "vm_delete"

    __args = [
        dict(name="id", type="IntParser", default=None,
             help="The id of the snapshot that will be deleted."),
        dict(name="name", type="String", default=None,
             help="The name of the snapshot that will be deleted.")
    ]

    def render(self, renderer):
        id = str(self.plugin_args.id) if self.plugin_args.id != None else None

        self.session.vmi.delvm(id, self.plugin_args.name)

class VMLoad(VMCommandPlugin):
    __name = "vm_load"

    __args = [
        dict(name="id", type="IntParser", default=None,
             help="The id of the snapshot to load."),
        dict(name="name", type="String", default=None,
             help="The name of the snapshot to load.")
    ]

    def render(self, renderer):
        id = str(self.plugin_args.id) if self.plugin_args.id != None else None

        self.session.vmi.loadvm(id, self.plugin_args.name)

        # Clear cache
        self.session.cache.Clear()

class VMSnapshots(VMCommandPlugin):
    __name = "vm_snapshots"
    __abstract = False

    __args = [
    ]

    def render(self, renderer):
        s = self.session.vmi.snapshots()

        renderer.table_header([
            ("ID", "id", ":>7"),("Name", "name", "20s"),
            ("Size", "size", ":>10"),("Date", "date", ":>25s"),
            ("VM Time", "vm_time", ":>25s")])

        for e in s:
            date = datetime.datetime.fromtimestamp(
                    int(e["date-sec"])).strftime('%Y-%m-%d %H:%M:%S')

            renderer.table_row(e["id"], e["name"],
                               "{0} Mb".format(int(e["vm-state-size"]) / (1024 * 1024)),
                               date, "{:d}.{:d} s".format(e["vm-clock-sec"],
                                                         e["vm-clock-nsec"]))

class VMTrapTaskSwitch(VMCommandPlugin):
    """ Enable trapping of CR3 writes.

    This command enables/disables the trapping of CR3 writes, which usually
    are a sign of a task switch. An event will be generated whenever the
    specified CR3 value is written into the CR3 or removed from the CR3
    depending on whether the in and/or the out flags are set.
    """

    __name = "vm_trap_task_switch"

    __args = [
        dict(name="enable", required=True, positional=False,
             type="Bool", default=False,
             help="Whether to enable or disable CR3 write trapping."),
        dict(name="cr3", type="IntParser", required=True, default=None,
             help="The CR3 value to look for."),
        dict(name="trap_in", required=False, positional=False,
             type="Bool", default=False,
             help="Trap when the given CR3 value is written into the CR3."),
        dict(name="trap_out", required=False, positional=False,
             type="Bool", default=False,
             help="Trap when the given CR3 value is removed from the CR3."),
    ]

    def render(self, renderer):
        pa = self.plugin_args

        if (pa.trap_in == False and pa.trap_out == False):
            raise ValueError("at least one of the flags (in, out) must be " \
                             "set to True")

        self.session.vmi.trap_task_switches(pa.enable, pa.cr3, pa.trap_in,
                                            pa.trap_out)

class VMLoadAsIso(VMCommandPlugin):
    """ Load a file/directory into the guest using an iso.

    This command allows to load files or directories into the guest. This is
    achieved by adding the target files to an iso which is then loaded by the
    virtual CD drive.
    """

    __name = "vm_load_as_iso"

    __args = [
        dict(name="target", required=True, type="String",
             help="Path to the file or directory that should be loaded")
    ]

    def render(self, renderer):
        target = self.plugin_args.target

        f = tempfile.mkdtemp(prefix="rVMI_iso_")

        try:
            subprocess.check_output(["cp", "-r", target, f],
                                    stderr=subprocess.STDOUT)
            subprocess.check_output(["mkisofs", "-D", "-J", "-o", f + ".iso", f],
                                    stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            renderer.format("Error (0}):\n".format(e.returncode))
            renderer.format("{0}\n".format(e.output))
            return

        self.session.vmi.change("ide1-cd0", f + ".iso")

class VMPrintMem(VMCommandPlugin):
    __name = "vm_print_mem"
    __abstract = False

    __args = [
        dict(name="output_format", type="String", default="xg",
             help="The output format to be used."),
        dict(name="length", positional=False, type="IntParser", default=10,
             help="The number of occurrences to print."),
        dict(name="addr", positional=False, required=True, type="IntParser",
             default=0, help="The address where to read from.")
    ]

    # Output bytes per line
    output_width = 16

    def _get_dec_output(self, addr, format, length):
        result = []
        elem_size = 0
        i = 0

        while i < length:
            if ('b' in format):
                data = self.session.default_address_space.read(addr + i, 1)
                elem_size = 1

                if ('d' in format):
                    result.append(struct.unpack("<b", data)[0])
                else:
                    result.append(struct.unpack("<B", data)[0])

                i += 1
            elif ('h' in format):
                data = self.session.default_address_space.read(addr + i * 2, 2)
                elem_size = 2

                if ('d' in format):
                    result.append(struct.unpack("<h", data)[0])
                else:
                    result.append(struct.unpack("<H", data)[0])

                i += 1
            elif ('w' in format):
                data = self.session.default_address_space.read(addr + i * 4, 4)
                elem_size = 4

                if ('d' in format):
                    result.append(struct.unpack("<i", data)[0])
                else:
                    result.append(struct.unpack("<I", data)[0])

                i += 1
            elif ('g' in format):
                data = self.session.default_address_space.read(addr + i * 8, 8)
                elem_size = 8

                if ('d' in format):
                    result.append(struct.unpack("<q", data)[0])
                else:
                    result.append(struct.unpack("<Q", data)[0])

                i += 1
            else:
                # Use w
                data = self.session.default_address_space.read(addr + i * 4, 4)
                elem_size = 4

                if ('d' in format):
                    result.append(struct.unpack("<i", data)[0])
                else:
                    result.append(struct.unpack("<I", data)[0])

                i += 1

        return (elem_size, result)

    def _get_hex_output(self, addr, format, length):
        result = []

        (elem_size, elements) = self._get_dec_output(addr, format, length)

        for e in elements:
            result.append(("0x{:0" + str(elem_size * 2) + "x}").format(e))

        return (elem_size, result)

    def _get_binary_output(self, addr, format, length):
        result = []

        (elem_size, elements) = self._get_dec_output(addr, format, length)

        for e in elements:
            result.append(("{:0" + str(elem_size * 8) + "b}").format(e))

        return (elem_size, result)

    def _get_octal_output(self, addr, format, length):
        result = []

        (elem_size, elements) = self._get_dec_output(addr, format, length)

        for e in elements:
            result.append(oct(e))

        return (elem_size, result)

    def _get_float_output(self, addr, format, length):
        result = []
        i = 0

        while i < length:
            data = self.session.default_address_space.read(addr + i * 4, 4)
            data = struct.unpack("<f", data)[0]
            result.append('{:.3f}'.format(data))

            i += 1

        return (4, result)

    def _get_char_output(self, addr, format, length):
        result = []
        i = 0

        while i < length:
            data = self.session.default_address_space.read(addr + i * 1, 1)
            data = struct.unpack("<B", data)[0]
            result.append("'{:s}' (0x{:02x})".format(chr(data) if data >= 0x20 and data <= 0x7f else " ", data))

            i += 1

        return (2, result)

    def _get_string_output(self, addr, format, length):
        result = []
        i = 0
        j = 0

        while i < length:
            data = ' '
            cur = ""
            while data != 0:
                data = self.session.default_address_space.read(addr + j, 1)
                data = struct.unpack("<B", data)[0]

                if data >= 0x20 and data <= 0x7f:
                    cur = chr(data)
                else:
                    cur = "\\x{:02x}".format(data)

                j += 1
                result.append(cur)

            i += 1

        return (1, result)

    def _get_output_by_format(self, addr, format, length):
        if ("d" in format or 'u' in format):
            return self._get_dec_output(addr, format, length)
        elif ('x' in format):
            return self._get_hex_output(addr, format, length)
        elif ('o' in format):
            return self._get_octal_output(addr, format, length)
        elif ('t' in format):
            return self._get_binary_output(addr, format, length)
        elif ('f' in format):
            return self._get_float_output(addr, format, length)
        elif ('c' in format):
            return self._get_char_output(addr, format, length)
        elif ('s' in format):
            return self._get_string_output(addr, format, length)
        else:
            raise ValueError("Unsupported output format '{0}'".format(format))

    def render(self, renderer):
        addr = self.plugin_args.addr
        format = self.plugin_args.output_format
        length = self.plugin_args.length

        (elem_size, elements) = self._get_output_by_format(addr, format, length)

        longest_element = 0

        for e in elements:
            if len(str(e)) > longest_element:
                longest_element = len(str(e))


        line = ""
        line_size = 0
        for e in elements:
            if (line == ""):
                line = "0x{:016x}: ".format(addr)

            line += ("{:>" + str(longest_element) + "}").format(e)
            line_size += elem_size

            if (line_size >= self.output_width or len(line) >= 80):
                renderer.format(line + "\n")
                line = ""
                addr += line_size
                line_size = 0
            else:
                if (not 's' in format):
                    line += " "

class VMICommandPlugin(plugin.PhysicalASMixin,
                       plugin.TypedProfileCommand,
                       plugin.ProfileCommand):
    """ Base class for all VMI based plugins.

    VMI plugins reuqire a VMI address space and a working profile.
    """

    __abstract = True

    mode = "mode_vmi_profile"

class VMIFindDTB(VMICommandPlugin, core.FindDTB):

    __name = "find_dtb"

    def dtb_hits(self):
        result = []

        for i in range(0, self.session.vmi.guest_state.num_cpus):
            result.append(self.session.vmi.guest_state.get_cpu_state(i)["cr3"])

        return result

    def CreateAS(self, dtb):
        self.session.SetCache("dtb", dtb)
        paging = self.session.profile.metadata("paging")

        if paging:
            return super(VMIFindDTB, self).CreateAS(dtb)
        else:
            # No paging
            return self.session.physical_address_space

    table_header = [
        dict(name="dtb", style="address")
    ]

    def collect(self):
        for dtb in self.dtb_hits():
            yield (dtb)

class VMIAddressResolver(VMICommandPlugin,
                         address_resolver.AddressResolverMixin):

    __name = "address_resolver"
