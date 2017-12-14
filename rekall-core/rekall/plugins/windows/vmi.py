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


""" VMI classes and commands that are specific for Windows."""
import struct

from rekall_lib import utils
from rekall import scan
from rekall.plugins.vmi import common as vmi_common
from rekall.plugins.windows import common as win_common
from rekall.plugins.windows.kpcr import KPCR
from rekall.plugins.windows import address_resolver

class WindowsGuestState(vmi_common.GuestState):
    """ The guest state for windows profiles. """
    def _fetch_all_kpcr(self):
        for i in range(self.vmi.guest_state.num_cpus):
            self.kpcr(i)

    def _kpcr(self,cpu_num):
        cpu_state = self.get_cpu_state(cpu_num)
        if self.cur_cpl(cpu_num) == 0:
            if self.session.profile.metadata("arch") == "AMD64":
                return cpu_state["gs"]["base"]
            elif self.session.profile.metadata("arch") == "I386":
                return cpu_state["fs"]["base"]
        else:
            # Find the KPCR through scanning
            if self.session.profile.metadata("arch") == "AMD64":
                pointer_size = 8
                mask = 0xffff000000000000
                unpack = "<Q"
            else:
                pointer_size = 4
                mask = 0
                unpack = "<I"

            _kpcr = KPCR(session=self.session).kpcr().v() | mask

            if cpu_num == 0:
                return _kpcr
            elif hasattr(self, "_kpcr_table"):
                table = self._kpcr_table
                addr = struct.unpack(unpack, table)[0]
                _kpcr = self.session.profile._KPCR(offset=addr)

                return _kpcr.v() | mask
            else:
                space = self.session.kernel_address_space

                scanner = scan.PointerScanner(session=self.session,
                                              address_space=space,
                                              pointers=[_kpcr])

                for hit in scanner.scan(end=space.end()):
                    table = space.read(hit + pointer_size * cpu_num,
                                       pointer_size)

                    addr = struct.unpack(unpack, table)[0]
                    _kpcr = self.session.profile._KPCR(offset=addr)
                    spointer = _kpcr.m("SelfPtr") or _kpcr.m("Self")

                    if spointer.v() != _kpcr.v():
                        continue

                    self._kpcr_table = table
                    return _kpcr.v() | mask

        return None

    def kpcr(self,cpu_num=None):
        update = False

        kpcr = self.session.GetParameter("kpcr",default=None)
        if kpcr is None:
            kpcr = [None] * self.vmi.guest_state.num_cpus

        for i in range(0, self.vmi.guest_state.num_cpus):
            if kpcr[i] == None:
                kpcr[i] = self._kpcr(i)
                update = True

        if update:
            self.session.SetCache("kpcr",kpcr)

        if (cpu_num != None):
            return kpcr[cpu_num]
        else:
            return kpcr

    def ethread(self, cpu_num=None):
        cpu_id = cpu_num

        if cpu_num == None:
            cpu_id = self.session.GetParameter("cur_cpu", default=0)


        kpcr_addr = self.kpcr(cpu_id)
        kpcr = self.session.profile._KPCR(kpcr_addr)
        return kpcr.Prcb.CurrentThread

    def kprocess(self, cpu_num=None):
        ethread = self.ethread(cpu_num=cpu_num)
        return ethread.Tcb.Process

    def eprocess(self, cpu_num=None):
        kprocess = self.kprocess(cpu_num=cpu_num)
        eproc_addr = kprocess.v()
        return self.session.profile._EPROCESS(eproc_addr)

    def process(self, cpu_num=None):
        return self.eprocess(cpu_num=cpu_num)

    def tid(self, cpu_num=None):
        ethread = self.ethread(cpu_num=cpu_num)
        return ethread.Cid.UniqueThread.v()

    def pid(self, cpu_num=None):
        eprocess = self.eprocess(cpu_num=cpu_num)
        return eprocess.pid

    def dtb(self, cpu_num=None):
        eprocess = self.eprocess(cpu_num=cpu_num)
        return eprocess.dtb

    def cache_period_flush(self, key):
        KEEP_LIST=["kernel_base","PsActiveProcessHead","kpcr"]
        if(key in KEEP_LIST):
            return False
        return super(WindowsGuestState, self).cache_period_flush(key)

class WindowsVMCommandPlugin(vmi_common.VMCommandPlugin,
                             win_common.WindowsCommandPlugin):
    """ Base class for all Windows VM commands. """

    __abstract = True

class WindowsVMContext(WindowsVMCommandPlugin, vmi_common.VMContext):
    """ Print the current context. """
    __name = "vm_context"

    def render(self, renderer):
        gs = self.session.vmi.guest_state

        for i in range(0, gs.num_cpus):
            tid = gs.tid(cpu_num=i)
            pid = gs.pid(cpu_num=i)
            dtb = gs.dtb(cpu_num=i)
            cr3 = self.session.vmi.guest_state.get_cpu_state(i)["cr3"]
            rip = self.session.vmi.guest_state.get_cpu_state(i)["rip"]

            renderer.format("CPU {:2d} @ 0x{:016x}, PID: {:d}, TID: {:d}," \
                            " DTB: 0x{:x} (CR3: 0x{:x})\n".format(i, rip, pid,
                                                                  tid, dtb,
                                                                  cr3))

class WindowsVMGetCpuState(WindowsVMCommandPlugin, vmi_common.VMGetCpuState):
    """ Print the current CPU state. """
    __name = "vm_cpu_state"

    def render(self, renderer):
        super(WindowsVMGetCpuState, self).render(renderer)

        cpu_num = self.plugin_args.cpu_num

        gs = self.session.vmi.guest_state

        kpcr_addr = gs.kpcr(cpu_num)
        renderer.format("\n")
        renderer.table_row("KPCR",self._64b_to_str(kpcr_addr),
                           "","")

        ethrd = gs.ethread(cpu_num)
        renderer.format("\n")
        renderer.table_row("ETHRD", self._64b_to_str(self._sign_extend(ethrd.v())),
                           "TID", gs.tid(cpu_num))

        eproc_addr = gs.eprocess(cpu_num).v()

        renderer.format("\n")
        renderer.table_row("EPROC",self._64b_to_str(self._sign_extend(eproc_addr)),
                           "DTB",self._64b_to_str(gs.dtb(cpu_num)))
        renderer.table_row("PID",str(gs.pid(cpu_num)),
                           "NAME",gs.eprocess(cpu_num).ImageFileName)


class WindowsVMBreakpointSW(WindowsVMCommandPlugin, win_common.WinProcessFilter, vmi_common.VMBreakpointSW):
    """ Set software breakpoint for a specified Windows process and GVA.

    A software breakpoint will be set for the specified Windows process
    on the specified guest virtual address (GVA).  If 'global' is true,
    the process specifier will be ignored and a global breakpoint will be set.
    """

    __name = "vm_breakpoint_add"

    __args = [
        dict(name="gva", positional=True, required=True, override=True, type="String",
             help="The guest virtual address on which to set the breakpoint.  This may also be a symbol string.")
    ]

    def render(self, renderer):
        if getattr(self.plugin_args,"globally"):
            dtb = 0
            gva = self.session.address_resolver.get_address_by_name(self.plugin_args.gva)
            gva = int(gva)
            self.session.vmi.breakpoint_sw_add(dtb=dtb,gva=gva)
            renderer.format("Successfully set breakpoint on {0}:{1}", dtb, self.plugin_args.gva)
        else:
            with self.session.plugins.cc() as cc:
                orig_context = self.session.GetParameter("process_context")
                for proc in self.filter_processes():
                    dtb = int(proc.Pcb.DirectoryTableBase)
                    if proc != self.session.GetParameter("process_context"):
                        cc.SwitchProcessContext(proc)
                    gva = self.session.address_resolver.get_address_by_name(self.plugin_args.gva)
                    self.session.vmi.breakpoint_sw_add(dtb=dtb,gva=gva)
                    renderer.format("Successfully set breakpoint on {0}:{1}", dtb, self.plugin_args.gva)
                if orig_context != self.session.GetParameter("process_context"):
                    cc.SwitchProcessContext(orig_context)


class WindowsVMWatchpoint(WindowsVMCommandPlugin, win_common.WinProcessFilter, vmi_common.VMWatchpoint):
    """ Set watchpoint for a specified Windows process and GVA.

    A watchpoint will be set for the specified Windows process
    on the specified guest virtual address (GVA).  If 'global' is true,
    the process specifier will be ignored and a global watchpoint will be set.
    """

    __name = "vm_watchpoint_add"

    __args = [
        dict(name="gva", positional=True, required=True, override=True, type="String",
             help="The guest virtual address on which to set the watchpoint.  This may also be a symbol string.")
    ]

    def render(self, renderer):
        if getattr(self.plugin_args,"globally"):
            dtb = 0
            gva = self.session.address_resolver.get_address_by_name(self.plugin_args.gva)
            self.session.vmi.watchpoint_add(dtb=dtb,gva=gva,length=self.plugin_args.length,
                                            type=self.plugin_args.type)
            renderer.format("Successfully set {0} watchpoint on {1}:{2}({3})",
                            self.plugin_args.type, dtb, self.plugin_args.gva,
                            self.plugin_args.length)
        else:
            with self.session.plugins.cc() as cc:
                orig_context = self.session.GetParameter("process_context")
                for proc in self.filter_processes():
                    dtb = int(proc.Pcb.DirectoryTableBase)
                    if proc != self.session.GetParameter("process_context"):
                        cc.SwitchProcessContext(proc)
                    gva = self.session.address_resolver.get_address_by_name(self.plugin_args.gva)
                    self.session.vmi.watchpoint_add(dtb=dtb,gva=gva,length=self.plugin_args.length,
                                                    type=self.plugin_args.type)
                    renderer.format("Successfully set {0} watchpoint on {1}:{2}({3})",
                                    self.plugin_args.type, dtb, self.plugin_args.gva,
                                    self.plugin_args.length)
                if orig_context != self.session.GetParameter("process_context"):
                    cc.SwitchProcessContext(orig_context)
