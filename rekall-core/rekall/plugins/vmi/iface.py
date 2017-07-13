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


from rekall import utils
from rekall import addrspace

from qmp import QEMUMonitorProtocol
from qmp import QMPTimeoutError

from event import EventHandler

from common import GuestState, vmi_init
from rekall.plugins.windows.vmi import WindowsGuestState

import mmap
import math
import base64
import socket
from enum import Enum

PAGE_BITS = 12
PAGE_SZ = 1 << PAGE_BITS
PAGE_MASK = PAGE_SZ - 1

class VMIInterface(object):
    """ Base class for all interface classes.

    Each interface class must implement all methods listed below.
    """

    @property
    def guest_state(self):
        raise NotImplementedError()

    def get_vminfo(self):
        raise NotImplementedError()

    def cont(self):
        raise NotImplementedError()

    def cont_until_stop(self, timeout=False):
        raise NotImplementedError()

    def stop(self):
        raise NotImplementedError()

    def get_cpu_state(self,cpu_num):
        raise NotImplementedError()

    def set_cpu_state(self,cpu_num,state):
        raise NotImplementedError()

    def lbr(self, enable, select):
        raise NotImplementedError()

    def get_lbr(self, cpu_num=None):
        raise NotImplementedError()

    def savevm(self, id=None, name=None):
        raise NotImplementedError()

    def loadvm(self, id=None, name=None):
        raise NotImplementedError()

    def delvm(self, id=None, name=None):
        raise NotImplementedError()

    def snapshots(self):
        raise NotImplementedError()

    def read_mem(self,offset,size):
        raise NotImplementedError()

    def write_mem(self,offset,data):
        raise NotImplementedError()

    def cache_period_flush(self,key):
        raise NotImplementedError()

class QMPVMI(VMIInterface):
    """ VMI interface for QMP. """
    def __init__(self,sock_path=None,session=None):
        if(session is None):
            raise ValueError("session must be set")
        if(sock_path is None):
            raise ValueError("must provide sock_path")
        self._sock_path = sock_path
        self.session = session
        self._qmp = None
        self._event_handler = EventHandler(session=session)
        self._guest_state = None
        self._debug_index_counter = 0
        self._debug_list = []

    @property
    def event_handler(self):
        return self._event_handler

    @property
    def current_event(self):
            return self.event_handler.last_event

    @property
    def guest_state(self):
        if self._qmp == None:
            raise RuntimeError("QMP socket not connected!")

        # Create the guest state based on the profile.
        # Check if we have a physical address space yet to avoid the case
        # where an access to the session leads to the creation of a new
        # QMPAddressspace that tries to connect to the same socket as the
        # current QMPAddressspace.
        if (self.session.HasParameter("mode_windows") and
            self.session.GetParameter("mode_windows")):
            if (isinstance(self._guest_state, WindowsGuestState)):
                return self._guest_state
            else:
                self._guest_state = WindowsGuestState(self.session, self)
                return self._guest_state
        else:
            if (isinstance(self._guest_state, GuestState)):
                return self._guest_state
            else:
                self._guest_state = GuestState(self.session, self)
                return self._guest_state

    def get_vminfo(self):
        rsp = self._qmp.command("vmi-get-vminfo")
        return rsp

    def connect(self):
        self._qmp = QEMUMonitorProtocol(self._sock_path)
        self._qmp.connect()

        try:
            rsp = self._qmp.command("stop")
            self.flush_events()
            self.session.register_flush_hook(self,self.close)
        except:
            self.close()
            raise

        # Init VMI
        vmi_init(self)

    def close(self):
        if(self._qmp is not None):
            self.cont()
            self._qmp.close()
        self._qmp = None

    def flush_events(self):
        self._qmp.get_events()
        self._qmp.clear_events()

    def cont(self):
        rsp = self._qmp.command("cont")
        return rsp

    def cont_until_stop(self, timeout=False):
        self.cont()
        self._event_handler.receive(timeout=timeout)

    def stop(self):
        rsp = self._qmp.command("stop")
        while True:
            try:
                event = self.get_event(wait=0.5)
                self.event_handler.dispatch_serialized(event)
            except socket.timeout:
                break
        if(event["event"] != "STOP"):
            raise RuntimeError("unexpected events: "+str(event))
        return rsp

    def get_event(self,wait=True):
        try:
            event = self._qmp.pull_event(wait=wait)
        except QMPTimeoutError:
            raise socket.timeout
        if event["event"] == "STOP" or event["event"] == "RESUME":
            period_func = getattr(self.session.cache, "Period", None)
            if(callable(period_func)):
                period_func()
        return event

    def cont_get_event(self,wait=True):
        rsp, event = self.cont()
        if("return" not in rsp.keys()):
            raise RuntimeError("unexpected response: "+str(rsp))
        return self.get_event(wait=wait)

    def get_cpu_state(self,cpu_num):
        #qemu qtypes dont implement unsigned ints
        def make_uint(d):
            for k,v in d.iteritems():
                if type(v) is dict:
                    make_uint(v)
                elif v < 0:
                    d[k] = 18446744073709551616 + v
        rsp = self._qmp.command("vmi-get-cpu-state", cpu_num=cpu_num)
        make_uint(rsp)
        return rsp

    def set_cpu_state(self,cpu_num,state):
        def make_int(d):
            for k,v in d.iteritems():
                if type(v) is dict:
                    make_int(v)
                elif (v & 0x8000000000000000):
                    d[k] = v - 18446744073709551616

        make_int(state)
        self._qmp.command("vmi-set-cpu-state", cpu_num=cpu_num, state=state)

    def lbr(self, enable, select):
        return self._qmp.command("vmi-lbr", enable=enable, select=select)

    def get_lbr(self, cpu_num=None):
        def make_uint_list(l):
            result = []

            for e in l:
                if e < 0:
                    e += 18446744073709551616

                result.append(e)

            return result

        def make_uint(d):
            if type(d) is dict:
                for k,v in d.iteritems():
                    if type(v) is dict:
                        make_uint(v)
                    elif type(v) is list:
                        d[k] = make_uint_list(v)
                    elif v < 0:
                        d[k] = 18446744073709551616 + v


        if cpu_num == None:
            cpu_num = self.session.GetParameter("cur_cpu",default=0)

        rsp = self._qmp.command("vmi-get-lbr", cpuid=cpu_num)

        make_uint(rsp)
        return rsp

    def trap_task_switches(self, enable, cr3, trap_in, trap_out):
        return self._qmp.command("vmi-task-switch", enable=enable, dtb=cr3,
                                                    trap_in=trap_in,
                                                    trap_out=trap_out)

    def _add_debug(self,dtb,gva,length,type):
        for debug_entry in self._debug_list:
            if (debug_entry["dtb"] == dtb and debug_entry["gva"] == gva and
                debug_entry["length"] == length and debug_entry["type"] == type):
                raise ValueError("entry already exists")
        self._debug_list.append({"index":self._debug_index_counter, "dtb":dtb, "gva":gva, "length":length, "type":type})
        self._debug_index_counter += 1

    def debug_remove(self, index):
        debug_entry = next((x for x in self._debug_list if x["index"] == index),None)
        if debug_entry is not None:
            self._debug_list = [x for x in self._debug_list if x["index"] != index]

            gva = debug_entry["gva"]
            if (gva & 0x8000000000000000):
                gva -= 18446744073709551616

            return self._qmp.command("vmi-bp", action="remove", dtb=debug_entry["dtb"],
                                     gva=gva, length=debug_entry["length"],
                                     type=debug_entry["type"])
        return None

    def debug_list(self):
        return self._debug_list

    def breakpoint_sw_add(self, dtb, gva):
        debug_entry = {"dtb":dtb, "gva":gva, "length":0, "type":"breakpoint_sw"}

        if (gva & 0x8000000000000000):
            gva -= 18446744073709551616

        rv = self._qmp.command("vmi-bp", action="add", dtb=debug_entry["dtb"],
                               gva=gva, length=debug_entry["length"],
                               type=debug_entry["type"])

        self._add_debug(debug_entry["dtb"],debug_entry["gva"],debug_entry["length"],
                        debug_entry["type"])

        return rv

    class WatchpointType(Enum):
        READ = "watchpoint_read"
        WRITE = "watchpoint_write"
        READ_WRITE = "watchpoint_access"

    def watchpoint_add(self, dtb, gva, length, type):
        if length not in [1,2,4]:
            raise ValueError("length have value 1, 2, or 4")

        debug_entry = {"dtb":dtb, "gva":gva, "length":length, "type":type}

        if (gva & 0x8000000000000000):
            gva -= 18446744073709551616

        rv = self._qmp.command("vmi-bp", action="add", dtb=debug_entry["dtb"],
                               gva=gva, length=debug_entry["length"],
                               type=debug_entry["type"])

        self._add_debug(debug_entry["dtb"],debug_entry["gva"],debug_entry["length"],
                        debug_entry["type"])

        return rv


    def single_step(self, cpu_num=None):
        if cpu_num == None:
            cpu_num = self.session.GetParameter("cur_cpu",default=0)

        return self._qmp.command("vmi-ss", cpu_id=cpu_num)


    def savevm(self, id=None, name=None):
        if (id != None and name != None):
            return self._qmp.command("savevm", id=id, name=name)
        elif (id != None and name == None):
            return self._qmp.command("savevm", id=id)
        elif (id == None and name != None):
            return self._qmp.command("savevm", name=name)
        else:
            return self._qmp.command("savevm")

    def loadvm(self, id=None, name=None):
        if (id != None and name != None):
            return self._qmp.command("loadvm", id=id, name=name)
        elif (id != None and name == None):
            return self._qmp.command("loadvm", id=id)
        elif (id == None and name != None):
            return self._qmp.command("loadvm", name=name)
        else:
            return self._qmp.command("loadvm")

    def delvm(self, id=None, name=None):
        if (id != None and name != None):
            return self._qmp.command("delvm", id=id, name=name)
        elif (id != None and name == None):
            return self._qmp.command("delvm", id=id)
        elif (id == None and name != None):
            return self._qmp.command("delvm", name=name)
        else:
            return self._qmp.command("delvm")

    def snapshots(self):
        return self._qmp.command("info-snapshots")

    def change(self, device, target):
        return self._qmp.command("change", device=device, target=target)

    # start: start gpn
    # size: size in pages
    def get_pages(self,start,size):
        page_cache = self.session.GetParameter("page_cache",default=None)
        if(page_cache is None):
            page_cache = {}

        page_list = []

        for gpn in range(start,start+size):
            offset = gpn << PAGE_BITS

            if(offset >= self.guest_state.mem_size):
                page_list.append(addrspace.ZEROER.GetZeros(PAGE_SZ))
            elif(gpn not in page_cache.keys()):
                remaining_pages = (start+size) - gpn
                remaining_size = remaining_pages * PAGE_SZ

                if self.guest_state.mem_filebacked:
                    with open(self.guest_state.mem_path, "r+b") as f:
                        space = mmap.mmap(f.fileno(), offset=offset, length=remaining_size)
                        data = space.read(remaining_size)
                else:
                    rsp = self._qmp.command("vmi-read-mem", offset=offset, size=remaining_size)
                    data = base64.b64decode(rsp)

                remaining_page_list = [data[x:x+PAGE_SZ] for x in range(0, len(data), PAGE_SZ)]
                for i, page in enumerate(remaining_page_list):
                    if(len(page) < PAGE_SZ):
                        break
                    page_cache[gpn+i] = page
                self.session.SetCache("page_cache",page_cache)
                page_list.append(page_cache[gpn])
            else:
                page_list.append(page_cache[gpn])

        return page_list

    def read_mem(self,offset,size):
        num_pages = int(math.ceil(float((offset & PAGE_MASK) + size) / float(PAGE_SZ)))
        start_page = offset >> PAGE_BITS

        buf = ""
        remaining_size = size
        for i, page in enumerate(self.get_pages(start_page,num_pages)):
            page_offset = (start_page+i) << PAGE_BITS
            in_page_offset = offset - page_offset
            in_page_size = PAGE_SZ - in_page_offset
            if(remaining_size < in_page_size):
                in_page_size = remaining_size
            buf += page[in_page_offset:in_page_offset + in_page_size]
            offset = page_offset + PAGE_SZ
            remaining_size -= in_page_size
        return buf

    def write_mem(self,offset,data):
        page_cache = self.session.GetParameter("page_cache",default=None)


        #if self.mem_filebacked:
        #    with open(self.mem_path, "w+b") as f:
        #        phys_offset = self.session.default_address_space.vtop(offset)
        #        space = mmap.mmap(f.fileno(), offset=offset, length=len(data))
        #        space.write(data)
        #else:
        encoded = base64.b64encode(data)
        self._qmp.command("vmi-write-mem", data=encoded, offset=offset)

        if page_cache != None:
            pages = math.ceil(len(data) / float(PAGE_SZ))
            gpn = offset >> PAGE_BITS

            for i in range(0, int(pages)):
                if gpn + i in page_cache:
                    del page_cache[gpn + i]

            self.session.SetCache("page_cache",page_cache)

        return len(data)

    def cache_period_flush(self,key):
        KEEP_LIST=["num_cpus", "mem_size", "mem_path", "mem_filebacked",
                   "profile", "profile_obj"]
        if(key in KEEP_LIST or
           key.startswith("mode_") or
           self.guest_state.cache_period_flush(key) == False):
            # Make sure we flush the profile when profile is VMI
            if (self.session.HasParameter("profile") and
                self.session.GetParameter("profile") == "VMI" and
                (key.startswith("mode_") or key.startswith("profile"))):
                return True
            elif (not self.session.HasParameter("profile") and
                  (key.startswith("mode_") or key.startswith("profile"))):
                return True
            return False
        return True

