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

from rekall import addrspace
from rekall.plugins.vmi.iface import QMPVMI

import os
import stat

class QMPAddressSpace(addrspace.BaseAddressSpace):
    """An address space which operates on a QEMU VMI interface."""

    __abstract = False
    __name = "qmp"
    order = 0
    __image = True

    def __init__(self, base=None, filename=None, session=None, **kwargs):
        self.as_assert(base is None, "must be first Address Space")
        self.as_assert(session is not None, "session must be passed")

        path = filename or (session and session.GetParameter("filename"))
        self.as_assert(path, "socket path missing and qmp not specified in session")

        # Is this a socket?
        mode = os.stat(path).st_mode
        self.as_assert(stat.S_ISSOCK(mode), "provided path does not point to a socket")

        super(QMPAddressSpace, self).__init__(base=base,session=session,**kwargs)
        vmi = QMPVMI(sock_path=path,session=session)
        vmi.connect()
        self.session.vmi = vmi

    def close(self):
        if(self.session.vmi is not None):
            self.session.vmi.close()
        self.session.vmi = None

    def read(self, offset, size):
        offset = int(offset)
        size = int(size)
        return self.session.vmi.read_mem(offset,size)

    def write(self, offset, data):
        return self.session.vmi.write_mem(offset,data)

    def is_valid_address(self, addr):
        if(addr is None or addr > self.session.vmi.guest_state.mem_size):
            return False
        return True

    def read_long(self, addr):
        string = self.read(addr, 4)
        (longval,) = struct.unpack('=I', string)
        return longval

    def get_mappings(self, start=0, end=2**64):
        _ = end
        yield addrspace.Run(start=0, end=self.session.vmi.guest_state.mem_size,
                            file_offset=0, address_space=self)
