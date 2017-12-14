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


""" VMI event callbacks. """
from .event import Callback, EventHandler, EventType


def callbacks_init(vmi):
    # Register the callbacks
    vmi.event_handler.register_callback(Callback(vmi_cb_all_context,
                                                 (EventType.ALL &
                                                 ~(EventType.RESUME |
                                                   EventType.DEVICE_TRAY_MOVED)),
                                                  False))


    vmi.event_handler.register_callback(Callback(vmi_cb_all_events,
                                                 (EventType.ALL &
                                                 ~(EventType.RESUME |
                                                   EventType.DEVICE_TRAY_MOVED |
                                                   EventType.RESET)),
                                                  True))

    vmi.event_handler.register_callback(Callback(vmi_cb_stop,
                                                 EventType.STOP, True))

    vmi.event_handler.register_callback(Callback(vmi_cb_reset,
                                                 EventType.RESET, False))


def vmi_cb_all_events(event, session):
    # Print all events execept resume in interactive mode
    renderer = session.GetRenderer()

    renderer.format("{0}\n".format(event.pprint()))

def vmi_cb_stop(event, session):
    # Print the current context in interactive mode
    renderer = session.GetRenderer()

    renderer.format("\nCurrent context:\n")
    renderer.format("----------------\n")
    r = session.locals["vm_context"]()
    renderer.format("\n")

def vmi_cb_reset(event, session):
    # Reset the session cache
    session.cache.Clear()

def vmi_cb_all_context(event, session):
    # Set current cpu and switch context
    if event.cpu_num != None:
        session.SetCache("cur_cpu", event.cpu_num)

    process = session.vmi.guest_state.process(event.cpu_num)
    r = session.plugins.cc().SwitchProcessContext(process)
