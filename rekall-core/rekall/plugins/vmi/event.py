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


"""This module implements the rVMI event handling."""
import datetime
import socket

from enum import IntEnum

from rekall.session import InteractiveSession
from utils import Registry

class EventTypeMeta(type):
    def __getattribute__(cls, key):
        # Try to return the attribute
        try:
            result = super(EventTypeMeta, cls).__getattribute__(key)
            return result
        except AttributeError:
            pass

        # Not part of the class. Check the enum.
        if cls._enum == None:

            value_list = Event.event_names()
            result = {}
            i = 1

            for v in value_list:
                result[v] = i
                i *= 2

            # Add a mask for all events
            result["ALL"] = i - 1

            cls._enum = IntEnum("EventType", result)

        return cls._enum.__getattr__(key)

    def __getitem__(cls, key):
        return cls._enum.__getitem__(key)

class EventType(object):
    __metaclass__ = EventTypeMeta

    _enum = None

    @classmethod
    def set_enum(cls, enum):
        cls.__enum = enum

    @classmethod
    def matches(cls, a, b):
        """ Check whether a certain event type matches an other event type. """
        if (a & b) > 0:
            return True
        else:
            return False

    @classmethod
    def from_string(cls, s):
        return cls[s]

class Event(object):
    """ Represents an event. """

    __metaclass__ = Registry

    # Used to identify the event type in a json string/dict
    _name = ""

    # Did we set the enum of the event type yet?
    _event_type_created = False

    def __init__(self, event_type, data):
        self._event_type = event_type
        self._data = data

        if "data" in self.data and "cpu_id" in self.data["data"]:
            self._cpu_num = self.data["data"]["cpu_id"]
        else:
            self._cpu_num = None

    @property
    def type(self):
        return self._event_type

    @property
    def data(self):
        return self._data

    @property
    def cpu_num(self):
        return self._cpu_num

    @property
    def timestamp(self):
        return self.data["timestamp"]

    def timestamp_to_string(self):
        secs = self.timestamp["seconds"]
        date = datetime.datetime.fromtimestamp(
               secs).strftime("%Y-%m-%d %H:%M:%S")

        return date

    def matches(self, event_type):
        return EventType.matches(self.type, event_type)

    def _pprint_prefix(self):
        return "[{0}][ EVENT on CPU {1} ]".format(self.timestamp_to_string(),
                                                  self.cpu_num)

    def _pprint_data(self):
        # Overwrite this function to print custom data
        return ""

    def _pprint_name(self):
        # Overwrite this function to print a custom event name
        return self._name

    def pprint(self):
        """ Return a formatted string representing the event. """
        return "{0}[ {1} ] {2}".format(self._pprint_prefix(),
                                       self._pprint_name(),
                                       self._pprint_data())


    @classmethod
    def event_names(cls):
        result = []

        for k, v in cls.registry.iteritems():
            result.append(v._name)

        return result

    @classmethod
    def from_dict(cls, d):
        for k, v in cls.registry.iteritems():
            if d["event"].lower() == v._name.lower():
                return v(EventType.from_string(d["event"]), d)

        return Event(EventType.from_string(d["event"]), d)

class ResumeEvent(Event):
    """ Emitted on VM resume. """

    _name = "RESUME"

class StopEvent(Event):
    """ Emitted on VM stop. """

    _name = "STOP"

class ShutdownEvent(Event):
    """ Emitted on VM shutdown. """

    _name = "SHUTDOWN"

class ResetEvent(Event):
    """ Emitted on VM reset. """

    _name = "RESET"

class DeviceTrayMovedEvent(Event):
    """ Emitted when a device try is moved. """

    _name = "DEVICE_TRAY_MOVED"

class TaskSwitchEvent(Event):
    """ Emitted when a task switch occurs. """

    _name = "VMI_TASK_SWITCH"

    def __init__(self, event_type, data):
        super(TaskSwitchEvent, self).__init__(event_type, data)

        self._old = self.data["data"]["old"]
        self._new = self.data["data"]["new"]

    @property
    def old(self):
        return self._old

    @property
    def new(self):
        return self._new

    def _pprint_data(self):
        return "0x{:016x} -> 0x{:016x}".format(self.old, self.new)

class BPEvent(Event):
    """ Emitted when a bp occurs. """

    _name = "VMI_BP"

    def __init__(self, event_type, data):
        super(BPEvent, self).__init__(event_type, data)

        self._gva = self.data["data"]["gva"]

        if self._gva < 0:
            self._gva += 18446744073709551616

        self._bp_type = self.data["data"]["type"]

    @property
    def gva(self):
        return self._gva

    @property
    def bp_type(self):
        return self._bp_type

    def _pprint_data(self):
        return "GVA: 0x{:016x}, Type: {:s}".format(self.gva, self.bp_type)

class SingleStepEvent(Event):
    """ Emitted when a singlestep occurs. """

    _name = "VMI_SS"

class Callback(object):
    """Represents an event callback."""
    def __init__(self, callback, event_type, interactive, *args, **kwargs):
        self._callback = callback
        self._event_type = event_type
        self._interactive = interactive
        self._args = args
        self._kwargs = kwargs

    def dispatch(self, event, session):
        self._callback(event, session, *self._args, **self._kwargs)

    def matches(self, event, interactive):
        if self._interactive and not interactive:
            return False

        return event.matches(self._event_type)

class EventHandler(object):
    """The main event handler."""

    def __init__(self, session):
        self.session = session

        self._callbacks = []
        self._events = []
        self._last_event = None

    @property
    def interactive(self):
        result = True if isinstance(self.session, InteractiveSession) \
                 else False

        return result

    @property
    def last_event(self):
        return self._last_event

    def dispatch(self, event):
        """Dispatch the event.

        Consider all register callbacks and dispatch the event to all callbacks
        that match.
        """
        for c in self._callbacks:
            if c.matches(event, self.interactive):
                c.dispatch(event, self.session)

    def dispatch_serialized(self, event):
        """ Dispatch a serialzed event.

        Dispatch events that are serialized and do not exist as an event object
        yet.
        """
        self.dispatch(Event.from_dict(event))

    def dispatch_multiple(self, events):
        """Dispatch multiple events."""
        for e in events:
            self.dispatch(e, self.interactive)

    def register_callback(self, callback):
        """Register a callback for an event."""
        self._callbacks.append(callback)

    def unregister_callback(self, callback):
        """Unregister a callback for an event."""
        index = None
        i = 0

        for c in self._callbacks:
            if c == callback:
                index = i
                break

            i += 1

        if index != None:
            del self._callbacks[index]
        else:
            raise KeyError("callback not found")

    def receive(self, timeout=False):
        """The main event loop.

        This behavior of this function depends on whether this is an
        interactive session or not. In the case of an interactive session,
        it will receive and dispatch events until the VM is stopped,
        the given timeout is met, or a KeyboardInterrupt occurs.

        In non-interactive session the function will receive events until
        the timeout is met.
        """
        period_func = getattr(self.session.cache, "Period", None)
        wait = not timeout if timeout == False else timeout

        while True:
            try:
                raw_event = self.session.vmi.get_event(wait=wait)
                event = Event.from_dict(raw_event)

                if (period_func):
                    period_func()

                self.dispatch(event)

                if event.type == EventType.STOP and self.interactive:
                    return
                else:
                    self._last_event = event

            except socket.timeout:
                if timeout != False:
                    if self.interactive:
                        if (period_func):
                            period_func()

                        self.session.vmi.stop()
                    return
            except KeyboardInterrupt:
                if self.interactive:
                    if (period_func):
                        period_func()

                    self.session.vmi.stop()

                    # Propagate
                    raise KeyboardInterrupt

                return

