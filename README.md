![rVMI Logo](/resources/rvmi-rekall.png)

# rVMI - Rekall

This is a fork of the Rekall Forensic and Incident Response Framework
that includes the **rVMI** extensions.

In the following, we will provide a brief overview of rVMI with a focus
on the Rekall extensions. If you are looking for the main rVMI repository
please go to <https://github.com/fireeye/rvmi/>.

If you are interested in Rekall go to <https://github.com/google/rekall/>
or take a look at the Rekall section below.

## About

rVMI is a debugger on steroids. It leverages Virtual Machine Introspection (VMI)
and memory forensics to provide full system analysis. This means that an analyst
can inspect userspace processes, kernel drivers, and preboot environments in a
single tool.

It was specifially designed for interactive dynamic malware analysis. rVMI isolates
itself from the malware by placing its interactive debugging environment out of the
virtual machine (VM) onto the hypervisor-level. Through the use of VMI the analyst
still has full control of the VM, which allows her to pause the VM at any point in
time and to use typical debugging features such as breakpoints and watchpoints. In
addtion, rVMI provides access to the entire Rekall feature set, which enables an
analyst to inspect the kernel and its data structures with ease.

## Installing Rekall with rVMI

Before installing Rekall with rVMI, we recommend that you remove any previously
installed versions of Rekall.

Begin by cloning the repository:

```
$ git clone https://github.com/fireeye/rvmi-rekall.git rvmi-rekall
```

Then install Rekall.  We found that we had some issues when simply installing
from the top level, so we recommend installing the rekall-agent and rekall-core
components explicitly first.

```
$ cd rvmi-rekall/rekall-core
$ sudo python ./setup.py install
$ cd ../rekall-agent
$ sudo python ./setup.py install
$ cd ..
$ sudo python ./setup.py install
```

You also require QEMU and KVM with rVMI extensions to run rVMI. You can find
the full installation instructions at <https://github.com/fireeye/rvmi/>.

## Using rVMI

To run rVMI please follow the instructions located at <https://github.com/fireeye/rvmi/>.

## The Rekall Forensic and Incident Response Framework

The Rekall Framework is a completely open collection of tools,
implemented in Python under the Apache and GNU General Public License,
for the extraction and analysis of digital artifacts computer systems.

The Rekall distribution is available from:
<http://www.rekall-forensic.com/>

Rekall should run on any platform that supports
[Python](http://www.python.org)

Rekall supports investigations of the following 32bit and 64bit memory
images:

- Microsoft Windows XP Service Pack 2 and 3
- Microsoft Windows 7 Service Pack 0 and 1
- Microsoft Windows 8 and 8.1
- Microsoft Windows 10
- Linux Kernels 2.6.24 to most recent.
- OSX 10.7-10.12.x.

Rekall also provides a complete memory sample acquisition capability for all
major operating systems (see the tools directory).

## Licensing and Copyright

Copyright (C) 2007-2011 Volatile Systems  
Copyright 2012-2016 Google Inc. All Rights Reserved.  
Copyright 2017 FireEye, Inc. All Rights Reserved.

All Rights Reserved

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.

## Bugs and Support

There is no support provided. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.

If you think you've found a bug particular to rvmi-rekall, please report it at:

https://github.com/fireeye/rvmi-rekall/issues

In order to help us solve your issues as quickly as possible,
please include the following information when filing a bug:

* The version of rvmi-rekall you're using
* The guest operating system you are analyzing
* The complete command line you used to run rvmi-rekall
* The exact steps required to reproduce the issue

If you think you have found a bug in one of the other rvmi components, please report appropriately:

https://github.com/fireeye/rvmi-qemu/issues  
https://github.com/fireeye/rvmi-kvm/issues

If you are not sure or would like to file a general bug, please report here:

https://github.com/fireeye/rvmi/issues

## More documentation

Further documentation is available at
https://github.com/fireeye/rvmi/
