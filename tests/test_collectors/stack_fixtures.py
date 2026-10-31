"""Synthetic show version / show inventory output from switch stacks.

Hostnames, serials and MACs are made up; MACs are from the documentation
range 00:00:5E:00:53:xx.
"""

# IOS 15.2 2960-X three-member stack. The main block carries the processor
# line but no "Model number" line; members 2 and 3 report theirs below the
# switch table, which has no Mode column on classic IOS.
C2960X_STACK_VERSION = """\
Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), Version 15.2(7)E4, RELEASE SOFTWARE (fc2)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2021 by Cisco Systems, Inc.
Compiled Wed 10-Feb-21 18:00 by prod_rel_team

ROM: Bootstrap program is C2960X boot loader
BOOTLDR: C2960X Boot Loader (C2960X-HBOOT-M) Version 15.2(3r)E1, RELEASE SOFTWARE (fc1)

SW-STK-1 uptime is 1 year, 2 weeks, 3 days, 4 hours, 5 minutes
System returned to ROM by power-on
System restarted at 10:11:12 UTC Mon Jan 1 2024
System image file is "flash:/c2960x-universalk9-mz.152-7.E4/c2960x-universalk9-mz.152-7.E4.bin"
Last reload reason: power-on



This product contains cryptographic features and is subject to United
States and local country laws governing import, export, transfer and
use.

cisco WS-C2960X-48FPD-L (APM86XXX) processor (revision B0) with 524288K bytes of memory.
Processor board ID FOC0000A0AA
Last reset from power-on
3 Virtual Ethernet interfaces
1 FastEthernet interface
156 Gigabit Ethernet interfaces
6 Ten Gigabit Ethernet interfaces
The password-recovery mechanism is enabled.

512K bytes of flash-simulated non-volatile configuration memory.
Base ethernet MAC Address       : 00:00:5E:00:53:01
Motherboard assembly number     : 73-00000-00
Power supply part number        : 341-0000-00
Motherboard serial number       : FOC0000A0AB
Power supply serial number      : FOC0000A0AC
Model revision number           : B0
Motherboard revision number     : A0
System serial number            : FOC0000A0AA
Top Assembly Part Number        : 800-00000-00
Top Assembly Revision Number    : A0
Version ID                      : V05
CLEI Code Number                : AAAAAAAAAA
Hardware Board Revision Number  : 0x14


Switch Ports Model                     SW Version            SW Image
------ ----- -----                     ----------            ----------
*    1 52    WS-C2960X-48FPD-L         15.2(7)E4             C2960X-UNIVERSALK9-M
     2 52    WS-C2960X-48FPD-L         15.2(7)E4             C2960X-UNIVERSALK9-M
     3 28    WS-C2960X-24PD-L          15.2(7)E4             C2960X-UNIVERSALK9-M


Switch 02
---------
Switch uptime                   : 1 year, 2 weeks, 3 days, 4 hours, 1 minute
Base ethernet MAC Address       : 00:00:5E:00:53:02
Motherboard assembly number     : 73-00000-00
Power supply part number        : 341-0000-00
Motherboard serial number       : FOC0000A0BB
Power supply serial number      : FOC0000A0BC
Model revision number           : B0
Motherboard revision number     : A0
Model number                    : WS-C2960X-48FPD-L
System serial number            : FOC0000A0BA
Top Assembly Part Number        : 800-00000-00
Top Assembly Revision Number    : A0
Version ID                      : V05
CLEI Code Number                : AAAAAAAAAA

Switch 03
---------
Switch uptime                   : 1 year, 2 weeks, 3 days, 4 hours, 2 minutes
Base ethernet MAC Address       : 00:00:5E:00:53:03
Motherboard assembly number     : 73-00000-00
Power supply part number        : 341-0000-00
Motherboard serial number       : FOC0000A0CB
Power supply serial number      : FOC0000A0CC
Model revision number           : B0
Motherboard revision number     : A0
Model number                    : WS-C2960X-24PD-L
System serial number            : FOC0000A0CA
Top Assembly Part Number        : 800-00000-00
Top Assembly Revision Number    : A0
Version ID                      : V05
CLEI Code Number                : AAAAAAAAAA

Configuration register is 0xF

"""

C2960X_STACK_INVENTORY = """\
NAME: "1", DESCR: "WS-C2960X-48FPD-L"
PID: WS-C2960X-48FPD-L , VID: V05  , SN: FOC0000A0AA

NAME: "Switch 1 - FlexStackPlus Module", DESCR: "Stacking Module"
PID: C2960X-STACK      , VID: V01  , SN: FOC0000A0AD

NAME: "2", DESCR: "WS-C2960X-48FPD-L"
PID: WS-C2960X-48FPD-L , VID: V05  , SN: FOC0000A0BA

NAME: "3", DESCR: "WS-C2960X-24PD-L"
PID: WS-C2960X-24PD-L  , VID: V05  , SN: FOC0000A0CA

"""

# IOS-XE 17 mixed three-member C9300 stack, member 2 is active (the '*'),
# and the main block has the processor line but no "Model Number" line.
C9300_MIXED_STACK_VERSION = """\
Cisco IOS XE Software, Version 17.09.04a
Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE (fc3)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2023 by Cisco Systems, Inc.
Compiled Fri 20-Oct-23 10:44 by mcpre


Cisco IOS-XE software, Copyright (c) 2005-2023 by cisco Systems, Inc.
All rights reserved.  Certain components of Cisco IOS-XE software are
licensed under the GNU General Public License ("GPL") Version 2.0.


ROM: IOS-XE ROMMON
BOOTLDR: System Bootstrap, Version 17.9.1r, RELEASE SOFTWARE (P)

SW-STK-2 uptime is 23 weeks, 4 days, 1 hour, 12 minutes
Uptime for this control processor is 23 weeks, 4 days, 1 hour, 15 minutes
System returned to ROM by Reload Command
System image file is "flash:packages.conf"
Last reload reason: Reload Command



This product contains cryptographic features and is subject to United
States and local country laws governing import, export, transfer and
use.


Technology Package License Information:

------------------------------------------------------------------------------
Technology-package                                     Technology-package
Current                        Type                       Next reboot
------------------------------------------------------------------------------
network-advantage       Smart License                    network-advantage
dna-advantage           Subscription Smart License       dna-advantage
AIR License Level: AIR DNA Advantage
Next reload AIR license Level: AIR DNA Advantage


Smart Licensing Status: Smart Licensing Using Policy

cisco C9300-48P (X86) processor with 1331521K/6147K bytes of memory.
Processor board ID FOC0000A1AA
3 Virtual Ethernet interfaces
156 Gigabit Ethernet interfaces
24 Ten Gigabit Ethernet interfaces
2048K bytes of non-volatile configuration memory.
8388608K bytes of physical memory.
1638400K bytes of Crash Files at crashinfo:.
11264000K bytes of Flash at flash:.

Base Ethernet MAC Address          : 00:00:5e:00:53:11
Motherboard Assembly Number        : 73-00000-00
Motherboard Serial Number          : FOC0000A1AB
Model Revision Number              : A0
Motherboard Revision Number        : A0
System Serial Number               : FOC0000A1AA
CLEI Code Number                   : AAAAAAAAAA


Switch Ports Model              SW Version        SW Image              Mode
------ ----- -----              ----------        ----------            ----
     1 52    C9300-48P          17.09.04a         CAT9K_IOSXE           INSTALL
*    2 52    C9300-48P          17.09.04a         CAT9K_IOSXE           INSTALL
     3 28    C9300-24T          17.09.04a         CAT9K_IOSXE           INSTALL


Switch 01
---------
Switch uptime                      : 23 weeks, 4 days, 1 hour, 10 minutes

Base Ethernet MAC Address          : 00:00:5e:00:53:12
Motherboard Assembly Number        : 73-00000-00
Motherboard Serial Number          : FOC0000A1BB
Model Revision Number              : A0
Motherboard Revision Number        : A0
Model Number                       : C9300-48P
System Serial Number               : FOC0000A1BA
CLEI Code Number                   : AAAAAAAAAA

Switch 03
---------
Switch uptime                      : 23 weeks, 4 days, 1 hour, 11 minutes

Base Ethernet MAC Address          : 00:00:5e:00:53:13
Motherboard Assembly Number        : 73-00000-00
Motherboard Serial Number          : FOC0000A1CB
Model Revision Number              : A0
Motherboard Revision Number        : A0
Model Number                       : C9300-24T
System Serial Number               : FOC0000A1CA
CLEI Code Number                   : AAAAAAAAAA

Configuration register is 0x102

"""

C9300_MIXED_STACK_INVENTORY = """\
NAME: "c93xx Stack", DESCR: "c93xx Stack"
PID: C9300-48P         , VID: V02  , SN: FOC0000A1BA

NAME: "Switch 1", DESCR: "C9300-48P"
PID: C9300-48P         , VID: V02  , SN: FOC0000A1BA

NAME: "Switch 1 - Power Supply A", DESCR: "Switch 1 - Power Supply A"
PID: PWR-C1-715WAC     , VID: V02  , SN: ART0000A1AA

NAME: "Switch 2", DESCR: "C9300-48P"
PID: C9300-48P         , VID: V02  , SN: FOC0000A1AA

NAME: "Switch 3", DESCR: "C9300-24T"
PID: C9300-24T         , VID: V02  , SN: FOC0000A1CA

"""

# IOS-XE 16 C9200L stack: processor line only, no switch Model Number lines.
C9200L_PROCESSOR_ONLY_VERSION = """\
Cisco IOS XE Software, Version 16.12.05b
Cisco IOS Software [Gibraltar], Catalyst L3 Switch Software (CAT9K_LITE_IOSXE), Version 16.12.5b, RELEASE SOFTWARE (fc3)
Copyright (c) 1986-2021 by Cisco Systems, Inc.

SW-STK-3 uptime is 2 years, 1 week, 5 hours, 2 minutes
System image file is "flash:packages.conf"
Last reload reason: PowerOn

cisco C9200L-48P-4X (ARM64) processor with 600133K/3071K bytes of memory.
Processor board ID JAE0000A2AA
2048K bytes of non-volatile configuration memory.

Configuration register is 0x102

"""


def big_stack_version(members=10):
    """A long C9300 stack show version: one table row and member block each."""
    head = C9300_MIXED_STACK_VERSION.split("Switch Ports Model")[0]
    rows = ["Switch Ports Model              SW Version        SW Image              Mode",
            "------ ----- -----              ----------        ----------            ----"]
    blocks = []
    for n in range(1, members + 1):
        mark = "*" if n == 1 else " "
        rows.append(f"{mark}    {n} 52    C9300-48P          17.09.04a         "
                    "CAT9K_IOSXE           INSTALL")
        if n == 1:
            continue
        blocks.append(
            f"Switch {n:02d}\n---------\n"
            "Switch uptime                      : 23 weeks, 4 days, 1 hour\n\n"
            f"Base Ethernet MAC Address          : 00:00:5e:00:53:{n:02x}\n"
            "Motherboard Assembly Number        : 73-00000-00\n"
            f"Motherboard Serial Number          : FOC0000B{n:03d}\n"
            "Model Revision Number              : A0\n"
            "Model Number                       : C9300-48P\n"
            f"System Serial Number               : FOC0000A{n:03d}\n"
            "CLEI Code Number                   : AAAAAAAAAA\n")
    return (head + "\n".join(rows) + "\n\n\n" + "\n".join(blocks)
            + "\nConfiguration register is 0x102\n\n")
