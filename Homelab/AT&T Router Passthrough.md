Bridge mode: a router connected to the internet simply relays packets using a low level protocol (IP or MAC?) to another router contained within the private network space. This is not supported by AT&T.

IP Passthrough: AT&Ts substitute for bridge mode, creates a DMZ between the ISP router and an assigned internal device in which it "shares" its IP with (packet forwarding, no NAT, no firewall). The ISP router can still be used directly if needed and actually allows your own router (set as the passthrough target) to create a subnet for the devices connected directly to it, as opposed to those directly connected to the ISP router.


RG = routing gateway. The most "upstream" router, usually the AT&T modem/router combo.

ONT = optical network terminal. The device that converts the signal from light sent over fiber to electrical signal used in ethernet. Sometimes it is a box outside your house, and sometimes it is the device serving as your modem/router combo. It's the device where the fiber line ends.

OLT = optical line terminal. Where the Passive Optical Network (PON) starts. The OLT is the "brains" of the PON and is located at your ISP's central office.