# Notes

- Ethernet is IEEE standard
  - Ethernet II Frame format is specifed in IEEE 802.3
- Part of the Data Link layer (Layer 2)
- Several RFCs described how to run over Ethernet:
  - IP over Ethernet: [RFC 894](https://datatracker.ietf.org/doc/html/rfc894)
  - ARP (Address Resolution Protocol): [RFC 826](https://datatracker.ietf.org/doc/html/rfc826)
  - IPv6 over Ethernet: [RFC 2464](https://datatracker.ietf.org/doc/html/rfc2464)
- To build and run:
```
zig build && sudo ./zig-out/bin/netl2 --iface veth0 --ip 192.168.38.2/24
```
  - You need to be root or set capabilite. See `cap_net_raw+ep` below.

# Current status
- [x] read raw frame
- [x] parse incoming ARP
- [ ] construct ARP reply
- [ ] send the frame back
- [ ] ...

# Tests

## Create virtual cable

We will create a *veth* pair, which acts like a virtual Ethernet cable connecting two interfaces.
One side can be configured on the host with an IP address and used like a normal network interface.
On the other side, we will write code to capture raw Ethernet frames, inspect packets (like ARP or ICMP),
and optionally respond directly. This setup allows us to experiment with **layer 2 (Ethernet) and
layer 3 (IP/ICMP) protocols** in a fully isolated environment.
- veth pair: purely at layer 2 (Ethernet frames).
- ARP: layer 2/3 boundary (it’s Ethernet-level broadcast for IP resolution).
- ICMP/ping: layer 3 (IP) over layer 2 (Ethernet).

First create the pair:
```bash
# ip link add veth0 type veth peer name veth0-peer
```

It creates:
```sh
3: veth0-peer@veth0: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether 9a:1b:1e:55:f0:95 brd ff:ff:ff:ff:ff:ff
4: veth0@veth0-peer: <BROADCAST,MULTICAST,M-DOWN> mtu 1500 qdisc noop state DOWN group default qlen 1000
    link/ether ba:71:bd:65:2a:4a brd ff:ff:ff:ff:ff:ff
```

Add an IP: 192.168.38.0/24 (allow 192.168.38.1 to 192.168.38.254)
```sh
# ip addr add 192.168.38.2/24 dev veth0
```

Links up:
```sh
# ip link set veth0 up
# ip link set veth0-peer up
```

You should now see:
```
3: veth0-peer@veth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether 9a:1b:1e:55:f0:95 brd ff:ff:ff:ff:ff:ff
    inet6 fe80::981b:1eff:fe55:f095/64 scope link proto kernel_ll
       valid_lft forever preferred_lft forever
4: veth0@veth0-peer: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default qlen 1000
    link/ether ba:71:bd:65:2a:4a brd ff:ff:ff:ff:ff:ff
    inet 192.168.38.2/24 scope global veth0
       valid_lft forever preferred_lft forever
    inet6 fe80::b871:bdff:fe65:2a4a/64 scope link proto kernel_ll
       valid_lft forever preferred_lft forever
```

NOTE: Note that raw sockets (AF_PACKET) require root privileges or CAP_NET_RAW.
      To run unprivileged, we can: `sudo setcap cap_net_raw+ep ./zig_program`

- For testing you can use `arping -c 1 192.168.38.3`

- You can also get raw data: `tshark -i veth0-peer -w - | xxd`
```
000000f0: 0600 0000 4c00 0000 0000 0000 aedd 7418  ....L.........t.
00000100: a67e d090 2a00 0000 2a00 0000 ffff ffff  .~..*...*.......
00000110: ffff c631 4c31 7104 0806 0001 0800 0604  ...1L1q.........
00000120: 0001 c631 4c31 7104 c0a8 2602 ffff ffff  ...1L1q...&..... 
```
- or decode info: `tshark -i veth0-peer -V`
```
Capturing on 'veth0-peer'
Frame 1: Packet, 42 bytes on wire (336 bits), 42 bytes captured (336 bits) on interface veth0-peer, id 0
    Section number: 1
    Interface id: 0 (veth0-peer)
        Interface name: veth0-peer
    Encapsulation type: Ethernet (1)
    Arrival Time: Nov  4, 2025 18:31:51.789530219 CET
    UTC Arrival Time: Nov  4, 2025 17:31:51.789530219 UTC
    Epoch Arrival Time: 1762277511.789530219
    [Time shift for this packet: 0.000000000 seconds]
    [Time since reference or first frame: 0.000000000 seconds]
    Frame Number: 1
    Frame Length: 42 bytes (336 bits)
    Capture Length: 42 bytes (336 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:arp]
    Character encoding: ASCII (0)
Ethernet II, Src: c6:31:4c:31:71:04 (c6:31:4c:31:71:04), Dst: Broadcast (ff:ff:ff:ff:ff:ff)
    Destination: Broadcast (ff:ff:ff:ff:ff:ff)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
        .... ...1 .... .... .... .... = IG bit: Group address (multicast/broadcast)
    Source: c6:31:4c:31:71:04 (c6:31:4c:31:71:04)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
        .... ...0 .... .... .... .... = IG bit: Individual address (unicast)
    Type: ARP (0x0806)
    [Stream index: 0]
Address Resolution Protocol (request)
    Hardware type: Ethernet (1)
    Protocol type: IPv4 (0x0800)
    Hardware size: 6
    Protocol size: 4
    Opcode: request (1)
    Sender MAC address: c6:31:4c:31:71:04 (c6:31:4c:31:71:04)
    Sender IP address: 192.168.38.2
    Target MAC address: Broadcast (ff:ff:ff:ff:ff:ff)
    Target IP address: 192.168.38.3 
```

