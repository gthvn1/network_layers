# Notes

- Ethernet is IEEE standard
  - Ethernet II Frame format is specifed in IEEE 802.3
- Part of the Data Link layer (Layer 2)
- Several RFCs described how to run over Ethernet:
  - IP over Ethernet: [RFC 894](https://datatracker.ietf.org/doc/html/rfc894)
  - ARP (Address Resolution Protocol): [RFC 826](https://datatracker.ietf.org/doc/html/rfc826)
  - IPv6 over Ethernet: [RFC 2464](https://datatracker.ietf.org/doc/html/rfc2464)

# Create virtual cable

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
# ip addr add 192.168.38.1/24 dev veth0
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
    inet 192.168.38.1/24 scope global veth0
       valid_lft forever preferred_lft forever
    inet6 fe80::b871:bdff:fe65:2a4a/64 scope link proto kernel_ll
       valid_lft forever preferred_lft forever
```

NOTE: Note that raw sockets (AF_PACKET) require root privileges or CAP_NET_RAW.
      To run unprivileged, we can: `sudo setcap cap_net_raw+ep ./zig_program`

- For testing we can listen on *veth0-peer* using tshark:
```sh
# tshark -i veth0-peer -V
Capturing on 'veth0-peer'
3 Frame 1: 42 bytes on wire (336 bits), 42 bytes captured (336 bits) on interface veth0-peer, id 0
    Section number: 1
    Interface id: 0 (veth0-peer)
        Interface name: veth0-peer
    Encapsulation type: Ethernet (1)
    Arrival Time: Nov  3, 2025 21:29:49.283657738 CET
    UTC Arrival Time: Nov  3, 2025 20:29:49.283657738 UTC
    Epoch Arrival Time: 1762201789.283657738
    [Time shift for this packet: 0.000000000 seconds]
    [Time delta from previous captured frame: 0.000000000 seconds]
    [Time delta from previous displayed frame: 0.000000000 seconds]
    [Time since reference or first frame: 0.000000000 seconds]
    Frame Number: 1
    Frame Length: 42 bytes (336 bits)
    Capture Length: 42 bytes (336 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:arp]
Ethernet II, Src: ba:71:bd:65:2a:4a (ba:71:bd:65:2a:4a), Dst: Broadcast (ff:ff:ff:ff:ff:ff)
    Destination: Broadcast (ff:ff:ff:ff:ff:ff)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
        .... ...1 .... .... .... .... = IG bit: Group address (multicast/broadcast)
    Source: ba:71:bd:65:2a:4a (ba:71:bd:65:2a:4a)
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
    Sender MAC address: ba:71:bd:65:2a:4a (ba:71:bd:65:2a:4a)
    Sender IP address: 192.168.38.1
    Target MAC address: 00:00:00_00:00:00 (00:00:00:00:00:00)
    Target IP address: 192.168.38.2

Frame 2: 42 bytes on wire (336 bits), 42 bytes captured (336 bits) on interface veth0-peer, id 0
    Section number: 1
    Interface id: 0 (veth0-peer)
        Interface name: veth0-peer
    Encapsulation type: Ethernet (1)
    Arrival Time: Nov  3, 2025 21:29:50.284146965 CET
    UTC Arrival Time: Nov  3, 2025 20:29:50.284146965 UTC
    Epoch Arrival Time: 1762201790.284146965
    [Time shift for this packet: 0.000000000 seconds]
    [Time delta from previous captured frame: 1.000489227 seconds]
    [Time delta from previous displayed frame: 1.000489227 seconds]
    [Time since reference or first frame: 1.000489227 seconds]
    Frame Number: 2
    Frame Length: 42 bytes (336 bits)
    Capture Length: 42 bytes (336 bits)
    [Frame is marked: False]
    [Frame is ignored: False]
    [Protocols in frame: eth:ethertype:arp]
Ethernet II, Src: ba:71:bd:65:2a:4a (ba:71:bd:65:2a:4a), Dst: Broadcast (ff:ff:ff:ff:ff:ff)
    Destination: Broadcast (ff:ff:ff:ff:ff:ff)
        .... ..1. .... .... .... .... = LG bit: Locally administered address (this is NOT the factory default)
        .... ...1 .... .... .... .... = IG bit: Group address (multicast/broadcast)
    Source: ba:71:bd:65:2a:4a (ba:71:bd:65:2a:4a)
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
    Sender MAC address: ba:71:bd:65:2a:4a (ba:71:bd:65:2a:4a)
    Sender IP address: 192.168.38.1
    Target MAC address: 00:00:00_00:00:00 (00:00:00:00:00:00)
    Target IP address: 192.168.38.2

Frame 3: 42 bytes on wire (336 bits), 42 bytes captured (336 bits) on interface veth0-peer, id 0
    Section number: 1
    Interface id: 0 (veth0-peer)
        Interface name: veth0-peer
    Encapsulation type: Ethernet (1)
    Arrival Time: Nov  3, 2025 21:29:51.308207098 CET
    UTC Arrival Time: Nov  3, 2025 20:29:51.308207098 UTC
    Epoch Arrival Time: 1762201791.308207098
```
