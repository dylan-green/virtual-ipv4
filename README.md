# virtual-ipv4
A virtual implementation of some basic IPv4 features. This is primarily for educational purposes; getting acquainted with Python and its out-of-box network programming features.

This is a basic implementation of the network layer for a host running on a virtual IP network, where UDP is used as the virtual network’s link layer.

The program can be invoked on a unix command line via `python3 virtual-ip.py ip-addr ll-addr` where the `ip-addr` and `ll-addr` parameters correspond to the IPv4 address in CIDR notation (indicating the client’s subnet) and link layer address (UDP port number) of your host program respectively.

Running the program will initiate a basic CLI that will allow the user to supply basic information about the network.

The following commands are allow the user to interact with the virtual network:

`gw set [ip-addr]` : set the gateway IP address of the subnet the client is a part of to [ip-addr] (overriding any existing gateway address)

`gw get` : print the currently stored gateway IP address to stdout, or None if no gateway address has been specified

`arp set [ip-addr] [ll-addr]` : insert a mapping from [ip-addr] to [ll-addr] in the host’s ARP table (overriding any existing entries for [ip-addr])

`arp get [ip-addr]` : print the currently stored link layer address mapped to [ip-addr] to stdout, or None if no mapping exists

`exit` : terminate the program

`msg [ip-addr] "[payload]"` : send a virtual IPv4 packet to [ip-addr] with the given payload (which will be supplied as a string)

`mtu set [value]` : set the MTU of the network’s links as the specified [value]

`mtu get` : print the currently stored MTU (the default MTU should be 1500)

The network can also receive messages from other hosts - when this host receives an IPv4 packet with the protocol indicator set to 0, the payload will be printed to stdout in the format:

`Message received from [ip-addr]:  "[message]"`

When the protocol is non-zero, the message will be:

`Message received from [ip-addr] with protocol [proto-num]`
