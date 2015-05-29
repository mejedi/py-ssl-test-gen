# Py-SSL-Test-Gen

A tool to simulate SSL conversations generating a PCAP file.

No data is ever sent over the network. Great control over client and server settings, entirely self-contained.

### Implementation Notes

Using stock OpenSSL server and client implementations via *PyOpenSSL* bindings. Server and client are hosted in the same process and connected through a memory buffer.

Server and client logic is implemented in *eventlet* coroutines.

Writing PCAP file using our own module, *pcapgen*. Pcapgen is implemented in C++11 using *libpcap* for writing PCAP files and *libnet* for rendering network packets. Python bindings are generated with *SWIG*.

### Project Goals, etc.

The author is responsible for maintaining and improving an SSL decoder in a network sniffer.
Numerous stock libraries implementing SSL/TLS clients and servers are available; unfortunately
these libraries are of a little use since a sniffer isn't an active participant of a network
connection. A sniffer must understand SSL protocol and it must decrypt both client and server
transmissions. In order to do so it has to maintain and update both client and server states.
For these reasons our SSL decoder implements protocol handling from scratch.

SSL/TLS protocol is a vast framework allowing for a plethora of parameters to be negotiated
between a client and the server. Paremeters include but are not limited to the protocol version,
plus authentication, encryption and verification crypto algorithms. In order to test our code
we feed the decoder with recorded SSL conversations with varying parameters. Capturing these
on the actual network is cumbersome hence we settled on simulation.

Initially the simulator was implemented entirely in C++. Lots of effort was invested in developing
a simulator configuration format based on YAML. In subsequent iterations the simulator logic was 
rewritten in Python with only the low level packet formating still in C++.

The flexibility of Python allowed us to drop the notion of simulator configuration format;
now a simulation task is just a little script in Python calling our simulator library. Besides
a great support for coroutines in Python lends itself naturally for simulation of
multiple simultaneous acitivities like a server and a client logic.
