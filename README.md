# Py-SSL-Test-Gen

A tool to simulate SSL conversations generating a PCAP file.

No data is ever sent over the network. Great control over client and server settings, entirely self-contained.

### Implementation Notes

Using stock OpenSSL server and client implementations via *PyOpenSSL* bindings. Server and client are hosted in the same process connected through a memory buffer.

Server and client logic is implemented in *eventlet* coroutines.

Writing PCAP file using our own module, *pcapgen*. Pcapgen is implemented in C++11 using *libpcap* for writing PCAP files and *libnet* for rendering network packets. Python bindings are generated with *SWIG*.
