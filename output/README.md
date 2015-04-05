# Py-SSL-Test-Gen-Output

Sample output for sharing with interested parties.

  * *simulation.pcap* — generated PCAP file, multiple SSL connections captured;
  * *simulation.list* — SSL versions/ciphersuites used, ex: *TLS1.2/AES256-SHA256*;
  
    Simulated client sends version/ciphersuite disguised as a HTTP request, ex: *GET /TLS1.2/AES256-SHA256*. If a line from *simulation.list* is missing in decryption output it means that the corresponding mode in decryptor is failing.
    
  * *simulation.conf* — a configuration for *tapered-tool*, references *server.key*;
  * *server.key* — a private key used by simulated SSL server.
