# dnslookup
DNS resolver library and command-line app in dlang language

## Features
------------
### Supported features
- DNS forward and reverse lookup over udp, tcp and tls
- Fall-back from udp to tcp as well as tls to tcp
- Record types A, NS, CNAME, SOA, PTR, MX, TXT, AAAA, SRV and DNAME

- Write raw DNS request in hex to stdout
- Read raw DNS request in hex from stdin and send request to resolver server

- Diffent levels of resolver server certificate checks

- Library and command-line app can both be build with and with-out tls support

### Not supported features
- IPv6 (not tested)
- BigEndian architectures
- Multiple resolver servers per request

## Library
------------
Separate functions to generate request, query resolver server, parse query & response, validate query & response and print request & response (full as well as short versions). See command-line source code in file source/app.d for usage.

## Command-line app usage
------------
	./dnslookup --help

### Forward lookup
	./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --udptcpport  53 --protocol udp

	./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls

	./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --udptcpport  53 --protocol udptcp --recursiondesired=false

### Reverse lookup
	./dnslookup --name 1.2.3.4       --reverse --server 8.8.8.8 --udptcpport  53 --protocol tcp

### Raw request output and input.
Output raw request and response messages

	./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8  --protocol udp --printdata

Use raw request message for lookup.

	echo "5b1f0100000100000000000003777777057961686f6f03636f6d0000010001" | ./dnslookup --hexstdin

Use raw response message without lookup. This will parse the response message (see 'QR: response') even though it says 'PRINTING REQUEST MESSAGE' and 'VALIDATING REQUEST MESSAGE: header_wrong_query_response'.

	echo "5b1f8180000100030000000003777777057961686f6f03636f6d0000010001c00c000500010000003500140b6e65772d66702d73686564037767310162c010c02b0001000100000011000457f864d8c02b0001000100000011000457f864d7" | ./dnslookup --hexstdin --protocol none

### Resolver server certificate checks
Different levels of certificate check in order from loose to strict

	./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls --trusted=false
	./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls --trusted=false --servername "dns.google"
	./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls --trusted=true  --servername "dns.google" --trustedcertfile "/etc/ssl/certs/ca-certificates.crt"

## Makefile
------------
### Build library and command-line app (tls and no-tls versions). See Makefile for how to only build some parts of the project.
	make buildall
or

	make buildallforce

### Run unittests
	make testall
