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
	./dnslookup --name 8.8.8.8       --reverse --server 8.8.8.8 --udptcpport  53 --protocol tcp

### Skip network part - only parse query
	./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --udptcpport  53 --protocol none

### Raw request output and input
Output raw request and response messages

	./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8  --protocol udp --printdata

Use raw request message for lookup.

	echo "5b1f0100000100000000000003777777057961686f6f03636f6d0000010001" | ./dnslookup --hexstdin

Use raw request or response message without lookup. This will parse the request or response message (see 'QR' for which one) even though it always says 'PRINTING REQUEST MESSAGE' and 'VALIDATING REQUEST MESSAGE.

	echo "5b1f8180000100030000000003777777057961686f6f03636f6d0000010001c00c000500010000002300210e6d652d796370692d63662d77777703673036087961686f6f646e73036e657400c02b00010001000000230004bc7d5eccc02b00010001000000230004bc7d5ece"  | ./dnslookup --hexstdin --protocol none

### Resolver server certificate checks
Different levels of certificate check in order from loose to strict

	./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls --trusted=false
	./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls --trusted=false --servername "dns.google"
	./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls --trusted=true  --servername "dns.google" --trustedcertfile "/etc/ssl/certs/ca-certificates.crt"

For trusted==false without servername: Require peer to always present a certificate and check certificate for basic validity.
For trusted==false with servername: As above and also validate actual peer name/address against certificate.
For trusted==true requires both servername and trustedcertfile: As above and also requires that certificate or any parent certificate is trusted.

## Command line examples
------------
The above command line examples are also listed in a bash script: commandlineexamples.sh

## Makefile
------------
### Build library and command-line app (tls and no-tls versions). See Makefile for how to only build some parts of the project.
	make buildall
or

	make buildallforce

### Run unittests
	make testall

