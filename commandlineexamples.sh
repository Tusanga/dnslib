# In bash shell stop script execution if any line fails
set -e

./dnslookup --help

./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --udptcpport  53 --protocol udp
./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls
./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --udptcpport  53 --protocol udptcp --recursiondesired=false

./dnslookup --name 8.8.8.8       --reverse --server 8.8.8.8 --udptcpport  53 --protocol tcp

	./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --udptcpport  53 --protocol none

./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8  --protocol udp --printdata
echo "5b1f0100000100000000000003777777057961686f6f03636f6d0000010001" | ./dnslookup --hexstdin
echo "5b1f8180000100030000000003777777057961686f6f03636f6d0000010001c00c000500010000003500140b6e65772d66702d73686564037767310162c010c02b0001000100000011000457f864d8c02b0001000100000011000457f864d7" | ./dnslookup --hexstdin --protocol none

./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls --trusted=false
./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls --trusted=false --servername "dns.google"
./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls --trusted=true  --servername "dns.google" --trustedcertfile "/etc/ssl/certs/ca-certificates.crt"
