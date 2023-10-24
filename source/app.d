// dnslib
// DNS resolver library and command-line app in dlang language
// Author: Adam Williams
// (c) 2020-2021

// ---------------------------------------------------------------------
// OUTSTANDING AND/OR NOT-SUPPORTED FEATURES:

// - IPv6 (for now only IPv4 tested) 
// - BigEndian
// - Support for more dnsTypes
// - Multiple server IPs in DnsNetConfig

// ---------------------------------------------------------------------
// TO-DO:

// - Create one or two combined functions (forward/reverse lookups) a la lookup(name, type, dnsNetConfig) -> string[]

// - Divide header flag 'reserved' into separate bit flags (needed for DNSSEC).
// - Verify bitdirection for opCode, responseCode and reserved.

// - Wording: Use 'query' or 'request' consistently

// - Add unittesting with errors: 2x generate, parse, validate
// - Add checks to dnsMessage.validate() for more record types
// - Add more error checking in general

// - Test parsing for NSCOUNT and ARCOUNT > 0
// - Look into improving functions tcp-/tls-Query in regards to timeout
// - Supporess print '[main(----) dia] Main thread exiting' at the end with -verbose option

// - Look into exit status/code returned to operation system
// - Look into size of executable - can it be reduced?

// ---------------------------------------------------------------------
// USAGE:

// Command-line app usage examples:
// ./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --udptcpport  53 --protocol udp
// ./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls
// ./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --udptcpport  53 --protocol udptcp --recursiondesired=false
// ./dnslookup --name 1.2.3.4       --reverse --server 8.8.8.8 --udptcpport  53 --protocol tcp
// ./dnslookup --help

// Output raw request and response messages
// ./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8  --protocol udp --printdata

// Use raw request message for lookup
// echo "5b1f0100000100000000000003777777057961686f6f03636f6d0000010001" | ./dnslookup --hexstdin 

// Use raw response message without lookup
// This will parse the response message (see 'QR: response') even though it says 'PRINTING REQUEST MESSAGE' and 'VALIDATING REQUEST MESSAGE: header_wrong_query_response'
// echo "5b1f8180000100030000000003777777057961686f6f03636f6d0000010001c00c000500010000003500140b6e65772d66702d73686564037767310162c010c02b0001000100000011000457f864d8c02b0001000100000011000457f864d7" | ./dnslookup --hexstdin --protocol none

// Different levels of certificate check in order from loose to strict
// ./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls --trusted=false
// ./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls --trusted=false --servername "dns.google"
// ./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls --trusted=true  --servername "dns.google" --trustedcertfile "/etc/ssl/certs/ca-certificates.crt"

// Below are servernames for some dns resolver providers
// "cloudflare-dns.com"	// 1.1.1.1  1.0.0.1
// "dns.google"			// 8.8.8.8  8.8.4.4
// "dns.quad9.net"		// 9.9.9.9

// Library usage: Se app main function and test cases in module unittest

// ---------------------------------------------------------------------

import dnslib.defs;
import dnslib.parser;
import dnslib.net;
import dnslib.aux: readHexString;

import std.stdio;
import core.stdc.stdlib: exit, EXIT_FAILURE, EXIT_SUCCESS;
import std.digest;
import std.conv;

// ---------------------------------------------------------------------

bool getOptions(ref string[] args, ref DnsOptions dnsOptions)
{
	import std.getopt;
	
	bool errorFlag = false;
	GetoptResult helpInformation;
	
	try
	{
		helpInformation = getopt(
			args,
			std.getopt.config.noPassThrough,
			"name",				"domain name",															&dnsOptions.name,
			"type",				"A, MX, PTR etc (A)",													&dnsOptions.type,
			"recursiondesired",	"recursive query (true)",												&dnsOptions.recursionDesired,
			"reverse",			"reverse query (false)",												&dnsOptions.reverse,

			"hexstdin",			"accept hexencoded message on stdin (false)", 							&dnsOptions.hexStdin,

			"protocol",			"name server protocol: udp, tcp, udptcp, tls, tlstcp or none (none)",	&dnsOptions.protocol,
			"server",			"name server address or name (127.0.0.1)",								&dnsOptions.server,
			"servername",		"certificate name of server",											&dnsOptions.serverName,

			"trusted",			"require trusted chain of certificates (true)",							&dnsOptions.trusted,
			"trustedcertfile",	"list of trusted certificates (/etc/ssl/certs/ca-certificates.crt)",	&dnsOptions.trustedCertificateFile,
			
			"udptcpport",		"name server port (53)",												&dnsOptions.udpTcpPort,
			"tlsport",			"name server port (853)",												&dnsOptions.tlsPort,
			
			"printdata",		"Print request and response raw data (false)",							&dnsOptions.printData,
			//"printparsing",	"Print parsing debug info (false)",										&dnsOptions.printParsing,  // Used for debugging
			
			"verbose|v",		"Prints more info (false)",												&dnsOptions.verbose,
			"quiet|q",			"Prints less info (false)",												&dnsOptions.quiet,
		);
	}
	catch(Exception e)
	{
		errorFlag = true;
	}
	finally
	{
		if (errorFlag || args.length != 1)
		{
			defaultGetoptPrinter("Error! Query domain name system a la dig or nslookup",
			helpInformation.options);
			exit(EXIT_FAILURE);
		}
		if (helpInformation.helpWanted)
		{
			string[] a =
			[
				"Query domain name system a la dig or nslookup",
				"",
				"Usage:",
				"./dnslookup --name www.yahoo.com --type A",
				"./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --udptcpport  53 --protocol udptcp",
				"./dnslookup --name www.yahoo.com --type A  --server 8.8.8.8 --tlsport    853 --protocol tls",
				"./dnslookup --name 1.2.3.4       --reverse --server 8.8.8.8 --udptcpport  53 --protocol udp",
				""
			];

			import std.string: join;
			import std.ascii;
			defaultGetoptPrinter(a.join(std.ascii.newline),
			helpInformation.options);
			exit(EXIT_SUCCESS);
		}
	}
	
	if ((dnsOptions.name == "") != dnsOptions.hexStdin)
	{
		defaultGetoptPrinter("Query domain name system a la dig or nslookup. Error: Use either name or hexstdin as argument",
		helpInformation.options);

		exit(EXIT_SUCCESS);
	}
	
	return !errorFlag;
}  // getOptions

// ---------------------------------------------------------------------

int main(string[] args)
{		
	DnsOptions dnsOptions;
	if (!getOptions(args, dnsOptions)) return EXIT_FAILURE;

	if (dnsOptions.verbose)
	{
		writeln("\nOPTIONS");
		//writeln(dnsOptions);
		write(dnsOptions.toString());
	}
	
	DnsNetConfig netConfig;
	netConfig.protocol					= dnsOptions.protocol;
	netConfig.server					= dnsOptions.server;
	netConfig.serverName				= dnsOptions.serverName;

	netConfig.trusted					= dnsOptions.trusted;
	netConfig.trustedCertificateFile	= dnsOptions.trustedCertificateFile;

	netConfig.udpTcpPort				= dnsOptions.udpTcpPort;
	netConfig.tlsPort					= dnsOptions.tlsPort;
	//netConfig.timeout					= ...
	//netConfig.udpSizeLimit			= ...

	// ------------
	
	ushort dnsId = 0;
	ubyte[] requestData = [];
	
	if (dnsOptions.hexStdin)
	{
		import std.stdio;
		string line;
		if ((line = readln()) is null)
		{
			writeln("Unable to read stdin line");
			return EXIT_FAILURE;
		}     

		assert (dnsOptions.name == "");

		import std.conv;
		import std.string;
		requestData = readHexString(line.strip());
	}
	else
	{
		assert(dnsOptions.name != "");

		import dnslib.generator: generateRequest, generateReverseRequest;
		if (dnsOptions.reverse)
		{
			generateReverseRequest(dnsOptions.name, dnsId, requestData);
		}
		else
		{
			generateRequest(dnsOptions.name, dnsOptions.type, dnsId, requestData, dnsOptions.recursionDesired);
		}
	}

	if (dnsOptions.printData)
	{
		writeln("\nREQUEST DATA");
		writeln(requestData);
		writeln();
		string requestDataHexString = toHexString!(LetterCase.lower)(requestData);
		writefln("%d : %s", requestData.length, requestDataHexString);
	}

	// ------------
	
	dnsMessage requestMessage;

	if (dnsOptions.verbose)
	{
		writeln("\nPARSING QUERY");
	}
	dnsParserResult requestParserResult = dnsParse(requestData, requestMessage, dnsOptions.printParsing);
	if (requestParserResult != dnsParserResult.success)
	{
		writefln("Parsning error: %s", requestParserResult);
		return EXIT_FAILURE;
	}

	if (!dnsOptions.quiet)
	{
		writeln("\nPRINTING REQUEST MESSAGE");
		requestMessage.print();
	}
	
	auto validateCodeQuery = requestMessage.validate(dnsHeaderFlagQueryResponse.query);
	writefln("\nVALIDATING REQUEST MESSAGE: %s", messageValidateCodeToString(validateCodeQuery));
	
	// ------------
		
	if (dnsOptions.protocol == Protocol.none)
	{
		writeln("\nSKIPPING NET");
		return EXIT_SUCCESS;
	}

	ubyte[] responseData;

	dnsQueryResult myDnsQueryResult;

	DnsNetStat netStat;
	myDnsQueryResult = query(netConfig, requestData, responseData, netStat);

	if (dnsOptions.verbose)
	{
		writeln("\nNET STAT");
		//writeln(netStat);
		write(netStat.toString());
	}
	
	if (myDnsQueryResult == dnsQueryResult.success)
	{
		writeln("\nQUERYING OK");
	}
	else
	{
		writefln("\nQUERY ERROR: %s", myDnsQueryResult);
		return EXIT_FAILURE;
	}

	if (responseData.length == 0)
	{
		writeln("\nNO RESPONSE RECEIVED");
		return EXIT_FAILURE;		
	}

	// ------------
	
	if (dnsOptions.printData)
	{
		writeln("\nRESPONSE DATA");
		writeln(responseData);
		writeln();
		auto responseDataHexString = toHexString!(LetterCase.lower)(responseData);
		writefln("%d : %s", responseData.length, responseDataHexString);
	}
	
	dnsMessage responseMessage;

	if (dnsOptions.verbose)
	{
		writeln("\nPARSING RESPONSE");
	}
	dnsParserResult responseParserResult = dnsParse(responseData, responseMessage, dnsOptions.printParsing);
	if (responseParserResult != dnsParserResult.success)
	{
		writefln("Parsning error: %s", responseParserResult);
		return EXIT_FAILURE;
	}

	if (!dnsOptions.quiet)
	{
		writeln("\nPRINTING RESPONSE MESSAGE");
		responseMessage.print();
	}

	if (!dnsOptions.hexStdin)
	{
		if (requestMessage.header.ID == responseMessage.header.ID)
		{
			writeln("\nIDs match");
		}
		else
		{
			writefln("\nIDs do not match: %d %d", requestMessage.header.ID, responseMessage.header.ID);
			return EXIT_FAILURE;
		}
	}
	
	if (dnsOptions.quiet)
	{
		writeln("\nPRINTING SHORT RESPONSE");
		responseMessage.printShort(dnsOptions.reverse ? dnsType.PTR : dnsOptions.type);
	}
	auto validateCodeResponse = responseMessage.validate(dnsHeaderFlagQueryResponse.response);
	writefln("\nVALIDATING RESPONSE MESSAGE: %s", messageValidateCodeToString(validateCodeResponse));
	writeln();
	
	if (validateCodeResponse == dnsMessageValidateCode.success)
	{
		return EXIT_FAILURE;
	}
		
	return EXIT_SUCCESS;
}  // main
