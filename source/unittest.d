module dnslib.unittesting;

import dnslib.defs;
import dnslib.parser;
import dnslib.aux;

import std.stdio;

unittest
{
	DnsOptions dnsOptions;
	//dnsOptions.printParsing = true;

	{
		// Source: https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf
		string hexData  = "db4201000001000000000000037777770c6e6f7274686561737465726e036564750000010001";
		auto messageData = readHexString(hexData);
		
		dnsMessage message;
		dnsParserResult requestParserResult = dnsParse(messageData, message, dnsOptions.printParsing);
		writeln(requestParserResult);
		assert (requestParserResult == dnsParserResult.success);
		auto validateResult = message.validate(dnsHeaderFlagQueryResponse.query, false);
		writeln(validateResult);
		assert (validateResult == dnsMessageValidateCode.success);
		
		writeln(message);

		assert (message.header.ID							== 56130);
		assert (message.header.flags.queryResponse			== dnsHeaderFlagQueryResponse.query);
		assert (message.header.flags.recursionDesired		== true);
		assert (message.header.flags.recursionAvailable		== false);
		assert (message.header.flags.authoritativeAnswer	== false);
		assert (message.header.flags.truncation				== false);
		assert (message.header.flags.opCode					== dnsOpCode.QUERY);
		assert (message.header.flags.responseCode			== dnsResponseCode.NOERROR);

		assert (message.header.flags.reserved				== 0);

		assert (message.header.QDCOUNT == 1);
		assert (message.header.ANCOUNT == 0);
		assert (message.header.NSCOUNT == 0);
		assert (message.header.ARCOUNT == 0);
		
		assert (message.query.length		== 1);
		assert (message.answer.length		== 0);
		assert (message.authority.length	== 0);
		assert (message.additional.length	== 0);
		
		assert (message.query[0].domainName		== "www.northeastern.edu");
		assert (message.query[0].queryType		== dnsType.A);
		assert (message.query[0].queryClass		== dnsClass.INET);
	}

// ---------------------------------------------------------------------

	{
		// Source: https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf
		string hexData = "db4281800001000100000000037777770c6e6f7274686561737465726e036564750000010001c00c000100010000025800049b211144";
		auto messageData = readHexString(hexData);
		
		dnsMessage message;
		dnsParserResult requestParserResult = dnsParse(messageData, message, dnsOptions.printParsing);
		writeln(requestParserResult);
		assert (requestParserResult == dnsParserResult.success);
		auto validateResult = message.validate(dnsHeaderFlagQueryResponse.response, false);
		writeln(validateResult);
		assert (validateResult == dnsMessageValidateCode.success);
		
		writeln(message);
		
		assert (message.header.ID							== 56130);
		assert (message.header.flags.queryResponse			== dnsHeaderFlagQueryResponse.response);
		assert (message.header.flags.recursionDesired		== true);
		assert (message.header.flags.recursionAvailable		== true);
		assert (message.header.flags.authoritativeAnswer	== false);
		assert (message.header.flags.truncation				== false);
		assert (message.header.flags.opCode					== dnsOpCode.QUERY);
		assert (message.header.flags.responseCode			== dnsResponseCode.NOERROR);

		assert (message.header.flags.reserved				== 0);

		assert (message.header.QDCOUNT == 1);
		assert (message.header.ANCOUNT == 1);
		assert (message.header.NSCOUNT == 0);
		assert (message.header.ARCOUNT == 0);

		assert (message.query.length		== 1);
		assert (message.answer.length		== 1);
		assert (message.authority.length	== 0);
		assert (message.additional.length	== 0);

		assert (message.query[0].domainName		== "www.northeastern.edu");
		assert (message.query[0].queryType		== dnsType.A);
		assert (message.query[0].queryClass		== dnsClass.INET);

		assert (message.answer[0].domainName		== "www.northeastern.edu");
		assert (message.answer[0].responseType		== dnsType.A);
		assert (message.answer[0].responseClass		== dnsClass.INET);

		assert (message.answer[0].TTL == 600);

		assert (message.answer[0].responseDataLength== 4);
		assert (message.answer[0].responseData		== [0x9b, 0x21, 0x11, 0x44]);
		assert (message.answer[0].responseString	== "155.33.17.68");

	}
	
// ---------------------------------------------------------------------

	{
		// Source: https://pypi.org/project/dnslib/
		string hexData = "d5ad818000010005000000000377777706676f6f676c6503636f6d0000010001c00c0005000100000005000803777777016cc010c02c0001000100000005000442f95b68c02c0001000100000005000442f95b63c02c0001000100000005000442f95b67c02c0001000100000005000442f95b93";
		auto messageData = readHexString(hexData);
		
		dnsMessage message;
		dnsParserResult requestParserResult = dnsParse(messageData, message, dnsOptions.printParsing);
		writeln(requestParserResult);
		assert (requestParserResult == dnsParserResult.success);
		auto validateResult = message.validate(dnsHeaderFlagQueryResponse.response, false);
		writeln(validateResult);
		assert (validateResult == dnsMessageValidateCode.success);
		
		writeln(message);
		
		assert (message.header.ID							== 0xd5ad);
		assert (message.header.flags.queryResponse			== dnsHeaderFlagQueryResponse.response);
		assert (message.header.flags.recursionDesired		== true);
		assert (message.header.flags.recursionAvailable		== true);
		assert (message.header.flags.authoritativeAnswer	== false);
		assert (message.header.flags.truncation				== false);
		assert (message.header.flags.opCode					== dnsOpCode.QUERY);
		assert (message.header.flags.responseCode			== dnsResponseCode.NOERROR);

		assert (message.header.flags.reserved				== 0);

		assert (message.header.QDCOUNT == 1);
		assert (message.header.ANCOUNT == 5);
		assert (message.header.NSCOUNT == 0);
		assert (message.header.ARCOUNT == 0);

		assert (message.query.length		== 1);
		assert (message.answer.length		== 5);
		assert (message.authority.length	== 0);
		assert (message.additional.length	== 0);

		assert (message.query[0].domainName		== "www.google.com");
		assert (message.query[0].queryType		== dnsType.A);
		assert (message.query[0].queryClass		== dnsClass.INET);

		assert (message.answer[0].domainName		== "www.google.com");
		assert (message.answer[0].responseType		== dnsType.CNAME);
		assert (message.answer[0].responseClass		== dnsClass.INET);

		assert (message.answer[0].TTL == 5);

		assert (message.answer[0].responseDataLength== 8);
		assert (message.answer[0].responseData		== [3, 119, 119, 119, 1, 108, 192, 16]);
		assert (message.answer[0].responseString	== "www.l.google.com");

		assert (message.answer[1].domainName		== "www.l.google.com");
		assert (message.answer[1].responseType		== dnsType.A);
		assert (message.answer[1].responseClass		== dnsClass.INET);

		assert (message.answer[1].TTL == 5);

		assert (message.answer[1].responseDataLength== 4);
		assert (message.answer[1].responseData		== [66, 249, 91, 104]);
		assert (message.answer[1].responseString	== "66.249.91.104");
	}
}

// ---------------------------------------------------------------------

// Example usage
unittest
{
	import dnslib.defs;

	import std.stdio;
	import core.stdc.stdlib: exit, EXIT_FAILURE, EXIT_SUCCESS;

	// Example data
	string	name				= "www.yahoo.com";
	dnsType	type				= dnsType.A;
	bool	recursionDesired	= true;
	
	ushort	dnsId;
	ubyte[]	requestData;
	import dnslib.generator: generateRequest;
	generateRequest(name, type, dnsId, requestData, recursionDesired);

	ubyte[]			responseData;
	import dnslib.net: DnsNetConfig, DnsNetStat, query, dnsQueryResult;
	DnsNetStat		netStat;
	
	DnsNetConfig	netConfig;
	netConfig.server		= "127.0.0.1";
	netConfig.udpTcpPort	= 53;
	netConfig.protocol		= Protocol.tcp;
	
	auto myDnsQueryResult = query(netConfig, requestData, responseData, netStat);
	if (myDnsQueryResult != dnsQueryResult.success)
	{
		writefln("QUERYING ERROR: %s", myDnsQueryResult);
		//return EXIT_FAILURE;
	}

	dnsMessage responseMessage;

	import dnslib.parser: dnsParse;
	bool printParsing = false;
	auto responseParserResult = dnsParse(responseData, responseMessage, printParsing);
	if (responseParserResult != dnsParserResult.success)
	{
		writefln("PARSNING ERROR: %s", responseParserResult);
		//return EXIT_FAILURE;
	}

	auto validateCodeResponse = responseMessage.validate(dnsHeaderFlagQueryResponse.response);
	
	if (validateCodeResponse != dnsMessageValidateCode.success)
	{
		writefln("VALIDATING RESPONSE MESSAGE: %s", validateCodeResponse.messageValidateCodeToString);
		//return EXIT_FAILURE;
	}
	
	string[] shortResult = responseMessage.getShortResult(type);
	writefln("SHORT RESULT: %s", shortResult);
}

