module dnslib.unittesting;

import dnslib.defs;
import dnslib.aux;
import dnslib.parser: dnsParse, dnsParserResult;

import std.stdio;

// ---------------------------------------------------------------------

unittest
{
  writeln("UNITTESTING - unittest module");
}

// ---------------------------------------------------------------------

unittest
{
  DnsOptions dnsOptions;

  // Enable printParsing to see output from unittest
  // dnsOptions.printParsing = true;

  {
    // Source: https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf
    string hexData  = "db4201000001000000000000037777770c6e6f7274686561737465726e036564750000010001";
    auto messageData = readHexString(hexData);

    dnsMessage message;
    dnsParserResult requestParserResult = dnsParse(messageData, message, dnsOptions.printParsing);
    writefln("Parser result: %s", requestParserResult);
    assert (requestParserResult == dnsParserResult.success);

    auto validateResult = message.validate(dnsHeaderFlagQueryResponse.query, false);
    writefln("Validate result: %d ; %s", validateResult, messageValidateCodeToString(validateResult));
    assert (validateResult == dnsMessageValidateCode.success);

    writeln(message);

    assert (message.header.ID                         == 56130);
    assert (message.header.flags.queryResponse        == dnsHeaderFlagQueryResponse.query);
    assert (message.header.flags.recursionDesired     == true);
    assert (message.header.flags.recursionAvailable   == false);
    assert (message.header.flags.authoritativeAnswer  == false);
    assert (message.header.flags.truncation           == false);
    assert (message.header.flags.opCode               == dnsOpCode.QUERY);
    assert (message.header.flags.responseCode         == dnsResponseCode.NOERROR);

    assert (message.header.flags.reserved             == 0);

    assert (message.header.QDCOUNT == 1);
    assert (message.header.ANCOUNT == 0);
    assert (message.header.NSCOUNT == 0);
    assert (message.header.ARCOUNT == 0);

    assert (message.query.length      == 1);
    assert (message.answer.length     == 0);
    assert (message.authority.length  == 0);
    assert (message.additional.length == 0);

    assert (message.query[0].domainName   == "www.northeastern.edu");
    assert (message.query[0].queryType    == dnsType.A);
    assert (message.query[0].queryClass   == dnsClass.INET);
  }

  // -------------------------------------------------------------------

  {
    // Source: https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf
    string hexData = "db4281800001000100000000037777770c6e6f7274686561737465726e036564750000010001c00c000100010000025800049b211144";
    auto messageData = readHexString(hexData);

    dnsMessage message;
    dnsParserResult requestParserResult = dnsParse(messageData, message, dnsOptions.printParsing);
    writefln("Parser result: %s", requestParserResult);
    assert (requestParserResult == dnsParserResult.success);

    auto validateResult = message.validate(dnsHeaderFlagQueryResponse.response, false);
    writefln("Validate result: %d ; %s", validateResult, messageValidateCodeToString(validateResult));
    assert (validateResult == dnsMessageValidateCode.success);

    writeln(message);

    assert (message.header.ID                         == 56130);
    assert (message.header.flags.queryResponse        == dnsHeaderFlagQueryResponse.response);
    assert (message.header.flags.recursionDesired     == true);
    assert (message.header.flags.recursionAvailable   == true);
    assert (message.header.flags.authoritativeAnswer  == false);
    assert (message.header.flags.truncation           == false);
    assert (message.header.flags.opCode               == dnsOpCode.QUERY);
    assert (message.header.flags.responseCode         == dnsResponseCode.NOERROR);

    assert (message.header.flags.reserved             == 0);

    assert (message.header.QDCOUNT == 1);
    assert (message.header.ANCOUNT == 1);
    assert (message.header.NSCOUNT == 0);
    assert (message.header.ARCOUNT == 0);

    assert (message.query.length      == 1);
    assert (message.answer.length     == 1);
    assert (message.authority.length  == 0);
    assert (message.additional.length == 0);

    assert (message.query[0].domainName   == "www.northeastern.edu");
    assert (message.query[0].queryType    == dnsType.A);
    assert (message.query[0].queryClass   == dnsClass.INET);

    assert (message.answer[0].domainName    == "www.northeastern.edu");
    assert (message.answer[0].responseType  == dnsType.A);
    assert (message.answer[0].responseClass == dnsClass.INET);

    assert (message.answer[0].TTL == 600);

    assert (message.answer[0].responseDataLength== 4);
    assert (message.answer[0].responseData    == [0x9b, 0x21, 0x11, 0x44]);
    assert (message.answer[0].responseString  == "155.33.17.68");

  }

  // -------------------------------------------------------------------

  {
    // Source: https://pypi.org/project/dnslib/
    string hexData = "d5ad818000010005000000000377777706676f6f676c6503636f6d0000010001c00c0005000100000005000803777777016cc010c02c0001000100000005000442f95b68c02c0001000100000005000442f95b63c02c0001000100000005000442f95b67c02c0001000100000005000442f95b93";
    auto messageData = readHexString(hexData);

    dnsMessage message;
    dnsParserResult requestParserResult = dnsParse(messageData, message, dnsOptions.printParsing);
    writefln("Parser result: %s", requestParserResult);
    assert (requestParserResult == dnsParserResult.success);

    auto validateResult = message.validate(dnsHeaderFlagQueryResponse.response, false);
    writefln("Validate result: %d ; %s", validateResult, messageValidateCodeToString(validateResult));
    assert (validateResult == dnsMessageValidateCode.success);

    writeln(message);

    assert (message.header.ID                         == 0xd5ad);
    assert (message.header.flags.queryResponse        == dnsHeaderFlagQueryResponse.response);
    assert (message.header.flags.recursionDesired     == true);
    assert (message.header.flags.recursionAvailable   == true);
    assert (message.header.flags.authoritativeAnswer  == false);
    assert (message.header.flags.truncation           == false);
    assert (message.header.flags.opCode               == dnsOpCode.QUERY);
    assert (message.header.flags.responseCode         == dnsResponseCode.NOERROR);

    assert (message.header.flags.reserved             == 0);

    assert (message.header.QDCOUNT == 1);
    assert (message.header.ANCOUNT == 5);
    assert (message.header.NSCOUNT == 0);
    assert (message.header.ARCOUNT == 0);

    assert (message.query.length      == 1);
    assert (message.answer.length     == 5);
    assert (message.authority.length  == 0);
    assert (message.additional.length == 0);

    assert (message.query[0].domainName == "www.google.com");
    assert (message.query[0].queryType  == dnsType.A);
    assert (message.query[0].queryClass == dnsClass.INET);

    assert (message.answer[0].domainName    == "www.google.com");
    assert (message.answer[0].responseType  == dnsType.CNAME);
    assert (message.answer[0].responseClass == dnsClass.INET);

    assert (message.answer[0].TTL == 5);

    assert (message.answer[0].responseDataLength  == 8);
    assert (message.answer[0].responseData        == [3, 119, 119, 119, 1, 108, 192, 16]);
    assert (message.answer[0].responseString      == "www.l.google.com");

    assert (message.answer[1].domainName          == "www.l.google.com");
    assert (message.answer[1].responseType        == dnsType.A);
    assert (message.answer[1].responseClass       == dnsClass.INET);

    assert (message.answer[1].TTL == 5);

    assert (message.answer[1].responseDataLength  == 4);
    assert (message.answer[1].responseData        == [66, 249, 91, 104]);
    assert (message.answer[1].responseString      == "66.249.91.104");
  }

  // -------------------------------------------------------------------

  {
    // hexData from first unittest appended with 0xFF
    string hexData  = "db4201000001000000000000037777770c6e6f7274686561737465726e036564750000010001FF";
    auto messageData = readHexString(hexData);

    dnsMessage message;
    dnsParserResult requestParserResult = dnsParse(messageData, message, dnsOptions.printParsing);
    writefln("Parser result: %s", requestParserResult);
    assert (requestParserResult == dnsParserResult.tooLarge);
  }

  // -------------------------------------------------------------------

  {
    // hexData from first unittest concatenated with one byte
    string hexData  = "db4201000001000000000000037777770c6e6f7274686561737465726e0365647500000100";
    auto messageData = readHexString(hexData);

    dnsMessage message;
    dnsParserResult requestParserResult = dnsParse(messageData, message, dnsOptions.printParsing);
    writefln("Parser result: %s", requestParserResult);
    assert (requestParserResult == dnsParserResult.dataMissing);
  }

  // -------------------------------------------------------------------

  {
    // hexData from first unittest with 'www' (i.e. 0x777777) changed to 0xFFFFFF
    string hexData  = "db420100000100000000000003FFFFFF0c6e6f7274686561737465726e036564750000010001";
    auto messageData = readHexString(hexData);

    dnsMessage message;
    dnsParserResult requestParserResult = dnsParse(messageData, message, dnsOptions.printParsing);
    writefln("Parser result: %s", requestParserResult);
    assert (requestParserResult == dnsParserResult.illegalCharacters);
  }

  // -------------------------------------------------------------------

  {
    // hexData from first unittest with length of 'www' (i.e. 0x03 bytes) change to 0x50 bytes
    string hexData  = "db4201000001000000000000507777770c6e6f7274686561737465726e036564750000010001";
    auto messageData = readHexString(hexData);

    dnsMessage message;
    dnsParserResult requestParserResult = dnsParse(messageData, message, dnsOptions.printParsing);
    writefln("Parser result: %s", requestParserResult);
    assert (requestParserResult == dnsParserResult.specificationError);
  }

  // -------------------------------------------------------------------

  {
    // Real world example: dig -tTXT stspg-customer.com with composite TXT record
    string hexData  = "7bfe818000010001000000000e73747370672d637573746f6d657203636f6d0000100001c00c001000010000003c018ced763d73706631206970343a32332e3235332e3138322e313033206970343a32332e3235332e3138332e313435206970343a32332e3235332e3138332e313436206970343a32332e3235332e3138332e313437206970343a32332e3235332e3138332e313438206970343a32332e3235332e3138332e313530206970343a3136362e37382e36382e323231206970343a3136372e38392e34362e313539206970343a3136372e38392e36342e39206970343a3136372e38392e36352e30206970343a3136372e38392e36352e3533206970343a3136372e38392e36352e313030206970343a3136372e38392e37349d2e323333206970343a3136372e38392e37352e3333206970343a3136372e38392e37352e313236206970343a3136372e38392e37352e313336206970343a3136372e38392e37352e313634206970343a3139322e3233372e3135392e3432206970343a3139322e3233372e3135392e3433206970343a3135392e3131322e3234322e313632206970343a3135392e3133352e3232382e3130202d616c6c";
    auto messageData = readHexString(hexData);

    dnsMessage message;
    dnsParserResult requestParserResult = dnsParse(messageData, message, dnsOptions.printParsing);
    writefln("Parser result: %s", requestParserResult);
    assert (requestParserResult == dnsParserResult.success);

    auto validateResult = message.validate(dnsHeaderFlagQueryResponse.response, false);
    writefln("Validate result: %d ; %s", validateResult, messageValidateCodeToString(validateResult));
    assert (validateResult == dnsMessageValidateCode.success);

    writeln(message);

    assert (message.header.ID                         == 31742);
    assert (message.header.flags.queryResponse        == dnsHeaderFlagQueryResponse.response);
    assert (message.header.flags.recursionDesired     == true);
    assert (message.header.flags.recursionAvailable   == true);
    assert (message.header.flags.authoritativeAnswer  == false);
    assert (message.header.flags.truncation           == false);
    assert (message.header.flags.opCode               == dnsOpCode.QUERY);
    assert (message.header.flags.responseCode         == dnsResponseCode.NOERROR);

    assert (message.header.flags.reserved             == 0);

    assert (message.header.QDCOUNT == 1);
    assert (message.header.ANCOUNT == 1);
    assert (message.header.NSCOUNT == 0);
    assert (message.header.ARCOUNT == 0);

    assert (message.query.length      == 1);
    assert (message.answer.length     == 1);
    assert (message.authority.length  == 0);
    assert (message.additional.length == 0);

    assert (message.query[0].domainName   == "stspg-customer.com");
    assert (message.query[0].queryType    == dnsType.TXT);
    assert (message.query[0].queryClass   == dnsClass.INET);

    assert (message.answer[0].domainName    == "stspg-customer.com");
    assert (message.answer[0].responseType  == dnsType.TXT);
    assert (message.answer[0].responseClass == dnsClass.INET);

    assert (message.answer[0].TTL == 60);

    assert (message.answer[0].responseDataLength== 396);
    assert (message.answer[0].responseData    == [237, 118, 61, 115, 112, 102, 49, 32, 105, 112, 52, 58, 50, 51, 46, 50, 53, 51, 46, 49, 56, 50, 46, 49, 48, 51, 32, 105, 112, 52, 58, 50, 51, 46, 50, 53, 51, 46, 49, 56, 51, 46, 49, 52, 53, 32, 105, 112, 52, 58, 50, 51, 46, 50, 53, 51, 46, 49, 56, 51, 46, 49, 52, 54, 32, 105, 112, 52, 58, 50, 51, 46, 50, 53, 51, 46, 49, 56, 51, 46, 49, 52, 55, 32, 105, 112, 52, 58, 50, 51, 46, 50, 53, 51, 46, 49, 56, 51, 46, 49, 52, 56, 32, 105, 112, 52, 58, 50, 51, 46, 50, 53, 51, 46, 49, 56, 51, 46, 49, 53, 48, 32, 105, 112, 52, 58, 49, 54, 54, 46, 55, 56, 46, 54, 56, 46, 50, 50, 49, 32, 105, 112, 52, 58, 49, 54, 55, 46, 56, 57, 46, 52, 54, 46, 49, 53, 57, 32, 105, 112, 52, 58, 49, 54, 55, 46, 56, 57, 46, 54, 52, 46, 57, 32, 105, 112, 52, 58, 49, 54, 55, 46, 56, 57, 46, 54, 53, 46, 48, 32, 105, 112, 52, 58, 49, 54, 55, 46, 56, 57, 46, 54, 53, 46, 53, 51, 32, 105, 112, 52, 58, 49, 54, 55, 46, 56, 57, 46, 54, 53, 46, 49, 48, 48, 32, 105, 112, 52, 58, 49, 54, 55, 46, 56, 57, 46, 55, 52, 157, 46, 50, 51, 51, 32, 105, 112, 52, 58, 49, 54, 55, 46, 56, 57, 46, 55, 53, 46, 51, 51, 32, 105, 112, 52, 58, 49, 54, 55, 46, 56, 57, 46, 55, 53, 46, 49, 50, 54, 32, 105, 112, 52, 58, 49, 54, 55, 46, 56, 57, 46, 55, 53, 46, 49, 51, 54, 32, 105, 112, 52, 58, 49, 54, 55, 46, 56, 57, 46, 55, 53, 46, 49, 54, 52, 32, 105, 112, 52, 58, 49, 57, 50, 46, 50, 51, 55, 46, 49, 53, 57, 46, 52, 50, 32, 105, 112, 52, 58, 49, 57, 50, 46, 50, 51, 55, 46, 49, 53, 57, 46, 52, 51, 32, 105, 112, 52, 58, 49, 53, 57, 46, 49, 49, 50, 46, 50, 52, 50, 46, 49, 54, 50, 32, 105, 112, 52, 58, 49, 53, 57, 46, 49, 51, 53, 46, 50, 50, 56, 46, 49, 48, 32, 45, 97, 108, 108]);
    assert (message.answer[0].responseString  == "v=spf1 ip4:23.253.182.103 ip4:23.253.183.145 ip4:23.253.183.146 ip4:23.253.183.147 ip4:23.253.183.148 ip4:23.253.183.150 ip4:166.78.68.221 ip4:167.89.46.159 ip4:167.89.64.9 ip4:167.89.65.0 ip4:167.89.65.53 ip4:167.89.65.100 ip4:167.89.74.233 ip4:167.89.75.33 ip4:167.89.75.126 ip4:167.89.75.136 ip4:167.89.75.164 ip4:192.237.159.42 ip4:192.237.159.43 ip4:159.112.242.162 ip4:159.135.228.10 -all");
  }

} // unittest

// ---------------------------------------------------------------------

// Example usage
unittest
{
  import core.stdc.stdlib: exit, EXIT_FAILURE, EXIT_SUCCESS;

  // Example data
  string  name              = "www.yahoo.com";
  dnsType type              = dnsType.A;
  bool    recursionDesired  = true;

  ushort  dnsId;
  ubyte[] requestData;
  import dnslib.generator: generateRequest;
  generateRequest(name, type, dnsId, requestData, recursionDesired);

  ubyte[]     responseData;
  import dnslib.net: DnsNetConfig, DnsNetStat, query, dnsQueryResult;
  DnsNetStat    netStat;

  DnsNetConfig  netConfig;
  netConfig.server      = "127.0.0.1";
  netConfig.udpTcpPort  = 53;
  netConfig.protocol    = Protocol.tcp;

  auto myDnsQueryResult = query(netConfig, requestData, responseData, netStat);
  if (myDnsQueryResult != dnsQueryResult.success)
  {
    writefln("QUERYING ERROR: %s", myDnsQueryResult);
    exit(EXIT_FAILURE);
  }

  dnsMessage responseMessage;

  bool printParsing = false;
  auto responseParserResult = dnsParse(responseData, responseMessage, printParsing);
  if (responseParserResult != dnsParserResult.success)
  {
    writefln("PARSING ERROR: %s", responseParserResult);
    exit(EXIT_FAILURE);
  }

  auto validateCodeResponse = responseMessage.validate(dnsHeaderFlagQueryResponse.response);

  if (validateCodeResponse != dnsMessageValidateCode.success)
  {
    writefln("VALIDATING RESPONSE MESSAGE: %s", validateCodeResponse.messageValidateCodeToString);
    exit(EXIT_FAILURE);
  }

  string[] shortResult = responseMessage.getShortResult(type);
  writefln("SHORT RESULT: %s", shortResult);
} // unittest

