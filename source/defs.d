module dnslib.defs;

import std.stdio;
import std.conv;
import std.bitmanip;

version(BigEndian)
{
	static assert(false);
}

// ---------------------------------------------------------------------

struct DnsOptions
{
	string		name					= "";
	dnsType		type					= dnsType.A;
	bool		recursionDesired		= true;
	bool		reverse					= false;

	bool		hexStdin				= false;
	
	Protocol	protocol				= Protocol.udptcp;
	string		server					= "127.0.0.1";
	string		serverName				= "";
	
	bool		trusted					= true;
	string		trustedCertificateFile	= "/etc/ssl/certs/ca-certificates.crt";
	
	ushort		udpTcpPort				=  53;	
	ushort		tlsPort					= 853;	
	
	bool		printData				= false;
	bool		printParsing			= false;
	
	bool		verbose					= false;
	bool		quiet					= false;
	
	string toString()
	{
		import std.string: leftJustify;
		static import std.ascii;
		import std.array:  join;

		string[] resultArray = [];
		import std.conv: to;
		import std.stdio;
		import std.traits;
		//const auto b = [ __traits(allMembers, DnsOptions) ];
		const auto b = FieldNameTuple!DnsOptions;
		
		static foreach(element; b)
		{
			mixin("resultArray ~= leftJustify(element, 23, ' ') ~ \": \"  ~ this." ~ element ~ ".text() ~ std.ascii.newline; ");
		}
			
		string s = resultArray.join();
		return s;	
	}
}

// ---------------------------------------------------------------------

version(ENABLE_TLS)
{
	enum Protocol : ubyte
	{
		none		= 0,
		udp			= 1,
		tcp			= 2,
		udptcp		= 3,
		tls			= 4,
		tlstcp		= 5,
		//https		= 6,
	}	
}
else
{
	enum Protocol : ubyte
	{
		none		= 0,
		udp			= 1,
		tcp			= 2,
		udptcp		= 3,
		//tls		= 4,
		//tlstcp	= 5,
		//https		= 6,
	}	
}

// ---------------------------------------------------------------------

enum dnsType : ushort
{
	A		=    1,
	NS		=    2,
	CNAME	=    5,
	SOA		=	 6,
	PTR		=   12,
	MX		=   15,
	TXT		=   16,
	AAAA	=   28,
	SRV		=   33,
	DNAME	=   39,
//	SSHFP	=	44,
//	TLSA	=   52,
//	CAA		=  257,
}

bool typeValidate(ushort type)
{
	import std.traits;
	const auto b = [ __traits(allMembers, dnsType) ];
	static foreach(element; b)
	{
		mixin("if (type == dnsType."~element~") return true;");
	}
	
	return false;
}

// ---------------------------------------------------------------------

enum dnsClass : ushort
{
	INET	=	1,
	CH		=	3,
	HS		=	4,
}

bool classValidate(ushort myClass)
{
	return (myClass == 1) || (myClass == 3) || (myClass == 4);
}

string queryClassToString(ushort queryClass)
{
	string res = "Other";
	switch(queryClass)
	{
		case 1:	res = "INET";	break;
		case 3: res = "CHAOS";	break;
		case 4: res = "HESIOD";	break;
		default: break;
	}
	
	return res;
}

// ---------------------------------------------------------------------

enum dnsOpCode : ubyte
{
	QUERY		= 0,
	IQUERY		= 1,
	STATUS		= 2,
	NOTIFY		= 4,
	UPDATE		= 5,
	DSO			= 6,
}

bool opCodeValidate(ubyte opCode)
{
	return (opCode <= 6 && opCode != 3);
}

string opCodeToString(ubyte	opCode)
{
	string res = "Unassigned";
	switch(opCode)
	{
		case 0: res = "Query"; break;
		case 1: res = "IQuery (OBSOLETE)"; break;
		case 2: res = "Status"; break;
		case 4: res = "Notify"; break;
		case 5: res = "Update"; break;
		case 6: res = "DNS Stateful Operations (DSO)"; break;
		default: break;
	}
	return res;
}

// ---------------------------------------------------------------------

enum dnsResponseCode : ubyte
{
	NOERROR		= 0,
	FORMERROR	= 1,
	SERVERFAIL	= 2,
	NXDOMAIN	= 3,
	NOTIMP		= 4,
	REFUSED		= 5,
}

bool responseCodeValidate(ubyte responseCode)
{
	return (responseCode <= 5);
}

string responseCodeToString(ubyte responseCode)
{
	string res = "Other";
	switch(responseCode)
	{
		case  0: res = "NoError";	break;
		case  1: res = "FormErr";	break;
		case  2: res = "ServFail";	break;
		case  3: res = "NXDomain";	break;
		case  4: res = "NotImp";	break;
		case  5: res = "Refused";	break;
		
		default: break;
	}
	
	return res;
}  // responseCodeToString

// ---------------------------------------------------------------------

struct dnsHeaderFlags
{
	union
	{
		ushort a;

		// ToDo: Check for bitdirection for opCode, responseCode and reserved
		mixin(bitfields!(
			bool,  "recursionDesired",		1,
			bool,  "truncation",			1,
			bool,  "authoritativeAnswer",	1,
			ubyte, "opCode",				4,
			bool,  "queryResponse",			1,

			// byte border

			ubyte, "responseCode",			4,

			// See https://tools.ietf.org/html/rfc2535#page-15
			ubyte, "reserved",				3,
			//bool,  "checkingDisabled",	1,
			//bool,  "authenticData",		1,
			//bool,  "recursionAvailable",	1,

			bool,  "recursionAvailable",	1,

			));
	}  // union
	
	string toString()
	{
		import std.format;
		return format!"%s - %s - %s - %d %d %d %d - %d"(dnsHeaderFlagQueryResponseToString(queryResponse), opCodeToString(opCode), responseCodeToString(responseCode), recursionDesired, recursionAvailable, truncation, authoritativeAnswer, reserved);
	}
	
}  // struct dnsHeaderFlags

static assert(dnsHeaderFlags.sizeof == 2); // 16 bits

unittest
{
	dnsHeaderFlags x;
	x.a = 0;
	assert(x.recursionDesired == false);
	assert(x.a == 0);
	
	x.recursionDesired = true;
	assert(x.recursionDesired == true);
	assert(x.a != 0);
}

// ---------------------------------------------------------------------

enum dnsHeaderFlagQueryResponse : bool
{
	query		= false,
	response	= true
}

string dnsHeaderFlagQueryResponseToString(bool x)
{
	if (x) { return "response"; } else { return "query"; }
}

struct dnsHeader{
	private ushort _ID;
	dnsHeaderFlags flags;	
	private ushort _QDCOUNT, _ANCOUNT, _NSCOUNT, _ARCOUNT;
	
	import std.bitmanip: swapEndian;
	
	@property ushort ID() { return _ID.swapEndian(); }
	@property ushort QDCOUNT() { return _QDCOUNT.swapEndian(); }
	@property ushort ANCOUNT() { return _ANCOUNT.swapEndian(); }
	@property ushort NSCOUNT() { return _NSCOUNT.swapEndian(); }
	@property ushort ARCOUNT() { return _ARCOUNT.swapEndian(); }
	
	void print()
	{
		writeln("HEADER SECTION:");
		writefln("ID:           %s", ID);
		writefln("QR:           %s", to!dnsHeaderFlagQueryResponse(flags.queryResponse));
		writefln("Opcode:       %s", flags.opCode.opCodeToString);
		writefln("Responsecode: %s", flags.responseCode.responseCodeToString);
		writefln("Reserved:     %s", flags.reserved);
		write(   "Flags:        ");
		if (flags.authoritativeAnswer)	write("authoritativeAnswer ");
		if (flags.truncation)			write("truncation ");
		if (flags.recursionDesired)		write("recursionDesired ");
		if (flags.recursionAvailable)	write("recursionAvailable ");
		writeln();
		//writefln("flagbits:     %b", flags.a);
		
		writefln("QDCOUNT: %d", QDCOUNT);					
		writefln("ANCOUNT: %d", ANCOUNT);					
		writefln("NSCOUNT: %d", NSCOUNT);					
		writefln("ARCOUNT: %d", ARCOUNT);					
	}
	
	string toString()
	{
		import std.format;
		return format!"%s ; %s ; %s %s %s %s"(ID().text(), flags.toString(), QDCOUNT().text(), ANCOUNT().text(), NSCOUNT().text(), ARCOUNT().text());
		
	}
}  // struct dnsHeader

static assert(dnsHeader.sizeof == 12);


struct querySection
{
	string domainName;
	ushort queryType;
	ushort queryClass;
	
	void print()
	{
		writeln("QUERY SECTION:");
		writefln("query name:  %s", domainName);
		writefln("query type:  %s", to!dnsType(queryType));
		writefln("query class: %s", queryClass.queryClassToString);			
	}
}

struct responseSection
{
	string	domainName;
	ushort	responseType;
	ushort	responseClass;
	uint	TTL;
	ushort	responseDataLength;
	ubyte[]	responseData;
	string[] responseElements;
	string	responseString;
	
	// Do not call function getMXPriority before responseType has been checked (type == MX) and message has been validated (and is valid)
	ushort	getMXPriority()
	{
		assert(responseDataLength >= 2);
		return responseData[0]*256 + responseData[1];
	}
	
	void print()
	{
		writeln("RESPONSE SECTION:");
		writefln("response name:  %s", domainName);
		writefln("response type:  %s", to!dnsType(responseType));
		writefln("response class: %s", responseClass.queryClassToString);			
		writefln("TTL: %d", TTL);			
		writefln("response data length: %d", responseDataLength);			
		writefln("response data:        %s", responseData);
		writefln("response elements:    %s", responseElements);
		writefln("response string:      %s", responseString);
	}
}

// ---------------------------------------------------------------------

enum dnsMessageValidateCode : uint
{
	success								= 0,

	// HEADER 
	header_wrong_query_response			= 2 ^^  1,
	invalid_op_code						= 2 ^^  2,
	query_op_code_error					= 2 ^^  3,
	query_flag_error					= 2 ^^  4,
	header_reserved_flag_use			= 2 ^^  5,
	invalid_response_code				= 2 ^^  6,
	query_response_code_error			= 2 ^^  7,
	section_count_mismatch				= 2 ^^  8,
	query_section_count_error			= 2 ^^  9,
	query_other_sections_count_error	= 2 ^^ 10,
	
	// SECTION
	msg_class_not_inet					= 2 ^^ 11,

	invalid_class						= 2 ^^ 12,
	invalid_type						= 2 ^^ 13,

	inconsistent_class					= 2 ^^ 14,
	inconsistent_type					= 2 ^^ 15,

	response_data_length_mismatch		= 2 ^^ 16,
	response_data_length_error			= 2 ^^ 17,

	authority_section_type_error		= 2 ^^ 18,
	
	// MISC
	unknown_error						= 2 ^^ 31,	
}

string messageValidateCodeToString(uint code)
{
	string[] resultArray = [];
	import std.conv: to;
	import std.stdio;
	import std.traits;
	const auto b = [ __traits(allMembers, dnsMessageValidateCode) ];
	static foreach(element; b)
	{
		mixin("if ((code & dnsMessageValidateCode."~element~") != 0) { resultArray ~= \""~element~"\"; }");
	}
	
	string result = "success";
	import std.string: join;
	if (resultArray.length > 0) result = resultArray.join(", ");
	
	return result;
}

// ---------------------------------------------------------------------

struct dnsMessage
{
	dnsHeader			header;
	querySection[]		query;
	responseSection[]	answer;
	responseSection[]	authority;
	responseSection[]	additional;

	uint validate(dnsHeaderFlagQueryResponse flagQueryResponse, bool strict = true)
	{
		immutable OPCODE_QUERY			= 0;
		immutable RESPONSECODE_NOERROR	= 0;

		uint result = dnsMessageValidateCode.success;

		// HEADER
		if (header.flags.queryResponse != flagQueryResponse)
			result |= dnsMessageValidateCode.header_wrong_query_response;

		if (!opCodeValidate(header.flags.opCode))
			result |= dnsMessageValidateCode.invalid_op_code;

		if (header.flags.queryResponse == dnsHeaderFlagQueryResponse.query && header.flags.opCode != OPCODE_QUERY) 
			result |= dnsMessageValidateCode.query_op_code_error;

		if (header.flags.queryResponse == dnsHeaderFlagQueryResponse.query && (header.flags.authoritativeAnswer || header.flags.truncation  || header.flags.recursionAvailable))
			result |= dnsMessageValidateCode.query_flag_error;

		if (header.flags.reserved != 0)
			result |= dnsMessageValidateCode.header_reserved_flag_use;

		if (!responseCodeValidate(header.flags.responseCode))
			result |= dnsMessageValidateCode.invalid_response_code;

		if (header.flags.queryResponse == dnsHeaderFlagQueryResponse.query && header.flags.responseCode != RESPONSECODE_NOERROR) 
			result |= dnsMessageValidateCode.query_response_code_error;

		if (header.QDCOUNT != query.length || header.ANCOUNT != answer.length || header.NSCOUNT != authority.length ||  header.ARCOUNT != additional.length) 
			result |= dnsMessageValidateCode.section_count_mismatch;

		if (header.QDCOUNT == 0)
			result |= dnsMessageValidateCode.query_section_count_error;

		if (header.flags.queryResponse == dnsHeaderFlagQueryResponse.query && header.QDCOUNT != 1 && strict)
			result |= dnsMessageValidateCode.query_section_count_error;

		if (header.flags.queryResponse == dnsHeaderFlagQueryResponse.query && (header.ANCOUNT != 0 || header.NSCOUNT != 0 || header.ARCOUNT != 0))
			result |= dnsMessageValidateCode.query_other_sections_count_error;

		// SECTIONS
		ushort  msgType		= ushort.max;	// DUMMY VALUE
		ushort  msgClass	= ushort.max;	// DUMMY VALUE

		if (header.QDCOUNT != 0)
		{
			msgType		= query[0].queryType;
			msgClass	= query[0].queryClass;
		}

		if (msgClass != dnsClass.INET && strict)
			result |= dnsMessageValidateCode.msg_class_not_inet;

		foreach(section; query)
		{
			if (!typeValidate(section.queryType))
				result |= dnsMessageValidateCode.invalid_type;

			if (!classValidate(section.queryClass))
				result |= dnsMessageValidateCode.invalid_class;

			if (section.queryType  != msgType)
				result |= dnsMessageValidateCode.inconsistent_type;
				
			if (section.queryClass != msgClass)
				result |= dnsMessageValidateCode.inconsistent_class;
		}

		foreach(section; answer)
		{
			if (!typeValidate(section.responseType))
				result |= dnsMessageValidateCode.invalid_type;

			if (!classValidate(section.responseClass))
				result |= dnsMessageValidateCode.invalid_class;

			if (section.responseType  != msgType && section.responseType != dnsType.CNAME)
				result |= dnsMessageValidateCode.inconsistent_type;
				
			if (section.responseClass != msgClass)
				result |= dnsMessageValidateCode.inconsistent_class;
		
			if (section.responseDataLength != section.responseData.length)
				result |= dnsMessageValidateCode.response_data_length_mismatch;

			// dnsType.A
			if (section.responseType == dnsType.A && section.responseDataLength != 4) 
				result |= dnsMessageValidateCode.response_data_length_error;
				
			// dnsType.MX
			if (section.responseType == dnsType.MX && section.responseDataLength <= 2) 
				result |= dnsMessageValidateCode.response_data_length_error;

			// ... ToDo for other responseTypes
		}

		foreach(section; authority)
		{
			if (!typeValidate(section.responseType))
				result |= dnsMessageValidateCode.invalid_type;

			if (!classValidate(section.responseClass))
				result |= dnsMessageValidateCode.invalid_class;

			if (section.responseType  != dnsType.NS
			||  section.responseType  != dnsType.SOA		// ToDo: Check RFC specification
			)
				result |= dnsMessageValidateCode.authority_section_type_error;
				
			if (section.responseClass != msgClass)
				result |= dnsMessageValidateCode.inconsistent_class;
				
			if (section.responseDataLength != section.responseData.length)
				result |= dnsMessageValidateCode.response_data_length_mismatch;
		}

		foreach(section; additional)
		{
			if (!typeValidate(section.responseType))
				result |= dnsMessageValidateCode.invalid_type;

			if (!classValidate(section.responseClass))
				result |= dnsMessageValidateCode.invalid_class;

			if (section.responseType  != msgType)
				result |= dnsMessageValidateCode.inconsistent_type;
				
			if (section.responseClass != msgClass)
				result |= dnsMessageValidateCode.inconsistent_class;
		
			if (section.responseDataLength != section.responseData.length)
				result |= dnsMessageValidateCode.response_data_length_mismatch;
		}

		return result;
	}  // validate

	void print()
	{
		header.print();

		if (query.length == 0)
		{
			writeln("NO QUERY SECTION");
		}
		else
		{
			writeln("QUERY SECTIONS");
			foreach(e; query)
			e.print;
			
		}

		if (answer.length == 0)
		{
			writeln("NO ANSWER SECTION");
		}
		else
		{
			writeln("ANSWER SECTIONS");
			foreach(e; answer)
			e.print;
		}

		if (authority.length == 0)
		{
			writeln("NO AUTHORITY SECTION");
		}
		else
		{
			writeln("AUTHORITY SECTIONS");
			foreach(e; authority)
			e.print;
		}

		if (additional.length == 0)
		{
			writeln("NO ADDITIONAL SECTION");
		}
		else
		{
			writeln("ADDITIONAL SECTIONS");
			foreach(e; additional)
			e.print;
		}
	}  // print

	string[] getShortResult(dnsType type = dnsType.A)
	{
		string[] result;
		foreach(element; answer)
		{
			if (element.responseType != type) continue;
			result ~= element.responseString;
		}
		
		return result;
	}  // getShortResult
	
	void printShort(dnsType type = dnsType.A)
	{		
		foreach(result; getShortResult(type))
		{
			writeln(result);
		}
	}  // printShort
	
}
