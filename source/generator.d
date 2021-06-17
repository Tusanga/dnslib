module dnslib.generator;


import dnslib.defs;

import std.conv: to;
import std.random;

ushort IDcounter = 0;

// Very simple random generator used for creating dns request ID values
auto randomEngine = MinstdRand(1);	// Generator is reseeded in module constructor

static this()
{
	randomEngine.seed(unpredictableSeed);
}

// ---------------------------------------------------------------------

ushort newDnsId()
{
	IDcounter = to!ushort((IDcounter + uniform(1, ushort.max-1, randomEngine)) % ushort.max);
	return IDcounter;
}

// ---------------------------------------------------------------------

bool generateRequest(string domainName, dnsType type, out ushort dnsId, out ubyte[] requestData, bool recursionDesired = true)
{
	import std.bitmanip: swapEndian;

	static assert (ushort.sizeof == 2);
	dnsId = newDnsId();
	ushort[] requestHeader = [dnsId, recursionDesired ? 0x0100 : 0x0000, 1, 0, 0, 0];  // 0x0100 = standard query with recursion desired; Only one query section.
	foreach(i,v; requestHeader)
	{
		requestHeader[i] = requestHeader[i].swapEndian();
	}
	
	requestData = cast(ubyte[])requestHeader;

	if (domainName.length == 0 || domainName.length > 253) { return false; }
	
	import std.string: split;
	string[] domainNameElements = domainName.split(".");
	if (domainNameElements.length > 127) { return false; }

	foreach(element; domainNameElements)
	{
		assert(1 <= element.length && element.length <= 63);
		if (element.length == 0 || element.length > 63) { return false; }
		requestData ~= to!ubyte(element.length);
		requestData ~= cast(ubyte[])element;
	}
	requestData ~= 0;

	ushort requestClass = dnsClass.INET;
	ushort[] typeAndClass = [(cast(ushort)type).swapEndian(), requestClass.swapEndian()];
	requestData ~= cast(ubyte[])typeAndClass;
	
	return true;
}  // generateRequest

// ---------------------------------------------------------------------

bool generateReverseRequest(string ipstring, out ushort dnsId, out ubyte[] requestData)
{
	if (ipstring.length < 7 || ipstring.length > 15) { return false; }
	
	import std.string: split, join;
	string[] ipstringElements = ipstring.split(".");
	assert(ipstringElements.length == 4);
	foreach(element; ipstringElements)
	{
		if (element.length == 0 || element.length > 3) { return false; }
		foreach (c; element)
		{
			import std.ascii: isDigit;
			if (!c.isDigit()) { return false; }
		}
	}
	
	import std.algorithm.mutation: reverse;
	string domainName = ipstringElements.reverse.join(".") ~ ".in-addr.arpa";
	
	dnsType reverseDnsType = dnsType.PTR;
	generateRequest(domainName, reverseDnsType, dnsId, requestData, true);
	
	return true;
}  // generateReverseRequest

