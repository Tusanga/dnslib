module dnslib.parser;

import dnslib.defs;
import dnslib.aux;

import std.stdio;
import std.conv: to;


// ---------------------------------------------------------------------

enum dnsParserResult
{
	success,
	tooLarge,
	dataMissing,
	specificationError,
	illegalCharacters
}

class dnsParserException : Exception
{
	dnsParserResult parserResult;
	
    this(dnsParserResult parserResult, string file = __FILE__, size_t line = __LINE__)
    {
		this.parserResult = parserResult;
		import std.conv: to;
        super("dnslib.parser exception " ~ to!string(parserResult), file, line);
    }
}

// ---------------------------------------------------------------------

dnsParserResult dnsParse(const ref ubyte[] input, ref dnsMessage myDnsMessage, bool printEnabled = false)
{
  dnsParserResult parserResult = dnsParserResult.success;
  try
  {
	dnsHeader		myDnsHeader;

	querySection	myQuerySection;
	responseSection	myResponseSection;

	ushort inputPtr = 0;
	
	// ----------

	void parseHeader()
	{
		if (input.length < dnsHeader.sizeof) { throw new dnsParserException(dnsParserResult.dataMissing); }

		myDnsHeader = cast(dnsHeader)cast(ubyte[dnsHeader.sizeof])(input[0 .. dnsHeader.sizeof]);
		inputPtr += dnsHeader.sizeof;
	}  // parseHeader
	
	// ----------

	uint readUINT32(const ref ubyte[] input)
	{
		if (input.length - inputPtr < 4) { throw new dnsParserException(dnsParserResult.dataMissing); }	
		
		union U
		{
			uint i;
			ubyte[4] a;
		}
		
		U x;
		x.a = input[inputPtr .. inputPtr+4];
		import core.bitop: bswap;
		x.i = bswap(x.i);
		inputPtr += 4;
		return x.i;
	}
	
	// ----------

	uint readUINT16(const ref ubyte[] input)
	{
		if (input.length - inputPtr < 2) { throw new dnsParserException(dnsParserResult.dataMissing); }	
		
		union U
		{
			uint i;
			ubyte[2] a;
		}
		
		U x;
		x.a = input[inputPtr .. inputPtr+2];
		inputPtr += 2;
		return x.a[0] * 256 + x.a[1];
	}
	// ----------

	string readCharacterString(const ref ubyte[] input)
	{
		if (input.length - inputPtr < 1) { throw new dnsParserException(dnsParserResult.dataMissing); }	

		ubyte length = input[inputPtr];
		inputPtr += 1;
		
		if (printEnabled) writefln("Read character string %d %d %d", input.length, inputPtr, length);

		if (input.length - inputPtr < length) { throw new dnsParserException(dnsParserResult.dataMissing); }	
		
		string element = cast(string)(input[inputPtr .. inputPtr+length]);
		if (printEnabled) writefln("Element: %s", element);

		inputPtr += length;
		return element;
	}

	// ----------

	string readDomainName(const ref ubyte[] input)
	{
		string[] elements;

		void readSingleElement(ref ushort myInputPtr)
		{
			if (input.length - myInputPtr < 1) { throw new dnsParserException(dnsParserResult.dataMissing); }	

			ubyte length = input[myInputPtr];
			myInputPtr += 1;

			if (length > 63) { throw new dnsParserException(dnsParserResult.specificationError); }	
			
			if (printEnabled) writefln("%d %d %d", input.length, myInputPtr, length);

			if (input.length - myInputPtr < length) { throw new dnsParserException(dnsParserResult.dataMissing); }	
			
			string element = cast(string)(input[myInputPtr .. myInputPtr+length]);
			if (printEnabled) writefln("Element: %s", element);

			if (!noIllegalCharacters(element)) { throw new dnsParserException(dnsParserResult.illegalCharacters); }	
			myInputPtr += length;

			elements ~= element;
		}  // readSingleElement

		void readMultipleElements(ref ushort myInputPtr)
		{
			if (input.length - myInputPtr < 1) { throw new dnsParserException(dnsParserResult.dataMissing); }	
			
			while(input.length > myInputPtr && input[myInputPtr] > 0 && (input[myInputPtr] & 0b11000000) != 0b11000000)
			{
				if (printEnabled) writefln("Input1[%s]: %d", myInputPtr, input[myInputPtr]);
				readSingleElement(myInputPtr);
			}

			if (input.length - myInputPtr < 1) { throw new dnsParserException(dnsParserResult.dataMissing); }	

			if(input.length > myInputPtr && (input[myInputPtr] & 0b11000000) == 0b11000000) // Compression pointer
			{
				if (printEnabled) writefln("Input2[%s]: %d", myInputPtr, input[myInputPtr]);
				
				if (input.length - myInputPtr < 2) { throw new dnsParserException(dnsParserResult.dataMissing); }
				
				ushort pointer = (input[myInputPtr] & 0b00111111) * 256 + input[myInputPtr+1];
				myInputPtr += 2;
				
				if (printEnabled) writefln("Pointer %d", pointer);

				auto oldInputPtr = myInputPtr;
				auto compressionInputPtr = pointer;

				readMultipleElements(compressionInputPtr);
				
				myInputPtr = oldInputPtr;

				if (printEnabled) writeln(elements);
			}
			else  // No compression pointer; Domain name is just a list of labels
			{
				if (input.length - myInputPtr < 1) { throw new dnsParserException(dnsParserResult.dataMissing); }	
				if (input[myInputPtr] != 0)        { throw new dnsParserException(dnsParserResult.specificationError); }	
				myInputPtr ++;
			}

		}  // readMultipleElements

		readMultipleElements(inputPtr);
		if (printEnabled) writefln("Input length: %d / %d", inputPtr, input.length);

		import std.string: join;
		return elements.join(".");		
	}  // readDomainName

	// ----------

	void parseQuery()
	{
		string parsedDomainName = readDomainName(input);
		myQuerySection.domainName = parsedDomainName;
		
		if (input.length - inputPtr < 4) { throw new dnsParserException(dnsParserResult.dataMissing); }	

		myQuerySection.queryType	= cast(ushort)(input[inputPtr+0]*256+input[inputPtr+1]);
		myQuerySection.queryClass	= cast(ushort)(input[inputPtr+2]*256+input[inputPtr+3]);
		if (printEnabled) writefln("Query type / class: %s / %s", myQuerySection.queryType, myQuerySection.queryClass);
		
		inputPtr += 4;	
	}  // parseQuery

	// ----------
	
	void parseResponse()
	{
		string parsedDomainName2 = readDomainName(input);
		if (printEnabled) writefln("Response domain name:  %s", parsedDomainName2);
		myResponseSection.domainName		= parsedDomainName2;

		if (input.length - inputPtr < 10) { throw new dnsParserException(dnsParserResult.dataMissing); }	

		myResponseSection.responseType		= cast(ushort)(input[inputPtr+0]*256+input[inputPtr+1]);
		myResponseSection.responseClass		= cast(ushort)(input[inputPtr+2]*256+input[inputPtr+3]);
		myResponseSection.TTL				= cast(uint)(input[inputPtr+4]*(256^3)+input[inputPtr+5]*(256^2)+input[inputPtr+6]*256+input[inputPtr+7]);
		myResponseSection.responseDataLength = cast(ushort)(input[inputPtr+8]*256+input[inputPtr+9]);

		if (printEnabled) writefln("Response type / class / TTL / datalength: %s / %s / %s / %s", myResponseSection.responseType, myResponseSection.responseClass, myResponseSection.TTL, myResponseSection.responseDataLength);
		
		inputPtr += 10;

		if (input.length - myResponseSection.responseDataLength < 1) { throw new dnsParserException(dnsParserResult.dataMissing); }		
		myResponseSection.responseData = input[inputPtr .. inputPtr + myResponseSection.responseDataLength].dup;

		ushort oldInputPtr = inputPtr;

		if (myResponseSection.responseType == dnsType.MX)
		{
			if (input.length - inputPtr < 2) { throw new dnsParserException(dnsParserResult.dataMissing); }	
			ushort priority = input[inputPtr]*256 + input[inputPtr+1];
			inputPtr += 2;
			import std.conv;
			myResponseSection.responseElements ~= to!string(priority);

			string parsedDomainName = readDomainName(input);
			myResponseSection.responseElements ~= parsedDomainName;

			myResponseSection.responseString = to!string(priority) ~ " " ~ parsedDomainName;
		}

		else if (myResponseSection.responseType == dnsType.TXT)
		{
			while(inputPtr < oldInputPtr + myResponseSection.responseDataLength) {
				string characterString = readCharacterString(input);
				myResponseSection.responseElements ~= characterString;
				myResponseSection.responseString ~= characterString;
			}
		}
		
		else if (myResponseSection.responseType == dnsType.CNAME 
			  || myResponseSection.responseType == dnsType.NS 
			  || myResponseSection.responseType == dnsType.DNAME 
			  || myResponseSection.responseType == dnsType.PTR 
		)
		{
			string parsedDomainName = readDomainName(input);
			myResponseSection.responseElements ~= parsedDomainName;
			myResponseSection.responseString = parsedDomainName;			
		}

		else if (myResponseSection.responseType == dnsType.A
			  || myResponseSection.responseType == dnsType.AAAA
		)
		{
			import std.algorithm.iteration;
			import std.conv;
			auto x = map!(to!string)(myResponseSection.responseData);
			import std.range;
			string[] xx = x.array();
			
			import std.string: join;
			string IPstring = xx.join(".");
			myResponseSection.responseElements ~= IPstring;

			myResponseSection.responseString = IPstring;
			
			if (myResponseSection.responseType == dnsType.A)
			{
				if (myResponseSection.responseDataLength != 4) { throw new dnsParserException(dnsParserResult.specificationError); }	
				
				inputPtr += 4;
			}
			else if (myResponseSection.responseType == dnsType.AAAA)
			{
				if (myResponseSection.responseDataLength != 8) { throw new dnsParserException(dnsParserResult.specificationError); }	
				inputPtr += 8;
			}
			else
			{
				assert(false);
			}
		}

		else if (myResponseSection.responseType == dnsType.SOA)
		{
			string parsedMNAME = readDomainName(input);		
			string parsedRNAME = readDomainName(input);
			uint serial		= readUINT32(input);
			uint refresh	= readUINT32(input);
			uint retry		= readUINT32(input);
			uint expire		= readUINT32(input);
			uint minimum	= readUINT32(input);
			
			myResponseSection.responseElements ~= [parsedMNAME, parsedRNAME, to!string(serial), to!string(refresh), to!string(retry), to!string(expire), to!string(minimum)];
			
			import std.format;
			myResponseSection.responseString = format!"%s %s %d %d %d %d %d"(parsedMNAME, parsedRNAME, serial, refresh, retry, expire, minimum);
		}

		else if (myResponseSection.responseType == dnsType.SRV)
		{
			uint priority	= readUINT16(input);
			uint weight		= readUINT16(input);
			uint port		= readUINT16(input);

			string parsedTarget = readDomainName(input);
			//string parsedtarget = readCharacterString(input);

			myResponseSection.responseElements ~= [to!string(priority), to!string(weight), to!string(port), parsedTarget];
			
			import std.format;
			myResponseSection.responseString = format!"%d %d %d %s"(priority, weight, port, parsedTarget);
		}

		else
		{
			assert(false);
		}

		ushort tempInputPtr = inputPtr;
		inputPtr = oldInputPtr;
		inputPtr += myResponseSection.responseDataLength;
		
		assert(tempInputPtr == inputPtr);

		import std.string: join;
		assert(myResponseSection.responseString == myResponseSection.responseElements.join(" "));

	}  // parseResponse

	// ----------

	if (printEnabled) writefln("Parsing header section: %d / %d", inputPtr, input.length);

	parseHeader();

	myDnsMessage.header = myDnsHeader;
	
	foreach (i; 0 .. myDnsMessage.header.QDCOUNT)
	{
		myQuerySection = querySection.init;
		if (printEnabled) writefln("Parsing query section %d: %d / %d", i, inputPtr, input.length);
		parseQuery();
		myDnsMessage.query ~= myQuerySection;
	}
	
	foreach (i; 0 .. myDnsMessage.header.ANCOUNT)
	{
		myResponseSection = responseSection.init;
		if (printEnabled) writefln("Parsing response section %d: %d / %d", i, inputPtr, input.length);
		parseResponse();
		myDnsMessage.answer ~= myResponseSection;
	}

	foreach (i; 0 .. myDnsMessage.header.NSCOUNT)
	{
		myResponseSection = responseSection.init;
		if (printEnabled) writefln("Parsing response section %d: %d / %d", i, inputPtr, input.length);
		parseResponse();
		myDnsMessage.authority ~= myResponseSection;
	}

	foreach (i; 0 .. myDnsMessage.header.ARCOUNT)
	{
		myResponseSection = responseSection.init;
		if (printEnabled) writefln("Parsing response section %d: %d / %d", i, inputPtr, input.length);
		parseResponse();
		myDnsMessage.additional ~= myResponseSection;
	}		

	if (printEnabled) writefln("Parsing done: %d / %d", inputPtr, input.length);
	if (input.length != inputPtr) return dnsParserResult.tooLarge;
  }  // try
  catch (dnsParserException e)
  {
	 parserResult = e.parserResult;
  }

  return parserResult;
}  // dnsParse

