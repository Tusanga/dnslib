module dnslib.aux;

import std.conv: to;

// ---------------------------------------------------------------------

ubyte[] readHexString(const string input)
{
	if(input.length % 2 != 0)
	{
		throw new Exception("readHexString input odd length");
	}
	
	bool ubyteOkay(ubyte ub)
	{
		return (48 <= ub && ub <= 57) || (65 <= ub && ub <= 70) || (97 <= ub && ub <= 102);
	}
	
	ubyte[] output;
	output.length = input.length / 2;
	uint j = 0;
	for (int i = 0; i < input.length; i += 2)
	{
		ubyte first  = input[i];
		ubyte second = input[i+1];

		if(!ubyteOkay(first) || !ubyteOkay(second))
		{
			throw new Exception("readHexString illegal char");
		}
		
		first  = to!ubyte(first >= 97 ? first - 87 : (first >= 65 ? first - 55 : first - 48));
		second = to!ubyte(second >= 97 ? second - 87 : (second >= 65 ? second - 55 : second - 48));
		
		output[j] = to!ubyte(16*first + second);
		j++;
	}
	
	assert(2*j == input.length);
	assert(1*j == output.length);
	
	return output;
}

unittest
{
  const string hexString = "00090a0f0A0F";
  ubyte[] byteArray = readHexString(hexString);
  assert(byteArray == [0,9,10,15,10,15]);
}

// ---------------------------------------------------------------------

// Simple check for legal domain name elements (including underscore in accordance RFC 2872)
bool noIllegalCharacters(ref string s)
{
	if ((s.length == 0) || (s[0] == '-') || (s[$-1] == '-'))
	{
		return false;
	}
	
	import std.regex;
	auto rx = ctRegex!(r"^(?:_|[_0-9a-zA-Z-](?:[0-9a-zA-Z-]{1,63})?(?<=[0-9a-zA-Z]))$");  // Length requirement (64) can be tightened.

	auto capture = matchFirst(s, rx);
	return (!capture.empty);  		
}

unittest
{
	string s = "";
	assert(!noIllegalCharacters(s));

	s = "a";
	assert( noIllegalCharacters(s));

	s = "1";
	assert( noIllegalCharacters(s));

	s = "-";
	assert(!noIllegalCharacters(s));

	s = "a-1";
	assert( noIllegalCharacters(s));

	s = "-a1";
	assert(!noIllegalCharacters(s));

	s = "_a1";
	assert( noIllegalCharacters(s));

	s = "_a_1";
	assert(!noIllegalCharacters(s));

	s = "a1-";
	assert(!noIllegalCharacters(s));

	s = "a1_";
	assert(!noIllegalCharacters(s));

	s = "0123456789012345678901234567890123456789012345678901234567890123";
	assert( noIllegalCharacters(s));

	s = "01234567890123456789012345678901234567890123456789012345678901234";
	assert(!noIllegalCharacters(s));

	s = "yahoo";
	assert( noIllegalCharacters(s));

	s = "com";
	assert( noIllegalCharacters(s));

}
