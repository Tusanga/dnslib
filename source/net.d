module dnslib.net;

import dnslib.defs;

import vibe.core.net;

import std.stdio;
import std.datetime.stopwatch;

import core.time:             Duration, seconds;
import std.datetime.systime:  SysTime, Clock;
import std.datetime.date:     DateTime;

immutable UDP_REQUEST_DATA_SIZE_LIMIT = 500;

version = ENABLE_EXCEPTION_PRINTING;

// ---------------------------------------------------------------------

enum dnsQueryResult : ubyte
{
  success = 0,
  requestTooLarge,
  connectionFailure,
  certificateFailure,
  timeout,
  dataMissing,
  tlsConfigurationError,
  idMismatch
} // enum dnsQueryResult

struct DnsNetConfig
{
  Protocol    protocol        = Protocol.udptcp;
  uint        udpSizeLimit    = UDP_REQUEST_DATA_SIZE_LIMIT;

  string      server          = "127.0.0.1";
  string      serverName      = "";

  bool        trusted         = false;
  string      trustedCertificateFile  = "/etc/ssl/certs/ca-certificates.crt";

  ushort      udpTcpPort      =  53;
  ushort      tlsPort         = 853;

  core.time.Duration  timeout = 10.seconds;
} // struct DnsNetConfig

// All dummy values that should never appear when running query function
struct DnsNetStat
{
  ulong       requestSize     = 0;
  ulong       responseSize    = 0;

  Protocol    protocol        = Protocol.none;
  string      server          = "";

  bool        trusted         = false;

  ushort      port            = 0;

  DateTime    timestamp       = DateTime(1, 1, 1, 0, 0, 0);
  ulong       duration        = 0;

  string toString()
  {
    import std.string: leftJustify;
    static import std.ascii;
    import std.array:  join;

    string[] resultArray = [];
    import std.conv: to, text;
    import std.traits;
    const auto b = FieldNameTuple!DnsNetStat;

    static foreach(element; b)
    {
      mixin("resultArray ~= leftJustify(element, 23, ' ') ~ \": \"  ~ this." ~ element ~ ".text() ~ std.ascii.newline; ");
    }

    string s = resultArray.join();
    return s;
  } // toString

} // struct DnsNetStat

// ---------------------------------------------------------------------

// Function query(...) also checks for matching IDs. This is not the case with functions udpQuery, tcpQuery and tlsQuery
dnsQueryResult query(ref DnsNetConfig netConfig, const ref ubyte[] requestData, ref ubyte[] responseData, out DnsNetStat netStat)
{
  auto result = dnsQueryResult.success;

  final switch(netConfig.protocol)
  {
    case Protocol.udp:
                result = udpQuery(netConfig, requestData, responseData, netStat);
                break;

    case Protocol.tcp:
                result = tcpQuery(netConfig, requestData, responseData, netStat);
                break;

    case Protocol.udptcp:
                if (requestData.length <= netConfig.udpSizeLimit)
                {
                  result = udpQuery(netConfig, requestData, responseData, netStat);
                }
                else
                {
                  result = tcpQuery(netConfig, requestData, responseData, netStat);
                }
                break;

  version(ENABLE_TLS)
  {
    case Protocol.tls:
                result = tlsQuery(netConfig, requestData, responseData, netStat);
                break;

    case Protocol.tlstcp:
                result = tlsQuery(netConfig, requestData, responseData, netStat);
                if (result != dnsQueryResult.success)
                {
                  result = tcpQuery(netConfig, requestData, responseData, netStat);
                }
                break;
  } // version(ENABLE_TLS)

    case Protocol.none:
                assert(false);
  }

  if (result == dnsQueryResult.success)
  {
    if (requestData.length < 2 || responseData.length < 2 || requestData[0..1] != responseData[0..1])
    {
      result = dnsQueryResult.idMismatch;
    }
  }

  return result;
} // query

// ---------------------------------------------------------------------

dnsQueryResult udpQuery(ref DnsNetConfig netConfig, const ref ubyte[] requestData, ref ubyte[] responseData, out DnsNetStat netStat)
{
  netStat.requestSize   = requestData.length;
  netStat.protocol      = Protocol.udp;
  netStat.server        = netConfig.server;
  netStat.port          = netConfig.udpTcpPort;
  netStat.timestamp     = cast(DateTime)(Clock.currTime());

  auto sw               = StopWatch(AutoStart.yes);

  scope(exit)
  {
    netStat.responseSize  = responseData.length;
    netStat.duration    = sw.peek().total!"msecs";
  }

  if (requestData.length > netConfig.udpSizeLimit)
  {
    return dnsQueryResult.requestTooLarge;
  }

  UDPConnection myUdpConnection;

  try
  {

    myUdpConnection = listenUDP(0);
    myUdpConnection.connect(netConfig.server, netConfig.udpTcpPort);
    myUdpConnection.send(requestData);
  }
  catch (Exception e)
  {
    return dnsQueryResult.connectionFailure;
  }

  ubyte[] buf = null;

  try
  {
    responseData = myUdpConnection.recv(netConfig.timeout, buf);
  }
  catch (Exception e)
  {
    return dnsQueryResult.timeout;
  }

  try
  {
    myUdpConnection.close();
  }
  catch (Exception e)
  {
    return dnsQueryResult.connectionFailure;
  }

  return dnsQueryResult.success;
} // udpQuery

// ---------------------------------------------------------------------

dnsQueryResult tcpQuery(ref DnsNetConfig netConfig, const ref ubyte[] requestData, ref ubyte[] responseData, out DnsNetStat netStat)
{
  netStat.requestSize   = requestData.length;
  netStat.protocol      = Protocol.tcp;
  netStat.server        = netConfig.server;
  netStat.port          = netConfig.udpTcpPort;
  netStat.timestamp     = cast(DateTime)(Clock.currTime());

  auto sw               = StopWatch(AutoStart.yes);

  scope(exit)
  {
    netStat.responseSize  = responseData.length;
    netStat.duration      = sw.peek().total!"msecs";
  }

  TCPConnection myTcpConnection;

  try
  {
    netStat.server                  = netConfig.server;

    immutable string bind_interface = null;
    immutable ushort bind_port      = cast(ushort)0u;

    myTcpConnection = connectTCP(netConfig.server, netConfig.udpTcpPort, bind_interface, bind_port, netConfig.timeout);
  }
  catch (Exception e)
  {
    return dnsQueryResult.connectionFailure;
  }

  scope(exit)
  {
    myTcpConnection.close();
  }

  if (!myTcpConnection.connected) return dnsQueryResult.connectionFailure;

  static import std.conv;
  ushort requestLength = std.conv.to!ushort(requestData.length);

  ubyte hi = requestLength / 256;
  ubyte lo = requestLength % 256;
  ubyte[] temp = [hi, lo];

  try
  {
    myTcpConnection.write(temp);
    myTcpConnection.write(requestData);
    myTcpConnection.flush();
  }
  catch (Exception e)
  {
    return dnsQueryResult.connectionFailure;
  }

  ushort bufferSize;

  try
  {
    if(myTcpConnection.waitForData(netConfig.timeout))
    {
      if (myTcpConnection.leastSize < 2) return dnsQueryResult.timeout;

      ubyte[2] size;
      myTcpConnection.read(size);

      bufferSize = size[0]*256 + size[1];
    }
    else
    {
      if (!myTcpConnection.connected) return dnsQueryResult.connectionFailure;

      return dnsQueryResult.timeout;
    }

    ubyte[] buffer = new ubyte[](bufferSize);

    if(myTcpConnection.waitForData(netConfig.timeout))
    {
      if (myTcpConnection.leastSize < bufferSize) return dnsQueryResult.dataMissing;

      // ToDo: This can be improved. What if octets come in several batches and time for last batch exceeds dnsTimeout limit?
      myTcpConnection.read(buffer);

      if (buffer.length < bufferSize) return dnsQueryResult.dataMissing;
    }
    else
    {
      if (!myTcpConnection.connected) return dnsQueryResult.connectionFailure;

      return dnsQueryResult.timeout;
    }

    responseData = buffer;
  }
  catch (Exception e)
  {
    return dnsQueryResult.connectionFailure;
  }

  return dnsQueryResult.success;
} // tcpQuery

// ---------------------------------------------------------------------

version(ENABLE_TLS)
{
  import vibe.stream.tls;
  import vibe.stream.wrapper;


dnsQueryResult tlsQuery(ref DnsNetConfig netConfig, const ref ubyte[] requestData, ref ubyte[] responseData, out DnsNetStat netStat)
{
  netStat.requestSize   = requestData.length;
  netStat.protocol      = Protocol.tls;
  netStat.server        = netConfig.server;
  netStat.trusted       = netConfig.trusted;

  netStat.port          = netConfig.tlsPort;
  netStat.timestamp     = cast(DateTime)(Clock.currTime());

  auto sw               = StopWatch(AutoStart.yes);

  scope(exit)
  {
    netStat.responseSize  = responseData.length;
    netStat.duration      = sw.peek().total!"msecs";
  }

  TCPConnection myTcpConnection;
  scope(exit)
  {
    if (myTcpConnection.connected)
    {
      myTcpConnection.flush();
      myTcpConnection.finalize();
      myTcpConnection.close();
    }
  }

  TLSStream connStream = null;

  scope(exit)
  {
    if (connStream !is null)
    {
        connStream.finalize();
    }
  }

  ConnectionProxyStream connProxStr = null;

  scope(exit)
  {
    if (connProxStr !is null)
    {
        connProxStr.finalize();
        connProxStr.close();
    }
  }

  auto tlsCtx = createTLSContext(TLSContextKind.client, TLSVersion.tls1_2);

  if (netConfig.trusted)
  {
    if (netConfig.serverName == "" || netConfig.trustedCertificateFile == "")
    {
      return dnsQueryResult.tlsConfigurationError;
    }
    // TLSPeerValidationMode.checkCert|requireCert forces:
    // 1) Require the peer to always present a certificate.
    // 2) Check the certificate for basic validity.
    // 3) Validate the actual peer name/address against the certificate.
    // 4) Requires that the certificate or any parent certificate is trusted.
    // Note: trustedCert = validCert + checkTrust
    tlsCtx.peerValidationMode = TLSPeerValidationMode.trustedCert;                    // FULL CHECK OF CERTIFICATE
    tlsCtx.useTrustedCertificateFile(netConfig.trustedCertificateFile);
  }

  // netConfig.trusted == false && netConfig.serverName != ""
  else if (netConfig.serverName != "")
  {
    // TLSPeerValidationMode.validCert forces:
    // 1) Require the peer to always present a certificate.
    // 2) Check the certificate for basic validity.
    // 3) Validate the actual peer name/address against the certificate.
    // Note: validCert = requireCert + checkCert + checkPeer
    tlsCtx.peerValidationMode = TLSPeerValidationMode.validCert;                    // ONLY BASIC CHECK AND VALIDATION OF CERTIFICATE
  }

  // netConfig.trusted == false and netConfig.serverName == ""
  else
  {
    // TLSPeerValidationMode.requireCert|checkCert forces:
    // 1) Require the peer to always present a certificate.
    // 2) Check the certificate for basic validity.
    tlsCtx.peerValidationMode = TLSPeerValidationMode.requireCert | TLSPeerValidationMode.checkCert;  // ONLY BASIC CHECK OF CERTIFICATE
  }

  //tlsCtx.useTrustedCertificateFile(netConfig.trustedCertificateFile);

  try
  {
    netStat.server = netConfig.server;

    immutable string bind_interface = null;
    immutable ushort bind_port      = cast(ushort)0u;
    myTcpConnection         = connectTCP(netConfig.server, netConfig.tlsPort, bind_interface, bind_port, netConfig.timeout);
  }
  catch(Exception e)
  {
    version(ENABLE_EXCEPTION_PRINTING)
    {
      writefln("Error in tlsQuery -> connectTCP : %s ; %s ; %s", e.msg, e.file, e.line);
    }
    return dnsQueryResult.connectionFailure;
  }

  try
  {
    connStream    = createTLSStream(myTcpConnection, tlsCtx, netConfig.serverName);
  }
  catch(Exception e)
  {
    version(ENABLE_EXCEPTION_PRINTING)
    {
      writefln("Error in tlsQuery -> createTLSStream : %s ; %s ; %s", e.msg, e.file, e.line);
    }
    return dnsQueryResult.certificateFailure;
  }

  try
  {
    connProxStr = vibe.stream.wrapper.createConnectionProxyStream(connStream, myTcpConnection);
  }
  catch(Exception e)
  {
    version(ENABLE_EXCEPTION_PRINTING)
    {
      writefln("Error in tlsQuery -> createConnectionProxyStream : %s ; %s ; %s", e.msg, e.file, e.line);
    }
    return dnsQueryResult.connectionFailure;
  }

  if (connStream is null || connProxStr is null)
  {
    version(ENABLE_EXCEPTION_PRINTING)
    {
      writeln("Error in tlsQuery; connStream or connProxStr is null");
    }
    return dnsQueryResult.connectionFailure;
  }

  if (!myTcpConnection.connected) return dnsQueryResult.connectionFailure;

  static import std.conv;
  ushort requestLength = std.conv.to!ushort(requestData.length);

  ubyte hi = requestLength / 256;
  ubyte lo = requestLength % 256;
  ubyte[] temp = [hi, lo];

  try
  {
    connProxStr.write(temp);
    connProxStr.write(requestData);
    connProxStr.flush();
  }
  catch (Exception e)
  {
    return dnsQueryResult.connectionFailure;
  }

  ushort bufferSize;

  if(myTcpConnection.waitForData(netConfig.timeout))
  {
    if (myTcpConnection.leastSize < 2) return dnsQueryResult.timeout;

    ubyte[2] size;
    connProxStr.read(size);

    bufferSize = size[0]*256 + size[1];
  }
  else
  {
    if (!connProxStr.connected) return dnsQueryResult.connectionFailure;

    return dnsQueryResult.timeout;
  }

  ubyte[] buffer = new ubyte[](bufferSize);

  if(connProxStr.waitForData(netConfig.timeout))
  {
    if (connProxStr.leastSize < bufferSize) return dnsQueryResult.dataMissing;

    // ToDo: This can be improved. What if octets come in several batches and time for last batch exceeds dnsTimeout limit?
    connProxStr.read(buffer);

    if (buffer.length < bufferSize) return dnsQueryResult.dataMissing;
  }
  else
  {
    if (!connProxStr.connected) return dnsQueryResult.connectionFailure;

    return dnsQueryResult.timeout;
  }

  responseData = buffer;

  return dnsQueryResult.success;
} // tlsQuery

}  // version(ENABLE_TLS)
