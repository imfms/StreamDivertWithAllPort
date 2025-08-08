#pragma once
#include <windows.h>
#include "ipaddr.h"
#include <vector>
#include <map>

enum InboundRelayEntryType
{
	None,
	Divert,
	Socks
};

struct InboundRelayEntry
{
	InboundRelayEntryType type;
	std::string protocol;
	UINT16 localPort;
	IpAddr srcAddr;
	IpAddr forwardAddr;
	UINT16 forwardPort;
	bool wildcardPort;      // true if using * for port matching
	bool passthroughPort;   // true if using * for forwarding port (keep original)
};

struct OutboundRelayEntry
{
	std::string protocol;
	IpAddr dstAddr;
	UINT16 dstPort;
	IpAddr forwardAddr;
	UINT forwardPort;
	UINT32 interfaceIdx;
	bool forceInterfaceIdx;
};



struct RelayConfig
{
	std::vector<InboundRelayEntry> inboundRelayEntries;
	std::vector<OutboundRelayEntry> outboundRelayEntries;
};

bool LoadConfig(std::string path, RelayConfig& result);
