#include "stdafx.h"
#include "config.h"
#include "utils.h"
#include <iostream>
#include <fstream>


bool LoadConfig(std::string path, RelayConfig& result)
{
	std::ifstream ifs((path));
	std::string line;	

	if (!ifs) {
		return false;
	}
	while (std::getline(ifs, line))
	{
		char proto[200] = { 0 };
		UINT16 localPort = 0;
		char srcAddr[200] = { 0 };
		char dstAddr[200] = { 0 };		
		UINT16 dstPort = 0;
		char forwardAddr[200] = { 0 };
		UINT16 forwardPort = 0;
		UINT32 interfaceIdx = -1;

		// Parse wildcard port syntax: tcp < * srcAddr -> forwardAddr *
		char localPortStr[10] = { 0 };
		char forwardPortStr[10] = { 0 };
		if (sscanf_s(line.c_str(), "%[a-z] < %s %s -> %s %s", &proto[0], _countof(proto), &localPortStr[0], _countof(localPortStr), &srcAddr[0], _countof(srcAddr), &forwardAddr[0], _countof(forwardAddr), &forwardPortStr[0], _countof(forwardPortStr)) == 5)
		{
			InboundRelayEntry entry;
			entry.type = InboundRelayEntryType::Divert;
			entry.protocol = std::string(proto);
			entry.srcAddr = IpAddr(srcAddr);
			entry.forwardAddr = IpAddr(forwardAddr);
			
			// Check for wildcard ports
			if (strcmp(localPortStr, "*") == 0)
			{
				entry.wildcardPort = true;
				entry.localPort = 0;  // Not used when wildcardPort is true
			}
			else
			{
				entry.wildcardPort = false;
				entry.localPort = (UINT16)atoi(localPortStr);
			}
			
			if (strcmp(forwardPortStr, "*") == 0)
			{
				entry.passthroughPort = true;
				entry.forwardPort = 0;  // Not used when passthroughPort is true
			}
			else
			{
				entry.passthroughPort = false;
				entry.forwardPort = (UINT16)atoi(forwardPortStr);
			}
			
			result.inboundRelayEntries.push_back(entry);
		}
		// Legacy syntax: tcp < port srcAddr -> forwardAddr forwardPort
		else if (sscanf_s(line.c_str(), "%[a-z] < %hu %s -> %s %hu", &proto[0], _countof(proto), &localPort, &srcAddr[0], _countof(srcAddr), &forwardAddr[0], _countof(forwardAddr), &forwardPort) == 5)
		{
			InboundRelayEntry entry;
			entry.type = InboundRelayEntryType::Divert;
			entry.protocol = std::string(proto);
			entry.localPort = localPort;
			entry.srcAddr = IpAddr(srcAddr);
			entry.forwardAddr = IpAddr(forwardAddr);
			entry.forwardPort = forwardPort;
			entry.wildcardPort = false;
			entry.passthroughPort = false;
			result.inboundRelayEntries.push_back(entry);			
		}
		else if (sscanf_s(line.c_str(), "%[a-z] < %hu %s -> socks", &proto[0], _countof(proto), &localPort, &srcAddr[0], _countof(srcAddr)) == 3)
		{
			InboundRelayEntry entry;
			entry.type = InboundRelayEntryType::Socks;
			entry.protocol = std::string(proto);
			entry.localPort = localPort;
			entry.srcAddr = IpAddr(srcAddr);			
			entry.wildcardPort = false;
			entry.passthroughPort = false;
			result.inboundRelayEntries.push_back(entry);
		}
		else if (sscanf_s(line.c_str(), "%[a-z] > %s %hu -> %s %hu force interface %u", &proto[0], _countof(proto), &dstAddr[0], _countof(dstAddr), &dstPort, &forwardAddr[0], _countof(forwardAddr), &forwardPort, &interfaceIdx) == 6)
		{
			OutboundRelayEntry entry;
			entry.protocol = std::string(proto);
			entry.dstAddr = IpAddr(dstAddr);
			entry.dstPort = dstPort;
			entry.forwardAddr = IpAddr(forwardAddr);
			entry.forwardPort = forwardPort;
			entry.interfaceIdx = interfaceIdx;
			entry.forceInterfaceIdx = true;
			result.outboundRelayEntries.push_back(entry);
		}
		else if (sscanf_s(line.c_str(), "%[a-z] > %s %hu -> %s %hu interface %u", &proto[0], _countof(proto), &dstAddr[0], _countof(dstAddr), &dstPort, &forwardAddr[0], _countof(forwardAddr), &forwardPort, &interfaceIdx) == 6)
		{
			OutboundRelayEntry entry;
			entry.protocol = std::string(proto);
			entry.dstAddr = IpAddr(dstAddr);
			entry.dstPort = dstPort;
			entry.forwardAddr = IpAddr(forwardAddr);
			entry.forwardPort = forwardPort;
			entry.interfaceIdx = interfaceIdx;
			entry.forceInterfaceIdx = false;
			result.outboundRelayEntries.push_back(entry);
		}
		else if(sscanf_s(line.c_str(), "%[a-z] > %s %hu -> %s %hu", &proto[0], _countof(proto), &dstAddr[0], _countof(dstAddr), &dstPort, &forwardAddr[0], _countof(forwardAddr), &forwardPort) == 5)
		{
			OutboundRelayEntry entry;
			entry.protocol = std::string(proto);
			entry.dstAddr = IpAddr(dstAddr);
			entry.dstPort = dstPort;
			entry.forwardAddr = IpAddr(forwardAddr);
			entry.forwardPort = forwardPort;
			entry.interfaceIdx = interfaceIdx;
			result.outboundRelayEntries.push_back(entry);			
		}		
		else if (sscanf_s(line.c_str(), "icmp < %s -> %s", &srcAddr[0], _countof(srcAddr), &forwardAddr[0], _countof(forwardAddr)) == 2)
		{
			InboundRelayEntry entry;
			entry.protocol = "icmp";
			entry.localPort = 0;
			entry.srcAddr = IpAddr(srcAddr);
			entry.forwardAddr = IpAddr(forwardAddr);
			entry.forwardPort = 0;
			entry.wildcardPort = false;
			entry.passthroughPort = false;
			result.inboundRelayEntries.push_back(entry);
		}
		else if (sscanf_s(line.c_str(), "icmp > %s -> %s", &dstAddr[0], _countof(dstAddr), &forwardAddr[0], _countof(forwardAddr)) == 2)
		{			
			OutboundRelayEntry entry;
			entry.protocol = "icmp";
			entry.dstAddr = IpAddr(dstAddr);
			entry.dstPort = 0;
			entry.forwardAddr = IpAddr(forwardAddr);
			entry.forwardPort = 0;
			result.outboundRelayEntries.push_back(entry);
		}		
	}
	return true;
}
