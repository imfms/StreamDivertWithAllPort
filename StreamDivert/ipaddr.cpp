#include "stdafx.h"
#include "ipaddr.h"
#include <cstring>
#include <ws2tcpip.h>
#include "utils.h"


void IpAddr::initIpv4(const in_addr & addr)
{
	memcpy(&this->m_addr.s6_addr[0], ipv4_mapped_prefix, sizeof(ipv4_mapped_prefix));
	memcpy(&this->m_addr.s6_addr[12], &addr.s_addr, sizeof(addr));
	this->init();
}

void IpAddr::initIpv6(const in6_addr & addr)
{
	this->m_addr = addr;
	this->init();
}

void IpAddr::init()
{
#if _DEBUG
	this->addrStr = this->to_string();
#endif
}

IpAddr::IpAddr()
{
	memset(&this->m_addr, 0, sizeof(in6_addr));
}

IpAddr::IpAddr(const in_addr& addr)
{
	this->initIpv4(addr);
}

IpAddr::IpAddr(const in6_addr& addr)
{
	this->initIpv6(addr);
}

IpAddr::IpAddr(const std::string & addrstr)
{
	struct in_addr addr;
	bool isipv4 = inet_pton(AF_INET, addrstr.c_str(), &addr) != 0;
	if (isipv4)
	{
		this->initIpv4(addr);
	}
	struct in6_addr addr6;
	bool isipv6 = inet_pton(AF_INET6, addrstr.c_str(), &addr6) != 0;
	if (isipv6)
	{
		this->initIpv6(addr6);
	}
}

IpAddr::~IpAddr()
{
}

IPFamily IpAddr::get_family() const
{
	if(memcmp(&this->m_addr.s6_addr[0], ipv4_mapped_prefix, sizeof(ipv4_mapped_prefix)) == 0)
	{
		return IPFamily::IPv4;
	}
	else
	{
		return IPFamily::IPv6;
	}
}

std::string IpAddr::to_string()
{
	std::string result;

	IPFamily ipfamily = this->get_family();
	if(ipfamily == IPFamily::IPv4)
	{
		result.resize(INET_ADDRSTRLEN);		
		const char* r = inet_ntop(AF_INET, &this->m_addr.s6_addr[12], &result[0], INET_ADDRSTRLEN);
		if (r == NULL)
		{
			error("Failed to convert ip to ipv4 address string!");
		}
	}
	else if(ipfamily == IPFamily::IPv6)
	{
		result.resize(INET6_ADDRSTRLEN);		
		const char* r = inet_ntop(AF_INET6, &this->m_addr, &result[0], INET6_ADDRSTRLEN);
		if (r == NULL)
		{
			error("Failed to convert ip to ipv6 address string!");
		}
	}
	result.resize(strlen(result.c_str()));
	return result;
}

in6_addr IpAddr::get_addr()
{
	return this->m_addr;
}

in_addr IpAddr::get_ipv4_addr() const
{
	return *(in_addr*)&this->m_addr.s6_addr[12];
}

bool IpAddr::operator==(const IpAddr& addr2)
{
	return memcmp(&this->m_addr, &addr2.m_addr, sizeof(in6_addr)) == 0;
}

bool IpAddr::operator==(const UINT32 & addr2)
{
	if (this->get_family() != IPFamily::IPv4)
	{
		return false;
	}
	return memcmp(&this->m_addr.s6_addr[12], &addr2, sizeof(in_addr)) == 0;
}

bool IpAddr::operator!=(const IpAddr& addr2)
{
	return ! (*this == addr2);
}

bool IpAddr::operator<(const IpAddr& addr2)
{
	return memcmp(&this->m_addr, &addr2.m_addr, sizeof(in6_addr)) < 0;
}

bool IpAddr::operator<=(const IpAddr& addr2)
{
	return *this < addr2 || *this == addr2;
}

bool IpAddr::operator>=(const IpAddr& addr2)
{
	return ! ( *this < addr2 );
}

bool IpAddr::operator>(const IpAddr& addr2)
{
	return ! ( *this <= addr2 );
}

bool IpAddr::isInSubnet(const IpAddr& networkAddr, int prefixLength) const
{
	if (this->get_family() != networkAddr.get_family())
	{
		return false;
	}

	if (this->get_family() == IPFamily::IPv4)
	{
		UINT32 thisAddr = ntohl(this->get_ipv4_addr().s_addr);
		UINT32 netAddr = ntohl(networkAddr.get_ipv4_addr().s_addr);
		
		// Create subnet mask
		UINT32 mask = 0xFFFFFFFF << (32 - prefixLength);
		
		// Check if both addresses are in the same subnet
		return (thisAddr & mask) == (netAddr & mask);
	}
	else
	{
		// IPv6 subnet matching (simplified for /64 subnets)
		// For full IPv6 support, would need more complex bit manipulation
		if (prefixLength <= 64)
		{
			int bytesToCompare = prefixLength / 8;
			int bitsInLastByte = prefixLength % 8;
			
			if (memcmp(&this->m_addr.s6_addr, &networkAddr.m_addr.s6_addr, bytesToCompare) != 0)
			{
				return false;
			}
			
			if (bitsInLastByte > 0)
			{
				UINT8 mask = 0xFF << (8 - bitsInLastByte);
				return (this->m_addr.s6_addr[bytesToCompare] & mask) == (networkAddr.m_addr.s6_addr[bytesToCompare] & mask);
			}
			return true;
		}
		return false;
	}
}

bool IpAddr::isNetworkAddress() const
{
	if (this->get_family() == IPFamily::IPv4)
	{
		UINT32 addr = ntohl(this->get_ipv4_addr().s_addr);
		// Check if it's a network address (any trailing zeros)
		// 192.0.0.0 (/8), 192.168.0.0 (/16), 192.168.200.0 (/24)
		return (addr & 0xFF) == 0;  // At least /24
	}
	else
	{
		// For IPv6, check if it ends with all zeros (simplified check)
		for (int i = 8; i < 16; i++)
		{
			if (this->m_addr.s6_addr[i] != 0)
			{
				return false;
			}
		}
		return true;
	}
}

int IpAddr::getNetworkPrefixLength() const
{
	if (this->get_family() == IPFamily::IPv4)
	{
		UINT32 addr = ntohl(this->get_ipv4_addr().s_addr);
		
		// Detect network class based on trailing zeros
		if ((addr & 0xFFFFFF) == 0)  // xxx.0.0.0
		{
			return 8;  // Class A (/8)
		}
		else if ((addr & 0xFFFF) == 0)  // xxx.xxx.0.0
		{
			return 16; // Class B (/16) 
		}
		else if ((addr & 0xFF) == 0)  // xxx.xxx.xxx.0
		{
			return 24; // Class C (/24)
		}
		else
		{
			return 32; // Host address
		}
	}
	else
	{
		// IPv6 simplified - assume /64 for network addresses
		return 64;
	}
}