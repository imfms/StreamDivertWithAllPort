#include "stdafx.h"
#include "InboundTCPDivertProxy.h"
#include "utils.h"
#include "windivert.h"
#include <ws2tcpip.h>
#include "sockutils.h"


InboundTCPDivertProxy::InboundTCPDivertProxy(bool verbose, const UINT16 localPort, const std::vector<InboundRelayEntry>& proxyRecords)
	: BaseProxy(verbose),
	socksServer(0)
{	
	this->localPort = localPort;
	this->localProxyPort = 0;
	this->proxyRecords = proxyRecords;
	this->proxySock = NULL;
	this->selfDescStr = this->getStringDesc();
	this->containsSocksRecords = false;
}

InboundTCPDivertProxy::~InboundTCPDivertProxy()
{
}

bool InboundTCPDivertProxy::Start()
{
	WSADATA wsa_data;
	WORD wsa_version = MAKEWORD(2, 2);
	int on = 1;
	int off = 0;
	struct sockaddr_in6 addr;

	//lock scope
	{
		std::lock_guard<std::recursive_mutex> lock(this->resourceLock);
		this->logInfo("Start");

		if (WSAStartup(wsa_version, &wsa_data) != 0)
		{
			this->logError("failed to start WSA (%d)", GetLastError());
			goto failure;
		}
		this->proxySock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
		if (this->proxySock == INVALID_SOCKET)
		{
			this->logError("failed to create socket (%d)", WSAGetLastError());
			goto failure;
		}
		if (setsockopt(this->proxySock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(int)) == SOCKET_ERROR)
		{
			this->logError("failed to re-use address (%d)", GetLastError());
			goto failure;
		}
		if (setsockopt(this->proxySock, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&off, sizeof(int)) == SOCKET_ERROR)
		{
			this->logError("failed to set socket dual-stack (%d)", GetLastError());
			goto failure;
		}
		memset(&addr, 0, sizeof(addr));
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(0);
		addr.sin6_addr = in6addr_any;
		//inet_pton(AF_INET6, "::1", &addr.sin6_addr);
		if (::bind(this->proxySock, (SOCKADDR *)&addr, sizeof(addr)) == SOCKET_ERROR)
		{
			this->logError("failed to bind socket (%d)", WSAGetLastError());
			goto failure;
		}

		struct sockaddr_in6 bind_addr;
		int bind_addr_len = sizeof(bind_addr);
		if (getsockname(this->proxySock, (struct sockaddr *)&bind_addr, &bind_addr_len) == -1)
		{
			this->logError("failed to get bind socket port (%d)", WSAGetLastError());
		}
		this->localProxyPort = ntohs(bind_addr.sin6_port);
		this->selfDescStr = this->getStringDesc();

		if (listen(this->proxySock, 16) == SOCKET_ERROR)
		{
			this->logError("failed to listen socket (%d)",  WSAGetLastError());
			goto failure;
		}

		for each (auto record in this->proxyRecords)
		{
			if (record.type == InboundRelayEntryType::Socks)
			{
				this->socksServer.Start();
				containsSocksRecords = true;
				break;
			}
		}

		BaseProxy::Start();
	}//lock scope

	this->proxyThread = std::thread(&InboundTCPDivertProxy::ProxyWorker, this);
	return true;

failure:
	this->Stop();
	return false;
}


std::string InboundTCPDivertProxy::getStringDesc()
{
	std::string result = std::string("InboundTCPDivertProxy(" + std::to_string(this->localPort) + ":");
	if (this->localProxyPort == 0)
	{
		result += "?";
	}
	else
	{
		result += std::to_string(this->localProxyPort);
	}
	result += ")";
	return result;
}

PacketAction InboundTCPDivertProxy::ProcessTCPPacket(unsigned char* packet, UINT& packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_TCPHDR tcp_hdr, IpAddr& srcAddr, IpAddr& dstAddr)
{
	if (!addr->Outbound)
	{
		for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
		{
			// Skip processing if this is a connection TO or FROM the forward destination (prevents loops)
			if (dstAddr == record->forwardAddr || srcAddr == record->forwardAddr)
			{
				this->logDebug("Skipping packet to/from forward destination: %s -> %s", srcAddr.to_string().c_str(), dstAddr.to_string().c_str());
				continue;
			}
			
			bool srcMatches = (srcAddr == record->srcAddr || record->srcAddr == anyIpAddr || 
							   (record->srcAddr.isNetworkAddress() && srcAddr.isInSubnet(record->srcAddr, record->srcAddr.getNetworkPrefixLength())));
			bool portMatches = false;
			
			if (record->wildcardPort)
			{
				// Wildcard port matches any port
				portMatches = true;
			}
			else
			{
				// Specific port must match
				portMatches = (tcp_hdr->DstPort == htons(this->localPort));
			}
			
			if (srcMatches && portMatches)
			{
				std::string dstAddrStr = dstAddr.to_string();
				
				// For wildcard port, store the mapping of client to original dest port
				if (record->wildcardPort)
				{
					std::string clientKey = srcAddr.to_string() + ":" + std::to_string(ntohs(tcp_hdr->SrcPort));
					std::lock_guard<std::mutex> lock(this->portMapMutex);
					PortMappingEntry entry = { ntohs(tcp_hdr->DstPort), std::chrono::steady_clock::now() };
					this->clientToOriginalPortMap[clientKey] = entry;
				}
				
				if (record->type == InboundRelayEntryType::Divert)
				{
					this->logDebug("Modify packet dst -> %s:%hu", dstAddrStr.c_str(), this->localProxyPort);
					tcp_hdr->DstPort = htons(this->localProxyPort);
					break;
				}
				else if (record->type == InboundRelayEntryType::Socks)
				{
					int socksPort = this->socksServer.GetPort();
					this->logDebug("Modify packet dst -> %s:%hu", dstAddrStr.c_str(), socksPort);
					tcp_hdr->DstPort = htons(socksPort);
					break;
				}
			}
		}
	}
	else
	{
		for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
		{
			// Skip processing outbound connections TO or FROM the forward destination (prevents loops)
			// This catches proxy's own connections to the target server
			if (dstAddr == record->forwardAddr || srcAddr == record->forwardAddr)
			{
				this->logDebug("Skipping outbound packet to/from forward destination: %s -> %s", srcAddr.to_string().c_str(), dstAddr.to_string().c_str());
				continue;
			}
			
			if ((dstAddr == record->srcAddr || record->srcAddr == anyIpAddr || 
				 (record->srcAddr.isNetworkAddress() && dstAddr.isInSubnet(record->srcAddr, record->srcAddr.getNetworkPrefixLength()))))
			{
				if (
					(record->type == InboundRelayEntryType::Divert && tcp_hdr->SrcPort == htons(this->localProxyPort) ) ||
					(record->type == InboundRelayEntryType::Socks && tcp_hdr->SrcPort == htons(this->socksServer.GetPort()))
					)
				{
					std::string srcAddrStr = srcAddr.to_string();
					if (record->wildcardPort)
					{
						// For wildcard port, we need to get the original dest port from the connection mapping
						// Note: In outbound packets, dstAddr is the original client, tcp_hdr->DstPort is the original client port
						std::string clientKey = dstAddr.to_string() + ":" + std::to_string(ntohs(tcp_hdr->DstPort));
						std::lock_guard<std::mutex> lock(this->portMapMutex);
						auto it = this->clientToOriginalPortMap.find(clientKey);
						if (it != this->clientToOriginalPortMap.end())
						{
							UINT16 originalPort = it->second.originalPort;
							this->logDebug("Modify packet src -> %s:%hu (restored from wildcard)", srcAddrStr.c_str(), originalPort);
							tcp_hdr->SrcPort = htons(originalPort);
						}
						else
						{
							// Fallback: try to find any mapping for this client IP
							std::string clientIP = dstAddr.to_string();
							UINT16 foundPort = 0;
							for (auto& mapping : this->clientToOriginalPortMap)
							{
								if (mapping.first.find(clientIP + ":") == 0)
								{
									foundPort = mapping.second.originalPort;
									break;
								}
							}
							if (foundPort > 0)
							{
								this->logDebug("Modify packet src -> %s:%hu (restored from wildcard fallback)", srcAddrStr.c_str(), foundPort);
								tcp_hdr->SrcPort = htons(foundPort);
							}
							else
							{
								this->logDebug("Modify packet src -> %s (wildcard port - no mapping found)", srcAddrStr.c_str());
							}
						}
					}
					else
					{
						this->logDebug("Modify packet src -> %s:%hu", srcAddrStr.c_str(), this->localPort);
						tcp_hdr->SrcPort = htons(this->localPort);
					}
					break;
				}				
			}
		}
	}
	return PacketAction::STATUS_PROCEED;
}

void InboundTCPDivertProxy::ProxyWorker()
{	
	while (true)
	{
		struct sockaddr_in6  clientSockAddr;
		int size = sizeof(clientSockAddr);
		SOCKET incommingSock = accept(this->proxySock, (SOCKADDR *)&clientSockAddr, &size);
		if (incommingSock == INVALID_SOCKET)
		{
			std::lock_guard<std::recursive_mutex> lock(this->resourceLock);
			if (this->running == false)
			{
				goto cleanup;
			}
			this->logWarning("failed to accept socket (%d)", WSAGetLastError());
			continue;
		}
		IpAddr clientSockIp = IpAddr(clientSockAddr.sin6_addr);
		std::string srcAddr = clientSockIp.to_string();
		this->logInfo("Incoming connection from %s:%hu", srcAddr.c_str(), ntohs(clientSockAddr.sin6_port));
		ProxyConnectionWorkerData* proxyConnectionWorkerData = new ProxyConnectionWorkerData();
		proxyConnectionWorkerData->clientSock = incommingSock;
		proxyConnectionWorkerData->clientAddr = clientSockAddr;
		
		// Look up original destination port for wildcard entries
		std::string clientKey = clientSockIp.to_string() + ":" + std::to_string(ntohs(clientSockAddr.sin6_port));
		{
			std::lock_guard<std::mutex> lock(this->portMapMutex);
			auto it = this->clientToOriginalPortMap.find(clientKey);
			if (it != this->clientToOriginalPortMap.end())
			{
				proxyConnectionWorkerData->originalDestPort = it->second.originalPort;
				// 注意：不要在这里删除映射，等连接结束后再清理
				// this->clientToOriginalPortMap.erase(it); // 移除这行
			}
			else
			{
				proxyConnectionWorkerData->originalDestPort = this->localPort; // Default to configured port
			}
		}
		try {
			std::thread proxyConnectionThread(&InboundTCPDivertProxy::ProxyConnectionWorker, this, proxyConnectionWorkerData);
			proxyConnectionThread.detach();
		}
		catch (...) {
			this->logError("Failed to create proxy connection thread");
			delete proxyConnectionWorkerData;
			closesocket(incommingSock);
		}
	}
cleanup:
	if (this->proxySock != NULL)
	{
		closesocket(this->proxySock);
		this->proxySock = NULL;
	}
	this->logInfo("ProxyWorker exiting");
}

void InboundTCPDivertProxy::ProxyConnectionWorker(ProxyConnectionWorkerData* proxyConnectionWorkerData)
{
	int off = 0;
	SOCKET destSock = NULL;
	
	// 防御性编程 - 检查空指针
	if (!proxyConnectionWorkerData) {
		this->logError("ProxyConnectionWorkerData is null");
		return;
	}
	
	SOCKET clientSock = proxyConnectionWorkerData->clientSock;
	sockaddr_in6 clientSockAddr = proxyConnectionWorkerData->clientAddr;
	IpAddr clientSockIp = IpAddr(clientSockAddr.sin6_addr);
	UINT16 originalDestPort = proxyConnectionWorkerData->originalDestPort;
	delete proxyConnectionWorkerData;
	proxyConnectionWorkerData = nullptr;  // 防止重复使用

	std::string selfDesc = this->getStringDesc();

	InboundRelayEntry proxyRecord;
	UINT16 clientSrcPort = ntohs(clientSockAddr.sin6_port);
	std::string srcAddr = clientSockIp.to_string();
	bool lookupSuccess = this->findProxyRecordBySrcAddr(clientSockIp, proxyRecord);
	if (lookupSuccess)
	{
		struct sockaddr_in6 destAddr;
		ZeroMemory(&destAddr, sizeof(destAddr));
		destAddr.sin6_family = AF_INET6;
		destAddr.sin6_addr = proxyRecord.forwardAddr.get_addr();
		
		// Use original port if passthrough is enabled, otherwise use configured forward port
		UINT16 destPort = proxyRecord.passthroughPort ? originalDestPort : proxyRecord.forwardPort;
		destAddr.sin6_port = htons(destPort);
		destSock = socket(AF_INET6, SOCK_STREAM, 0);
		if (destSock == INVALID_SOCKET)
		{
			this->logError("failed to create socket (%d)", WSAGetLastError());
			goto cleanup;
		}
		if (setsockopt(destSock, IPPROTO_IPV6, IPV6_V6ONLY, (const char*)&off, sizeof(int)) == SOCKET_ERROR)
		{
			this->logError("failed to set connect socket dual-stack (%d)", GetLastError());
			goto cleanup;
		}
		std::string forwardAddr = proxyRecord.forwardAddr.to_string();
		this->logInfo("Connecting to forward host %s:%hu", forwardAddr.c_str(), destPort);
		if (connect(destSock, (SOCKADDR *)&destAddr, sizeof(destAddr)) == SOCKET_ERROR)
		{
			this->logError("failed to connect socket (%d)", WSAGetLastError());
			goto cleanup;
		}

		this->logInfo("Starting to route %s:%hu -> %s:%hu", srcAddr.c_str(), clientSrcPort, forwardAddr.c_str(), destPort);
		ProxyTunnelWorkerData* tunnelDataA = new ProxyTunnelWorkerData();
		ProxyTunnelWorkerData* tunnelDataB = new ProxyTunnelWorkerData();
		tunnelDataA->sockA = clientSock;
		tunnelDataA->sockAAddr = clientSockIp;
		tunnelDataA->sockAPort = clientSrcPort;
		tunnelDataA->sockB = destSock;
		tunnelDataA->sockBAddr = proxyRecord.forwardAddr;
		tunnelDataA->sockBPort = proxyRecord.forwardPort;

		tunnelDataB->sockA = destSock;
		tunnelDataB->sockAAddr = proxyRecord.forwardAddr;
		tunnelDataB->sockAPort = proxyRecord.forwardPort;
		tunnelDataB->sockB = clientSock;
		tunnelDataB->sockBAddr = clientSockIp;
		tunnelDataB->sockBPort = clientSrcPort;
		std::thread tunnelThread(&ProxyTunnelWorker, tunnelDataA, this->selfDescStr);
		ProxyTunnelWorker(tunnelDataB, this->selfDescStr);
		tunnelThread.join();
	}

cleanup:
	if (clientSock != NULL)
		closesocket(clientSock);
	if (destSock != NULL)
		closesocket(destSock);

	// 清理端口映射
	std::string clientKey = srcAddr + ":" + std::to_string(clientSrcPort);
	{
		std::lock_guard<std::mutex> lock(this->portMapMutex);
		auto it = this->clientToOriginalPortMap.find(clientKey);
		if (it != this->clientToOriginalPortMap.end())
		{
			this->logDebug("Cleaning up port mapping for %s", clientKey.c_str());
			this->clientToOriginalPortMap.erase(it);
		}
	}

	this->logInfo("ProxyConnectionWorker exiting for client %s:%hu", srcAddr.c_str(), clientSrcPort);
	return;
}

std::string InboundTCPDivertProxy::generateDivertFilterString()
{
	std::string result = "tcp";
	std::vector<std::string> orExpressions;
	std::string proxyFilterStr = "(tcp.SrcPort == " + std::to_string(this->localProxyPort) + ")";
	orExpressions.push_back(proxyFilterStr);

	if (this->containsSocksRecords)
	{
		proxyFilterStr = "(tcp.SrcPort == " + std::to_string(this->socksServer.GetPort()) + ")";
		orExpressions.push_back(proxyFilterStr);
	}

	//check for wildcard address and wildcard port
	bool containsWildcard = false;
	bool containsWildcardPort = false;
	for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
	{
		if (record->wildcardPort)
		{
			containsWildcardPort = true;
		}
		if (record->srcAddr == anyIpAddr)
		{
			if (record->wildcardPort)
			{
				// For wildcard port with wildcard source, only capture inbound traffic
				// This prevents capturing the proxy's own outbound connections
				std::string recordFilterStr = "(inbound and tcp)";
				orExpressions.push_back(recordFilterStr);
			}
			else
			{
				// For specific port with wildcard address
				std::string recordFilterStr = "(tcp.DstPort == " + std::to_string(this->localPort) + ")";
				orExpressions.push_back(recordFilterStr);
			}
			containsWildcard = true;
			break;
		}
		else if (record->srcAddr.isNetworkAddress())
		{
			// Network address - create filter for the entire subnet with dynamic prefix
			std::string srcAddrIpStr = this->getIpAddrIpStr(record->srcAddr);
			int prefixLength = record->srcAddr.getNetworkPrefixLength();
			
			if (record->wildcardPort)
			{
				// For wildcard port with network address, exclude connections TO forward destinations
				// Use simplified filter for now - just capture all TCP, handle exclusion in code
				std::string recordFilterStr = "tcp";
				orExpressions.push_back(recordFilterStr);
			}
			else
			{
				// For specific port with network address, fall back to port-only for now
				std::string recordFilterStr = "(tcp.DstPort == " + std::to_string(this->localPort) + ")";
				orExpressions.push_back(recordFilterStr);
			}
			containsWildcard = true;
			break;
		}
	}

	if (!containsWildcard)
	{
		for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
		{
			std::string srcAddrIpStr = this->getIpAddrIpStr(record->srcAddr);

			if (record->wildcardPort)
			{
				// For wildcard port with specific source address
				std::string recordFilterStr = "(" + srcAddrIpStr + ".SrcAddr == " + record->srcAddr.to_string() + ")";
				orExpressions.push_back(recordFilterStr);
			}
			else
			{
				// For specific port with specific source address
				std::string recordFilterStr = "(tcp.DstPort == " + std::to_string(this->localPort) + " and " + srcAddrIpStr + ".SrcAddr == " + record->srcAddr.to_string() + ")";
				orExpressions.push_back(recordFilterStr);
			}
		}
	}

	result += " and (";
	joinStr(orExpressions, std::string(" or "), result);
	result += ")";
	return result;
}

bool InboundTCPDivertProxy::findProxyRecordBySrcAddr(IpAddr& srcAddr, InboundRelayEntry& proxyRecord)
{
	for (auto record = this->proxyRecords.begin(); record != this->proxyRecords.end(); ++record)
	{
		if (record->srcAddr == anyIpAddr)
		{
			// Wildcard match (0.0.0.0)
			proxyRecord = *record;
			return true;
		}
		else if (record->srcAddr == srcAddr)
		{
			// Exact IP match
			proxyRecord = *record;
			return true;
		}
		else if (record->srcAddr.isNetworkAddress())
		{
			// Subnet match - check if srcAddr is in the network defined by record->srcAddr
			int prefixLength = record->srcAddr.getNetworkPrefixLength();
			if (srcAddr.isInSubnet(record->srcAddr, prefixLength))
			{
				proxyRecord = *record;
				return true;
			}
		}
	}
	return false;
}

bool InboundTCPDivertProxy::Stop()
{	
	this->logInfo("Stop");
	{//lock scope
		std::lock_guard<std::recursive_mutex> lock(this->resourceLock);
		BaseProxy::Stop();
		if (this->proxySock != NULL)
		{
			shutdown(this->proxySock, SD_BOTH);
			closesocket(this->proxySock);
			this->proxySock = NULL;
		}
	}//lock scope

	if (this->proxyThread.joinable())
	{
		this->proxyThread.join();
	}
	if (this->socksServer.IsRunning())
	{
		return this->socksServer.Stop();
	}
	return true;
}

PacketAction InboundTCPDivertProxy::ProcessICMPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_ICMPHDR icmp_hdr, PWINDIVERT_ICMPV6HDR icmp6_hdr, IpAddr & srcAddr, IpAddr & dstAddr)
{
	return PacketAction::STATUS_PROCEED;
}

PacketAction InboundTCPDivertProxy::ProcessUDPPacket(unsigned char * packet, UINT & packet_len, PWINDIVERT_ADDRESS addr, PWINDIVERT_IPHDR ip_hdr, PWINDIVERT_IPV6HDR ip6_hdr, PWINDIVERT_UDPHDR udp_header, IpAddr & srcAddr, IpAddr & dstAddr)
{
	return PacketAction::STATUS_PROCEED;
}

