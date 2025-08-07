//
//  fDNS.cpp
//  fDNS
//
//  Author: Sotiris Karagiannis
//
//  v0.66
//  Supported features:
//      - fDNS_Resolve(hostname {; timeoutMs}): Resolves a hostname to an IPv4 address.
//      - fDNS_Reverse(ipAddress {; timeoutMs}): Resolves an IPv4 address to a hostname.
//      - fDNS_Resolve_Extended(hostname {; timeoutMs}): Returns all DNS records (A, AAAA, CNAME, MX, TXT, NS, SRV, PTR, etc.) for a hostname as a JSON string.
//      - fDNS_Set_Server(dnsServer): Sets the DNS server to use for subsequent requests (empty string "" resets to system default).
//      - fDNS_Get_Systems_Server(): Returns the system's DNS server(s).
//      - fDNS_Get_Current_Server(): Returns the DNS server currently set in the plugin.
//      - fDNS_Initialize() / DNS_Uninitialize(): Initialize and cleanup the DNS subsystem (should be called at plugin load/unload).
//  Behavior:
//      - 3 seconds is the default timeout for DNS_Resolve, DNS_Reverse, and DNS_Resolve_Extended if not specified.
//      - If dnsServer is not specified or is empty (""), the system default DNS resolver is used.
//      - When using the system default DNS, the plugin uses the OS system resolver (getaddrinfo/getnameinfo), which works reliably on macOS, Linux, and Windows.
//      - When a custom DNS server is set, the plugin uses c-ares for DNS queries, supporting all record types.
//      - This hybrid approach ensures robust DNS resolution across platforms and avoids known c-ares/macOS issues.
//

#include "FMWrapper/FMXTypes.h"
#include "FMWrapper/FMXText.h"
#include "FMWrapper/FMXFixPt.h"
#include "FMWrapper/FMXData.h"
#include "FMWrapper/FMXCalcEngine.h"

#include <string>
#include <cstring>
#include <mutex>
#include <vector>
#include <netdb.h>
#include <ares.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <sys/select.h>
#include <unistd.h>

#define DEFAULT_TIMEOUT 3000

std::string DNSRecordsToJson(const std::string& hostname, const std::vector<std::pair<std::string, std::string>>& records)
{
	std::string json = "{\"hostname\":\"" + hostname + "\",\"records\":[";
	for (size_t i = 0; i < records.size(); ++i) {
		json += "{\"type\":\"" + records[i].first + "\",\"value\":\"" + records[i].second + "\"}";
		if (i + 1 < records.size()) json += ",";
	}
	json += "]}";
	return json;
}


std::string getString(const fmx::Text& text);
int GetIntFromDataVect(const fmx::DataVect& dataVect, fmx::uint32 position);

// DNS plugin state
static std::string g_currentDnsServer; // empty = system default
static bool g_dnsInitialized = false;
static std::mutex g_dnsMutex;
static ares_channel g_channel = nullptr;

// A function to convert fmx::Text to std::string (with a 512-byte buffer limit)
std::string getString(const fmx::Text& Text)
{
	char buffer[512] = {0}; // NOTE: string size limit
	Text.GetBytes(buffer, sizeof(buffer) - 1, 0, Text.GetSize(), fmx::Text::kEncoding_Native);
	return std::string(buffer);
}

// Use system resolver for default DNS (forward)
std::string resolve_with_system(const std::string& hostname) {
	struct addrinfo hints = {}, *res = nullptr;
	hints.ai_family = AF_INET;
	int err = getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
	if (err != 0 || !res) return "?";
	char ip[INET_ADDRSTRLEN] = {0};
	inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, ip, sizeof(ip));
	freeaddrinfo(res);
	return std::string(ip);
}

// Use system resolver for default DNS (reverse)
std::string reverse_with_system(const std::string& ipAddress) {
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	if (inet_pton(AF_INET, ipAddress.c_str(), &sa.sin_addr) != 1)
		return "?";
	char host[NI_MAXHOST] = {0};
	int err = getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), nullptr, 0, NI_NAMEREQD);
	if (err != 0)
		return "?";
	return std::string(host);
}

int GetIntFromDataVect(const fmx::DataVect& dataVect, fmx::uint32 position) {
	return static_cast<int>(dataVect.AtAsNumber(position).AsLong());
}

// DNS State Management ====================================================================

static fmx::errcode fDNS_Initialize()
{
	std::lock_guard<std::mutex> lock(g_dnsMutex);
	if (!g_dnsInitialized) {
		if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS)
			return 1;
		g_currentDnsServer.clear(); // use system default
		g_dnsInitialized = true;
	}
	// (Re)create the channel for the current DNS server (should be default at init)
	if (g_channel) {
		ares_destroy(g_channel);
		g_channel = nullptr;
	}
	if (g_currentDnsServer.empty()) {
		if (ares_init(&g_channel) != ARES_SUCCESS)
			return 1;
	} else {
		struct ares_options options;
		memset(&options, 0, sizeof(options));
		int optmask = 0;
		if (ares_init_options(&g_channel, &options, optmask) != ARES_SUCCESS)
			return 1;
		if (ares_set_servers_ports_csv(g_channel, g_currentDnsServer.c_str()) != ARES_SUCCESS) {
			ares_destroy(g_channel);
			g_channel = nullptr;
			return 1;
		}
	}
	return 0;
}

static fmx::errcode fDNS_Uninitialize()
{
	std::lock_guard<std::mutex> lock(g_dnsMutex);
	if (g_channel) {
		ares_destroy(g_channel);
		g_channel = nullptr;
	}
	if (g_dnsInitialized) {
		ares_library_cleanup();
		g_dnsInitialized = false;
		g_currentDnsServer.clear();
	}
	return 0;
}

static fmx::errcode fDNS_Set_Server(const std::string& dnsServer)
{
	std::lock_guard<std::mutex> lock(g_dnsMutex);
	if (!g_dnsInitialized)
		return 1;
	g_currentDnsServer = dnsServer;
	// Recreate the channel with the new server
	if (g_channel) {
		ares_destroy(g_channel);
		g_channel = nullptr;
	}
	if (g_currentDnsServer.empty()) {
		if (ares_init(&g_channel) != ARES_SUCCESS)
			return 1;
	} else {
		struct ares_options options;
		memset(&options, 0, sizeof(options));
		int optmask = 0;
		if (ares_init_options(&g_channel, &options, optmask) != ARES_SUCCESS)
			return 1;
		if (ares_set_servers_ports_csv(g_channel, g_currentDnsServer.c_str()) != ARES_SUCCESS) {
			ares_destroy(g_channel);
			g_channel = nullptr;
			return 1;
		}
	}
	return 0;
}

static std::string fDNS_Get_Current_Server()
{
	std::lock_guard<std::mutex> lock(g_dnsMutex);
	return g_currentDnsServer;
}

static std::string fDNS_Get_Systems_Server()
{
	std::string serverList;
	ares_channel channel;
	if (ares_init(&channel) != ARES_SUCCESS)
		return "?";

	struct ares_addr_node* servers = nullptr;
	if (ares_get_servers(channel, &servers) == ARES_SUCCESS)
	{
		char ip[INET6_ADDRSTRLEN];
		for (struct ares_addr_node* node = servers; node != nullptr; node = node->next)
		{
			memset(ip, 0, sizeof(ip));
			if (node->family == AF_INET)
			{
				inet_ntop(AF_INET, &node->addr.addr4, ip, sizeof(ip));
			}
			else if (node->family == AF_INET6)
			{
				inet_ntop(AF_INET6, &node->addr.addr6, ip, sizeof(ip));
			}
			if (!serverList.empty())
				serverList += ", ";
			serverList += ip;
		}
		ares_free_data(servers);
	}
	else
	{
		serverList = "?";
	}
	ares_destroy(channel);
	return serverList;
}

// DNS_Resolve: hostname, timeoutMs
static FMX_PROC(fmx::errcode) fDNS_Resolve(short /*funcId*/, const fmx::ExprEnv& /*env*/, const fmx::DataVect& dataVect, fmx::Data& results)
{
	if (!g_dnsInitialized)
		return 1;
	if (dataVect.Size() < 1) return 956;

	const fmx::Data& inputData = dataVect.At(0);
	std::string hostname = getString(inputData.GetAsText());
	if (hostname.empty())
		return 956;

	int timeoutMs = DEFAULT_TIMEOUT;
	if (dataVect.Size() > 1) {
		timeoutMs = GetIntFromDataVect(dataVect, 1);
		if (timeoutMs < 0) timeoutMs = DEFAULT_TIMEOUT;
	}

	std::string dnsServer;
	{
		std::lock_guard<std::mutex> lock(g_dnsMutex);
		dnsServer = g_currentDnsServer;
	}

	std::string result_ip;
	if (dnsServer.empty()) {
		// Use system resolver for default DNS
		result_ip = resolve_with_system(hostname);
	} else {
		ares_channel channel;
		struct ares_options options;
		int optmask = 0;

		if (!dnsServer.empty())
		{
			memset(&options, 0, sizeof(options));
			if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS)
				return 1;
			if (ares_set_servers_ports_csv(channel, dnsServer.c_str()) != ARES_SUCCESS)
			{
				ares_destroy(channel);
				return 1;
			}
		}
		else
		{
			if (ares_init(&channel) != ARES_SUCCESS)
				return 1;
		}

		struct CallbackData {
			bool done = false;
			std::string ip;
		} callbackData;

		auto callback = [](void* arg, int status, int /*timeouts*/, struct hostent* host) {
			auto* data = static_cast<CallbackData*>(arg);
			if (status == ARES_SUCCESS && host && host->h_addr_list[0])
			{
				char ip[INET_ADDRSTRLEN] = {0};
				inet_ntop(AF_INET, host->h_addr_list[0], ip, sizeof(ip));
				data->ip = ip;
			}
			else
			{
				data->ip = "?";
			}
			data->done = true;
		};

		ares_gethostbyname(channel, hostname.c_str(), AF_INET, callback, &callbackData);

		int totalWaitMs = 0;

		while (!callbackData.done && totalWaitMs < timeoutMs)
		{
			fd_set read_fds, write_fds;
			int nfds;
			struct timeval tv, *tvp;

			FD_ZERO(&read_fds);
			FD_ZERO(&write_fds);
			nfds = ares_fds(channel, &read_fds, &write_fds);
			if (nfds == 0)
				break;

			tvp = ares_timeout(channel, nullptr, &tv);

			int waitMs = (tvp->tv_sec * 1000) + (tvp->tv_usec / 1000);
			if (waitMs > (timeoutMs - totalWaitMs))
				waitMs = timeoutMs - totalWaitMs;

			struct timeval tv_limit = { waitMs / 1000, (waitMs % 1000) * 1000 };

			int waited = select(nfds, &read_fds, &write_fds, nullptr, &tv_limit);
			if (waited >= 0)
			{
				ares_process(channel, &read_fds, &write_fds);
				totalWaitMs += waitMs;
			}
			else
			{
				break; // select error
			}
		}

		if (!callbackData.done)
			callbackData.ip = "?";  // Timed out
		ares_destroy(channel);

		result_ip = callbackData.ip;
	}

	fmx::TextUniquePtr outText;
	outText->Assign(result_ip.c_str(), fmx::Text::kEncoding_UTF8);
	results.SetAsText(*outText, inputData.GetLocale());

	return 0;
}


// DNS_Reverse: ipAddress, timeoutMs
static FMX_PROC(fmx::errcode) fDNS_Reverse(short /*funcId*/, const fmx::ExprEnv& /*env*/, const fmx::DataVect& dataVect, fmx::Data& results)
{
	if (!g_dnsInitialized)
		return 1;
	if (dataVect.Size() < 1) return 956;

	std::string ipAddress = getString(dataVect.At(0).GetAsText());
	if (ipAddress.empty()) return 956;

	int timeoutMs = DEFAULT_TIMEOUT;
	if (dataVect.Size() > 1) {
		timeoutMs = GetIntFromDataVect(dataVect, 1);
		if (timeoutMs < 0) timeoutMs = DEFAULT_TIMEOUT;
	}

	std::string dnsServer;
	{
		std::lock_guard<std::mutex> lock(g_dnsMutex);
		dnsServer = g_currentDnsServer;
	}

	std::string result_hostname;
	if (dnsServer.empty()) {
		// Use system resolver for default DNS (reverse)
		result_hostname = reverse_with_system(ipAddress);
	} else {
		ares_channel channel;
		struct ares_options options;
		int optmask = 0;

		if (!dnsServer.empty())
		{
			memset(&options, 0, sizeof(options));
			if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS)
				return 1;
			if (ares_set_servers_ports_csv(channel, dnsServer.c_str()) != ARES_SUCCESS)
			{
				ares_destroy(channel);
				return 1;
			}
		}
		else
		{
			if (ares_init(&channel) != ARES_SUCCESS)
				return 1;
		}

		struct sockaddr_in sa;
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;

		if (inet_pton(AF_INET, ipAddress.c_str(), &sa.sin_addr) != 1)
		{
			ares_destroy(channel);
			return 956;
		}

		struct CallbackData {
			bool done = false;
			std::string hostname;
		} callbackData;

		auto callback = [](void* arg, int status, int /*timeouts*/, struct hostent* host) {
			auto* data = static_cast<CallbackData*>(arg);
			if (status == ARES_SUCCESS && host && host->h_name)
			{
				data->hostname = host->h_name;
			}
			else
			{
				data->hostname = "?";
			}
			data->done = true;
		};

		ares_gethostbyaddr(channel, &sa.sin_addr, sizeof(sa.sin_addr), AF_INET, callback, &callbackData);

		int totalWaitMs = 0;

		while (!callbackData.done && totalWaitMs < timeoutMs)
		{
			fd_set read_fds, write_fds;
			int nfds;
			struct timeval tv, *tvp;

			FD_ZERO(&read_fds);
			FD_ZERO(&write_fds);
			nfds = ares_fds(channel, &read_fds, &write_fds);
			if (nfds == 0)
				break;

			tvp = ares_timeout(channel, nullptr, &tv);

			int waitMs = (tvp->tv_sec * 1000) + (tvp->tv_usec / 1000);
			if (waitMs > (timeoutMs - totalWaitMs))
				waitMs = timeoutMs - totalWaitMs;

			struct timeval tv_limit = { waitMs / 1000, (waitMs % 1000) * 1000 };

			int waited = select(nfds, &read_fds, &write_fds, nullptr, &tv_limit);
			if (waited >= 0)
			{
				ares_process(channel, &read_fds, &write_fds);
				totalWaitMs += waitMs;
			}
			else
			{
				break; // select error
			}
		}

		if (!callbackData.done)
			callbackData.hostname = "?";  // Timed out
		ares_destroy(channel);

		result_hostname = callbackData.hostname;
	}

	fmx::TextUniquePtr outText;
	outText->Assign(result_hostname.c_str(), fmx::Text::kEncoding_UTF8);
	results.SetAsText(*outText, dataVect.At(0).GetLocale());

	return 0;
}

// DNS_Resolve_Extended: hostname, timeoutMs
static FMX_PROC(fmx::errcode) fDNS_Resolve_Extended(short /*funcId*/, const fmx::ExprEnv& /*env*/, const fmx::DataVect& dataVect, fmx::Data& results)
{
	if (!g_dnsInitialized)
		return 1;
	if (dataVect.Size() < 1) return 956;

	std::string hostname = getString(dataVect.At(0).GetAsText());
	if (hostname.empty()) return 956;

	int timeoutMs = DEFAULT_TIMEOUT;
	if (dataVect.Size() > 1) {
		timeoutMs = GetIntFromDataVect(dataVect, 1);
		if (timeoutMs < 0) timeoutMs = DEFAULT_TIMEOUT;
	}

	std::string dnsServer;
	{
		std::lock_guard<std::mutex> lock(g_dnsMutex);
		dnsServer = g_currentDnsServer;
	}

	std::vector<std::pair<std::string, std::string>> records;

	if (dnsServer.empty()) {
		// --- System resolver ---
		// A records
		struct hostent* he = gethostbyname(hostname.c_str());
		if (he && he->h_addrtype == AF_INET) {
			for (int i = 0; he->h_addr_list[i] != nullptr; ++i) {
				char ip[INET_ADDRSTRLEN];
				inet_ntop(AF_INET, he->h_addr_list[i], ip, sizeof(ip));
				records.emplace_back("A", ip);
			}
		}
		// AAAA records
		struct addrinfo hints = {0}, *res = nullptr;
		hints.ai_family = AF_INET6;
		if (getaddrinfo(hostname.c_str(), nullptr, &hints, &res) == 0) {
			for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
				char ip[INET6_ADDRSTRLEN];
				inet_ntop(AF_INET6, &((struct sockaddr_in6*)p->ai_addr)->sin6_addr, ip, sizeof(ip));
				records.emplace_back("AAAA", ip);
			}
			freeaddrinfo(res);
		}
		// CNAME (best effort)
		if (he && he->h_name && strcmp(he->h_name, hostname.c_str()) != 0) {
			records.emplace_back("CNAME", he->h_name);
		}
		// NOTE: System resolver does not provide MX, TXT, NS, etc.
	} else {
		// --- c-ares resolver ---
		ares_channel channel;
		struct ares_options options;
		int optmask = 0;
		memset(&options, 0, sizeof(options));
		if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS)
			return 1;
		if (ares_set_servers_ports_csv(channel, dnsServer.c_str()) != ARES_SUCCESS) {
			ares_destroy(channel);
			return 1;
		}

		struct QueryType {
			const char* type;
			int dns_type;
		};
		QueryType queryTypes[] = {
			{"A", ns_t_a},
			{"AAAA", ns_t_aaaa},
			{"CNAME", ns_t_cname},
			{"MX", ns_t_mx},
			{"TXT", ns_t_txt},
			{"NS", ns_t_ns},
			{"SRV", ns_t_srv},
			{"PTR", ns_t_ptr}
		};

		struct CallbackData {
			std::vector<std::pair<std::string, std::string>>* records;
			std::string type;
			bool done;
		};

		int outstanding = sizeof(queryTypes)/sizeof(QueryType);
		std::vector<CallbackData> callbacks(outstanding);

		auto callback = [](void* arg, int status, int timeouts, unsigned char* abuf, int alen) {
			CallbackData* cb = static_cast<CallbackData*>(arg);
			if (status == ARES_SUCCESS) {
				// Parse DNS response
				ns_msg handle;
				if (ns_initparse(abuf, alen, &handle) == 0) {
					int count = ns_msg_count(handle, ns_s_an);
					for (int i = 0; i < count; ++i) {
						ns_rr rr;
						if (ns_parserr(&handle, ns_s_an, i, &rr) == 0) {
							std::string value;
							if (cb->type == "A" && ns_rr_type(rr) == ns_t_a) {
								char ip[INET_ADDRSTRLEN];
								inet_ntop(AF_INET, ns_rr_rdata(rr), ip, sizeof(ip));
								value = ip;
							} else if (cb->type == "AAAA" && ns_rr_type(rr) == ns_t_aaaa) {
								char ip[INET6_ADDRSTRLEN];
								inet_ntop(AF_INET6, ns_rr_rdata(rr), ip, sizeof(ip));
								value = ip;
							} else if (cb->type == "CNAME" && ns_rr_type(rr) == ns_t_cname) {
								char cname[256];
								dn_expand(abuf, abuf + alen, ns_rr_rdata(rr), cname, sizeof(cname));
								value = cname;
							} else if (cb->type == "MX" && ns_rr_type(rr) == ns_t_mx) {
								uint16_t preference = (ns_rr_rdata(rr)[0] << 8) | ns_rr_rdata(rr)[1];
								char mx[256];
								dn_expand(abuf, abuf + alen, ns_rr_rdata(rr) + 2, mx, sizeof(mx));
								value = std::to_string(preference) + " " + mx;
							} else if (cb->type == "TXT" && ns_rr_type(rr) == ns_t_txt) {
								const unsigned char* txt = ns_rr_rdata(rr);
								int txt_len = *txt;
								std::string txt_str(reinterpret_cast<const char*>(txt + 1), txt_len);
								value = txt_str;
							} else if (cb->type == "NS" && ns_rr_type(rr) == ns_t_ns) {
								char nsdname[256];
								dn_expand(abuf, abuf + alen, ns_rr_rdata(rr), nsdname, sizeof(nsdname));
								value = nsdname;
							} else if (cb->type == "SRV" && ns_rr_type(rr) == ns_t_srv) {
								uint16_t priority = (ns_rr_rdata(rr)[0] << 8) | ns_rr_rdata(rr)[1];
								uint16_t weight = (ns_rr_rdata(rr)[2] << 8) | ns_rr_rdata(rr)[3];
								uint16_t port = (ns_rr_rdata(rr)[4] << 8) | ns_rr_rdata(rr)[5];
								char target[256];
								dn_expand(abuf, abuf + alen, ns_rr_rdata(rr) + 6, target, sizeof(target));
								value = std::to_string(priority) + " " + std::to_string(weight) + " " + std::to_string(port) + " " + target;
							} else if (cb->type == "PTR" && ns_rr_type(rr) == ns_t_ptr) {
								char ptrdname[256];
								dn_expand(abuf, abuf + alen, ns_rr_rdata(rr), ptrdname, sizeof(ptrdname));
								value = ptrdname;
							}
							if (!value.empty())
								cb->records->emplace_back(cb->type, value);
						}
					}
				}
			}
			cb->done = true;
		};

		for (int i = 0; i < outstanding; ++i) {
			callbacks[i].records = &records;
			callbacks[i].type = queryTypes[i].type;
			callbacks[i].done = false;
			ares_query(channel, hostname.c_str(), ns_c_in, queryTypes[i].dns_type, callback, &callbacks[i]);
		}

		int totalWaitMs = 0;
		while (true) {
			bool all_done = true;
			for (int i = 0; i < outstanding; ++i) {
				if (!callbacks[i].done) {
					all_done = false;
					break;
				}
			}
			if (all_done || totalWaitMs >= timeoutMs)
				break;

			fd_set read_fds, write_fds;
			int nfds;
			struct timeval tv, *tvp;

			FD_ZERO(&read_fds);
			FD_ZERO(&write_fds);
			nfds = ares_fds(channel, &read_fds, &write_fds);
			if (nfds == 0)
				break;

			tvp = ares_timeout(channel, nullptr, &tv);

			int waitMs = (tvp->tv_sec * 1000) + (tvp->tv_usec / 1000);
			if (waitMs > (timeoutMs - totalWaitMs))
				waitMs = timeoutMs - totalWaitMs;

			struct timeval tv_limit = { waitMs / 1000, (waitMs % 1000) * 1000 };

			int waited = select(nfds, &read_fds, &write_fds, nullptr, &tv_limit);
			if (waited >= 0) {
				ares_process(channel, &read_fds, &write_fds);
				totalWaitMs += waitMs;
			} else {
				break; // select error
			}
		}
		ares_destroy(channel);
	}

	std::string jsonResult = DNSRecordsToJson(hostname, records);

	fmx::TextUniquePtr outText;
	outText->Assign(jsonResult.c_str(), fmx::Text::kEncoding_UTF8);
	results.SetAsText(*outText, dataVect.At(0).GetLocale());

	return 0;
}
// Registration Info =======================================================================

static const char* kfDNS = "fDNS";

enum {
	kfDNS_DNSResolveID = 300,
	kfDNS_DNSSetServerID = 301,
	kfDNS_DNSReverseID = 302,
	kfDNS_DNSResolveExtendedID = 307,
	kfDNS_DNSInitID = 303,
	kfDNS_DNSUninitID = 304,
	kfDNS_DNSGetSysServerID = 305,
	kfDNS_DNSGetCurServerID = 306
};

static const char* kfDNS_DNSResolveName = "fDNS_Resolve";
static const char* kfDNS_DNSResolveDefinition = "fDNS_Resolve(hostname {; timeoutMs})";
static const char* kfDNS_DNSResolveDescription = "Resolves a hostname to an IPv4 address using the current DNS server";

static const char* kfDNS_DNSResolveExtendedName = "fDNS_Resolve_Extended";
static const char* kfDNS_DNSResolveExtendedDefinition = "fDNS_Resolve_Extended(hostname {; timeoutMs})";
static const char* kfDNS_DNSResolveExtendedDescription = "Resolves a hostname to all DNS records (A, AAAA, etc.) and returns a JSON string";

static const char* kfDNS_DNSSetServerName = "fDNS_Set_Server";
static const char* kfDNS_DNSSetServerDefinition = "fDNS_Set_Server(dnsServer)";
static const char* kfDNS_DNSSetServerDescription = "Sets the DNS server to use (empty for system default)";

static const char* kfDNS_DNSReverseName = "fDNS_Reverse";
static const char* kfDNS_DNSReverseDefinition = "fDNS_Reverse(ipAddress {; timeoutMs})";
static const char* kfDNS_DNSReverseDescription = "Resolves an IP address to a hostname using reverse DNS lookup and the current DNS server";

static const char* kfDNS_DNSInitName = "fDNS_Initialize";
static const char* kfDNS_DNSInitDefinition = "fDNS_Initialize";
static const char* kfDNS_DNSInitDescription = "Initializes the DNS plugin";

static const char* kfDNS_DNSUninitName = "fDNS_Uninitialize";
static const char* kfDNS_DNSUninitDefinition = "fDNS_Uninitialize";
static const char* kfDNS_DNSUninitDescription = "Uninitializes the DNS plugin";

static const char* kfDNS_DNSGetSysServerName = "fDNS_Get_Systems_Server";
static const char* kfDNS_DNSGetSysServerDefinition = "fDNS_Get_Systems_Server";
static const char* kfDNS_DNSGetSysServerDescription = "Returns the system's DNS server(s)";

static const char* kfDNS_DNSGetCurServerName = "fDNS_Get_Current_Server";
static const char* kfDNS_DNSGetCurServerDefinition = "fDNS_Get_Current_Server";
static const char* kfDNS_DNSGetCurServerDescription = "Returns the DNS server currently set in the plugin";

// Plugin Initialization ===================================================================

static FMX_PROC(fmx::errcode) fDNS_Plugin_Initialize(short /*funcId*/, const fmx::ExprEnv&, const fmx::DataVect&, fmx::Data&)
{
	return fDNS_Initialize();
}

static FMX_PROC(fmx::errcode) fDNS_Plugin_Uninitialize(short /*funcId*/, const fmx::ExprEnv&, const fmx::DataVect&, fmx::Data&)
{
	return fDNS_Uninitialize();
}

static FMX_PROC(fmx::errcode) fDNS_Plugin_Set_Server(short /*funcId*/, const fmx::ExprEnv&, const fmx::DataVect& dataVect, fmx::Data&)
{
	if (!g_dnsInitialized)
		return 1;
	if (dataVect.Size() < 1)
		return 956;
	std::string dnsServer = getString(dataVect.At(0).GetAsText());
	return fDNS_Set_Server(dnsServer);
}

static FMX_PROC(fmx::errcode) fDNS_Plugin_Get_Systems_Server(short /*funcId*/, const fmx::ExprEnv&, const fmx::DataVect&, fmx::Data& results)
{
	std::string sysServer = fDNS_Get_Systems_Server();
	fmx::TextUniquePtr outText;
	outText->Assign(sysServer.c_str(), fmx::Text::kEncoding_UTF8);
	results.SetAsText(*outText, results.GetLocale());
	return 0;
}

static FMX_PROC(fmx::errcode) fDNS_Plugin_Get_Current_Server(short /*funcId*/, const fmx::ExprEnv&, const fmx::DataVect&, fmx::Data& results)
{
	std::string curServer = fDNS_Get_Current_Server();
	fmx::TextUniquePtr outText;
	outText->Assign(curServer.c_str(), fmx::Text::kEncoding_UTF8);
	results.SetAsText(*outText, results.GetLocale());
	return 0;
}

static fmx::ptrtype Do_PluginInit(fmx::int16 version)
{
	fmx::ptrtype result = static_cast<fmx::ptrtype>(kDoNotEnable);
	const fmx::QuadCharUniquePtr pluginID(kfDNS[0], kfDNS[1], kfDNS[2], kfDNS[3]);
	fmx::TextUniquePtr name;
	fmx::TextUniquePtr definition;
	fmx::TextUniquePtr description;
	fmx::uint32 flags = fmx::ExprEnv::kDisplayInAllDialogs | fmx::ExprEnv::kFutureCompatible;

	bool ok = true;

	if (version >= k150ExtnVersion)
	{
		name->Assign(kfDNS_DNSInitName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSInitDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSInitDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSInitID, *name, *definition, *description, 0, 0, flags, fDNS_Plugin_Initialize) == 0);

		name->Assign(kfDNS_DNSUninitName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSUninitDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSUninitDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSUninitID, *name, *definition, *description, 0, 0, flags, fDNS_Plugin_Uninitialize) == 0);

		name->Assign(kfDNS_DNSSetServerName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSSetServerDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSSetServerDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSSetServerID, *name, *definition, *description, 1, 1, flags, fDNS_Plugin_Set_Server) == 0);

		name->Assign(kfDNS_DNSResolveName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSResolveDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSResolveDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSResolveID, *name, *definition, *description, 1, 2, flags, fDNS_Resolve) == 0);

		name->Assign(kfDNS_DNSReverseName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSReverseDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSReverseDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSReverseID, *name, *definition, *description, 1, 2, flags, fDNS_Reverse) == 0);

		name->Assign(kfDNS_DNSResolveExtendedName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSResolveExtendedDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSResolveExtendedDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSResolveExtendedID, *name, *definition, *description, 1, 2, flags, fDNS_Resolve_Extended) == 0);

		name->Assign(kfDNS_DNSGetSysServerName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSGetSysServerDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSGetSysServerDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSGetSysServerID, *name, *definition, *description, 0, 0, flags, fDNS_Plugin_Get_Systems_Server) == 0);

		name->Assign(kfDNS_DNSGetCurServerName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSGetCurServerDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSGetCurServerDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSGetCurServerID, *name, *definition, *description, 0, 0, flags, fDNS_Plugin_Get_Current_Server) == 0);
	}

	if (ok)
		result = kCurrentExtnVersion;

	return result;
}

// Plugin Shutdown =========================================================================

static void Do_PluginShutdown(fmx::int16 version)
{
	const fmx::QuadCharUniquePtr pluginID(kfDNS[0], kfDNS[1], kfDNS[2], kfDNS[3]);

	if (version >= k140ExtnVersion)
	{
		fmx::ExprEnv::UnRegisterExternalFunction(*pluginID, kfDNS_DNSInitID);
		fmx::ExprEnv::UnRegisterExternalFunction(*pluginID, kfDNS_DNSUninitID);
		fmx::ExprEnv::UnRegisterExternalFunction(*pluginID, kfDNS_DNSSetServerID);
		fmx::ExprEnv::UnRegisterExternalFunction(*pluginID, kfDNS_DNSResolveID);
		fmx::ExprEnv::UnRegisterExternalFunction(*pluginID, kfDNS_DNSReverseID);
		fmx::ExprEnv::UnRegisterExternalFunction(*pluginID, kfDNS_DNSGetSysServerID);
		fmx::ExprEnv::UnRegisterExternalFunction(*pluginID, kfDNS_DNSGetCurServerID);
		fmx::ExprEnv::UnRegisterExternalFunction(*pluginID, kfDNS_DNSResolveExtendedID);
	}
}

// Get String Handler ======================================================================

static void CopyUTF8StrToUnichar16Str(const char* inStr, fmx::uint32 outStrSize, fmx::unichar16* outStr)
{
	fmx::TextUniquePtr txt;
	txt->Assign(inStr, fmx::Text::kEncoding_UTF8);
	const fmx::uint32 txtSize = (outStrSize <= txt->GetSize()) ? (outStrSize - 1) : txt->GetSize();
	txt->GetUnicode(outStr, 0, txtSize);
	outStr[txtSize] = 0;
}

static void Do_GetString(fmx::uint32 whichString, fmx::uint32 /*winLangID*/, fmx::uint32 outBufferSize, fmx::unichar16* outBuffer)
{
	switch (whichString)
	{
		case kFMXT_NameStr:
			CopyUTF8StrToUnichar16Str("FMDNS_Plugin", outBufferSize, outBuffer);
			break;
		case kFMXT_AppConfigStr:
			CopyUTF8StrToUnichar16Str("DNS Plugin for FileMaker", outBufferSize, outBuffer);
			break;
		case kFMXT_OptionsStr:
			CopyUTF8StrToUnichar16Str(kfDNS, outBufferSize, outBuffer);
			outBuffer[4] = '1';  // Always "1"
			outBuffer[5] = 'n';  // No config dialog
			outBuffer[6] = 'n';
			outBuffer[7] = 'Y';  // Register init/shutdown
			outBuffer[8] = 'n';
			outBuffer[9] = 'n';
			outBuffer[10] = 'n';
			outBuffer[11] = 0;
			break;
		case kFMXT_HelpURLStr:
			CopyUTF8StrToUnichar16Str("https://github.com/sotiriskaragiannis/fDNS", outBufferSize, outBuffer);
			break;
		default:
			outBuffer[0] = 0;
			break;
	}
}

// Unused Callbacks ========================================================================

static void Do_PluginIdle(FMX_IdleLevel, fmx::ptrtype) {}
static void Do_PluginPrefs(void) {}
static void Do_SessionNotifications(fmx::uint64) {}
static void Do_FileNotifications(fmx::uint64, fmx::uint64) {}
static void Do_SchemaNotifications(char*, fmx::uint64) {}

// FMExternCallProc Entry ==================================================================

FMX_ExternCallPtr gFMX_ExternCallPtr = nullptr;

void FMX_ENTRYPT FMExternCallProc(FMX_ExternCallPtr pb)
{
	gFMX_ExternCallPtr = pb;

	switch (pb->whichCall)
	{
		case kFMXT_Init:
			pb->result = Do_PluginInit(pb->extnVersion);
			break;
		case kFMXT_Idle:
			Do_PluginIdle(pb->parm1, pb->parm2);
			break;
		case kFMXT_Shutdown:
			Do_PluginShutdown(pb->extnVersion);
			break;
		case kFMXT_DoAppPreferences:
			Do_PluginPrefs();
			break;
		case kFMXT_GetString:
			Do_GetString(static_cast<fmx::uint32>(pb->parm1), static_cast<fmx::uint32>(pb->parm2),
				static_cast<fmx::uint32>(pb->parm3), reinterpret_cast<fmx::unichar16*>(pb->result));
			break;
		case kFMXT_SessionShutdown:
			Do_SessionNotifications(pb->parm2);
			break;
		case kFMXT_FileShutdown:
			Do_FileNotifications(pb->parm2, pb->parm3);
			break;
		case kFMXT_SchemaChange:
			Do_SchemaNotifications(reinterpret_cast<char*>(pb->parm2), pb->parm3);
			break;
	}
}
