//
//  fDNS.cpp
//  fDNS
//
//  Author: Sotiris Karagiannis
//
// 	v0.4 fDNS_Resolve(hostname {; dnsServer}), fDNS_Reverse(ipAddress {; dnsServer}) and fDNS_Get_Default_Server()
// 			with 3 seconds timeout for the dns requests in fDNS_Resolve and fDNS_Reverse.
//

#include "FMWrapper/FMXTypes.h"
#include "FMWrapper/FMXText.h"
#include "FMWrapper/FMXFixPt.h"
#include "FMWrapper/FMXData.h"
#include "FMWrapper/FMXCalcEngine.h"

#include <netdb.h>
#include <ares.h>
#include <vector>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <unistd.h>

#include <string>
#include <cstring>

std::string getString(const fmx::Text& text);

// A function to convert fmx::Text to std::string (with a 512-byte buffer limit)
std::string getString(const fmx::Text& Text)
{
	char buffer[512] = {0}; // NOTE: string size limit
	Text.GetBytes(buffer, sizeof(buffer) - 1, 0, Text.GetSize(), fmx::Text::kEncoding_Native);
	return std::string(buffer);
}

// Simple DNS Get Server Function ====================================================================

static FMX_PROC(fmx::errcode) DNS_Get_Default_Server(short /*funcId*/, const fmx::ExprEnv& /*env*/, const fmx::DataVect& /*dataVect*/, fmx::Data& results)
{
	if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS)
		return 1;

	ares_channel channel;
	if (ares_init(&channel) != ARES_SUCCESS)
	{
		ares_library_cleanup();
		return 1;
	}

	struct ares_addr_node* servers = nullptr;
	std::string serverList;

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
		serverList = "?";  // could not fetch
	}

	ares_destroy(channel);
	ares_library_cleanup();

	fmx::TextUniquePtr outText;
	outText->Assign(serverList.c_str(), fmx::Text::kEncoding_UTF8);
	results.SetAsText(*outText, results.GetLocale());

	return 0;
}

// Simple DNS Resolve Function ====================================================================

static FMX_PROC(fmx::errcode) Do_DNS_Resolve(short /*funcId*/, const fmx::ExprEnv& /*env*/, const fmx::DataVect& dataVect, fmx::Data& results)
{
	if (dataVect.Size() < 1) return 956;

	const fmx::Data& inputData = dataVect.At(0);
	std::string hostname = getString(inputData.GetAsText());
	if (hostname.empty())
		return 956;

	std::string dnsServer;
	if (dataVect.Size() > 1)
		dnsServer = getString(dataVect.At(1).GetAsText());

	if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS)
		return 1;

	ares_channel channel;
	struct ares_options options;
	int optmask = 0;

	if (!dnsServer.empty())
	{
		memset(&options, 0, sizeof(options));
		if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS)
		{
			ares_library_cleanup();
			return 1;
		}
		if (ares_set_servers_ports_csv(channel, dnsServer.c_str()) != ARES_SUCCESS)
		{
			ares_destroy(channel);
			ares_library_cleanup();
			return 1;
		}
	}
	else
	{
		if (ares_init(&channel) != ARES_SUCCESS)
		{
			ares_library_cleanup();
			return 1;
		}
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
	const int maxWaitMs = 3000;  // max 3 seconds

	while (!callbackData.done && totalWaitMs < maxWaitMs)
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
		int waited = select(nfds, &read_fds, &write_fds, nullptr, tvp);
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
	ares_library_cleanup();

	fmx::TextUniquePtr outText;
	outText->Assign(callbackData.ip.c_str(), fmx::Text::kEncoding_UTF8);
	results.SetAsText(*outText, inputData.GetLocale());

	return 0;
}
// Simple DNS Reverse Function ====================================================================

static FMX_PROC(fmx::errcode) Do_DNS_Reverse(short /*funcId*/, const fmx::ExprEnv& /*env*/, const fmx::DataVect& dataVect, fmx::Data& results)
{
	if (dataVect.Size() < 1) return 956;

	std::string ipAddress = getString(dataVect.At(0).GetAsText());
	if (ipAddress.empty()) return 956;

	std::string dnsServer;
	if (dataVect.Size() > 1)
		dnsServer = getString(dataVect.At(1).GetAsText());

	if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS)
		return 1;

	ares_channel channel;
	struct ares_options options;
	int optmask = 0;

	if (!dnsServer.empty())
	{
		memset(&options, 0, sizeof(options));
		if (ares_init_options(&channel, &options, optmask) != ARES_SUCCESS)
		{
			ares_library_cleanup();
			return 1;
		}
		if (ares_set_servers_ports_csv(channel, dnsServer.c_str()) != ARES_SUCCESS)
		{
			ares_destroy(channel);
			ares_library_cleanup();
			return 1;
		}
	}
	else
	{
		if (ares_init(&channel) != ARES_SUCCESS)
		{
			ares_library_cleanup();
			return 1;
		}
	}

	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;

	if (inet_pton(AF_INET, ipAddress.c_str(), &sa.sin_addr) != 1)
		return 956;

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
	const int maxWaitMs = 3000;  // max 3 seconds

	while (!callbackData.done && totalWaitMs < maxWaitMs)
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
		int waited = select(nfds, &read_fds, &write_fds, nullptr, tvp);
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
	ares_library_cleanup();

	fmx::TextUniquePtr outText;
	outText->Assign(callbackData.hostname.c_str(), fmx::Text::kEncoding_UTF8);
	results.SetAsText(*outText, dataVect.At(0).GetLocale());

	return 0;
}

// Registration Info =======================================================================

static const char* kfDNS = "fDNS";

enum {
	kfDNS_DNSResolveID = 300,
	kfDNS_DNSGetServerID = 301,
	kfDNS_DNSReverseID = 302
};

static const char* kfDNS_DNSResolveName = "fDNS_Resolve";
static const char* kfDNS_DNSResolveDefinition = "fDNS_Resolve(hostname {; dnsServer})";
static const char* kfDNS_DNSResolveDescription = "Resolves a hostname to an IPv4 address";

static const char* kfDNS_DNSGetServerName = "fDNS_Get_Default_Server";
static const char* kfDNS_DNSGetServerDefinition = "fDNS_Get_Default_Server";
static const char* kfDNS_DNSGetServerDescription = "Returns the system's DNS server address";

static const char* kfDNS_DNSReverseName = "fDNS_Reverse";
static const char* kfDNS_DNSReverseDefinition = "fDNS_Reverse(ipAddress {; dnsServer})";
static const char* kfDNS_DNSReverseDescription = "Resolves an IP address to a hostname using reverse DNS lookup";

// Plugin Initialization ===================================================================

static fmx::ptrtype Do_PluginInit(fmx::int16 version)
{
	fmx::ptrtype result = static_cast<fmx::ptrtype>(kDoNotEnable);
	const fmx::QuadCharUniquePtr pluginID(kfDNS[0], kfDNS[1], kfDNS[2], kfDNS[3]);
	fmx::TextUniquePtr name;
	fmx::TextUniquePtr definition;
	fmx::TextUniquePtr description;
	fmx::uint32 flags = fmx::ExprEnv::kDisplayInAllDialogs | fmx::ExprEnv::kFutureCompatible;

	bool dnsResolveRegistered = false;
	bool dnsGetServerRegistered = false;
	bool dnsReverseRegistered = false;

	if (version >= k150ExtnVersion)
	{
		// fDNS_Resolve
		name->Assign(kfDNS_DNSResolveName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSResolveDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSResolveDescription, fmx::Text::kEncoding_UTF8);
		dnsResolveRegistered = (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSResolveID, *name, *definition, *description,
			1, 2, flags, Do_DNS_Resolve) == 0);

		// fDNS_Get_Default_Server
		name->Assign(kfDNS_DNSGetServerName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSGetServerDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSGetServerDescription, fmx::Text::kEncoding_UTF8);
		dnsGetServerRegistered = (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSGetServerID, *name, *definition, *description,
			0, 0, flags, DNS_Get_Default_Server) == 0);

		// fDNS_Reverse
		name->Assign(kfDNS_DNSReverseName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSReverseDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSReverseDescription, fmx::Text::kEncoding_UTF8);
		dnsReverseRegistered = (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSReverseID, *name, *definition, *description,
			1, 2, flags, Do_DNS_Reverse) == 0);
	}
	else if (version == k140ExtnVersion)
	{
		// fDNS_Resolve
		name->Assign(kfDNS_DNSResolveName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSResolveDefinition, fmx::Text::kEncoding_UTF8);
		dnsResolveRegistered = (fmx::ExprEnv::RegisterExternalFunction(*pluginID, kfDNS_DNSResolveID, *name, *definition,
			1, 2, flags, Do_DNS_Resolve) == 0);

		// fDNS_Get_Default_Server
		name->Assign(kfDNS_DNSGetServerName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSGetServerDefinition, fmx::Text::kEncoding_UTF8);
		dnsGetServerRegistered = (fmx::ExprEnv::RegisterExternalFunction(*pluginID, kfDNS_DNSGetServerID, *name, *definition,
			0, 0, flags, DNS_Get_Default_Server) == 0);

		// fDNS_Reverse
		name->Assign(kfDNS_DNSReverseName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSReverseDefinition, fmx::Text::kEncoding_UTF8);
		dnsReverseRegistered = (fmx::ExprEnv::RegisterExternalFunction(*pluginID, kfDNS_DNSReverseID, *name, *definition,
			1, 2, flags, Do_DNS_Reverse) == 0);
	}

	if (dnsResolveRegistered && dnsGetServerRegistered && dnsReverseRegistered)
		result = kCurrentExtnVersion;

	return result;
}

// Plugin Shutdown =========================================================================

static void Do_PluginShutdown(fmx::int16 version)
{
	const fmx::QuadCharUniquePtr pluginID(kfDNS[0], kfDNS[1], kfDNS[2], kfDNS[3]);

	if (version >= k140ExtnVersion)
	{
		fmx::ExprEnv::UnRegisterExternalFunction(*pluginID, kfDNS_DNSResolveID);
		fmx::ExprEnv::UnRegisterExternalFunction(*pluginID, kfDNS_DNSGetServerID);
		fmx::ExprEnv::UnRegisterExternalFunction(*pluginID, kfDNS_DNSReverseID);
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
			CopyUTF8StrToUnichar16Str("fDNS", outBufferSize, outBuffer);
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
			CopyUTF8StrToUnichar16Str("https://example.com/help", outBufferSize, outBuffer);
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
