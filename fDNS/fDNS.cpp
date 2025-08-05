//
//  fDNS.cpp
//  fDNS
//
//  Author: Sotiris Karagiannis
//
//  v0.61

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
#include <sys/select.h>
#include <unistd.h>

#define DEFAULT_TIMEOUT 3000


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

int GetIntFromDataVect(const fmx::DataVect& dataVect, fmx::uint32 position) {
	return static_cast<int>(dataVect.AtAsNumber(position).AsLong());
}

// DNS State Management ====================================================================

static fmx::errcode DNS_Initialize()
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

static fmx::errcode DNS_Uninitialize()
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

static fmx::errcode DNS_Set_Server(const std::string& dnsServer)
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

static std::string DNS_Get_Current_Server()
{
	std::lock_guard<std::mutex> lock(g_dnsMutex);
	return g_currentDnsServer;
}

static std::string DNS_Get_Systems_Server()
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
static FMX_PROC(fmx::errcode) DNS_Resolve(short /*funcId*/, const fmx::ExprEnv& /*env*/, const fmx::DataVect& dataVect, fmx::Data& results)
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

	// Do NOT destroy the channel here; it's persistent

	fmx::TextUniquePtr outText;
	outText->Assign(callbackData.ip.c_str(), fmx::Text::kEncoding_UTF8);
	results.SetAsText(*outText, inputData.GetLocale());

	return 0;
}


// DNS_Reverse: ipAddress, timeoutMs
static FMX_PROC(fmx::errcode) DNS_Reverse(short /*funcId*/, const fmx::ExprEnv& /*env*/, const fmx::DataVect& dataVect, fmx::Data& results)
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

	// Do NOT destroy the channel here; it's persistent

	fmx::TextUniquePtr outText;
	outText->Assign(callbackData.hostname.c_str(), fmx::Text::kEncoding_UTF8);
	results.SetAsText(*outText, dataVect.At(0).GetLocale());

	return 0;
}
// Registration Info =======================================================================

static const char* kfDNS = "fDNS";

enum {
	kfDNS_DNSResolveID = 300,
	kfDNS_DNSSetServerID = 301,
	kfDNS_DNSReverseID = 302,
	kfDNS_DNSInitID = 303,
	kfDNS_DNSUninitID = 304,
	kfDNS_DNSGetSysServerID = 305,
	kfDNS_DNSGetCurServerID = 306
};

static const char* kfDNS_DNSResolveName = "fDNS_Resolve";
static const char* kfDNS_DNSResolveDefinition = "fDNS_Resolve(hostname; timeoutMs)";
static const char* kfDNS_DNSResolveDescription = "Resolves a hostname to an IPv4 address using the current DNS server";

static const char* kfDNS_DNSSetServerName = "fDNS_Set_Server";
static const char* kfDNS_DNSSetServerDefinition = "fDNS_Set_Server(dnsServer)";
static const char* kfDNS_DNSSetServerDescription = "Sets the DNS server to use (empty for system default)";

static const char* kfDNS_DNSReverseName = "fDNS_Reverse";
static const char* kfDNS_DNSReverseDefinition = "fDNS_Reverse(ipAddress; timeoutMs)";
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

static FMX_PROC(fmx::errcode) DNS_Plugin_Initialize(short /*funcId*/, const fmx::ExprEnv&, const fmx::DataVect&, fmx::Data&)
{
	return DNS_Initialize();
}

static FMX_PROC(fmx::errcode) DNS_Plugin_Uninitialize(short /*funcId*/, const fmx::ExprEnv&, const fmx::DataVect&, fmx::Data&)
{
	return DNS_Uninitialize();
}

static FMX_PROC(fmx::errcode) DNS_Plugin_Set_Server(short /*funcId*/, const fmx::ExprEnv&, const fmx::DataVect& dataVect, fmx::Data&)
{
	if (!g_dnsInitialized)
		return 1;
	if (dataVect.Size() < 1)
		return 956;
	std::string dnsServer = getString(dataVect.At(0).GetAsText());
	return DNS_Set_Server(dnsServer);
}

static FMX_PROC(fmx::errcode) DNS_Plugin_Get_Systems_Server(short /*funcId*/, const fmx::ExprEnv&, const fmx::DataVect&, fmx::Data& results)
{
	std::string sysServer = DNS_Get_Systems_Server();
	fmx::TextUniquePtr outText;
	outText->Assign(sysServer.c_str(), fmx::Text::kEncoding_UTF8);
	results.SetAsText(*outText, results.GetLocale());
	return 0;
}

static FMX_PROC(fmx::errcode) DNS_Plugin_Get_Current_Server(short /*funcId*/, const fmx::ExprEnv&, const fmx::DataVect&, fmx::Data& results)
{
	std::string curServer = DNS_Get_Current_Server();
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
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSInitID, *name, *definition, *description, 0, 0, flags, DNS_Plugin_Initialize) == 0);

		name->Assign(kfDNS_DNSUninitName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSUninitDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSUninitDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSUninitID, *name, *definition, *description, 0, 0, flags, DNS_Plugin_Uninitialize) == 0);

		name->Assign(kfDNS_DNSSetServerName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSSetServerDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSSetServerDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSSetServerID, *name, *definition, *description, 1, 1, flags, DNS_Plugin_Set_Server) == 0);

		name->Assign(kfDNS_DNSResolveName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSResolveDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSResolveDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSResolveID, *name, *definition, *description, 1, 2, flags, DNS_Resolve) == 0);

		name->Assign(kfDNS_DNSReverseName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSReverseDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSReverseDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSReverseID, *name, *definition, *description, 1, 2, flags, DNS_Reverse) == 0);

		name->Assign(kfDNS_DNSGetSysServerName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSGetSysServerDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSGetSysServerDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSGetSysServerID, *name, *definition, *description, 0, 0, flags, DNS_Plugin_Get_Systems_Server) == 0);

		name->Assign(kfDNS_DNSGetCurServerName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_DNSGetCurServerDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_DNSGetCurServerDescription, fmx::Text::kEncoding_UTF8);
		ok &= (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_DNSGetCurServerID, *name, *definition, *description, 0, 0, flags, DNS_Plugin_Get_Current_Server) == 0);
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
