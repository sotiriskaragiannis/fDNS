//
//  fDNS.cpp
//  fDNS
//
//  Author: Sotiris Karagiannis
//
// 	v0.1 simple fDNS_Resolve(hostname) function that returns the ip of hostname based on the DNS Lookup
//
//

#include "FMWrapper/FMXTypes.h"
#include "FMWrapper/FMXText.h"
#include "FMWrapper/FMXFixPt.h"
#include "FMWrapper/FMXData.h"
#include "FMWrapper/FMXCalcEngine.h"

#include <netdb.h>
#include <ares.h>
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

// Simple DNS Resolve Function ====================================================================

static FMX_PROC(fmx::errcode) Do_DNS_Resolve(short /*funcId*/, const fmx::ExprEnv& /*environment*/, const fmx::DataVect& dataVect, fmx::Data& results)
{
	if (dataVect.Size() == 0) return 956; // Parameter missing

		const fmx::Data& inputData = dataVect.At(0);
		const fmx::Text& inputText = inputData.GetAsText();

		std::string hostname = getString(inputText);

		if (hostname.empty())
			return 956; // invalid hostname

	if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS)
		return 1; // c-ares init failed

	ares_channel channel;
	if (ares_init(&channel) != ARES_SUCCESS)
	{
		ares_library_cleanup();
		return 1; // c-ares channel init failed
	}

	struct CallbackData {
		bool done = false;
		std::string ip;
	};

	CallbackData callbackData;

	// c-ares callback
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

	// Wait for query to complete (simple event loop)
	while (!callbackData.done)
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
		select(nfds, &read_fds, &write_fds, nullptr, tvp);
		ares_process(channel, &read_fds, &write_fds);
	}

	ares_destroy(channel);
	ares_library_cleanup();

	fmx::TextUniquePtr outText;
	outText->Assign(callbackData.ip.c_str(), fmx::Text::kEncoding_UTF8);
	results.SetAsText(*outText, dataVect.At(0).GetLocale());

	return 0; // Success
}
// Registration Info =======================================================================

static const char* kfDNS = "fDNS";

enum { kfDNS_DNSResolveID = 300, kfDNS_DNSResolveMin = 1, kfDNS_DNSResolveMax = 1 };
static const char* kfDNS_DNSResolveName = "fDNS_Resolve";
static const char* kfDNS_DNSResolveDefinition = "fDNS_Resolve(hostname)";
static const char* kfDNS_DNSResolveDescription = "Resolves a hostname to an IPv4 address";

// Plugin Initialization ===================================================================

static fmx::ptrtype Do_PluginInit(fmx::int16 version)
{
	fmx::ptrtype result = static_cast<fmx::ptrtype>(kDoNotEnable);
	const fmx::QuadCharUniquePtr pluginID(kfDNS[0], kfDNS[1], kfDNS[2], kfDNS[3]);
	fmx::TextUniquePtr name;
	fmx::TextUniquePtr definition;
	fmx::TextUniquePtr description;
	fmx::uint32 flags = fmx::ExprEnv::kDisplayInAllDialogs | fmx::ExprEnv::kFutureCompatible;

	if (version >= k150ExtnVersion)
	{
		name->Assign(kfDNS_fDNSResolveName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_fDNSResolveDefinition, fmx::Text::kEncoding_UTF8);
		description->Assign(kfDNS_fDNSResolveDescription, fmx::Text::kEncoding_UTF8);

		if (fmx::ExprEnv::RegisterExternalFunctionEx(*pluginID, kfDNS_fDNSResolveID, *name, *definition, *description,
			kfDNS_fDNSResolveMin, kfDNS_fDNSResolveMax, flags, Do_fDNS_Resolve) == 0)
			result = kCurrentExtnVersion;
	}
	else if (version == k140ExtnVersion)
	{
		name->Assign(kfDNS_fDNSResolveName, fmx::Text::kEncoding_UTF8);
		definition->Assign(kfDNS_fDNSResolveDefinition, fmx::Text::kEncoding_UTF8);

		if (fmx::ExprEnv::RegisterExternalFunction(*pluginID, kfDNS_fDNSResolveID, *name, *definition,
			kfDNS_fDNSResolveMin, kfDNS_fDNSResolveMax, flags, Do_fDNS_Resolve) == 0)
			result = kCurrentExtnVersion;
	}

	return result;
}

// Plugin Shutdown =========================================================================

static void Do_PluginShutdown(fmx::int16 version)
{
	const fmx::QuadCharUniquePtr pluginID(kfDNS[0], kfDNS[1], kfDNS[2], kfDNS[3]);
	if (version >= k140ExtnVersion)
		fmx::ExprEnv::UnRegisterExternalFunction(*pluginID, kfDNS_fDNSResolveID);
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
