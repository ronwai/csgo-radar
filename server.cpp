#include "stdafx.h"
#include "json.hpp"

using namespace std;
using json = nlohmann::json;
typedef websocketpp::server<websocketpp::config::asio> server;

using websocketpp::lib::placeholders::_1;
using websocketpp::lib::placeholders::_2;
using websocketpp::lib::bind;

// pull out the type of messages sent by our config
typedef server::message_ptr message_ptr;

struct EntInfo {
	LPVOID entity;
	LPVOID sn;
	LPVOID prev;
	LPVOID next;
};

HANDLE gameHandle;
LPVOID clientOffset;
LPVOID engineOffset;
LPVOID elOffset = (LPVOID)0x4AC9154;
LPVOID lpOffset = (LPVOID)0x5CA514;

wchar_t * deobfuscate(char *str) {
	int i;
	char *deobfuscatedString = (char *) malloc(strlen(str));
	for (i = 0; i < strlen(str); i++) {
		deobfuscatedString[i] = str[i] ^ 4;
	};
	deobfuscatedString[strlen(str)] = '\0';

	size_t newsize = strlen(str) + 1;
	wchar_t *wcstring = new wchar_t[newsize];
	size_t convertedChars = 0;
	mbstowcs_s(&convertedChars, wcstring, newsize, deobfuscatedString, _TRUNCATE);
	return wcstring;
}

HANDLE getHandle() {
	DWORD processes[1024], cbNeeded, cProcesses;
	unsigned int i;

	if (!EnumProcesses(processes, sizeof(processes), &cbNeeded))
	{
		return nullptr;
	}

	cProcesses = cbNeeded / sizeof(DWORD);
	for (i = 0; i < cProcesses; i++)
	{
		if (processes[i] != 0)
		{
			TCHAR processName[MAX_PATH] = TEXT("<unknown>");
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
			if (hProcess != NULL)
			{
				HMODULE hMod;
				DWORD numModules;
				if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod), &numModules, LIST_MODULES_ALL))
				{
					GetModuleBaseName(hProcess, hMod, processName, sizeof(processName) / sizeof(TCHAR));
					if (_tcscmp(processName, deobfuscate("gwck*a|a")) == 0) {
						return hProcess;
					}
				}
			}
			CloseHandle(hProcess);
		}
	}
	return nullptr;
}

LPVOID getOffset(HANDLE hProcess, wchar_t *module) {
	HMODULE hMods[1024];
	DWORD numModules;
	unsigned int i;

	if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &numModules, LIST_MODULES_ALL))
	{
		for (i = 0; i < (numModules / sizeof(HMODULE)); i++) {
			TCHAR moduleName[MAX_PATH];
			if (GetModuleBaseName(hProcess, hMods[i], moduleName, sizeof(moduleName) / sizeof(TCHAR)))
			{
				if (_tcscmp(moduleName, module) == 0) {
					MODULEINFO moduleInfo;
					if (GetModuleInformation(hProcess, hMods[i], &moduleInfo, sizeof(MODULEINFO))) {
						return moduleInfo.lpBaseOfDll;
					}
				}
			}
		}
	}
	return nullptr;
}

json getEntities(HANDLE hProcess, LPVOID clientOffset, LPVOID entityListOffset) {
	DWORD entities = (DWORD) clientOffset + (DWORD) entityListOffset;
	json j = {
		{"e", json::array()}
	};
	EntInfo entity;
	int i;
	for (i = 0; i < 64; i++)
	{
		if (!ReadProcessMemory(hProcess, (LPVOID)(entities + i * sizeof(EntInfo)), &entity, sizeof(entity), NULL))
		{
			std::cout << "R EL ERROR" << std::endl;
			return j;
		}

		if (entity.entity == NULL)
			continue;
		int dormant;
		ReadProcessMemory(hProcess, (char *)entity.entity + 0xE9, &dormant, sizeof(int), NULL);
		if (dormant == 0) 
		{
			float loc[3];
			float ang[3];
			int health, team;
			if (!ReadProcessMemory(hProcess, (char *)entity.entity + 0xFC, &health, sizeof(int), NULL))
				std::cout << "R h ERROR" << std::endl;
			if (!ReadProcessMemory(hProcess, (char *)entity.entity + 0xF0, &team, sizeof(int), NULL))
				std::cout << "R t ERROR" << std::endl;
			if (!ReadProcessMemory(hProcess, (char *)entity.entity + 0x134, loc, sizeof(float) * 3, NULL))
				std::cout << "R l ERROR" << std::endl;
			if (!ReadProcessMemory(hProcess, (char *)entity.entity + 0xAA08, ang, sizeof(float) * 3, NULL))
				std::cout << "R a ERROR" << std::endl;

			j["e"].push_back({ { "h", health },{ "t", team },{ "a", loc[0] },{ "b", loc[1] },{ "c", ang[1] } });
		}
	}
	return j;
}

json getMapName(HANDLE hProcess, LPVOID engineOffset, LPVOID mapOffset)
{
	DWORD clientStateAddr = (DWORD)engineOffset + (DWORD)mapOffset;
	LPVOID clientState;
	if (ReadProcessMemory(hProcess, (LPVOID)clientStateAddr, &clientState, sizeof(LPVOID), NULL))
	{
		char map[256];
		if (ReadProcessMemory(hProcess, (char *)clientState + 0x284, map, 256, NULL))
			return { {"m", map} };
	}
	return{ {"m", json::array()} };
}

// Define a callback to handle incoming messages
void on_message(server* s, websocketpp::connection_hdl hdl, message_ptr msg) {
	std::cout << "on_message called with hdl: " << hdl.lock().get()
		<< " and message: " << msg->get_payload()
		<< " and opcode: " << msg->get_opcode()
		<< std::endl;

	// check for a special command to instruct the server to stop listening so
	// it can be cleanly exited.
	if (msg->get_payload() == "stop-listening") {
		s->stop_listening();
		return;
	}

	try {
		json j;
		if (msg->get_payload() == "e")
			j = getEntities(gameHandle, clientOffset, elOffset);
		else
			j = getMapName(gameHandle, engineOffset, lpOffset);

		s->send(hdl, j.dump(), msg->get_opcode());
	}
	catch (const websocketpp::lib::error_code& e) {
		std::cout << "Echo failed because: " << e
			<< "(" << e.message() << ")" << std::endl;
	}
}

int main()
{
	gameHandle = getHandle();
	if (gameHandle == nullptr)
	{
		std::cout << "Err handle" << std::endl;
	}
	else
	{
		clientOffset = getOffset(gameHandle, deobfuscate("ghmajp*`hh"));
		engineOffset = getOffset(gameHandle, deobfuscate("ajcmja*`hh"));
		std::wcout << deobfuscate("gwck*a|a") << std::endl;
		std::wcout << clientOffset << std::endl;
		std::wcout << engineOffset << std::endl;
	}

	// Create a server endpoint
	server echo_server;

	try {
		// Set logging settings
		echo_server.set_access_channels(websocketpp::log::alevel::all);
		echo_server.clear_access_channels(websocketpp::log::alevel::frame_payload);

		// Initialize Asio
		echo_server.init_asio();

		// Register our message handler
		echo_server.set_message_handler(bind(&on_message, &echo_server, ::_1, ::_2));

		// Listen on port 9002
		echo_server.listen(9002);

		// Start the server accept loop
		echo_server.start_accept();

		// Start the ASIO io_service run loop
		echo_server.run();
	}
	catch (websocketpp::exception const & e) {
		std::cout << e.what() << std::endl;
	}
	catch (...) {
		std::cout << "other exception" << std::endl;
	}
	
}

