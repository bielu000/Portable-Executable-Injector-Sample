#include <Windows.h>
#include <Psapi.h>
#include <tchar.h>
#include <TlHelp32.h>

#include "pe_helper.h"

DWORD get_process_id(const char* process)
{
	DWORD aProcess[1024];
	DWORD cbNeeded;
	DWORD cProcess;

	if (!EnumProcesses(&aProcess, sizeof(aProcess), &cbNeeded)) {
		printf("Error! Cannot enum processes! LastError: %d\n", GetLastError());

		return;
	}

	cProcess = cbNeeded / sizeof(DWORD);

	for (int i = 0; i < cProcess; i++) {
		DWORD processId = aProcess[i];

		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);

		if (hProcess == NULL) {
			continue;
		}

		HANDLE hModule;
		DWORD cbModNeeded;

		if (!EnumProcessModules(hProcess, &hModule, sizeof(hModule), &cbModNeeded)) {
			CloseHandle(hProcess);

			continue;
		}
		
		//Get const char to the same foramt as current process name;
		TCHAR processToFind[MAX_PATH] = TEXT("");
		DWORD cProcessToFind = strlen(process);
		memcpy(&processToFind, process, cProcessToFind);
		
		TCHAR processName[MAX_PATH] = TEXT("<none>");
		GetModuleBaseName(hProcess, hModule, processName, MAX_PATH / sizeof(TCHAR));

		const char* proc = &processName;

		CloseHandle(hProcess); //Handle are already not required

		if (strcmp(process, proc) == 0) {	
			return processId;
		}
	}

	return 0;
}

PIMAGE_NT_HEADERS get_current_process_nt_headers()
{
	DWORD processId = GetCurrentProcessId();

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);

	if (hSnapshot == NULL) {
		printf("Error! Module snapshot is NULL. Cannot get NT_HEADERS\n");

		return NULL;
	}

	MODULEENTRY32 modEntry;

	if (!Module32First(hSnapshot, &modEntry)) {
		printf("Cannot get Module32First\n");

		return NULL;
	}

	PIMAGE_NT_HEADERS inth = get_nt_headers(modEntry.modBaseAddr);

	if (inth == NULL) {
		printf("Error! Func: 'get_current_process_nt_headers' failed! IMAGE_NT_HEADERS are null.\n");

		return NULL;
	}
	
	return inth;
}