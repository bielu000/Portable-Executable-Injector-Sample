#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <stdio.h>
#include "file_helper.h"
#include "memory_helper.h"
#include "pe_helper.h"


#include <tchar.h>
void print_image_info(LPVOID baseAddress, const char* imageName)
{

	PIMAGE_DOS_HEADER idh = get_dos_headers(baseAddress);

	if (idh == NULL) {
		printf("Cannot print image info: IMAGE_NT_HEADERS NULL\n");

		return;
	}

	PIMAGE_NT_HEADERS inth = get_nt_headers(baseAddress);

	if (inth == NULL) {
		printf("Cannot print image info: IMAGE_NT_HEADERS NULL\n");

		return;
	}
	
	printf("Dumping image: %s...\n", imageName);
	printf("Size of code: %#08x\n", inth->OptionalHeader.SizeOfCode);
	printf("Size of init data: %#08x\n", inth->OptionalHeader.SizeOfInitializedData);
	printf("Size of not-init data: %#08x\n", inth->OptionalHeader.SizeOfUninitializedData);
	printf("Address of entry point: %#08x\n", inth->OptionalHeader.AddressOfEntryPoint);
	printf("Base of code: %#08x\n", inth->OptionalHeader.BaseOfCode);
	printf("Base of data: %#08x\n", inth->OptionalHeader.BaseOfData);
	printf("ImageBase: %#08x\n", inth->OptionalHeader.ImageBase);
	printf("Size of image: %#08x\n", inth->OptionalHeader.SizeOfImage);
	printf("Size of headers(all): %#08x\n", inth->OptionalHeader.SizeOfHeaders);
	printf("Size of Optionalheader: %#08x\n", inth->FileHeader.SizeOfOptionalHeader);

	DWORD kOptHeaderSize = inth->FileHeader.SizeOfOptionalHeader;
	DWORD kNumberOfSections = inth->FileHeader.NumberOfSections;

	printf("\n-------------- SECTIONS HEADERS --------------\n");
	for (int i = 0; i < kNumberOfSections; i++) {
		PIMAGE_SECTION_HEADER sec_header = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&inth->OptionalHeader + kOptHeaderSize + i * sizeof(IMAGE_SECTION_HEADER));
		printf("Section name: %s\n", sec_header->Name);
		printf("Virtual address: %#08x\n", sec_header->VirtualAddress);
	}
	printf("----------------- END -----------------\n");

	
	printf("\n----------------- IMPORTS -----------------\n");
	PIMAGE_DATA_DIRECTORY importDirectory = get_data_directory(baseAddress, IMAGE_DIRECTORY_ENTRY_IMPORT);

	PIMAGE_IMPORT_DESCRIPTOR imd = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG_PTR)baseAddress + importDirectory->VirtualAddress);
	
	DWORD parsedSize = 0;
	DWORD maxSize = importDirectory->Size;

	while (parsedSize < maxSize) {
		if (imd->FirstThunk == NULL || imd->OriginalFirstThunk == NULL) {
			break;
		}

		printf("\nModule name: %s\n", ((ULONG_PTR)baseAddress + imd->Name));
		PIMAGE_THUNK_DATA pimth = (PIMAGE_THUNK_DATA)((ULONG_PTR)baseAddress + imd->OriginalFirstThunk);
		
		while (pimth->u1.ForwarderString != NULL) {
			DWORD hintBytes = sizeof(BYTE) * 2;
			printf("  %s\n", ((ULONG_PTR)baseAddress + pimth->u1.ForwarderString+ hintBytes));
			pimth++;
		}

		imd++;
		parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}


	printf("----------------- END -----------------\n");
}


void print_current_proc_info()
{
	DWORD currentProcId = GetCurrentProcessId();
	
	printf("Current process id: %d\n", currentProcId);
	
	HANDLE procSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, currentProcId);

	MODULEENTRY32 mod;

	Module32First(procSnap, &mod);


	PIMAGE_DOS_HEADER idh = (PIMAGE_DOS_HEADER)mod.modBaseAddr;

	PIMAGE_NT_HEADERS inth = (PIMAGE_NT_HEADERS)((ULONG_PTR)mod.modBaseAddr + idh->e_lfanew);

	print_image_info((LPVOID)mod.modBaseAddr, "PeDumper.exe");

}


void print_proc_info(const char* process)
{
	DWORD aProcesses[1024];
	DWORD cbNeeded;
	DWORD cProcess;

	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
		printf("Cannot enumerate all processes.\n");

		return;
	}

	cProcess = cbNeeded / sizeof(DWORD);

	for (int i = 0; i < cProcess; i++) {
		if (aProcesses[i] == NULL) {
			continue;
		}

		DWORD processId = aProcesses[i];
		printf("Process PID: %d\n", processId);
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);

		if (hProcess == NULL) {
			continue;
		}



		HMODULE hMod;
		DWORD cbNeeded;

		TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

		if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
			&cbNeeded))
		{
			GetModuleBaseName(hProcess, hMod, szProcessName,
				sizeof(szProcessName) / sizeof(TCHAR));
		}
		_tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processId);

		CloseHandle(hProcess);
	}

}



int main()
{
	//print_proc_info();
	print_proc_info("calc.exe");
	const char* exe = "C:\\Windows\\system32\\calc.exe";

	BYTE* payload = get_file_buffer(exe);

	printf("Buffer pointer: %p\n", payload);

	IMAGE_NT_HEADERS* inth = get_nt_headers(payload);

	LPVOID pe_buffer = VirtualAlloc(NULL, inth->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	copy_payload_to_local(pe_buffer, payload);

	print_image_info(pe_buffer, "Calc.exe");

	VirtualFree(pe_buffer, inth->OptionalHeader.SizeOfImage, MEM_RELEASE);
	free(payload);
	getchar();
	return 0;
}

