#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <stdio.h>
#include <tchar.h>
#include "file_helper.h"
#include "memory_helper.h"
#include "pe_helper.h"
#include "process_helper.h"



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
	//printf("Base of data: %#08x\n", inth->OptionalHeader.BaseOfData);
	printf("ImageBase: %#08x\n", inth->OptionalHeader.ImageBase);
	printf("Size of image: %#08x\n", inth->OptionalHeader.SizeOfImage);
	printf("Size of headers(all): %#08x\n", inth->OptionalHeader.SizeOfHeaders);
	printf("Size of Optionalheader: %#08x\n", inth->FileHeader.SizeOfOptionalHeader);

	DWORD kOptHeaderSize = inth->FileHeader.SizeOfOptionalHeader;
	DWORD kNumberOfSections = inth->FileHeader.NumberOfSections;

	printf("\n-------------- SECTIONS HEADERS --------------\n");
	for (unsigned int i = 0; i < kNumberOfSections; i++) {
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
		printf(" OriginalFirstThunk: %#008x\n",  imd->OriginalFirstThunk);
		printf(" FirstThunk: %#010x\n", imd->FirstThunk);
		printf(" Functions: \n");
		 
		PIMAGE_THUNK_DATA p_thunk_data = (PIMAGE_THUNK_DATA)((ULONG_PTR)baseAddress + imd->FirstThunk);

		PIMAGE_THUNK_DATA p_org_thunk_data = (PIMAGE_THUNK_DATA)((ULONG_PTR)baseAddress + imd->OriginalFirstThunk);
		while (p_org_thunk_data->u1.ForwarderString != 0) {
			DWORD hintBytes = sizeof(BYTE) * 2;
			printf("    %s\n", ((ULONG_PTR)baseAddress + p_org_thunk_data->u1.ForwarderString+ hintBytes));
			p_org_thunk_data++;

		}

		
		
		//ImportNameTableRVA -> OriginalFirstThunk
		//ImportAddressTableRVA -> FirstThunk

		//
		//DWORD ForwarderString;      // PBYTE 
		//DWORD Function;             // PDWORD
		//DWORD Ordinal;
		//DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME

		imd++;
		parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}


	printf("----------------- END -----------------\n");

	printf("\n----------------- REALOCS -----------------\n");
	PIMAGE_DATA_DIRECTORY rel_dir = get_data_directory(baseAddress, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	if (rel_dir == NULL) {
		printf("Cannot print rellocation. Dir is null\n");
	}
	
	PIMAGE_BASE_RELOCATION rel_entry = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)baseAddress + rel_dir->VirtualAddress);


	printf("----------------- END -----------------\n");
}

void remote_process()
{
	char* payload = "DummyApp.exe";

	DWORD payloadProcId = get_process_id("DummyApp.exe");

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, payloadProcId);

	if (hSnapshot == NULL) {
		printf("Cannot create process snapshot!\n");

		return ;
	}

	MODULEENTRY32 mod;

	Module32First(hSnapshot, &mod);

	DWORD moduleSize = mod.modBaseSize;
	LPVOID localBuffer = VirtualAlloc(NULL, moduleSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, payloadProcId);

	SIZE_T bytesRead;

	if (!ReadProcessMemory(hProcess, mod.modBaseAddr, localBuffer, moduleSize, &bytesRead)) {
		printf("Cannot read process memory: %d\n", GetLastError());
	}

	print_image_info(localBuffer, "DummyApp.exe");

	CloseHandle(hProcess);

	VirtualFree(localBuffer, moduleSize, MEM_DECOMMIT);
}

void run_local_copy(LPVOID entryPoint)
{
	LPTHREAD_START_ROUTINE routine = (LPTHREAD_START_ROUTINE)(entryPoint);

	DWORD threadId;
	CreateThread(NULL, 0, routine, NULL, 0, &threadId);
}

void adjust_imports(LPVOID payload)
{
	printf("\nAdjusting imports...\n");
	printf("Dlls:\n");
	PIMAGE_DATA_DIRECTORY import_dir = get_data_directory(payload, IMAGE_DIRECTORY_ENTRY_IMPORT);

	if (import_dir == NULL) {
		printf("Cannot fix imports. IMPORT_DIRECTORY is NULL\n");
	}

	DWORD kImportsSize = import_dir->Size;
	DWORD kCountDirs = kImportsSize / sizeof(IMAGE_IMPORT_DESCRIPTOR);
	
	for (unsigned int i = 0; i < kCountDirs; i++) {
		ULONG_PTR desc_addr = (ULONG_PTR)payload + import_dir->VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) * i;
		PIMAGE_IMPORT_DESCRIPTOR imp_desc = (PIMAGE_IMPORT_DESCRIPTOR)desc_addr;

		if (imp_desc->FirstThunk == NULL || imp_desc->OriginalFirstThunk == NULL) {
			continue;
		}


		printf("  %s\n", (ULONG_PTR)payload+imp_desc->Name);

		if (strcmp((LPCSTR)((ULONG_PTR)payload + imp_desc->Name), "USER32.dll") != 0) {
			printf("Cannot resolve module\n");

			continue;
		}

		PIMAGE_THUNK_DATA org_first_thunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)payload+imp_desc->OriginalFirstThunk);

		if (org_first_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
			printf("Resolving imports by ordinal not supported!\n");

			continue;
		}

		//REFACTOR ! ! ! ! ! ! ! ! ! !
		//ADD ERROR CHECKING ! ! ! 
		// ADD LIBRARY CHECK ! ! !

		PIMAGE_IMPORT_BY_NAME import_by_name = (PIMAGE_IMPORT_BY_NAME)((ULONG_PTR)payload+org_first_thunk->u1.AddressOfData);

		printf("    %s\n", import_by_name->Name);

		HANDLE hLib = LoadLibrary((LPCSTR)(ULONG_PTR)payload + imp_desc->Name);
		FARPROC proc = GetProcAddress(hLib, import_by_name->Name);

		PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)((ULONG_PTR)payload + imp_desc->FirstThunk);
		firstThunk->u1.AddressOfData = (ULONG_PTR)proc;
	}
}

/*
	1. Open raw payload file 
	2. Allocate local buffer 
	3. Copy raw image to local buffer => loc_buff
	4. Get remote process id
	5. Allocate page on remote process
	6. Adjust relocation using base address of allocated page
	7. Adjust imports
	8. Copy local buffer "loc_buff" to remote using allocated page
	9. Free local buffer
	10. Create remote thread started from entrypoint
*/

void inject_into_remote(DWORD pid)
{
	char* target_n = "InjectTarget.exe";
	//char* payload_path  = "C:\\Users\\pbiel\\source\\repos\\PeDumper\\Debug\\DummyApp.exe";
	char* payload_path  = "C:\\Users\\pbiel\\source\\repos\\PeDumper\\x64\\Debug\\DummyApp.exe";

	BYTE* raw_payload = get_file_buffer(payload_path);
	PIMAGE_NT_HEADERS inth = get_nt_headers(raw_payload);

	DWORD kImageSize = inth->OptionalHeader.SizeOfImage;
	//DWORD kTargetProcId = get_process_id(target_n);
	DWORD kTargetProcId = 27472;

	//HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, NULL, kTargetProcId);
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, kTargetProcId);
	if (hProcess == NULL) {
		printf("Error: Process handle is NULL\n");
	}
	
	LPVOID imageBaseRemote = VirtualAllocEx(hProcess, NULL, kImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (imageBaseRemote == NULL) {
		printf("Error: Image base remote is NULL. Error code: %d\n", GetLastError());
	}

	LPVOID imageBaseLocal = VirtualAlloc(NULL, kImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	copy_raw_to_image_local(imageBaseLocal, raw_payload);
	adjust_relocations(imageBaseRemote, imageBaseLocal);
	adjust_imports(imageBaseLocal);
	
	SIZE_T bytesWritten;
	if (!WriteProcessMemory(hProcess, imageBaseRemote, imageBaseLocal, kImageSize, &bytesWritten)) {
		printf("Cannot write to remote process!\n");
	}

	LPTHREAD_START_ROUTINE routine = (LPTHREAD_START_ROUTINE)((ULONG_PTR)imageBaseRemote + inth->OptionalHeader.AddressOfEntryPoint);

	DWORD threadId;
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, routine, NULL, 0, &threadId);

	if (hThread == NULL) {
		printf("Error! Cannot create remote thread. Error code: %d\n", GetLastError());
	}

	printf("Done...! Thread id: %d\n", threadId);

	VirtualFree(imageBaseLocal, kImageSize, MEM_RELEASE);
	
	free(raw_payload);
}

int main(int argc, char* argv[])
{
	//FILE * raw_payload = get_file_buffer("C:\\Users\\pbiel\\source\\repos\\PeDumper\\Debug\\DummyApp.exe");
	//PIMAGE_NT_HEADERS inth = get_nt_headers(raw_payload);


	//LPVOID local_pe = VirtualAlloc(NULL, inth->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//copy_raw_to_image_local(local_pe, raw_payload);
	//
	//adjust_relocations(local_pe, local_pe);
	//adjust_imports(local_pe);
	//run_local_copy((ULONG_PTR)local_pe + inth->OptionalHeader.AddressOfEntryPoint);

	//free(raw_payload);
	//VirtualFree(local_pe, inth->OptionalHeader.SizeOfImage, MEM_RELEASE);

	DWORD pid;
	/*if (strcmp(argv[1], "pid") == 0) {
		pid = argv[2];
	}
	else {
		pid = get_process_id(argv[2]);
	}

	printf("%s\n", argv[1]);
	printf("%s\n", argv[2])*/;
	pid = 6076;
	inject_into_remote(pid);

	getchar();

	return 0;
}

