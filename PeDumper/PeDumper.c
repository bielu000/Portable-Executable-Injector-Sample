#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <stdio.h>
#include <tchar.h>
#include "file_helper.h"
#include "memory_helper.h"
#include "pe_helper.h"
#include "process_helper.h"

typedef struct {
	WORD offset : 12;
	WORD type : 4;
} BaseRelocationEntry, *PBaseRelocationEntry;

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
		printf(" OriginalFirstThunk: %#008x\n",  imd->OriginalFirstThunk);
		printf(" FirstThunk: %#010x\n", imd->FirstThunk);
		printf(" Functions: \n");

		PIMAGE_THUNK_DATA p_thunk_data = (PIMAGE_THUNK_DATA)((ULONG_PTR)baseAddress + imd->FirstThunk);

		PIMAGE_THUNK_DATA p_org_thunk_data = (PIMAGE_THUNK_DATA)((ULONG_PTR)baseAddress + imd->OriginalFirstThunk);
		while (p_org_thunk_data->u1.ForwarderString != NULL) {
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

	DWORD payloadProcId = find_process_id("DummyApp.exe");

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, payloadProcId);

	if (hSnapshot == NULL) {
		printf("Cannot create process snapshot!\n");

		return 1;
	}

	MODULEENTRY32 mod;

	Module32First(hSnapshot, &mod);

	DWORD moduleSize = mod.modBaseSize;
	LPVOID localBuffer = VirtualAlloc(NULL, moduleSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, NULL, payloadProcId);

	DWORD bytesRead;

	if (!ReadProcessMemory(hProcess, mod.modBaseAddr, localBuffer, moduleSize, &bytesRead)) {
		printf("Cannot read process memory: %d\n", GetLastError());
	}

	print_image_info(localBuffer, "DummyApp.exe");

	CloseHandle(hProcess);

	VirtualFree(localBuffer, moduleSize, MEM_DECOMMIT);
}


BOOL fix_relocations(LPVOID baseAddress, LPVOID payload)
{
	PIMAGE_NT_HEADERS p_nt_headers = get_nt_headers(payload);

	if (p_nt_headers == NULL) {
		printf("Cannot fix relocations : Nt headers are null.\n");

		return FALSE;
	}

	PIMAGE_DATA_DIRECTORY reloc_dir = get_data_directory(payload, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	if (reloc_dir == NULL) {
		printf("Cannot fix relactions: reloc directory is null.\n");

		return FALSE;
	}

	PIMAGE_BASE_RELOCATION reloc_block = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)payload + reloc_dir->VirtualAddress);
	DWORD section_size = reloc_dir->Size;

	while (reloc_block->VirtualAddress != NULL) {
		printf("Block: %#08x Size: %#08x\n", reloc_block->VirtualAddress, reloc_block->SizeOfBlock);
		DWORD maxParsedEntryBytes = reloc_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
		DWORD parsedBytes = 0;
		while (parsedBytes < maxParsedEntryBytes) {

			PBaseRelocationEntry reloc_entry = (PBaseRelocationEntry)((ULONG_PTR)reloc_block + sizeof(IMAGE_BASE_RELOCATION) + parsedBytes);
			parsedBytes += sizeof(BaseRelocationEntry);
			if (reloc_entry->type == NULL) {
				continue;
			}

			printf(" Address: %#08x, Bytes: %#08x, Value:  %#08x\n", reloc_entry, parsedBytes, reloc_entry->offset);

		} ;

		reloc_block = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)reloc_block + reloc_block->SizeOfBlock);
	}
	
}


int main()
{
	FILE * raw_payload = get_file_buffer("C:\\Users\\pbiel\\source\\repos\\PeDumper\\Debug\\PeDumper.exe");
	PIMAGE_NT_HEADERS inth = get_nt_headers(raw_payload);

	LPVOID pe_buffer = VirtualAlloc(NULL, inth->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	copy_raw_to_image_local(pe_buffer, raw_payload);
	

	PIMAGE_DATA_DIRECTORY pim = get_data_directory(pe_buffer, IMAGE_DIRECTORY_ENTRY_BASERELOC);

	if (pim == NULL) {
		printf("Relocc pim is NULL\n");
	}

	DWORD_PTR rel_dir_address = pim->VirtualAddress;
	DWORD rel_dir_size = pim->Size;

	PIMAGE_BASE_RELOCATION p_rel_block =  (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pe_buffer + rel_dir_address);

	DWORD parsed = 0;
	DWORD maxParseSize = rel_dir_size - sizeof(IMAGE_BASE_RELOCATION);

	while (parsed < maxParseSize) {
		PBaseRelocationEntry p_base_rel_entry = (PBaseRelocationEntry)((ULONG_PTR)&p_rel_block->SizeOfBlock + sizeof(p_rel_block->SizeOfBlock) + parsed);
		

		parsed += sizeof(BaseRelocationEntry);
	}


	fix_relocations(inth->OptionalHeader.ImageBase, pe_buffer);
	free(raw_payload);
	VirtualFree(pe_buffer, inth->OptionalHeader.SizeOfImage, MEM_RELEASE);


	getchar();

	return 0;
}

