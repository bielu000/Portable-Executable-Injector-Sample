#include <Windows.h>
#include <stdio.h>
#include "memory_helper.h"

typedef struct {
	WORD offset : 12;
	WORD type : 4;
} BaseRelocationEntry, *PBaseRelocationEntry;

PIMAGE_DOS_HEADER get_dos_headers(LPVOID baseAddress)
{
	if (baseAddress == NULL) {
		printf("Cannot get DOS HEADERS. BaseAddress is NULL\n");
		
		return NULL;
	}

	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)baseAddress;

	if (pidh == NULL) {
		printf("Cannot get DOS HEADERS. Buffer is invalid\n");

		return NULL;
	}

	
	if (pidh->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("Cannot get DOS HEADERS. Fiel is invalid PE. Signature invalid.\n");

		return NULL;
	}

	return pidh;
}

PIMAGE_NT_HEADERS get_nt_headers(BYTE* buffer)
{
	PIMAGE_DOS_HEADER idh = (PIMAGE_DOS_HEADER)buffer;

	if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("File is not valid PE. DOS signature not match!\n");

		return NULL;
	}

	PIMAGE_NT_HEADERS inth = (PIMAGE_NT_HEADERS)((ULONG_PTR)buffer + idh->e_lfanew);

	if (inth == NULL) {
		printf("Invalid IMAGE_NT_HEADERS!\n");

		return NULL;
	}

	return inth;
}

PIMAGE_DATA_DIRECTORY get_data_directory(BYTE* buffer, DWORD dir_id)
{
	PIMAGE_NT_HEADERS inth = get_nt_headers(buffer);

	if (inth == NULL) {
		printf("Cannot print data director. IMAGE_NT_HEADERS or PE_BUFFER is NULL\n");

		return NULL;
	}

	IMAGE_DATA_DIRECTORY* imdd = &(inth->OptionalHeader.DataDirectory[dir_id]);
	//printf("Directory size: %#08x VA: %#08x\n", imdd->Size, imdd->VirtualAddress);

	return imdd;
}

BOOL copy_raw_to_image_local(LPVOID base_address, BYTE* payload)
{
	PIMAGE_NT_HEADERS inth = get_nt_headers(payload);

	if (inth == NULL) {
		printf("Cannot copy payload to local buffer. IMAGE_NT_HEADERS is null\n");

		return FALSE;
	}

	// Copy headers, from start of payload.
	// SizeOfHeaders is size of all headers inlcuding ms dos stub etc
	// so it can be copied like below
	memcpy(base_address, payload, inth->OptionalHeader.SizeOfHeaders);

	DWORD kSizeOptHeader = inth->FileHeader.SizeOfOptionalHeader;

	//Copy section one by one to VA address.
	for (int i = 0; i < inth->FileHeader.NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER section_ptr = (PIMAGE_SECTION_HEADER)((ULONG_PTR)&inth->OptionalHeader + kSizeOptHeader + i * sizeof(IMAGE_SECTION_HEADER));
		LPVOID section_location = (LPVOID)((ULONG_PTR)base_address + section_ptr->VirtualAddress);
		LPVOID pointer_raw_data = (LPVOID)((ULONG_PTR)payload + section_ptr->PointerToRawData);
		DWORD section_size = section_ptr->SizeOfRawData;

		memcpy(section_location, pointer_raw_data, section_size);
	}

	return TRUE;
}

void adjust_relocations(LPVOID imageBase, LPVOID payload)
{
	printf("\nAdjusting relocations...\n");
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

	if (reloc_dir->VirtualAddress == NULL) {
		printf("Not need to do relocations.\n");
		return TRUE;
	}

	PIMAGE_BASE_RELOCATION reloc_block = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)payload + reloc_dir->VirtualAddress);
	DWORD section_size = reloc_dir->Size;
	ULONG_PTR preferedImageBase = p_nt_headers->OptionalHeader.ImageBase;

	printf("Current image base: %#010x\n", imageBase);
	printf("Prefered image base: %#010x\n", preferedImageBase);

	while (reloc_block->VirtualAddress != NULL) {
		printf("Block: %#010x Size: %#010x\n", reloc_block->VirtualAddress, reloc_block->SizeOfBlock);
		DWORD maxParsedEntryBytes = reloc_block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION);
		DWORD parsedBytes = 0;
		while (parsedBytes < maxParsedEntryBytes) {
			PBaseRelocationEntry reloc_entry = (PBaseRelocationEntry)((ULONG_PTR)reloc_block + sizeof(IMAGE_BASE_RELOCATION) + parsedBytes);
			parsedBytes += sizeof(BaseRelocationEntry);

			if (reloc_entry->type == NULL) {
				continue;
			}

			//Add error checking
			PULONG_PTR reloc = ((ULONG_PTR)payload + (reloc_block->VirtualAddress + reloc_entry->offset));
			if (reloc == NULL) {
				printf("Relocations is null!\n");

				continue;
			}

			ULONG_PTR copy = (ULONG_PTR)*reloc; //only for info purpose
			ULONG_PTR calculated_value = (*reloc - preferedImageBase) + (ULONG_PTR)imageBase;
			*reloc = calculated_value;

			printf(" Address: %#010x, Value:  %#010x, Before: %#010x, After: %#010x\n", reloc_entry, reloc_entry->offset, copy, *reloc);

		};
		reloc_block = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)reloc_block + reloc_block->SizeOfBlock);
	}

	printf("\nDone...!\n");
}