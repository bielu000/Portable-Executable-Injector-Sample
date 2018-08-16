#include <Windows.h>
#include <stdio.h>
#include "memory_helper.h"

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

BOOL copy_payload_to_local(LPVOID base_address, BYTE* payload)
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