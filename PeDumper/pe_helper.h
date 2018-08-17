#pragma once
#include <Windows.h>

BOOL copy_raw_to_image_local(LPVOID base_address, BYTE* payload);
BOOL copy_remote_to_image_local(LPVOID base_address, LPVOID remote_base_address);
PIMAGE_DATA_DIRECTORY get_data_directory(BYTE* buffer, DWORD dir_id);
PIMAGE_NT_HEADERS get_nt_headers(BYTE* buffer);
PIMAGE_DOS_HEADER get_dos_headers(LPVOID baseAddress);