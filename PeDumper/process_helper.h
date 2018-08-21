#include <Windows.h>

DWORD get_process_id(const char* process);
PIMAGE_NT_HEADERS get_current_process_nt_headers();