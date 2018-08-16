#include <Windows.h>

void print_memory(BYTE* buffer, DWORD max)
{
	for (int i = 0; i < max; i++)
	{
		printf("Pointer: %p I: %d : %#08x\n", &buffer[i], i, buffer[i]);
	}
}