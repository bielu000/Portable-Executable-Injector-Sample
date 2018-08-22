#pragma once
#pragma once

#include <Windows.h>
#include <stdio.h>

long _get_file_size(FILE* file)
{
	long file_size;

	if (file == NULL) {
		printf("Cannot get size which is NULL\n");
	}

	fseek(file, 0, SEEK_END);
	file_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	return file_size;
}

long get_file_size(char* filename)
{
	FILE* file;
	fopen_s(&file, filename, "rb");
	if (file == NULL) {
		printf("Invalid file!\n");

		return NULL;
	}

	long file_size;

	fseek(file, 0, SEEK_END);
	file_size = ftell(file);
	fseek(file, 0, SEEK_SET);

	return file_size;
}

BYTE* get_file_buffer(char* filename)
{
	FILE* file;
	fopen_s(&file, filename, "rb");
	if (file == NULL) {
		printf("Invalid file!\n");

		return NULL;
	}

	long file_size = _get_file_size(file);

	if (file_size == 0) {
		printf("File loaded invalid.\n");

		return NULL;
	}

	BYTE* buffer;
	buffer = malloc(file_size);
	fread(buffer, sizeof(BYTE), file_size, file);
	fclose(file);

	return buffer;
}