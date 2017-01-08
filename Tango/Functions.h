#pragma once
#include <windows.h>
#include <psapi.h>
#pragma comment(lib, "psapi.lib")
#include <stdio.h>

// Usage: unsigned long address = signature_scanner->search("3AB2DFAB????????3FBACD300200A1XXXXXXXXB1C4DA");
// X is the address
// ? is a wildcard

class signature_scanner
{
private:
	unsigned long BaseAddress;
	unsigned long ModuleSize;

public:
	signature_scanner()
	{
		//SYSTEM_INFO info;
		//GetSystemInfo(&info);
		//this->BaseAddress = (unsigned long)info.lpMinimumApplicationAddress;

		// Could be injected earlier than expected

		while (!(this->BaseAddress = (unsigned long)GetModuleHandle(NULL)))
			Sleep(100);

		// Getting size of image

		MODULEINFO modinfo;

		while (!GetModuleInformation(GetCurrentProcess(), GetModuleHandle(NULL), &modinfo, sizeof(MODULEINFO)))
			Sleep(100);

		this->ModuleSize = modinfo.SizeOfImage;

		// Wait for the application to finish loading

		MEMORY_BASIC_INFORMATION meminfo;

		while (true)
		{
			if (VirtualQuery((void*)this->ModuleSize, &meminfo, sizeof(MEMORY_BASIC_INFORMATION)))
				if (!(meminfo.Protect &PAGE_EXECUTE_WRITECOPY))
					break;

			Sleep(100);
		}
	}

	unsigned long search(const char* string, unsigned short offset = 0)
	{
		unsigned int p_length = strlen(string);// Pattern's length

		if (p_length % 2 != 0 || p_length < 2 || !this->BaseAddress || !this->ModuleSize) return NULL;// Invalid operation

		unsigned short length = p_length / 2;// Number of bytes

											 // The buffer is storing the real bytes' values after parsing the string
		unsigned char* buffer = new unsigned char[length];
		SecureZeroMemory(buffer, length);

		// Copy of string

		char* pattern = new char[p_length + 1];// +1 for the null terminated string
		ZeroMemory(pattern, p_length + 1);
		strcpy_s(pattern, p_length + 1, string);
		_strupr_s(pattern, p_length + 1);

		// Set vars

		unsigned char f_byte;
		unsigned char s_byte;

		// Parsing of string

		for (unsigned short z = 0; z < length; z++)
		{
			f_byte = pattern[z * 2];// First byte
			s_byte = pattern[(z * 2) + 1];// Second byte

			if (((f_byte <= 'F' && f_byte >= 'A') || (f_byte <= '9' && f_byte >= '0')) && ((s_byte <= 'F' && s_byte >= 'A') || (s_byte <= '9' && s_byte >= '0')))
			{
				if (f_byte <= '9') buffer[z] += f_byte - '0';
				else buffer[z] += f_byte - 'A' + 10;
				buffer[z] *= 16;
				if (s_byte <= '9') buffer[z] += s_byte - '0';
				else buffer[z] += s_byte - 'A' + 10;
			}
			else if (f_byte == 'X' || s_byte == 'X') buffer[z] = 'X';
			else buffer[z] = '?';// Wildcard
		}

		// Remove buffer

		delete[] pattern;

		// Start searching

		unsigned short x;
		unsigned long i = this->BaseAddress;
		MEMORY_BASIC_INFORMATION meminfo;
		unsigned long EOR;

		while (i < this->ModuleSize)
		{
			VirtualQuery((void*)i, &meminfo, sizeof(MEMORY_BASIC_INFORMATION));

			if (!(meminfo.Protect &PAGE_EXECUTE_READWRITE))// Good for AVA for now
			{// !(meminfo.Protect &(PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) || !(meminfo.State &MEM_COMMIT)
				i += meminfo.RegionSize;
				continue;
			}

			EOR = i + meminfo.RegionSize;

			for (; i < EOR; i++)
			{
				for (x = 0; x < length; x++)
					if (buffer[x] != ((unsigned char*)i)[x] && buffer[x] != '?' && buffer[x] != 'X')
						break;

				if (x == length)
				{
					delete[] buffer;
					const char* s_offset = strstr(string, "X");

					if (s_offset != NULL)
						return *(unsigned long*)&((unsigned char*)i)[length - strlen(s_offset) / 2];
					else
						return *(unsigned long*)&((unsigned char*)i)[length + offset];
				}
			}
		}

		// Didn't find anything

		delete[] buffer;
		return NULL;
	}
};