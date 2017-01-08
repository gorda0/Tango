#define _CRT_SECURE_NO_DEPRECATE
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "Functions.h"

void main()
{
	Beep(1000, 100);
	int i;
	int mybytes = 3;
	int nocust = 6;
	int money_nochange = 10;

	//MONEY HACK
	DWORD dwPointer = *(DWORD*)0x00731DA0;
	DWORD dwOffset = *(DWORD*)(dwPointer + 0x868);
	*(DWORD*)(dwOffset + 0x5578) = 1000;
	while (true)
	{
		//NO WAIT 
		for (i = 0; i < mybytes; i++) {
			if (!(*(BYTE*)(0x004958C2 + i) = 0x90)) {
				printf_s("Nao\n");
			}		
		}
		
		//NO Item CUST
		for (i = 0; i < nocust; i++) {
			if (!(*(BYTE*)(0x0041F636 + i) = 0x90)) {
				printf_s("Nao\n");
			}
		}

		//NO money change
		for (i = 0; i < money_nochange; i++) {
			if (!(*(BYTE*)(0x0040E4f5 + i) = 0x90)) {
				printf_s("Nao\n");
			}
		}
	}
	Sleep(2000);
}

bool WINAPI DllMain(HINSTANCE hDLLInst, DWORD fdwReason, LPVOID lpvReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
		DisableThreadLibraryCalls(hDLLInst);

		if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)main, NULL, 0, NULL) == NULL)
		{

			return false;
		}
	}

	return true;
}