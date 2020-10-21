#pragma once
#include <windows.h>


#pragma pack(push, 1)


struct _nextcall_info_
{
	LONG	dwHandler;

	LONG	dwOriAddr;
	LONG	dwOriNextAddr;
	LONG	dwHasFilled;
	LONG	dwHookingAddr;
	LONG	dwOriOffset;
	_nextcall_info_()
	{
		// 		dwOriAddr = 0;
		// 		dwOriNextAddr = 0;
		// 		dwHasFilled = 0;
		ZeroMemory(this, sizeof(_nextcall_info_));

	}
};

struct _regcontext_
{
	DWORD flags;
	DWORD rEDI;
	DWORD rESI;
	DWORD rEBP;
	DWORD rESP;
	DWORD rEBX;
	DWORD rEDX;
	DWORD rECX;
	DWORD rEAX;
};


#pragma pack(pop)


//***NOT*** thread-safe
bool ACH_Hook(DWORD E8CallAddr, DWORD dwHandler);

bool ACH_UnHookAll();
bool ACH_UnHook(DWORD E8CallAddr);

DWORD ACH_GetPar(_regcontext_ context, DWORD indexOfPar);