/*!
 * \file AnyCallHookerX86.cpp
 * \date 2020/10/21 
 *
 * \author kkindof
 *
 *
*/

#include "AnyCallHookerX86.h"
#include <windows.h>

static _nextcall_info_ gNextcallAddrs[0x100];


_nextcall_info_* __stdcall AnyCallHooker_GetNextHookAddrInfo(DWORD dwAddr)
{
	for (int i = 0; i < sizeof(gNextcallAddrs) / sizeof(gNextcallAddrs[0]); i++)
	{
		if (gNextcallAddrs[i].dwHasFilled == 1 && gNextcallAddrs[i].dwOriNextAddr == dwAddr)
		{
			return &gNextcallAddrs[i];
		}
	}
	return nullptr;
}



__declspec(naked) void AnyCallHooker_CommonNakedHandler()
{
	_asm
	{

		lea esp, [esp - 4]//
		//sub esp, 4
		pushad
		pushfd
		//EAX,ECX,EDX,EBX,ESP,EBP,ESI,EDI
		lea eax, [esp + 4 + 4 + 4 + 4]//fix esp
		mov ebx, [eax]
		lea ebx, [ebx + 8]
		mov[eax], ebx//fix esp

		mov eax, [esp + 32 + 4 + 4]//next call addr
		push eax
		call AnyCallHooker_GetNextHookAddrInfo //has to succ
		mov ebx, [eax + 4]
		mov[esp + 32 + 4], ebx 
		mov eax, [eax]
		call eax //call myhandle,
		popfd
		popad


		ret
		ret
	}

}

bool ACH_Hook(DWORD E8CallAddr, DWORD dwHandler)
{
	unsigned char* op = (unsigned char*)E8CallAddr;
	if (op==nullptr || op[0]!=0xe8 || dwHandler==0)
	{
		return false;
	}
	DWORD dwHookAddr = E8CallAddr;
	LONG relativeaddr = 0;
	LONG OriAddr = 0;
	memcpy(&relativeaddr, (char*)dwHookAddr + 1, 4);
	OriAddr = (LONG)(relativeaddr + (LONG)dwHookAddr + 5);
	LONG NextAddr = dwHookAddr + 5;


	BYTE callopcodes[5] = { 0xe8 };
	*(DWORD*)&callopcodes[1] = (DWORD)AnyCallHooker_CommonNakedHandler - dwHookAddr - 5;
	for (int i = 0; i < sizeof(gNextcallAddrs) / sizeof(gNextcallAddrs[0]); i++)
	{
		_nextcall_info_* info = &gNextcallAddrs[i];
		if (info->dwHasFilled)
		{
			continue;
		}
		info->dwHasFilled = 1;//
		info->dwHandler = (DWORD)dwHandler;
		info->dwOriAddr = OriAddr;
		info->dwOriNextAddr = NextAddr;
		info->dwHookingAddr = E8CallAddr;
		info->dwOriOffset = relativeaddr;
		break;
	}
	
	return !!WriteProcessMemory(GetCurrentProcess(), (LPVOID)dwHookAddr, callopcodes, 5, 0);

}

bool ACH_UnHookAll()
{
	for (int i = 0; i < sizeof(gNextcallAddrs) / sizeof(gNextcallAddrs[0]); i++)
	{
		_nextcall_info_* info = &gNextcallAddrs[i];
		if (info->dwHasFilled)
		{

			!!WriteProcessMemory(GetCurrentProcess(), (char*)info->dwHookingAddr + 1, &info->dwOriOffset, 4, 0);

		}
	}
	return true;
}

bool ACH_UnHook(DWORD E8CallAddr)
{
	for (int i = 0; i < sizeof(gNextcallAddrs) / sizeof(gNextcallAddrs[0]); i++)
	{
		_nextcall_info_* info = &gNextcallAddrs[i];
		if (info->dwHasFilled && info->dwHookingAddr==E8CallAddr)
		{

			return !!WriteProcessMemory(GetCurrentProcess(), (char*)info->dwHookingAddr + 1, &info->dwOriOffset, 4, 0);
		}
	}
	
	return false;
}

DWORD ACH_GetPar(_regcontext_ context, DWORD indexOfPar)
{
	DWORD esp = context.rESP;
	DWORD par = 0;
	memcpy(&par, (void*)(esp + indexOfPar * 4), 4);
	return par;
}

