// AnyCallHooker.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <iostream>
#include <windows.h>
#include "AnyCallHookerX86.h"

int thisismytest2(int p1, int p2)
{
	printf("internal %d,%d\n", p1, p2);
	return 1;
}

int thisismytest(int p1, int p2)
{
	printf("%s:%d\n", __FUNCDNAME__, p1 + p2);
	thisismytest2(p1, p2);
	return 1;
}

void myhookhandler(_regcontext_ context)
{
	printf("enter:%s\n", __FUNCDNAME__);

	DWORD par1 = ACH_GetPar(context, 0);
	DWORD par2 = ACH_GetPar(context, 1);
	printf("par1:%d\npar2:%d\n", par1, par2);

	printf("leave:%s\n", __FUNCDNAME__);
}

int main()
{
	DWORD dwHookAddr = (DWORD)thisismytest + 0x24;
	ACH_Hook(dwHookAddr,(DWORD) myhookhandler);
	thisismytest(1, 2);

	printf("\n------------next---\n");
	ACH_UnHookAll();
	thisismytest(1, 2);

    std::cout << "Hello World!\n";
}
