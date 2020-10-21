# AnyCallHooker
觉得好用的点个赞
hook any x86 raw call instruction

easy to use, usage as follow:
```

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
	//address of this call instruction is thisismytest + 0x24;
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

}

```
