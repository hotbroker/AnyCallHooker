# AnyCallHooker
hook any x86 raw call instruction

easy to use, usage as follow:
```
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
