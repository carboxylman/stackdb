#include<stdio.h>
#include "clipssrc/clips.h"

void main()
{
    InitializeEnvironment();
    printf("Loding initial condtructs\n");
    Load("policies.clp");
    Reset();
    Run(-1L);
}
/*void killprocess_func( DATA_OBJECT_PTR ptr)
{
    void * pid;

    if(ArcCountCheck("killprocess", EXACTLY,1) == -1)
    {
	return;
    }

    if(GetpType(ptr) == INTEGER)
    {
	pid = GetpValue(ptr);
	printf("Kill process with pid %d\n",ValueToInt(pid));
	SetpValue(ptr,AddInt(1));
    }
    else
    {
	SetpValue(ptr,AddInt(0));
    }
    return;
}
*/
