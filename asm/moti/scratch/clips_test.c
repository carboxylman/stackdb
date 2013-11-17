//#include<stdio.h>
#include "clips.h"
#include "clips_test.h"
/*void main()
{
    InitializeEnvironment();
    printf("Loding initial condtructs\n");
    Load("policies.clp");
    Reset();
    Run(-1L);
}
*/
void killprocess_func( DATA_OBJECT_PTR ptr)
{
    void * pid;

    if(ArgCountCheck("killprocess", EXACTLY,1) == -1)
    {
	return;
    }

    if(GetpType(ptr) == INTEGER)
    {
	pid = GetpValue(ptr);
	printf("Kill process with pid %d\n",ValueToDouble(pid));
	SetpValue(ptr,AddDouble(1));
    }
    else
    {
	SetpValue(ptr,AddDouble(0));
    }
    return;
}
    
    

