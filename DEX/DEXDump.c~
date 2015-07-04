#include<stdio.h>
#include<fcntl.h>
#include "DEXDump.h"


int main(int argc , char **argv)
{
    int boolean;
    
    if(argc == 2)
    {
       boolean = OpenDex(argv[1]);
       if(boolean  == 0){
          return -1;
       }
       ReadDexFile(boolean);
    }
    return 0;
}
