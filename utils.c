#include <string.h>
#include <stdio.h>
#include "utils.h"

int getNum(char ch)
{
    int num=0;
    if(ch>='0' && ch<='9')
    {
        num = ch - 0x30;
    }
    else
    {
        switch(ch)
        {
            case 'A': case 'a': num=10; break;
            case 'B': case 'b': num=11; break;
            case 'C': case 'c': num=12; break;
            case 'D': case 'd': num=13; break;
            case 'E': case 'e': num=14; break;
            case 'F': case 'f': num=15; break;
            default: num=0;
        }
    }
    return num;
}

unsigned int hex2int(unsigned char hex[])
{
    unsigned int x = 0;
    int power = 1;
    for (int i = strlen(hex) - 1; i >= 0; --i)
    {
    	x += getNum(hex[i]) * power;
    	power *= 16;
    }
    return x;
}

unsigned int char2int(unsigned char hex[])
{
    unsigned int x = 0;
    int power = 1;
    for (int i = strlen(hex) - 1; i >= 0; --i)
    {
    	x += getNum(hex[i]) * power;
    	power *= 10;
    }
    return x;
}