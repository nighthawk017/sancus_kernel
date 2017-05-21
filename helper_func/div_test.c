#include<stdio.h>

int main() {
	
	unsigned long result ,a;
	a = 66;
	result = ((unsigned long)a * (unsigned long)0xBA2F);
	printf("result=%lu\n",result);
	result = (result >> 16) >> 3;
	printf("result=%lu\n",result);
	
	return 0;

}
