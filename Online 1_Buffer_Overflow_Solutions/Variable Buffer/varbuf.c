#include<stdlib.h>
#include<stdio.h>
#include<string.h>

#ifndef BUF_SIZE
#define BUF_SIZE 100
#endif

void dummy_function(char *str);

int bof(char *str)
{
	char buffer[BUF_SIZE];
	strcpy(buffer, str);
	return 1;
}
int main(int argc, char **argv)
{
	char str[517];
	FILE *badfile;
	
	badfile = fopen("badfile", "rb");
	
	if(!badfile)
	{
		perror("Opening badfile");
		exit(1);
	}
	
	int length = fread(str, sizeof(char), 517, badfile);
	printf("Buffer size %d\n", BUF_SIZE);
	dummy_function(str);
	fprintf(stdout, "returned properly\n");
	return 1;
}
void dummy_function(char *str)
{
	char dummy_buffer[1000];
	memset(dummy_buffer, 0, 1000);
	bof(str);
}