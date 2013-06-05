/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *|
 *				main.c
 * 
 *	Pruebas para el TDES File Cleaner
 *	Copyright 2013 Ana Irina Calvo Carvajal, TEC, Costa Rica
 *	Email: acalvo@ic-itcr.ac.cr / anairinac@gmail.com
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define __USE_LARGEFILE64
#define _LARGEFILE_SOURCE
#define _LARGEFILE64_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int argc, char * argv[])
{
	int mode;
	FILE * InputFile, * OutputFile;
	struct stat64 fileStats;
	
	if ((InputFile = fopen(argv[1],"r")) == NULL) 
	{
		printf("tdes: file not found: %s\n",argv[1]);
	}
	else 
	{
		if(stat64(argv[1], &fileStats) == -1)
		{
			perror("fstat");
			return 1;
		}
		
		printf("Filename: %s\n",argv[1]);		
		printf("File size in bytes: %ld\n", fileStats.st_size);
		printf("Block size in op: %ld\n", fileStats.st_blksize);
	}
	
	fclose(InputFile);
	return 0;
}
