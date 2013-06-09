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
	int mode, tamano, i, j, initialBlockSize;
	char c;
	FILE * InputFile, * tempFile;
	struct stat64 fileStats;
	unsigned char block[8];

	if ((InputFile = fopen(argv[1],"r+")) == NULL)
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

        tamano = (int)fileStats.st_size - 1;

        tempFile = fopen("temp","w+");
        initialBlockSize = createSizeBlock(tempFile,tamano);

        fseeko(InputFile,0,SEEK_SET);
        fseeko(tempFile,0,SEEK_END);
        i = 0;
        while ((c = getc(InputFile)) != EOF)
        {
            block[i] = c;
            i = (i < 7) ? i + 1: 0;

            if (i == 0)
            {
                for (j = 0; j < 8; putc((block[j]),tempFile),j++);
            }
        }

	}
	fclose(InputFile);
	remove(argv[1]);
	fclose(tempFile);
	rename("temp",argv[1]);
	tempFile = fopen(argv[1],"r+");
	printf("Open again %s\n",argv[1]);
	fseeko(tempFile,0,SEEK_SET);
	for(i = 0;i < initialBlockSize;putc('0x7F',tempFile),i ++);
	printf("Bloque inicial de %d borrado\n",initialBlockSize);
	fclose(tempFile);

	return 0;
}

int createSizeBlock(FILE * fd, int fileSize)
{
    char * fileSizeStr, * blockString, * zeros;
    unsigned char block[8];
    int i = 0, j = 0, k = 0;
    int digits, sizePart, charsNeeded, zerosNeeded;

    //guarda posicion actual
    off_t inicialPos = ftello(fd);
    //cambia posicion a inicio
    fseeko(fd,0,SEEK_SET);
    //calcula bloques para descripcion de tamano

    //653520~00000~textoblablabla
    digits = getDigits(fileSize);
    fileSizeStr = malloc(digits * sizeof(* fileSizeStr));
    snprintf(fileSizeStr, sizeof(fileSizeStr),"%d",fileSize);

    sizePart = digits+1; //sizechars~
    charsNeeded = 8 - (sizePart % 8);
    zerosNeeded = charsNeeded - 1;
    if (charsNeeded == 0) {zerosNeeded = 7;}
    if (zerosNeeded > 0)
    {
        zeros = malloc(zerosNeeded * sizeof(* zeros));
        for(i = 0;i < zerosNeeded;i++) sprintf(zeros,"%s%d",zeros,0);
    }
    blockString = malloc(snprintf(NULL,0,"%s~%s~",fileSizeStr,zeros) + 1);
    sprintf(blockString,"%s~%s~",fileSizeStr,zeros);
    printf("blockString: %s\n",blockString);//653520~00000~

    //escribe bloques
    i = 0, j = 0;
    while(i < (int)strlen(blockString))
    {
        block[j] = blockString[i];
        j = (j < 7) ? j + 1: 0;

        if(j == 0)
        {
            for (k = 0; k < 8; putc((block[k]),fd),k++);
        }
        i++;
    }
    printf("Ya escribi tamano en archivo\n");

    //unsigned char buffer[8];
    //cambia a posicion anterior
    fseeko(fd,inicialPos,SEEK_SET);

    i = (int)strlen(blockString);
    printf("Retornar %d\n",i);

    printf("Liberando memo...\n");
    //liberar memoria
    free(fileSizeStr);
    free(zeros);
    free(blockString);
    printf("Liberando memo...\n");
    fileSizeStr = NULL;
    zeros = NULL;
    blockString = NULL;
    printf("Memo liberada...\n");
    return i;
}

void retrieveSizeBlock(FILE * fd, char buffer[8], int fileSize)
{

    return;
}

int getDigits(int num)
{
    int digits = 1;
    while(num > 9)
    {
        num /= 10;
        digits++;
    }
    return digits;
}
