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
    FILE * archivo;
    char c;
    char * buffer, * buffer2;
    int cantidadChars;
    off_t posActual;

    if ((archivo = fopen(argv[1],"r")) == NULL)
	{
		printf("tdes: file not found: %s\n",argv[1]);
	}
	else
	{
        //reposiciono en archivo
        fseeko(archivo,0,SEEK_SET);
        //leo cantidad original de chars
        buffer = malloc(255 * sizeof(* buffer));
        while ((c = getc(archivo)) != '~')
        {
            sprintf(buffer,"%s%c",buffer,c);
        }
        printf("Buffer: %s\n",buffer);
        posActual = ftello(archivo);
        printf("Pos actual: %d\n",(int)posActual);

        //int cantidad = atoi(newbuffer);
        //sscanf(buffer, "%d", &cantidadChars);
        int cantidadChars = strtol(buffer, NULL, 10);
        //int cantidad = strtol(buffer, &buffer, 10);

        printf("Cantidad: %d\n",cantidadChars);
        free(buffer);
        buffer = NULL;

        posActual = ftello(archivo);
        printf("Pos actual: %d\n",(int)posActual);

        buffer = malloc(255 * sizeof(* buffer));
        while ((c = getc(archivo)) != '~')
        {
            sprintf(buffer,"%s%c",buffer,c);
        }
        printf("Buffer: %s\n",buffer);
        free(buffer);
        buffer = NULL;

        posActual = ftello(archivo);
        printf("Pos actual: %d\n",(int)posActual);

        buffer2 = malloc(255 * sizeof(* buffer2));
        while (cantidadChars != 0)
        {
            c = getc(archivo);
            sprintf(buffer2,"%s%c",buffer2,c);
            cantidadChars--;
        }
        printf("Buffer: %s\n",buffer2);
        free(buffer2);
        buffer2 = NULL;


        fclose(archivo);
	}

	return 0;
}
