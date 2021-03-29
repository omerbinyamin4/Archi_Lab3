#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void PrintHex(unsigned char *buffer, short length, FILE* output){
    int i;
    for (i = 0; i<length; i++){
        fprintf(output, "%hhX ", *(buffer+i));
    }
    fprintf(output, "\n");
}

typedef struct virus{
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
}virus;

virus* readVirus(FILE* input){
    //char *sigSize;
    char *buffer = (char *)calloc(18, sizeof(char));
    unsigned char *sig;
    unsigned short size;
    //fread(sigSize, 1, 2, input);
    fread(buffer, 1, 18, input);
    //decode size
    size = (unsigned short)((buffer[1]&0xff)<<8) + (unsigned short)(buffer[0]&0xff);
    sig = (unsigned char *)(calloc(size , sizeof(char)));
    fread(sig, 1, size, input);
    virus *output = (virus *)(malloc(sizeof(virus)));
    output->SigSize = size;
    strcpy(output->virusName, buffer+2);
    //free(buffer); //?
    output->sig = sig;
    return output;
}

void printVirus(virus *virus, FILE *output){
    fprintf(output, "Virus name: %s\n", virus->virusName);
    fprintf(output, "Virus size: %d\n", virus->SigSize);
    PrintHex(virus->sig, virus->SigSize, output);
    fprintf(output, "\n");
}

int main(int argc, char **argv) {
    FILE *input = fopen(argv[1], "r");
    //fseek(input, 4, 0);
    while (feof(input) != 0){
        printf("test\n");
        virus *curr = readVirus(input);
        printVirus(curr, stdout);
        free(curr);
    }
    fclose(input);
}