#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void PrintHex(unsigned char *buffer, unsigned short length, FILE* output){
    unsigned short i;
    for (i = 0; i<length; i++){
        fprintf(output, "%02X ", *(buffer+i));
    }
    fprintf(output, "\n");
}

typedef struct virus{
    unsigned short SigSize;
    char virusName[16];
    unsigned char* sig;
}virus;

typedef struct link link;
struct link {
    link *nextVirus;
    virus *vir;
};



struct fun_desc{
        char *name;
        link* (*fun)(char*, unsigned int, link*, FILE*);
    };


virus* readVirus(FILE* input, char endian){
    //char *sigSize;
    char buffer[18]; 
    unsigned char *sig;
    unsigned short size;
    size_t isRead;
    //fread(sigSize, 1, 2, input);
    isRead = fread(buffer, 1, 18, input);
    if (isRead == 0)
        return NULL;
    //decode size
    if (endian == 'L')
        size = (unsigned short)((buffer[1]&0xff)<<8) + (unsigned short)(buffer[0]&0xff);
    else
        size = (unsigned short)((buffer[0]&0xff)<<8) + (unsigned short)(buffer[1]&0xff);
    sig = (unsigned char *)(calloc(size , sizeof(char))); 
    fread(sig, 1, size, input);
    virus *output = (virus *)(malloc(sizeof(virus)));
    output->SigSize = size;
    strcpy(output->virusName, buffer+2);
    output->sig = sig;
    return output;
}

void printVirus(virus *virus, FILE *output){
    fprintf(output, "Virus name: %s\n", virus->virusName);
    fprintf(output, "Virus size: %d\n", virus->SigSize);
    PrintHex(virus->sig, virus->SigSize, output);
    fprintf(output, "\n");
}

link* list_print(char *g1, unsigned int g2, link *virus_list, FILE* output){
    link *curr = virus_list;
    while((curr != NULL) && (curr->vir != NULL)){
        printVirus(curr->vir, stdout);
        curr = curr->nextVirus;
    }
    return virus_list;
}
    
 
link* list_append(link* virus_list, virus* data){
     /* Add a new link with the given data to the list 
        (either at the end or the beginning, depending on what your TA tells you),
        and return a pointer to the list (i.e., the first link in the list).
        If the list is null - create a new entry and return a pointer to the entry. */
        if (virus_list->vir == NULL){
            //link *newLink = (link *)(malloc(sizeof(link)));
            virus_list->nextVirus = NULL;
            virus_list->vir = data;
            return virus_list;
        }
        else{
            link *curr = virus_list;
            while (curr->nextVirus != NULL){
                curr = curr->nextVirus;
            }
            link *newLink = (link *)(malloc(sizeof(link)));
            newLink->nextVirus = NULL;
            newLink->vir = data;
            curr->nextVirus = newLink;
            return virus_list;
        }
        //link *newLink = (link *)(malloc(sizeof(link));
        //newLink->nextVirus = virus_list;
        //newLink->vir = data;
        //return newLink;
}

 
void list_free(link *virus_list){
/* Free the memory allocated by the list. */
    link *curr = virus_list;
    link *next;
    if (virus_list != NULL){
        while (curr->nextVirus != NULL){
            next = curr->nextVirus;
            free((curr->vir)->sig);
            free(curr->vir);
            free(curr);
            curr = next;
        }
        free(curr);
    }


}

link* LoadSig(char *g1, unsigned int g2, link* virusList, FILE* input){
    char fileName[50];
    char endian[1];
    fgets(fileName, 50, stdin);
    sscanf(fileName, "%s", fileName);
    input = fopen(fileName, "r");
    fseek(input, 3, SEEK_SET);
    fread(endian, 1, 1, input);
    fseek(input, 4, SEEK_SET);
    while (!feof(input)){
        virusList = list_append(virusList, readVirus(input, endian[0]));
    }
    rewind(input);
    fclose(input);
    return virusList;
}

link* detect_virus(char *fileName, unsigned int size, link *virus_list, FILE *output){
    unsigned int i;
    char buffer[10000];
    unsigned min;
    unsigned suspected_size;
    //set suspected file
    FILE* suspected = fopen(fileName, "r");
    fseek(suspected, 0L, SEEK_END);
    suspected_size = (unsigned int)(ftell(suspected));
    rewind(suspected);
    min = 10000 > suspected_size ? suspected_size : 10000;
    fread(buffer, min, 1, suspected);
    link *curr = virus_list;
     while((curr != NULL) && (curr->vir != NULL)){
        for (i=0; i < size-(curr->vir)->SigSize; i++){
            if (memcmp((curr->vir)->sig, buffer+i, (curr->vir)->SigSize) == 0)
                fprintf(output, "Starting byte: %d\nVirus Name: %s\nVirus Signature Size: %d\n", i, (curr->vir)->virusName,(curr->vir)->SigSize);
        }
        curr = curr->nextVirus;
    }
    fclose(suspected);
    return virus_list;
    
}

void kill_virus(char *fileName, int signatureOffset, int signatureSize){
    char toWrite[signatureSize];
    int i;
    for (i=0; i < signatureSize; i++){
        toWrite[i] = 0x90;
    }
    FILE *suspected = fopen(fileName, "r+");
    fseek(suspected, signatureOffset, SEEK_SET);
    fwrite(toWrite, 1, signatureSize, suspected);
    fclose(suspected);
}

link* kill_virus_wrapper(char *fileName, unsigned int g1, link *g2, FILE *g3){
    char buffer[50];
    int sigOffset;
    int sigSize;
    printf("Enter starting byte location: ");
    fgets(buffer, 50, stdin);
    sscanf(buffer, "%d", &sigOffset);
    printf("Enter signature size: ");
    fgets(buffer, 50, stdin);
    sscanf(buffer, "%d", &sigSize);
    kill_virus(fileName, sigOffset, sigSize);
    return g2;
}


int main(int argc, char **argv) {
    struct fun_desc menu[5] = { {"Load signatures", LoadSig},
                                {"Print signatures", list_print},
                                {"Detect viruses", detect_virus},
                                {"Fix file", kill_virus_wrapper},
                                {NULL, NULL}
                                };
    char func_num[50];
    int op;
    int i;
    int bound;
    bound = sizeof(menu)/sizeof(struct fun_desc) - 1;
    link *virusList = (link *)malloc(sizeof(link));
    virusList->vir = NULL;

    //set output file for detetcted viruses
    FILE *detected_output = fopen("output", "w");
    
    while (1){
        op = -1;
        printf("Please choose a function:\n");
        for (i=0; i < (sizeof(menu)/sizeof(struct fun_desc))-1; i++){
            printf("%i) %s\n", i+1, (menu+i)->name);
        }
        printf("Option: ");
        fgets(func_num, 50, stdin);
        sscanf(func_num, "%d", &op);
            if (op < 1 || op > bound){
                printf("Not within bounds\n");
                fclose(detected_output);
                list_free(virusList);
                exit(0);
            }
            else{
                printf("Within bounds\n");
                virusList = (menu[func_num[0] - 49].fun)(argv[1], 0, virusList, detected_output);
                printf("DONE.\n\n");
            }
        
    }
    //list_free(virusList);
    
}