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
        link* (*fun)(void*, unsigned int, link*, FILE*);
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
    sig = (unsigned char *)(calloc(size , sizeof(char))); //freed in 52
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

link* list_print(void *g1, unsigned int g2, link *virus_list, FILE* output){
    link *curr = virus_list;
    while((curr != NULL) && (curr->vir != NULL)){
        printVirus(curr->vir, output);
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
            link *newLink = (link *)(malloc(sizeof(link)));
            newLink->nextVirus = NULL;
            newLink->vir = data;
            return newLink;
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

        free((curr->vir)->sig);
        free(curr->vir);
        free(curr);
    }

}

link* LoadSig(void *g1, void *g2, link* virusList, FILE* input){
    char fileName[50];
    char endian[1];
    fgets(fileName, 50, stdin);
    sscanf(fileName, "%s", fileName);
    printf("%s\n", fileName);
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

link* detect_virus(char *buffer, unsigned int size, link *virus_list, FILE *output){
    unsigned int i;
    link *curr = virus_list;
     while((curr != NULL) && (curr->vir != NULL)){
        for (i=0; i < size-(curr->vir)->SigSize; i++){
            if (memcmp((curr->vir)->sig, buffer+i, (curr->vir)->SigSize) == 0)
                fprintf(output, "Starting byte: %d\nVirus Name: %s\nVirus Signature Size: %d\n", i, (curr->vir)->virusName,(curr->vir)->SigSize);
        }
        curr = curr->nextVirus;
    }
    
}

int main(int argc, char **argv) {
    struct fun_desc menu[4] = { {"Load signatures", LoadSig},
                                {"Print signatures", list_print},
                                {"Detect viruses", detect_virus},
                                {NULL, NULL}
                                };
    char func_num[50];
    int op;
    int i;
    int bound;
    unsigned int suspected_size;
    unsigned min;
    char buffer[10000];
    
    FILE* suspected = fopen(argv[1], "r");
    fseek(suspected, 0L, SEEK_END);
    suspected_size = (unsigned int)(ftell(suspected));
    rewind(suspected);

    min = 10000 > suspected_size ? suspected_size : 10000;
    
    fread(buffer, min, 1, suspected);

    bound = sizeof(menu)/sizeof(struct fun_desc) - 1;
    link *virusList = (link *)malloc(sizeof(link));
    
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
                exit(0);
            }
            else{
                printf("Within bounds\n");
                virusList = (menu[func_num[0] - 49].fun)(buffer, min, virusList, stdout);
                printf("DONE.\n\n");
            }
        
    }
    list_free(virusList);
}