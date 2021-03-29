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
        link* (*fun)(link*, FILE*);
    };


virus* readVirus(FILE* input){
    //char *sigSize;
    char buffer[18]; 
    unsigned char *sig;
    unsigned short size;
    //fread(sigSize, 1, 2, input);
    fread(buffer, 1, 18, input);
    //decode size
    size = (unsigned short)((buffer[1]&0xff)<<8) + (unsigned short)(buffer[0]&0xff);
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

link* list_print(link *virus_list, FILE* output){
    link *curr = virus_list;
    while(curr->vir != NULL){
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
        if (virus_list == NULL){
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

link* LoadSig(link* virusList, FILE* input){
    char fileName[50];
    fgets(fileName, 50, stdin);
    input = fopen(fileName, "r");
    while (!feof(input)){
        virusList = list_append(virusList, readVirus(input));
    }
    return virusList;
}

int main(int argc, char **argv) {
    struct fun_desc menu[4] = { {"Load signatures", LoadSig},
                                {"Print signatures", list_print},
                                {"Detect viruses", list_print},
                                {NULL, NULL}
                                };
    char func_num[50];
    int op;
    int i;
    int bound;

    bound = sizeof(menu)/sizeof(struct fun_desc) - 2;
    link *virusList = (link *)malloc(sizeof(link));
    
    while (1){
        op = -1;
        printf("Please choose a function:\n");
        for (i=0; i < (sizeof(menu)/sizeof(struct fun_desc))-1; i++){
            printf("%i) %s\n", i, (menu+i)->name);
        }
        printf("Option: ");
        fgets(func_num, 50, stdin);
        sscanf(func_num, "%d", &op);
            if (op < 0 || op > bound){
                printf("Not within bounds\n");
                exit(0);
            }
            else{
                printf("Within bounds\n");
                virusList = (menu[func_num[0] - 48].fun)(virusList, stdout);
                printf("DONE.\n\n");
            }
        
    }
}