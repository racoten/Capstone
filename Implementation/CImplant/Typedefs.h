typedef struct {
    char Input[256];
    unsigned char* ImplantUser[256];
    unsigned char* Operator[256];
    char TimeToExec[256];
    char Delay[256];
    unsigned char* File[256];
    unsigned char* Command[256];
} Command;

typedef struct {
    char ID[256];
    char DeviceName[256];
    char Username[256];
    char OperatorID[256]; // int type instead of string
    char CPUArchitecture[256];
    char GPUInfo[256];
    char RAMInfo[256]; // int type instead of string
    char OSName[256];
    char NetworkInfo[256];
    char CurrentDate[256];
} Victim;

typedef struct Output {
    char *ImplantID;
    char *Operator;
    char *Output;
    char *DateFromLast;
} Output;
