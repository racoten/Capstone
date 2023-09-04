#define MAX_BUFFER_SIZE 4096

typedef struct {
    char Input[MAX_BUFFER_SIZE];
    char ImplantUser[MAX_BUFFER_SIZE];
    char Operator[MAX_BUFFER_SIZE];
    char TimeToExec[MAX_BUFFER_SIZE];
    char Delay[MAX_BUFFER_SIZE];
    char File[MAX_BUFFER_SIZE];
    char Cmd[MAX_BUFFER_SIZE];
    char NullTerm[MAX_BUFFER_SIZE];
} Command;

typedef struct {
    char ID[256];
    char DeviceName[256];
    char Username[256];
    char OperatorID[256];
    char CPUArchitecture[256];
    char GPUInfo[256];
    char RAMInfo[256];
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

typedef struct NetAssembly {
    char* Name;
    unsigned char* Bytes;
    char* Namespace;
    char* Method;
    char* Args;
};