#include <stdio.h>
#include <stdlib.h>

#define LINE_MAX_BUFFER_SIZE 256

int runCmd(char cmd[LINE_MAX_BUFFER_SIZE], char lines[][256]) {
	FILE *fp;
	char path[LINE_MAX_BUFFER_SIZE];

	fp = _popen(cmd, "r");
	if (fp == NULL) {
		return -1;
	}

	int count = 0;
	while (fgets(path, sizeof(path), fp) != NULL) {
		strncpy(lines[count++], path, LINE_MAX_BUFFER_SIZE);
	}
	_pclose(fp);

	return count;
}