#include "Includes.h"
#pragma once

class Command {
private:
    std::string input;
    std::string command;  // Renamed to avoid conflict with member name
    std::string args;
    std::string implantUser;
    std::string op;
    std::string timeToExec;
    std::string delay;
    std::string file;
    std::string usesmb;
}