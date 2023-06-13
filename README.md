# Server

First off, the server will contain the following things:

1. APIs:

    1. API `registerNewImplant` to register the implant that will contain the information in order to be inserted into the database
    2. API `sendNextInstruction` to hold the next instruction which the operator will send for the implant
    3. API `receiveImplantOutput` to hold the output of the instruction that was executed on the implant
    4. API `operator` to hold all necessary information about the operator controlling the framework
        
    These APIs will be implemented using JSON with the following structure:
    - `registerNewImplant` :
    ```json
    {
        "implantId" : "<ID of the implant, Genesis do this using maybe like a simple MD5 hash of the device name>",
        "deviceName" : "<Name of the device/computer that has the implant running>",
        "username" : "<Username of the victim that has the implant running>",
        "operatorId": "<ID of the operator controlling the implant>",
        "cpuArchitecture" : "<Architecture of the computer CPU>",
        "gpuInformaton" : "<Information about the graphical processing unit>",
        "ramInformation" : "<Amount of Random Access Memory>",
        "operatingSystem" : "<Operating System the victim is running>",
        "networkInformation" : "<Information about the network the victim is connected to>",
        "currentDate" : "<Date which the implant registered for the first time>"
    }
    ```
    - `sendNextInstruction` :
    ```json
    {
        "implantId" : "<ID of the implant to which the instruction will be sent to. '*' if the instruction would be for all implants connected>",
        "operatorId" : "<ID of the operator sending the instruction>",
        "instructionId" : "<ID of the instruction which the implant will look for in the Module Handler>",
        "timeToExec" : "<Specify when the implant will execute said instruction. Leave as '0' if it will be executed immediately>",
        "delay" : "<Specify the delay which the implant will execute an instruction>"
    }
    ```
    - `receiveImplantOutput`:
    ```json
    {
        "implantId" : "<ID of the implant sending the output of an instruction>",
        "operatorId" : "<ID of the operator who will receive the output>",
        "output" : "<Output of the instruction that was executed>",
        "dateFromLast" : "<Time the last instruction was executed in the implant and the output was received>"
    }
    ```
    - `operator`:
    ```json
    {
        "id" : "<ID of the operator>",
        "username" : "<Hold the username handle of the operator>",
        "password" : "<Hold encrypted password of the operator>",
        "dateRegistered" : "<Date which the operator was registered and created>",
        "firstName" : "<First name of the operator>",
        "lastName" : "<Last name of the operator>",
        "email" : "<Registered email of the operator>",
        "phoneNumber" : "<Phone number of the operator>"
    }
    ```