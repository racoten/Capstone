Portable Executable (PE) is the file format for executables on Windows. A few examples of PE file extensions are `.exe`, `.dll`, `.sys` and `.scr`. This module discusses the PE structure which is important to know when building or reverse engineering malware.

Note that this module and future modules will often interchangeably refer to executables (e.g. EXEs, DLLs) as "Images".

# PE Structure

![[Pasted image 20231218124835.png]]

# DOS Header (IMAGE_DOS_HEADER)

The first header is always prefixed with two bytes, `0x4D` and `0x5A`, commonly referred to as `MZ`.  They represent the DOS header signature and they are used to confirm that the file is a valid PE. The data structure for the DOS header is defined as follows:
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

The most important members of the struct are `e_magic` and `e_lfanew`:
- `e_magic` is 2 bytes with a fixed value of `0x5A4D` or `MZ`.
- `e_lfanew` is a 4-byte value that holds an offset to the start of the NT Header. Note that `e_lfanew` is always located at an offset of `0x3C`.
#### DOS Stub

Before moving on to the NT header structure, there is the DOS stub which is an error message that prints "This program cannot be run in DOS mode" in case the program is loaded in [DOS mode](https://en.wikipedia.org/wiki/DOS) or "Disk Operating Mode". It is worth noting that the error message can be changed by the programmer at compile time. This is not a PE header, but it's good to be aware of it.

# NT Header (IMAGE_NT_HEADERS)

The NT header incorporates two important other images: `FileHeader` and `OptionalHeader` which include a large amount of information about the PE. This header contains a signature to verify in the form of a string "PE" which is represented as `0x50` and `0x45`. But since the signature is a `DWORD`, it is represented as `0x50450000`. The NT Header can be reached from the DOS Header via the `IMAGE_DOS_HEADER->e_lfanew` member.

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

The only difference is the `OptionalHeader` data structure, `IMAGE_OPTIONAL_HEADER32` and `IMAGE_OPTIONAL_HEADER64`.

# File Header (IMAGE_FILE_HEADER)

The `IMAGE_FILE_HEADER` provides essential information for loading and executing a PE file. It defines key characteristics of the file, like the machine type and the structure of the file (number of sections, presence of symbol table, etc.). This information is crucial for the operating system to correctly map the executable into memory and execute it.

The File Header structure is as follows:
```c
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

The most important struct members are:
- `NumberOfSections` - The number of sections in the PE file (discussed later).
- `Characteristics` - Flags that specify certain attributes about the executable file, such as whether it is a dynamic-link library (DLL) or a console application.
- `SizeOfOptionalHeader` - The size of the following optional header.

Additional information about the file header can be found on the [official documentation page](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_file_header).

# Optional Header (IMAGE_OPTIONAL_HEADER)

The Optional Header is important although it is called "Optional" because some PEs may not have it. 

The optional header has two versions, a version for 32-bit and 64-bit systems. Both versions have nearly identical members in their data structure with the main difference being the size of some members. `ULONGLONG` is used in the 64-bit version and `DWORD` in the 32-bit version. Additionally, the 32-bit version has some members which are not found in the 64-bit version.

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
- `Magic` - Describes the state of the image file (32 or 64-bit image)
- `MajorOperatingSystemVersion` - The major version number of the required operating system (e.g. 11, 10)
- `MinorOperatingSystemVersion` - The minor version number of the required operating system (e.g. 1511, 1507, 1607)
- `SizeOfCode` - The size of the `.text` section (Discussed later)
- `AddressOfEntryPoint` - Offset to the entry point of the file (Typically the _main_ function)
- `BaseOfCode` - Offset to the start of the `.text` section
- `SizeOfImage` - The size of the image file in bytes
- `ImageBase` - It specifies the preferred address at which the application is to be loaded into memory when it is executed. However, due to Window's memory protection mechanisms like Address Space Layout Randomization (ASLR), it's rare to see an image mapped to its preferred address because the Windows PE Loader maps the file to a different address. This random allocation done by the Windows PE loader will cause issues in the implementation of future techniques because some addresses that are considered constant were changed. The Windows PE loader will then go through _PE relocation_ to fix these addresses.
- `DataDirectory` - One of the most important members in the optional header. This is an array of [IMAGE_DATA_DIRECTORY](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_data_directory), which contains the directories in a PE file (discussed below).

# Data Directory (IMAGE_DATA_DIRECTORY)

The Data Directory is a data structure that has the following format:
```c
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```

It can be accessed by the last member of the Optional Header. 

The Data Directory is an array of size `IMAGE_NUMBER_OF_DIRECTORY_ENTRIES` which is a constant value of 16. Each element represents a data directory that contains information about a PE section or Data Table. We can access an index in this array as follows:
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

The two important sections are the Export Directory and the Import Address Table.
## Export Directory

A PE's export directory is a data structure that contains information about functions and variables that are exported from the executable. It contains the addresses of the exported functions and variables, which can be used by other executable files to access the functions and data. The export directory is generally found in DLLs that export functions (e.g. `kernel32.dll` exporting `CreateFileA`).

## Import Address Table

The import address table is a data structure in a PE that contains information about the addresses of functions imported from other executable files. The addresses are used to access the functions and data in the other executables (e.g. `Application.exe` importing `CreateFileA` from `kernel32.dll`).

# PE Sections

PE sections contain the code and data used to create an executable program. Each PE section is given a unique name and typically contains executable code, data, or resource information. There is no constant number of PE sections because different compilers can add, remove or merge sections depending on the configuration. Some sections can also be added later on manually, therefore it is dynamic and the `IMAGE_FILE_HEADER.NumberOfSections` helps determine that number.

The following PE sections are the most important ones and exist in almost every PE.

- `.text` - Contains the executable code which is the written code.
- `.data` - Contains initialized data which are variables initialized in the code.
- `.rdata` - Contains read-only data. These are constant variables prefixed with `const`.
- `.idata` - Contains the import tables. These are tables of information related to the functions called using the code. This is used by the Windows PE Loader to determine which DLL files to load to the process, along with what functions are being used from each DLL.
- `.reloc` - Contains information on how to fix up memory addresses so that the program can be loaded into memory without any errors.
- `.rsrc` - Used to store resources such as icons and bitmaps

Each PE section has an [IMAGE_SECTION_HEADER](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-image_section_header) data structure that contains valuable information about it. These structures are saved under the NT headers in a PE file and are stacked above each other where each structure represents a section.

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

- `Name` - The name of the section. (e.g. .text, .data, .rdata).
- `PhysicalAddress` or `VirtualSize` - The size of the section when it is in memory.
- `VirtualAddress` - Offset of the start of the section in memory.
### Additional References

In case further clarification is required on certain sections, the following blog posts on [0xRick's Blog](https://0xrick.github.io/) are highly recommended.

- PE Overview - [https://0xrick.github.io/win-internals/pe2/](https://0xrick.github.io/win-internals/pe2/)
- DOS Header, DOS Stub and Rich Header - [https://0xrick.github.io/win-internals/pe3/](https://0xrick.github.io/win-internals/pe3/)
- NT Headers - [https://0xrick.github.io/win-internals/pe4/](https://0xrick.github.io/win-internals/pe4/)
- Data Directories, Section Headers and Sections - [https://0xrick.github.io/win-internals/pe5/](https://0xrick.github.io/win-internals/pe5/)
- PE Imports (Import Directory Table, ILT, IAT) - [https://0xrick.github.io/win-internals/pe6/](https://0xrick.github.io/win-internals/pe6/)