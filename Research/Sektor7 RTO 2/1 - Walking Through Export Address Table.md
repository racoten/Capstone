# Export Directory
```c
typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD Characteristics;
	DWORD TimeDateStamp;
	WORD MajorVersion;
	WORD MinorVersion;
	DWORD Name;                   // Name of DLL
	DWORD Base;                   // First ordinal number
	DWORD NumberOfFuctions        // Number of entries in EAT
	DWORD NumberOfNames;          // Number of entries in (1)(2)
	DWORD AddressOfFunctions;     // Export Address Table
	DWORD AddressOfNames;         // Pointers to names (1)
	DWORD AddressOfNameOrdinals;  // Array of indexes to EAT (2)
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

#### Parsing Tables

![[Pasted image 20221029152847.png]]

