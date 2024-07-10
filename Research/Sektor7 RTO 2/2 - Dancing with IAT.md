# Import Directory

```c
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
	union {
		DWORD Characteristics;
		DWORD OriginalFirstThunk;      // RVA of Import Lookup Tbl
	} DUMMYUNIONNAME;
	
	DWORD TimeDateStamp;
	DWORD ForwarderChain;
	DWORD Name;                        // Name of imported DLL
	DWORD FirstThunk;                  // RVA of Import Address Tbl
} IMAGE_IMPORT_DESCRIPTOR;
```

#### Parsing

![[Pasted image 20221029160512.png]]

