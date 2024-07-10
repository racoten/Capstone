- Allocate a virtual memory space
- Copy headers and sections from the loaded PE into that space
- Go through the the IAT of the loaded PE to resolve its functions dinamically
- Fix all relocations in the PE
- Call the entry point of the PE

https://github.com/stephenfewer/ReflectiveDLLInjection/blob/master/dll/src/ReflectiveLoader.c

# Step 0
We begin calling our `ReflectiveLoader()` function.
```c
DLLEXPORT ULONG_PTR WINAPI ReflectiveLoader( VOID )
```

Calculate our images current base address
```c
uiLibraryAddress = caller();
```

`caller()` is a function built into the compiler, we puts the `ReturnAddress();` function into the binary. It returns the Return Address of caller and is taken from the stack.
```c
__declspec(noinline) ULONG_PTR caller( VOID ) { return (ULONG_PTR)_ReturnAddress(); }
```

`ulibraryAddress` will hold the next instruction's address as a return address from the stack

Now we look through the memory backwards searching for our image's base address in look for the `IMAGE_DOS_SIGNATURE` ANSI magic value in memory.
```c
	// we dont need SEH style search as we shouldnt generate any access violations with this
	while( TRUE )
	{
		if( ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_magic == IMAGE_DOS_SIGNATURE )
```

When it's found, we make sure to jump to the PE header, NT header structure
```c
uiHeaderValue = ((PIMAGE_DOS_HEADER)uiLibraryAddress)->e_lfanew;
```

Then check if we actually reached the NT header
```c
uiHeaderValue += uiLibraryAddress;
// break if we have found a valid MZ/PE header
if( ((PIMAGE_NT_HEADERS)uiHeaderValue)->Signature == IMAGE_NT_SIGNATURE )
```

# Step 1

We need to process the kernel exports

Locate virtual address functions in memory  in kernel32 and ntdll

We can do this with the PEB. We can get the PEB by reading `0x60` bytes for 64 bit or `0x30` for 32 bit from the gs/fs keyword
```c
#ifdef WIN_X64
	uiBaseAddress = __readgsqword( 0x60 );
#else
#ifdef WIN_X86
	uiBaseAddress = __readfsdword( 0x30 );
#else WIN_ARM
	uiBaseAddress = *(DWORD *)( (BYTE *)_MoveFromCoprocessor( 15, 0, 13, 0, 2 ) + 0x30 );
#endif
#endif 
```

We now jump to the `Ldr` member
```c
uiBaseAddress = (ULONG_PTR)((_PPEB)uiBaseAddress)->pLdr;
```

We then jump to the `InMemoryOrderModuleList` linked list
```c
uiValueA = (ULONG_PTR)((PPEB_LDR_DATA)uiBaseAddress)->InMemoryOrderModuleList.Flink;
```

And we iterate through the Flink

We start by getting the name and size of the DLL
```c
while( uiValueA )
	{
		// get pointer to current modules name (unicode string)
		uiValueB = (ULONG_PTR)((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.pBuffer;
		// set bCounter to the length for the loop
		usCounter = ((PLDR_DATA_TABLE_ENTRY)uiValueA)->BaseDllName.Length;
		// clear uiValueC which will store the hash of the module name
		uiValueC = 0;
```

We then try to look for the `kernel32` dll
```c
if( (DWORD)uiValueC == KERNEL32DLL_HASH )
```

The comparison is not done as string but as a hash, so we compute the hash of the DLL current residing in `uiValueB`
```c
// compute the hash of the module name...
		do
		{
			uiValueC = ror( (DWORD)uiValueC );
			// normalize to uppercase if the madule name is in lowercase
			if( *((BYTE *)uiValueB) >= 'a' )
				uiValueC += *((BYTE *)uiValueB) - 0x20;
			else
				uiValueC += *((BYTE *)uiValueB);
			uiValueB++;
		} while( --usCounter );
```

If we find it, we go through the Export Directory
```c
// uiNameArray = the address of the modules export directory entry
uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
```

And now we iterate 3 times to look for `LoadLibraryA` , `GetProcAddress` and `VirtualAlloc`
```c
if( dwHashValue == LOADLIBRARYA_HASH )
	pLoadLibraryA = (LOADLIBRARYA)( uiBaseAddress + DEREF_32( uiAddressArray ) );
else if( dwHashValue == GETPROCADDRESS_HASH )
	pGetProcAddress = (GETPROCADDRESS)( uiBaseAddress + DEREF_32( uiAddressArray ) );
else if( dwHashValue == VIRTUALALLOC_HASH )
	pVirtualAlloc = (VIRTUALALLOC)( uiBaseAddress + DEREF_32( uiAddressArray ) );
```

Now we go for NTDLL
```c
else if( (DWORD)uiValueC == NTDLLDLL_HASH )
```

We again get the Export Directory
```c
uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
```

And we look for `NtFlushInstructionCache`
```c
if( dwHashValue == NTFLUSHINSTRUCTIONCACHE_HASH )
	pNtFlushInstructionCache = (NTFLUSHINSTRUCTIONCACHE)( uiBaseAddress + DEREF_32( uiAddressArray ) );
```

# Step 2

After finding all 4 functions, we start loading our image to memory

We first create a memory region using `VirtualAlloc`
```c
uiBaseAddress = (ULONG_PTR)pVirtualAlloc( NULL, ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfImage, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE );
```

Copy the headers into the new region
```c
uiValueA = ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.SizeOfHeaders;
uiValueB = uiLibraryAddress;
uiValueC = uiBaseAddress;

// Like memcpy
while( uiValueA-- )
	*(BYTE *)uiValueC++ = *(BYTE *)uiValueB++;
```

# Step 3

Now we will load our sections

Locate the Section Headers
```c
uiValueA = ( (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader + ((PIMAGE_NT_HEADERS)uiHeaderValue)->FileHeader.SizeOfOptionalHeader );
```

We can then start parsing the section headers

We get the address of the section
```c
uiValueB = ( uiBaseAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->VirtualAddress );
```

Get a address to the data
```c
uiValueC = ( uiLibraryAddress + ((PIMAGE_SECTION_HEADER)uiValueA)->PointerToRawData );
```

And then copy the data into the address of the section
```c
while( uiValueD-- )
	*(BYTE *)uiValueB++ = *(BYTE *)uiValueC++;
```

# Step 4

We start resolving now the functions of the Import Address Table

First get the address of the import directory
```c
uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
```

Load the first library from the IAT
```c
uiLibraryAddress = (ULONG_PTR)pLoadLibraryA( (LPCSTR)( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->Name ) );
```

Parse the import table in our own module
```c
uiValueD = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->OriginalFirstThunk );
```

Save the address of IAT
```c
uiValueA = ( uiBaseAddress + ((PIMAGE_IMPORT_DESCRIPTOR)uiValueC)->FirstThunk );
```

Extract the address of a function from the loaded library

Reach out to the export table, but only if we are dealing with ordinals
```c
if( uiValueD && ((PIMAGE_THUNK_DATA)uiValueD)->u1.Ordinal & IMAGE_ORDINAL_FLAG )
	uiNameArray = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];
```

And the get the address of the function
```c
DEREF(uiValueA) = ( uiLibraryAddress + DEREF_32(uiAddressArray) );
```

If we are dealing with the name, we can just the `GetProcAddress`
```c
else
	DEREF(uiValueA) = (ULONG_PTR)pGetProcAddress( (HMODULE)uiLibraryAddress, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)uiValueB)->Name );
```

# PE Relocations

Nowadays, binaries can be loaded in memory at any address

But they contain a preferred image base

And they have that as hardcoded address

They can crash because the system can load them at any address different from the hardcoded one

To fix this, the `Linker` adds a relocation option

Which is a map of the hardcoded addresses in memory

The relocation section is a set of blocks of type `IMAGE_BASE_RELOCATION`. Each block contains that structure and is followed by a 2 byte record.

Each block is a specific map with locations where the relocation should be applied

The first byte record is a relocation type:
![[Pasted image 20230730010601.png]]

# Step 5

Calculate delta of base address to do relocations
```c
uiLibraryAddress = uiBaseAddress - ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.ImageBase;
```

Jump to the `IMAGE_DIRECTORY_ENTRY_BASERELOC`
```c
uiValueB = (ULONG_PTR)&((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
```

If it's there, we parse it by getting the first block
```c
while( ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock )
```

Get the address of the relocation block
```c
uiValueA = ( uiBaseAddress + ((PIMAGE_BASE_RELOCATION)uiValueC)->VirtualAddress );
```

Get number of entries in the block
```c
uiValueB = ( ((PIMAGE_BASE_RELOCATION)uiValueC)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION) ) / sizeof( IMAGE_RELOC );
```

Then we start going through all the values in the block

Check type, if 64 bit, add delta to the offset
```c
if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_DIR64 )
	*(ULONG_PTR *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += uiLibraryAddress;
```

If 32 bit, we also add delta as a DWORD
```c
else if( ((PIMAGE_RELOC)uiValueD)->type == IMAGE_REL_BASED_HIGHLOW )
	*(DWORD *)(uiValueA + ((PIMAGE_RELOC)uiValueD)->offset) += (DWORD)uiLibraryAddress;
```

# Step 6

Find the entry point of the image and call it

Get the address of the entry point
```c
uiValueA = ( uiBaseAddress + ((PIMAGE_NT_HEADERS)uiHeaderValue)->OptionalHeader.AddressOfEntryPoint );
```

Empty the CPU cache from any residue code updated by relocation
```c
pNtFlushInstructionCache( (HANDLE)-1, NULL, 0 );
```

Finally, call the entry point
```c
#ifdef REFLECTIVEDLLINJECTION_VIA_LOADREMOTELIBRARYR
	// if we are injecting a DLL via LoadRemoteLibraryR we call DllMain and pass in our parameter (via the DllMain lpReserved parameter)
	((DLLMAIN)uiValueA)( (HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, lpParameter );
#else
	// if we are injecting an DLL via a stub we call DllMain with no parameter
	((DLLMAIN)uiValueA)( (HINSTANCE)uiBaseAddress, DLL_PROCESS_ATTACH, NULL );
#endif 
```

