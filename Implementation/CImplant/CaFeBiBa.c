/*

 Red Team Operator course code template
 CaFeBiBa (pron. ka-feh-bee-bah) - COFF parsing engine
 
 author: reenz0h (twitter: @SEKTOR7net)
 inspiration: COFFLoader (by Kevin Haubris/@kev169)

*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <strsafe.h>
#include "CaFeBiBa.h"


// main COFF parsing function
int ParseCOFF(unsigned char * COFF_data) {
    COFF_FILE_HEADER * 	coff_header_ptr = NULL;
    COFF_SECTION *		coff_sect_ptr = NULL;
    COFF_RELOCATION * 	coff_reloc_ptr = NULL;
    COFF_SYMBOL * 		coff_sym_ptr = NULL;
	BOOL prn = FALSE;
	
	// Step 1a. Allocate some extra memory for internal parsing structures (not necessary, will be used during loading)
	size_t MemSectionsSize = sizeof(COFF_MEM_SECTION) * coff_header_ptr->NumberOfSections;
	COFF_MEM_SECTION * MemSections = calloc(coff_header_ptr->NumberOfSections, sizeof(COFF_MEM_SECTION));
	if (!MemSections) {
		return -1;
	}

	for (int i = 0 ; i < coff_header_ptr->NumberOfSections ; i++) {
		// get pointer to current section to parse
		coff_sect_ptr = (COFF_SECTION *)(COFF_data + sizeof(COFF_FILE_HEADER) + (sizeof(COFF_SECTION) * i));
		
		// if the section is not empty, save the data in the internal structure
		if (coff_sect_ptr->SizeOfRawData > 0) {
			MemSections[i].Counter = i;
			StringCchCopyA(MemSections[i].Name, strlen(coff_sect_ptr->Name) + 1, coff_sect_ptr->Name);
			MemSections[i].Name[8] = '\0';
			MemSections[i].SizeOfRawData = coff_sect_ptr->SizeOfRawData;
			MemSections[i].PointerToRawData = coff_sect_ptr->PointerToRawData;
			MemSections[i].PointerToRelocations = coff_sect_ptr->PointerToRelocations;
			MemSections[i].NumberOfRelocations = coff_sect_ptr->NumberOfRelocations;
			MemSections[i].Characteristics = coff_sect_ptr->Characteristics;
			MemSections[i].InMemorySize = MemSections[i].SizeOfRawData  + (0x1000 - MemSections[i].SizeOfRawData % 0x1000); // align to page size
			MemSections[i].InMemoryAddress = NULL;   // VirtuAlloc(...)
			
			prn = TRUE;
		}
		
		prn = FALSE;

		// now work on all relocations in the section, if there are any		
		if (MemSections[i].NumberOfRelocations != 0) {
			for (int x = 0 ; x < MemSections[i].NumberOfRelocations ; x++) {
				coff_reloc_ptr = (COFF_RELOCATION *) (COFF_data + MemSections[i].PointerToRelocations + sizeof(COFF_RELOCATION) * x);
			}
		}
	}

	// Step 3. Parse and print the entire Symbol Table
	coff_sym_ptr = (COFF_SYMBOL *) (COFF_data + coff_header_ptr->PointerToSymbolTable);
	char * 	coff_strings_ptr = (char *)((COFF_data + coff_header_ptr->PointerToSymbolTable) + coff_header_ptr->NumberOfSymbols * sizeof(COFF_SYMBOL));
	for (int i = 0 ; i < coff_header_ptr->NumberOfSymbols ; i++) {
		if (coff_sym_ptr[i].SectionNumber == 0 && coff_sym_ptr[i].StorageClass == 0) {}	// according to COFF docs this is IMAGE_SYM_UNDEFINED										// otherwise, get a string from the Strings Table
		if (coff_sym_ptr[i].first.Zeros != 0) {			// check if the string is in the Strings Table
			char n[10];									// if not, make sure that a string from ShortName is ending with null byte
			StringCchCopyA(n, strlen(coff_sym_ptr[i].first.ShortName) + 1, coff_sym_ptr[i].first.ShortName);
			n[8] = '\0';
		}
	}
	
	// cleanup
	VirtualFree(MemSections, 0, MEM_RELEASE);
	
	return 0;
}


int cafebiba_coff_loader(int argc, char * argv[]) {
	
	if (argc < 2) {
		printf("[!] ERROR! Run: %s <path_2_file>\n", argv[0]);
		return -1;
	}

	// map the COFF file into memory for parsing
	HANDLE COFFfile = CreateFile(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (COFFfile == INVALID_HANDLE_VALUE) {
			printf("[!] Could not open file: %s\n", argv[1]);
			return -1;
	}

	HANDLE FileMapping = CreateFileMapping(COFFfile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (FileMapping == NULL) {
			printf("[!] Could not call CreateFileMapping (%#x)\n", GetLastError());
			return -1;
	}

	LPVOID COFF_data = MapViewOfFile(FileMapping, FILE_MAP_READ, 0, 0, 0);
	if (COFF_data == NULL) {
			printf("[!] Could not call MapViewOfFile (%#x)\n", GetLastError());
			return -1;
	}

	// if file is mapped, proceed with parsing...
	int result = ParseCOFF((unsigned char *) COFF_data);
	if (result)
		printf("[!] ERROR parsing the input file! Exiting...\n");

	// clean up before saying Good-bye!
	UnmapViewOfFile(COFF_data);
	CloseHandle(FileMapping);
	CloseHandle(COFFfile);

	return 0;
}