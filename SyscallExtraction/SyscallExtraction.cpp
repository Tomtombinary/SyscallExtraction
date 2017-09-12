// SyscallExtraction.cpp : définit le point d'entrée pour l'application console.
//

#include "stdafx.h"
#include <Windows.h>

int _tmain(int argc, _TCHAR* argv[])
{
	DWORD dwFileSize = 0;
	LPBYTE lpBuffer = NULL;
	HANDLE hFileMapping = INVALID_HANDLE_VALUE;
	PIMAGE_DOS_HEADER DOSHeader = NULL;
	PIMAGE_NT_HEADERS64 NTHeader = NULL;

	lpBuffer = (LPBYTE)LoadLibraryA("ntdll.dll");
	DOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;
	if (DOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		fprintf(stderr, "[-] Invalid DOS Signature\n");
		goto clean;
	}

	NTHeader = (PIMAGE_NT_HEADERS64)(lpBuffer + DOSHeader->e_lfanew);

	DWORD dwExportRVA = NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD dwExportSize = NTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	
	PIMAGE_EXPORT_DIRECTORY lpIED = (PIMAGE_EXPORT_DIRECTORY)(lpBuffer + dwExportRVA);
	PDWORD pdwAddressOfFunctions = (PDWORD)(lpBuffer + lpIED->AddressOfFunctions);
	PWORD pwAddressOfNameOrdinals = (PWORD)(lpBuffer + lpIED->AddressOfNameOrdinals);
	PDWORD pszFunctionName = (PDWORD)(lpBuffer + lpIED->AddressOfNames);
	DWORD dwExports = lpIED->NumberOfNames;
	LPBYTE pCode = NULL;
	for (DWORD i = 0; i < lpIED->NumberOfNames; i++)
	{
		LPCSTR Name = (LPCSTR)(lpBuffer + pszFunctionName[i]);
		pCode = (LPBYTE)(lpBuffer + pdwAddressOfFunctions[pwAddressOfNameOrdinals[i]]);
		DWORD syscallNum = 0;
		// ONLY X64
		// mov r10,rcx
		// mov eax,IMM32
		if (memcmp(pCode, "\x4C\x8B\xD1\xB8", 4) == 0)
		{
			// syscall
			// ret
			if (memcmp(pCode + 8, "\x0F\x05\xC3", 3) == 0)
			{
				syscallNum = *((INT32*)(pCode + 4));
				printf("%-40s %08.8x %08.8x\n", Name, pCode,syscallNum);
			}
		}
	}
clean:
	system("pause");
	return 0;
}

