/*
 * main.cc
 *
 *  Created on: May 21, 2018
 *      Author: rujas
 *
 *      dynamic linking library injection with manual memory mapping, sections relocation & imports
 */

#include "mem.hh"

// this file contain binary code of target dll (code to be injected into target process)
#include "testlib64.hh"

BOOLEAN __stdcall InjectDll(HANDLE, LPVOID);
DWORD __stdcall GetIdByName(LPCSTR szProcName);

INT WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR CmdLine, INT ShowConsole)
{
	// try to inject dll into explorer.exe
	DWORD id = GetIdByName("explorer.exe");
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, id);

	// inject code;
	InjectDll(hProc, rawData);

	return EXIT_SUCCESS;
}

// this code will run into remote process;
// if code relocation is required or target dll has dependencies
// these should be resolved from within target process
static void __stdcall Shellcode(MANUAL_MAPPING_DATA _In_ _Out_ *Arguments)
{
	if(!Arguments) return;

	BYTE *pBase = reinterpret_cast<BYTE *>(Arguments);
	// get dll headers
	IMAGE_DOS_HEADER *DOSHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(pBase);
	IMAGE_NT_HEADERS *NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(pBase + DOSHeader->e_lfanew);

	IMAGE_OPTIONAL_HEADER *OptHeader = &NtHeaders->OptionalHeader;

	// addressees of LoadLibrayA and GetProcAddress API functions
	MANUAL_MAPPING_DATA::__LoadLibraryA _LoadLibraryA = Arguments->_LoadLibraryA;
	MANUAL_MAPPING_DATA::__GetProcAddress _GetProcAddress = Arguments->_GetProcAddress;

	// get pointer to DllMain (entry point)
	MANUAL_MAPPING_DATA::__DllMain _DllMain = reinterpret_cast<MANUAL_MAPPING_DATA::__DllMain>(pBase + OptHeader->AddressOfEntryPoint);

	// check if data should be relocated
	// relocation is required only when dll image base and 
	// address of allocated space into remote process are different
	// so, pBase represent the address of allocated space, and OptHeader->ImageBase
	// represent the address where the executable should be loaded
	// if they match, no further modifications are required
	BYTE *LocationDelta = pBase - OptHeader->ImageBase;
	if(LocationDelta)
	{
		// otherwise ... :(((
		
		// check if there is data that need relocation
		// maybe relocation isn't required...
		if(!OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size) return;

		// if there is data to be relocated..
		// get the virtual address of data to be relocated;
		IMAGE_BASE_RELOCATION *pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION *>(pBase + OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

		// if the address is valid (i.e. not null)
		while(pRelocData->VirtualAddress)
		{
			// calculate number of entries into block
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD *pRelativeInfo = reinterpret_cast<WORD *>(pRelocData + 1);

			// iterate over all entries;
			for(WORD i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
			{
				// some entries need to be relocated, others don't
				if(RELOC_FLAG(*pRelativeInfo))
				{
					// current address
					UINT_PTR *pPatch = reinterpret_cast<UINT_PTR*>(pBase + pRelocData->VirtualAddress + RELOC_DATA_POSITION(*pRelativeInfo));
					// modify current address according to location delta
					*pPatch += reinterpret_cast<UINT_PTR>(LocationDelta);
				}
			}

			// go to next block
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION *>(reinterpret_cast<BYTE *>(pRelocData) + pRelocData->SizeOfBlock);
		}
	}

	// if injected dll depends on other libraries, these must be loaded too
	if(OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		IMAGE_IMPORT_DESCRIPTOR *pImportDescriptor = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR *>(pBase + OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

		// check if name is valid
		while(pImportDescriptor->Name)
		{
			// get name of library to be imported
			LPSTR szDllName = reinterpret_cast<LPSTR>(pBase + pImportDescriptor->Name);

			// load library
			HINSTANCE hDll = _LoadLibraryA(szDllName);

			ULONG_PTR *pThunkRef = reinterpret_cast<ULONG_PTR *>(pBase + pImportDescriptor->OriginalFirstThunk);
			ULONG_PTR *pFuncRef = reinterpret_cast<ULONG_PTR *>(pBase + pImportDescriptor->FirstThunk);

			if(!pThunkRef) pThunkRef = pFuncRef;

			for(; *pThunkRef; ++pThunkRef, ++pFuncRef)
			{
				// some functions should be imported by name, others by ordinal
				if(IMAGE_SNAP_BY_ORDINAL(*pThunkRef))
				{
					*pFuncRef = reinterpret_cast<ULONG_PTR>(_GetProcAddress(hDll, reinterpret_cast<LPSTR>(ORDINAL_FUNC(*pThunkRef))));
				}
				else
				{
					
					IMAGE_IMPORT_BY_NAME *pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(pBase + (*pThunkRef));
					*pFuncRef = reinterpret_cast<ULONG_PTR>(_GetProcAddress(hDll, reinterpret_cast<LPSTR>(pImport->Name)));
				}
			}

			++pImportDescriptor;
		}
	}

	if(OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		IMAGE_TLS_DIRECTORY *pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY *>(pBase + OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK *pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK *>(pTLS->AddressOfCallBacks);
		for(; pCallback && *pCallback; ++pCallback)
			(*pCallback)(pBase, DLL_PROCESS_ATTACH, nullptr);
	}

	_DllMain(pBase, DLL_PROCESS_ATTACH, nullptr);

	Arguments->hMod = reinterpret_cast<HINSTANCE>(pBase);

	return;
}
static void __stdcall Shellcode_end()
{

}

size_t __stdcall Strlen(LPCSTR str)
{
	size_t sz = 0;
	while(*str)
	{
		sz ++;
		str ++;
	}

	return sz;
}

BOOLEAN __stdcall Strcmp(LPCSTR str1, LPCSTR str2)
{
	if(Strlen(str1) != Strlen(str2)) return FALSE;

	for(;*str1; ++str1, ++str2)
		if(*str1 != *str2) return FALSE;

	return TRUE;
}

// this function get process name as input and return process ID
DWORD __stdcall GetIdByName(LPCSTR szProcName)
{
	DWORD id = 0;
	HANDLE Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe32 = { 0 };

	pe32.dwSize = sizeof(PROCESSENTRY32);
	if(!Snapshot) return id;

	if(Process32First(Snapshot, &pe32))
		do
		{
			if(Strcmp(szProcName, pe32.szExeFile))
			{
				id = pe32.th32ProcessID;
				break;
			}
		}while(Process32Next(Snapshot, &pe32));

	CloseHandle(Snapshot);

	return id;
}

// this function inject the code into remote process
// it takes a handle to target process and the code to be injected
BOOLEAN __stdcall InjectDll(HANDLE hProcess, LPVOID lpImage)
{
	if(!hProcess || !lpImage)
		return FALSE;

	IMAGE_DOS_HEADER *DOSHeader 		= nullptr;
	IMAGE_NT_HEADERS *NtHeaders 		= nullptr;
	IMAGE_FILE_HEADER *FileHeader 		= nullptr;
	IMAGE_OPTIONAL_HEADER *OptHeader 	= nullptr;
	IMAGE_SECTION_HEADER *SectionHeader = nullptr;

	BYTE *pTargetBase 	= nullptr;
	BYTE *pSrcData 		= nullptr;
	LPVOID pShellcode   = nullptr;
	HANDLE hThread 		= nullptr;

	DWORD_PTR ShellcodeSize;

	// binary code to be injected
	pSrcData = reinterpret_cast<BYTE *>(lpImage);

	// pointer to DOS Header
	// check if the code is indeed executable code (dll)
	DOSHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(pSrcData);
	if(DOSHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	// pointer to NT Headers
	NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS *>(pSrcData + DOSHeader->e_lfanew);
	if(NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	FileHeader 	= &NtHeaders->FileHeader;
	OptHeader 	= &NtHeaders->OptionalHeader;

	// try to allocate space into target process at ImageBase,
	// address in virtual memory where the executable should be loaded at to avoid any adjustment
	if(!(pTargetBase = reinterpret_cast<BYTE *>(VirtualAllocEx(hProcess, reinterpret_cast<LPVOID>(OptHeader->ImageBase), OptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))))
	{
		// if not possible, allocate space at any address
		if(!(pTargetBase = reinterpret_cast<BYTE *>(VirtualAllocEx(hProcess, nullptr, OptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE))))
			return FALSE;
	}

	// get pointer to first section;
	SectionHeader = IMAGE_FIRST_SECTION(NtHeaders);

	// iterate over all sections
	for(WORD i = 0; i < FileHeader->NumberOfSections; ++ i, ++ SectionHeader)
	{
		if(SectionHeader->SizeOfRawData)

			// try to write data into remote process
			if(!WriteProcessMemory(hProcess, pTargetBase + SectionHeader->VirtualAddress, pSrcData + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData, nullptr))
			{
				// release memory into remote process if data writing fails;
				VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
				return FALSE;
			}
	}

	// calculate shell code size
	ShellcodeSize = (DWORD_PTR)Shellcode_end - (DWORD_PTR)Shellcode;

	// try to allocate space into remote process for shellcode
	if(!(pShellcode = VirtualAllocEx(hProcess, nullptr, ShellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)))
	{
		VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
		return FALSE;
	}

	// LoadLibrayA will be required to load User32.dll into target process
	MANUAL_MAPPING_DATA::__LoadLibraryA _LoadLibraryA = (MANUAL_MAPPING_DATA::__LoadLibraryA)GetProcAddress(LoadLibrary("Kernel32.dll"), "LoadLibraryA");
	// GetProcAddress will be required to find MessageBoxA into User32.dll
	MANUAL_MAPPING_DATA::__GetProcAddress _GetProcAddress = (MANUAL_MAPPING_DATA::__GetProcAddress)GetProcAddress(LoadLibrary("Kernel32.dll"), "GetProcAddress");

	MANUAL_MAPPING_DATA data = { 0 };
	data._GetProcAddress = _GetProcAddress;
	data._LoadLibraryA = _LoadLibraryA;

	memcpy(pSrcData, &data, sizeof(data));
	// write APIs addresses into target process
	if(!WriteProcessMemory(hProcess, pTargetBase, pSrcData, 0x1000, nullptr))
	{
		VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
		return FALSE;
	}

	// write shellcode into remote process
	if(!WriteProcessMemory(hProcess, pShellcode, reinterpret_cast<LPVOID>(Shellcode), ShellcodeSize, nullptr))
	{
		VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
		return FALSE;
	}

	// run shellcode into remote process
	if(!(hThread = CreateRemoteThread(hProcess, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pShellcode), pTargetBase, 0, nullptr)))
	{
		VirtualFreeEx(hProcess, pTargetBase, 0, MEM_RELEASE);
		VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);
		return FALSE;
	}

	CloseHandle(hThread);

	HANDLE hCheck = nullptr;

	while(!hCheck)
	{
		MANUAL_MAPPING_DATA hDataCheck = { 0 };
		ReadProcessMemory(hProcess, pTargetBase, &hDataCheck, sizeof(MANUAL_MAPPING_DATA), nullptr);
		hCheck = hDataCheck.hMod;
		Sleep(10);
	}

	VirtualFreeEx(hProcess, pShellcode, 0, MEM_RELEASE);

	return TRUE;
}


