/*
 * mem.h
 *
 *  Created on: May 13, 2018
 *      Author: rujas
 */

#ifndef MEM_H_
#define MEM_H_

#include <windows.h>
#include <tlhelp32.h>
//#include "testlib64.h"

typedef struct _MANUAL_MAPPING_DATA
{
	typedef HINSTANCE (WINAPI *__LoadLibraryA)(_In_ LPCSTR);
	typedef ULONG_PTR (WINAPI *__GetProcAddress)(_In_ HINSTANCE, _In_ LPCSTR);
	typedef BOOLEAN (WINAPI *__DllMain)(_In_ LPVOID, _In_ DWORD, _In_opt_ LPVOID);

	// needed in order to resolve dependencies (target dll may depend on other libraries)
	_In_ __LoadLibraryA _LoadLibraryA;

	// needed to get addresses of API functions from required libraries
	// injected dll may depend on other API functions from other libraries
	_In_ __GetProcAddress _GetProcAddress;
	_Out_opt_ HMODULE hMod;
} MANUAL_MAPPING_DATA;

// some sections may need relocation, others don't
// anyway, the checks are made different, depending on system architecture (32 or 64 bit)
#define RELOC_FLAG64(pRelativeInfo) ((pRelativeInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
#define RELOC_FLAG32(pRelativeInfo) ((pRelativeInfo >> 0x0C) == IMAGE_REL_BASED_HIGHLOW)

#ifdef _WIN64
#define RELOC_FLAG RELOC_FLAG64
#else
#define RELOC_FLAG RELOC_FLAG32
#endif

#define RELOC_DATA_POSITION(pRelativeInfo) (pRelativeInfo & 0xFFF)
#define ORDINAL_FUNC(pThunkRef) (pThunkRef & 0xFFFF)

#endif /* MEM_H_ */
