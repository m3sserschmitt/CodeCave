/*
 * mem.h
 *
 *  Created on: May 21, 2018
 *      Author: rujas
 */

#ifndef MEM_H_
#define MEM_H_

#include <windows.h>
#include <stdio.h>
#include "testproc.h"

typedef LONG (__stdcall *_NtUnmapViewOfSection)(HANDLE, LPVOID);
BOOLEAN __stdcall RunPe(LPVOID);

FARPROC __NtUnmapViewOfSection = GetProcAddress(LoadLibraryA("ntdll.dll"), "NtUnmapViewOfSection");
_NtUnmapViewOfSection NtUnmapViewOfSection = reinterpret_cast<_NtUnmapViewOfSection>(__NtUnmapViewOfSection);

#endif /* MEM_H_ */
