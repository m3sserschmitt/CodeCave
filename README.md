# Windows Memory Hacks

This repository contains some basic exploits used by a computer malware in order to hide his malicious code.

The code in this repository comes with no warranty and you should seriously consider to __test them on a virtual machine__. Code injection may result into __system crashes__.

All directories contain a file `main.cc` in which  all of important stuff takes place.

### Table of content.
***

* *CodeCave:* it will try to inject code into `explorer.exe` by default. You'll also find here the `Shellcode` method which contains the code to be injected. Basically, it displays a message box from within target process (`explorer.exe`). The others methods have suggestive names, and it'll be quite easy for you to figure it out what they're actually doing. Most important API functions used here are `AllocateMemoryEx`, `WriteProcessMemory` and `CreateRemoteThread`.

* *DllInjection:* a dll (dynamic linking library) is, as the name suggests, a library which it's loaded into memory at runtime (or after the process already started, in this case). It will try to inject the byte-array dll from `testlib64.h` into `explorer.exe` (you can change it into `main.cc`, `WinMain` function).
`Shellcode` function will also be written into target process memory. This function handles code relocation and imports (injected library may have other dependencies and these must be imported into target process).

* *MainHijack:* if you run this code, it will make a copy of itself into suspended state and try to overwrite the code of `main` into copy process with the code written into `Shellcode` function.

* *PortableExecutable:* it creates a copy process into suspended mode and then overwrites all of its sections with code from a byte-array, which should be a valid Windows PE.
