//Windows Functions
#include <Windows.h>
#include <TlHelp32.h>

//Functions for me
#include <iostream>
#include <string>

DWORD GetPID(const std::wstring& name)
{
	std::wcout << L"Searching for: " << name << std::endl;
	
	//Structure for a process entry
	//https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
	PROCESSENTRY32 proc_info;

	//The size of the structure, in bytes. Before calling the Process32First function, 
	//set this member to sizeof(PROCESSENTRY32). If you do not initialize dwSize, Process32First fails.
	proc_info.dwSize = sizeof(PROCESSENTRY32);
	
	/*
	* TTP:
	*	MITRE T1057: https://attack.mitre.org/techniques/T1057
	* Details:
	*	Get a snapshot of only processes on the system, second argument is not needed for processes
	*	https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
	*/
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	//Make sure we actually got a snapshot before enumuerating them
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		std::cerr << "Failed to obtain process snapshot" << std::endl;
		return 0;
	}

	//Get the first process from the snapshot and load it into our structure
	Process32First(snapshot, &proc_info);

	//Check to see if the exe name matches what we want to inject into
	//Needs inverse beause 0 = strings match
	if(!name.compare(proc_info.szExeFile))
	{
		std::wcout << L"Found: " << name << std::endl;
		//No danling handles here ;)
		CloseHandle(snapshot);

		//Return the PID
		return proc_info.th32ProcessID;
	}
	else
	{
		//Loop the snapshot until Process32Next returns FALSE
		while (Process32Next(snapshot, &proc_info))
		{
			if (!name.compare(proc_info.szExeFile))
			{
				std::wcout << L"Found: " << name << std::endl;
				//No danling handles here ;)
				CloseHandle(snapshot);

				//Return the PID
				return proc_info.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);
	return 0;
}