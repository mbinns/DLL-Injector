//Windows Functions
#include <Windows.h>
#include <TlHelp32.h>

//Functions for me
#include <iostream>
#include <string>
#include <codecvt>

//Injection Functions
#include <proc_info.h>
#include <mem.h>

int main(int argc, const char** argv)
{
	if (argc != 3)
	{
		std::cout << "[!] USAGE:\n-----------------\n" << "inject.exe <process_name> <path-to-dll>" << std::endl;
		return 1;
	}

	//Convert Char * to wstring (which is like using w_char *)
	//https://riptutorial.com/cplusplus/example/4190/conversion-to-std--wstring
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring w_name = converter.from_bytes(argv[1]);
	
	//Convert Char * to string for DLL path injection
	std::string dll_path = argv[2];

	//Spin and wait for target to open
	DWORD pid = 0;
	while (pid == 0)
	{
		pid = GetPID(w_name);
		Sleep(1000);
	}

	//Extra sanity check
	if (pid)
	{
		std::wcout << L"[*] Process: " << w_name << " found!" << std::endl;
		std::cout << "[*] PID: " << pid << std::endl;
		InjectDLL(pid, dll_path);
	}
	else
	{
		std::wcerr << L"[!] Process: " << w_name << " not found!" << std::endl;
	}

	return 0;
}