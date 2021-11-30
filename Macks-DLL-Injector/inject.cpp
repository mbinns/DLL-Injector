//Windows Functions
#include <Windows.h>
#include <TlHelp32.h>

//Functions for me
#include <iostream>
#include <string>
#include <codecvt>

//Injection Functions
#include <proc_info.h>

int main(int argc, const char** argv)
{
	if (argc != 2)
	{
		std::cout << "USAGE:\n-----------------\n" << "inject.exe <process_name> <path-to-dll>" << std::endl;
		return 1;
	}

	//Convert Char * to wstring (which is like using w_char *)
	//https://riptutorial.com/cplusplus/example/4190/conversion-to-std--wstring
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	std::wstring w_name = converter.from_bytes(argv[1]);
	
	DWORD pid = GetPID(w_name);
	if (pid)
	{
		std::wcout << L"Process " << w_name << " found!" << std::endl;
		std::cout << "PID: " << pid << std::endl;
	}
	else
	{
		std::wcerr << L"Process " << w_name << " not found!" << std::endl;
	}

	return 0;
}