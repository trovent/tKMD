#include <Windows.h>
#include <stdio.h>
#include "../tKMD/ioctl.h"

int main(int argc, char * argv[])
{
	HANDLE hDriver;
	BOOL success; 

	hDriver = CreateFile(L"\\\\.\\tKMD", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
		printf("[-] failed to open a handle to the driver: %d", GetLastError());
		return 1;
	}

	success = DeviceIoControl(hDriver, IOCTL_CALLBACK_PROCESS, nullptr, 0, nullptr, 0, nullptr, nullptr);

	if (success)
	{
		printf("[+] processing IOCTL_CALLBACK_PROCESS\n");
	}
	else 
	{
		printf("[+] failed processing IOCTL_CALLBACK_PROCESS: %d\n", GetLastError());
	}

	CloseHandle(hDriver);
}