#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "../tKMD/ioctl.h"

void PrintCallbackInfo(CALLBACK_INFO callbacks[]);

int main(int argc, char * argv[])
{
	if (argc < 2)
	{
		printf("Usage: .exe <int:toggle>\n\t1: LIST KERNEL MODULES\n\t2: LIST PROCESSNOTIFY CALLBACKS\n\t3: LIST THREADNOTIFY CALLBACKS\n\t4: LIST IMAGENOTIFY CALLBACKS\n\t5: DISABLE CALLBACK <PVOID>\n");
		return 1;
	}

	int toggle = atoi(argv[1]);

	HANDLE hDriver;
	BOOL success; 

	hDriver = CreateFile(L"\\\\.\\tKMD", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
		printf("[-] failed to open a handle to the driver: %d\n", GetLastError());
		return 1;
	}

	switch (toggle)
	{
	case 1: 
	{
		MODULE_NAMES modules[256];
		RtlZeroMemory(modules, sizeof(modules));

		if (success = DeviceIoControl(hDriver, IOCTL_LIST_MODULES, nullptr, 0, &modules, sizeof(modules), nullptr, nullptr))
		{
			printf("[*] Listing all system modules...\n");
			for (auto i = 0; i < 256; i++)
			{
				if (strlen(modules[i].Name) > 0)
				{
					printf("\t[%d] %s\n", i, modules[i].Name);
				}
			}
		}
		break;
	}
	case 2:
	{
		CALLBACK_INFO callbacks[256];
		RtlZeroMemory(callbacks, sizeof(callbacks));

		printf("[*] Listing process notify callbacks...\n");
		if (success = DeviceIoControl(hDriver, IOCTL_CALLBACK_PROCESS, nullptr, 0, &callbacks, sizeof(callbacks), nullptr, nullptr)) PrintCallbackInfo(callbacks);
		break;
	}
	case 3:
	{
		CALLBACK_INFO callbacks[256];
		RtlZeroMemory(callbacks, sizeof(callbacks));

		printf("[*] Listing thread notify callbacks...\n");
		if (success = DeviceIoControl(hDriver, IOCTL_CALLBACK_THREAD, nullptr, 0, &callbacks, sizeof(callbacks), nullptr, nullptr)) PrintCallbackInfo(callbacks);
		break;
	}
	case 4:
	{
		CALLBACK_INFO callbacks[256];
		RtlZeroMemory(callbacks, sizeof(callbacks));
		
		printf("[*] Listing image notify callbacks...\n");
		if (success = DeviceIoControl(hDriver, IOCTL_CALLBACK_IMAGE, nullptr, 0, &callbacks, sizeof(callbacks), nullptr, nullptr)) PrintCallbackInfo(callbacks);
		break;
	}
	}

	CloseHandle(hDriver);
}

void PrintCallbackInfo(CALLBACK_INFO callbacks[])
{
	for (auto i = 0; i < 256; i++)
	{
		if (callbacks[i].Address == 0) continue;
		printf("\t[%d] 0x%llx -> %s\n", i, callbacks[i].Address, callbacks[i].Module);
	}
}