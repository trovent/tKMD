#include <ntddk.h>
#include <ntdef.h>
#include <aux_klib.h>
#include "ioctl.h"

constexpr auto TAG = 'tKMD';

UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\tKMD"); 
UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\tKMD");

NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
void Unload(PDRIVER_OBJECT DriverObject);

ULONG64 GetSystemRoutineAddress(PCWSTR routineName);

extern "C" NTSTATUS DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	PDEVICE_OBJECT deviceObject;
	NTSTATUS status = STATUS_SUCCESS;

	DbgPrint("[+] driver has been loaded\n");

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;
	DriverObject->DriverUnload = Unload;

	if (!IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &deviceObject))
	{
		DbgPrint("[!] CreateDevice: 0x%08X\n", status);
	}

	if (!IoCreateSymbolicLink(&symLink, &deviceName))
	{
		DbgPrint("[!] CreateSymbolicLink: 0x%08X\n", status);
	}
	else {
		DbgPrint("[-] failed to create symlink\n");
		IoDeleteDevice(deviceObject);
		status = STATUS_FAILED_DRIVER_ENTRY;
	}

	return status;
}

NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS status = STATUS_SUCCESS;
	ULONG_PTR length = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_LIST_MODULES:
	{
		DbgPrint("[*] IOCTL_LIST_MODULES\n");
		ULONG szBuffer = 0;

		if (NT_SUCCESS(status = AuxKlibInitialize()))
		{
			if (!NT_SUCCESS(status = AuxKlibQueryModuleInformation(&szBuffer, sizeof(AUX_MODULE_EXTENDED_INFO), nullptr)))
			{
				DbgPrint("[+] AuxKlibQueryModuleInformation failed: 0x%08X\n", status);
				break;
			}
		}
		else
		{
			DbgPrint("[+] AuxKlibInitialize failed: 0x%08X\n", status);
			break;
		}

		auto modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePool2(POOL_FLAG_PAGED, szBuffer, TAG);
		if (modules == nullptr)
		{
			DbgPrint("[-] PAUX_MODULE_EXTENDED_INFO was null\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		RtlZeroMemory(modules, szBuffer);

		if (!NT_SUCCESS(status = AuxKlibQueryModuleInformation(&szBuffer, sizeof(AUX_MODULE_EXTENDED_INFO), modules)))
		{
			DbgPrint("[+] AuxKlibQueryModuleInformation failed: 0x%08X\n", status);
			break;
		}

		auto numberOfModules = szBuffer / sizeof(AUX_MODULE_EXTENDED_INFO);

		if (stack->Parameters.DeviceIoControl.OutputBufferLength < (sizeof(PMODULE_NAMES) * 256))
		{
			DbgPrint("[!] Caller's buffer is too small to hold MODULE_NAMES\n");
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PMODULE_NAMES names = (PMODULE_NAMES)Irp->UserBuffer;

		if (names == nullptr)
		{
			DbgPrint("[!] PMODULE_NAMES was null\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		for (auto m = 0; m < numberOfModules; m++)
		{
			strcpy(names[m].Name, (char*)(modules[m].FullPathName));
			length += sizeof(MODULE_NAMES);
		}

		ExFreePoolWithTag(modules, TAG);
		break;
	}
	case IOCTL_CALLBACK_PROCESS:
	{
		DbgPrint("[*] IOCTL_CALLBACK_PROCESS");
		ULONG64 psSetCreateProcessNotifyRoutine = GetSystemRoutineAddress(L"PsSetCreateProcessNotifyRoutine");
		ULONG64 pspCreateProcessNotifyRoutineArray = psSetCreateProcessNotifyRoutine + PROCESS_NOTIFY_OFFSET;

		ULONG szBuffer = 0;
		
		if (NT_SUCCESS(status = AuxKlibInitialize()))
		{
			if (!NT_SUCCESS(status = AuxKlibQueryModuleInformation(&szBuffer, sizeof(AUX_MODULE_EXTENDED_INFO), nullptr)))
			{
				DbgPrint("[+] AuxKlibQueryModuleInformation failed: 0x%08X\n", status);
				break;
			}
		}
		else
		{
			DbgPrint("[+] AuxKlibInitialize failed: 0x%08X\n", status);
			break;
		}

		auto modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePool2(POOL_FLAG_PAGED, szBuffer, TAG);
		if (modules == nullptr)
		{
			DbgPrint("[-] PAUX_MODULE_EXTENDED_INFO was null\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		RtlZeroMemory(modules, szBuffer);

		if (!NT_SUCCESS(status = AuxKlibQueryModuleInformation(&szBuffer, sizeof(AUX_MODULE_EXTENDED_INFO), modules)))
		{
			DbgPrint("[+] AuxKlibQueryModuleInformation failed: 0x%08X\n", status);
			break;
		}

		auto numberOfModules = szBuffer / sizeof(AUX_MODULE_EXTENDED_INFO);
		ULONG64 arrayPointer = pspCreateProcessNotifyRoutineArray;

		if (stack->Parameters.DeviceIoControl.OutputBufferLength < (sizeof(CALLBACK_PROCESS) * 256))
		{
			DbgPrint("[!] Buffer too small to hold CALLBACK_PROCESS\n");
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PCALLBACK_PROCESS callbackInfo = (PCALLBACK_PROCESS)Irp->UserBuffer;

		if (callbackInfo == nullptr)
		{
			DbgPrint("[!] PCALLBACK_PROCESS was null.\n");
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		for (auto i = 0; i < 64; i++)
		{
			ULONG64 callbackAddress = *(PULONG64)(arrayPointer);
			if (callbackAddress > 0)
			{
				ULONG64 rawPointer = *(PULONG64)(callbackAddress & 0xfffffffffffffff8);
				for (auto m = 0; m < numberOfModules; m++)
				{
					auto startAddress = (ULONG64)modules[m].BasicInfo.ImageBase;
					auto endAddress = (ULONG64)(startAddress + modules[m].ImageSize);

					if (rawPointer > startAddress && rawPointer < endAddress)
					{
						strcpy(callbackInfo[i].Module, (char*)modules[m].FullPathName);
						callbackInfo[i].Address = rawPointer;
						break;
					}
				}
				length += sizeof(CALLBACK_PROCESS);
			}
			arrayPointer += 8;
		}

		ExFreePoolWithTag(modules, TAG);
		break;
	}
	case IOCTL_CALLBACK_THREAD:
	{
		DbgPrint("[*] IOCTL_CALLBACK_THREAD\n");
		break;
	}
	case IOCTL_CALLBACK_IMAGE:
	{
		DbgPrint("[*] IOCTL_CALLBACK_IMAGE\n");
		break;
	}
	default:
	{
		status = STATUS_INVALID_DEVICE_REQUEST;
		DbgPrint("[-] unknown IOCTL code\n");
		break;
	}
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = length;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
		
	return status;
}

void Unload(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint("[+] driver has been unloaded\n");
}

NTSTATUS CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

ULONG64 GetSystemRoutineAddress(PCWSTR routineName)
{
	UNICODE_STRING functionName;
	RtlInitUnicodeString(&functionName, routineName);

	return (ULONG64)MmGetSystemRoutineAddress(&functionName);
}