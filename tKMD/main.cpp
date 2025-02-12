#include <ntddk.h>
#include <ntdef.h>
#include "ioctl.h"

constexpr auto TAG = 'tKMD';

UNICODE_STRING deviceName = RTL_CONSTANT_STRING(L"\\Device\\tKMD"); 
UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\tKMD");

NTSTATUS DeviceControl(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
NTSTATUS CreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
void Unload(PDRIVER_OBJECT DriverObject);

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
	case IOCTL_CALLBACK_PROCESS:
	{
		DbgPrint("[*] IOCTL_CALLBACK_PROCESS");
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
		
	return STATUS_SUCCESS;
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