#pragma once
#include "main.h"
#include "ida_defs.h"

PUNICODE_STRING drvName;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = BuddyUnload;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = BuddyCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = BuddyCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = BuddyDeviceControl;

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\DriverBuddy");

	PDEVICE_OBJECT DeviceObject;
	NTSTATUS	   status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Failed to create device object (0x%08X)\n", status));
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\DriverBuddy");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Failed to create symbolic link (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	DbgPrint("DriverBuddy Entry completed.\n");
	return STATUS_SUCCESS;
}

NTSTATUS BuddyDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	// get our IO_STACK_LOCATION
	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
		DbgPrint("[DriverBuddy] DeviceControl called!\n");
		case IOCTL_DRIVER_BUDDY_WATCH_DRIVER:
			if (stack->Parameters.DeviceIoControl.InputBufferLength < sizeof(DriverInfo))
			{
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}

			// DriverInfo* data = stack->Parameters.DeviceIoControl.Type3InputBuffer;

			// RtlInitUnicodeString(drvName, data->driverName);
			PsSetLoadImageNotifyRoutine(LoadImageNotifyRoutine);
			DbgPrint("[DriverBuddy] LoadImageNotify routine set!\n");
			// DbgPrint("Watching for %wZ\n", drvName);
			break;
		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	wchar_t path[260];
	memset(path, 0, 260);
	memcpy(path, FullImageName->Buffer, FullImageName->Length);

	path[FullImageName->Length / sizeof(wchar_t)] = L'\0';

	wchar_t* last_backslash = wcsrchr(path, L'\\');


	wchar_t* last_component = last_backslash + 1;
	size_t	 len = wcslen(last_component);

	if (wcsncmp(last_component, L"BEDaisy.sys", len) == 0)
	{
		DbgPrint("[DriverBuddy] IMAGE MATCH! %ws\n", last_component);
		// DO STUFF
	}
}

NTSTATUS BuddyCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

void BuddyUnload(_In_ PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);

	PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\DriverBuddy");
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);
	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint("DriverBuddy unloaded!\n");
}
