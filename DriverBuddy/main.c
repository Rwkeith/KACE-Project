#pragma once
#include "main.h"
#include "util.h"
#include <intrin.h>

PUNICODE_STRING drvName;
char			orig_bytes[3];
char*			image_ep = 0;
int				smap_enabled = 0;

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
		
	DbgPrint("DriverBuddy Entry completed. (Latest)\n");
	return STATUS_SUCCESS;
}

NTSTATUS BuddyDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	// get our IO_STACK_LOCATION
	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);
	auto status = STATUS_SUCCESS;
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
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

			break;
		case IOCTL_DRIVER_BUDDY_UNWATCH_UNPATCH_DRIVER:
			// Stop watching
			
			PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
			// Unpatch
			if (image_ep)
			{
				__try
				{
					ClearWP();
					for (int i = 0; i < 3; i++)
					{
						*((char*)image_ep + i) = orig_bytes[i];
					}
					SetWP();
				}
				__except (EXCEPTION_EXECUTE_HANDLER)
				{
					_enable();
					unsigned long ex_code = GetExceptionCode();
					DbgPrint("[DriverBuddy] Failed to clear WP, exception code: %ul\n", ex_code);
				}
				DbgPrint("[DriverBuddy] Restored original bytes and unregistered NotifyImageRoutine\n");
			}
			else
			{
				DbgPrint("[DriverBuddy] Nothing to unpatch...\n");
				status = STATUS_INVALID_DEVICE_REQUEST;
			}
			
			break;
		// not actually needed
		case IOCTL_DRIVER_BUDDY_DISABLE_SMAP:
			__try
			{
				set_smap(0);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				unsigned long ex_code = GetExceptionCode();
				DbgPrint("[DriverBuddy] Failed to dsiable SMAP, exception code: %ul\n", ex_code);
			}
			break;
		case IOCTL_DRIVER_BUDDY_ENABLE_SMAP:
			__try
			{
				set_smap(1);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				unsigned long ex_code = GetExceptionCode();
				DbgPrint("[DriverBuddy] Failed to enable SMAP, exception code: %ul\n", ex_code);
			}
			break;
		default:
			DbgPrint("[DriverBuddy] Received unrecognized command...\n");
			status = STATUS_INVALID_DEVICE_REQUEST;
			break;
	}

	Irp->IoStatus.Status = status;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return status;
}

// Patches DriverEntry to return immediately (gets unpatched later)
void LoadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	UNREFERENCED_PARAMETER(ProcessId);
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
		// Patch DriverEntry to return 0
		int *image_ep_offset = (int*)((UINT64)ImageInfo->ImageBase + EP_OFFSET);
		image_ep = (char*)((UINT64) ImageInfo->ImageBase + (UINT64)*image_ep_offset);

		if (*(char*)image_ep != '\xE9')
		{
			DbgPrint("[DriverBuddy] Error, expected a jmp instruction.\n");
			return;
		}

		char byte_patch[] = {'\x33', '\xc0', '\xc3'}; // xor EAX, EAX ; ret ;
		
		// backup original bytes to unpatch later
		for (int i = 0; i < 3; i++)
		{
			orig_bytes[i] = *((char*)image_ep + i);
		}

		__try
		{
			set_cet(0);
			ClearWP();
			for (int i = 0; i < 3; i++)
			{
				*((char*)image_ep + i) = byte_patch[i];
			}
			SetWP();
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			_enable();
			unsigned long ex_code = GetExceptionCode();
			DbgPrint("[DriverBuddy] Failed to clear WP, exception code: %ul\n", ex_code);
		}	
	}
}



NTSTATUS BuddyCreateClose(_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
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

