#pragma once
#include "main.h"
#include "util.h"
#include "comm.h"

#define SYMLINK_NAME L"\\DosDevices\\DriverBuddy"

char		 g_origBytes[3];
char*		 g_imageEP = 0;
PEPROCESS	 g_kaceProc = 0;
PBUDDY_SHMEM g_sharedBuff = 0;

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\DriverBuddy");

	PDEVICE_OBJECT DeviceObject;
	NTSTATUS	   status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[DriverBuddy] Failed to create device object (0x%08X)\n", status));
		return status;
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[DriverBuddy] Failed to create symbolic link (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = BuddyCreateClose;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = BuddyDeviceControl;
	DriverObject->DriverUnload = BuddyUnload;

	HANDLE threadHandle = NULL;

	// Create the communication thread
	status = PsCreateSystemThread(
		&threadHandle,	 // Pointer to a HANDLE in which the thread's handle is returned
		(ACCESS_MASK)0,	 // Desired access for the thread's handle (0 if you do not need to access the thread handle
						 // from kernel mode)
		NULL,			 // Pointer to an OBJECT_ATTRIBUTES structure (NULL if you do not need to specify attributes)
		(HANDLE)0,		 // Handle for the process in which the thread is to run (0 for the current process)
		NULL,  // Pointer to a CLIENT_ID structure that receives the thread and process IDs of the new thread (NULL if
			   // not needed)
		ListenerThread,	 // Start routine for the thread
		NULL			 // Parameter to be passed to the start routine (NULL if not needed)
	);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[DriverBuddy] Failed to create system thread.\n"));
		return status;
	}

	DbgPrint("[DriverBuddy] System Thread Started\n");

	DbgPrint("[DriverBuddy] Entry completed...\n");
	return STATUS_SUCCESS;
}

NTSTATUS BuddyDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);

	auto status = STATUS_SUCCESS;
	switch (stack->Parameters.DeviceIoControl.IoControlCode)
	{
		case IOCTL_DRIVER_BUDDY_WATCH_DRIVER:
		{
			PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
			if (buffer == 0)
			{
				DbgPrint("[DriverBuddy] Invalid buffer\n");
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			SIZE_T proc_id = *((SIZE_T*)buffer);
			if (PsLookupProcessByProcessId((HANDLE)proc_id, &g_kaceProc) != STATUS_SUCCESS)
			{
				DbgPrint("[DriverBuddy] Failed to get process\n");
				status = STATUS_INVALID_PARAMETER;
				break;
			}
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
		}
		case IOCTL_DRIVER_BUDDY_UNWATCH_UNPATCH_DRIVER:
			// stop watching
			PsRemoveLoadImageNotifyRoutine(LoadImageNotifyRoutine);
			// unpatch
			if (g_imageEP)
			{
				__try
				{
					ClearWP();
					for (int i = 0; i < 3; i++)
					{
						*((char*)g_imageEP + i) = g_origBytes[i];
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
				SetSMAP(0);
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
				SetSMAP(1);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				unsigned long ex_code = GetExceptionCode();
				DbgPrint("[DriverBuddy] Failed to enable SMAP, exception code: %ul\n", ex_code);
			}
			break;
		case IOCTL_DRIVER_BUDDY_INIT_SHARED_MEM:
		{
			// this has to happen in an IOCTL because the security token of the system process doesn't allow user-mode
			// handles to be opened to it....I think
			g_sharedBuff = InitSharedMemory();
			break;
		}
		case IOCTL_DRIVER_BUDDY_EXECUTE:
		{
			PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
			DbgPrint("[DriverBuddy] Trying to execute...\n");
			__try
			{
				/*
				if (!g_kaceProc)
				{
					DbgPrint("[DriverBuddy] Process not set, did you call watch first?\n");
					status = STATUS_INVALID_DEVICE_REQUEST;
					break;
				}*/

				/*
				PCONTEXT ctx = (PCONTEXT)buffer;

				DbgPrint("RIP = 0x%p\n", ctx->Rip);
				DbgPrint("RSP = 0x%p\n", ctx->Rsp);
				DbgPrint("RAX = 0x%p\n", ctx->Rax);

				DbgPrint("[DriverBuddy] Executing 0x%p\n", ctx->Rip);*/
				KAPC_STATE apcState;
				// KeStackAttachProcess(g_kaceProc, &apcState);
				g_sharedBuff = InitSharedMemory();
				// ExecAddressWithCtx((PCONTEXT)buffer);
				// KeUnstackDetachProcess(&apcState);
				DbgPrint("[DriverBuddy] Done executing...\n");

				Irp->IoStatus.Status = status;
				Irp->IoStatus.Information = 0;	// sizeof(CONTEXT);
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				return status;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				unsigned long ex_code = GetExceptionCode();
				DbgPrint("[DriverBuddy] Failed to execute, exception code: %ul\n", ex_code);
			}
			break;
		}
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
		DbgPrint("[DriverBuddy] Base: 0x%p  Size: 0x%p %ws\n", ImageInfo->ImageBase, ImageInfo->ImageSize);
		// Patch DriverEntry to return 0
		int* image_ep_offset = (int*)((UINT64)ImageInfo->ImageBase + EP_OFFSET);
		g_imageEP = (char*)((UINT64)ImageInfo->ImageBase + (UINT64)*image_ep_offset);

		if (*(char*)g_imageEP != '\xE9')
		{
			DbgPrint("[DriverBuddy] Error, expected a jmp instruction.\n");
			return;
		}

		char byte_patch[] = {'\x33', '\xc0', '\xc3'};  // xor EAX, EAX ; ret ;

		// backup original bytes to unpatch later
		for (int i = 0; i < 3; i++)
		{
			g_origBytes[i] = *((char*)g_imageEP + i);
		}

		__try
		{
			SetCET(0);
			ClearWP();
			for (int i = 0; i < 3; i++)
			{
				*((char*)g_imageEP + i) = byte_patch[i];
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

	// Free the Fast I/O dispatch table
	if (DriverObject->FastIoDispatch)
	{
		ExFreePool(DriverObject->FastIoDispatch);
	}

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);
	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint("DriverBuddy unloaded!\n");
}
