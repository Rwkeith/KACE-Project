#pragma once
#include "main.h"
#include "util.h"
#include <intrin.h>

#define SYMLINK_NAME L"\\DosDevices\\DriverBuddy"

// CONTEXT			ctxBackup = 0;
PUNICODE_STRING drvName;
char			orig_bytes[3];
char*			image_ep = 0; 
int				smap_enabled = 0;
PEPROCESS		Process = 0;

void* GenerateAsmForMe(PCONTEXT ctx)
{
	ULONG64 reg1 = ctx->Rcx;
	ULONG64 reg2 = ctx->Rdx;
	ULONG64 reg3 = ctx->R8;
	ULONG64 reg4 = ctx->R9;
	ULONG64 reg5 = ctx->R10;
	ULONG64 reg6 = ctx->R11;
	ULONG64 reg7 = ctx->R12;
	ULONG64 reg8 = ctx->R13;
	ULONG64 reg9 = ctx->R14;
	ULONG64 reg10 = ctx->R15;
	ULONG64 reg11 = ctx->Rax;
	ULONG64 reg12 = ctx->Rbx;
	ULONG64 reg13 = ctx->Rsp;
	ULONG64 reg14 = ctx->Rbp;
	ULONG64 reg15 = ctx->Rsi;
	ULONG64 reg16 = ctx->Rdi;

	ULONG64 reg17 = ctx->Rip;

	reg1 = reg1+reg2+reg3+reg4+reg5+reg6+reg7+reg8+reg9+reg10+reg11+reg12+reg13+reg14+reg15+reg16+reg17;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	
	UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\DriverBuddy");

	PDEVICE_OBJECT DeviceObject;
	NTSTATUS	   status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Failed to create device object (0x%08X)\n", status));
		return status;
	}

	// DeviceObject->Flags |= DO_BUFFERED_IO;	// DO_DIRECT_IO;

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("Failed to create symbolic link (0x%08X)\n", status));
		IoDeleteDevice(DeviceObject);
		return status;
	}

	for (int i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++)
	{
		DriverObject->MajorFunction[i] = BuddyCreateClose;
	}

	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = BuddyDeviceControl;
	DriverObject->DriverUnload = BuddyUnload;

	DbgPrint("DriverBuddy Entry completed. (Latest)\n");
	return STATUS_SUCCESS;
}

NTSTATUS BuddyDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	// get our IO_STACK_LOCATION
	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);
	// static PEPROCESS   Process = 0;
	

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
			if (PsLookupProcessByProcessId((HANDLE)proc_id, &Process) != STATUS_SUCCESS)
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
		case IOCTL_DRIVER_BUDDY_EXECUTE:
		{
			PVOID buffer = Irp->AssociatedIrp.SystemBuffer;
			__try
			{
				if (!Process)
				{
					DbgPrint("[DriverBuddy] Process not set, did you call watch first?\n");
					status = STATUS_INVALID_DEVICE_REQUEST;
					break;
				}

				
				PCONTEXT ctx = (PCONTEXT)buffer;

				DbgPrint("RIP = 0x%p\n", ctx->Rip);
				DbgPrint("RSP = 0x%p\n", ctx->Rsp);
				DbgPrint("RAX = 0x%p\n", ctx->Rax);

				DbgPrint("[DriverBuddy] Executing 0x%p\n", ctx->Rip);
				KAPC_STATE apcState;
				KeStackAttachProcess(Process, &apcState);
				ExecAddressWithCtx((PCONTEXT)buffer);
				KeUnstackDetachProcess(&apcState);
				DbgPrint("[DriverBuddy] Done executing...\n");
				
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

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(SYMLINK_NAME);
	// delete symbolic link
	IoDeleteSymbolicLink(&symLink);
	// delete device object
	IoDeleteDevice(DriverObject->DeviceObject);
	DbgPrint("DriverBuddy unloaded!\n");
}
