#include "comm.h"
#include "buddy_common.h"
#include "util.h"
#include "main.h"

extern PBUDDY_SHMEM g_sharedBuff;
extern PEPROCESS	g_kaceProc;

int		  attached = 0;
PCONTEXT* g_pSharedCtx = NULL;

void WriteSharedMemory(int cmd, PVOID data, size_t size)
{
	memcpy(((int*)g_sharedBuff + 1), data, size);
	*((int*)g_sharedBuff) = cmd;
}

void* InitSharedMemory()
{
	NTSTATUS status;
	// OBJECT_ATTRIBUTES objectAttributes;
	//  HANDLE			  sectionHandle;
	LARGE_INTEGER maximumSize;
	maximumSize.QuadPart = 0x1000;	// 4KB
	PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
	WCHAR				 sectionName[] = L"\\BaseNamedObjects\\Global\\" BUDDY_MEM_ID;
	PACL				 pAcl = NULL;
	PUNICODE_STRING		 tmpUniString = NULL;

	HANDLE			  sectionHandle;
	OBJECT_ATTRIBUTES objAttr;
	UNICODE_STRING	  sectionNameUni;

	RtlInitUnicodeString(&sectionNameUni, sectionName);
	InitializeObjectAttributes(&objAttr, &sectionNameUni, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenSection(&sectionHandle, SECTION_MAP_READ, &objAttr);

	// status = InitObjectWithUserModeAccess(&objectAttributes, sectionName, &pSecurityDescriptor, &pAcl,
	// &tmpUniString);

	// Create the section
	// status = ZwCreateSection(
	//	&sectionHandle, SECTION_ALL_ACCESS, &objectAttributes, &maximumSize, PAGE_READWRITE, SEC_COMMIT, NULL);

	// It's safe to free the ACL memory here
	if (pAcl)
	{
		ExFreePool(pAcl);
	}

	if (pSecurityDescriptor)
	{
		ExFreePool(pSecurityDescriptor);
	}

	if (tmpUniString)
	{
		ExFreePool(tmpUniString);
	}

	if (NT_SUCCESS(status))
	{
		// Map the entire section into the current address space
		PVOID  baseAddress = NULL;
		SIZE_T viewSize = 0;  // Set to 0 to map the entire section

		status = ZwMapViewOfSection(
			sectionHandle, ZwCurrentProcess(), &baseAddress, 0, 0, NULL, &viewSize, ViewShare, 0, PAGE_READWRITE);

		if (!NT_SUCCESS(status))
		{
			// Handle failure
			KdPrint(("[DriverBuddy] Failed to map view of section. Status: 0x%X\n", status));
			return NULL;
		}

		// baseAddress is now the kernel's pointer to the shared memory
		// *(int*)baseAddress = 0x1337;
		DbgPrint("[DriverBuddy] Shared Memory Setup.  Kernel Address: 0x%p\n", baseAddress);
		DbgPrint("[DriverBuddy] SharedMemory first int: 0x%u\n", *(int*)baseAddress);
		return baseAddress;
	}
	else
	{
		// Handle section creation failure
		KdPrint(("[DriverBuddy] Failed to create section: Status: 0x%X\n", status));
		return NULL;
	}
}

void ListenerThread(PVOID Context)
{
	UNREFERENCED_PARAMETER(Context);

	NTSTATUS status;

	WCHAR userObjectName[] = L"\\BaseNamedObjects\\Global\\" USER_ID;

	OBJECT_ATTRIBUTES* objectAttributes;
	OBJECT_ATTRIBUTES  objectAttributesStruct;
	objectAttributes = &objectAttributesStruct;
	PSECURITY_DESCRIPTOR pSecurityDescriptor = NULL;
	PACL				 pAcl = NULL;
	PUNICODE_STRING		 tmpUniString = NULL;

	status = InitObjectWithUserModeAccess(objectAttributes, userObjectName, &pSecurityDescriptor, &pAcl, &tmpUniString);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[DriverBuddy] Failed to init object with user mode access. Status: 0x%X\n", status));
		PsTerminateSystemThread(STATUS_SUCCESS);
	}

	HANDLE userEventHandle;
	status = ZwCreateEvent(&userEventHandle, EVENT_ALL_ACCESS, objectAttributes, NotificationEvent, FALSE);

	if (pAcl)
	{
		ExFreePool(pAcl);
	}

	if (pSecurityDescriptor)
	{
		ExFreePool(pSecurityDescriptor);
	}

	if (tmpUniString)
	{
		ExFreePool(tmpUniString);
	}

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[DriverBuddy] Failed to create user event. Status: 0x%X\n", status));
		PsTerminateSystemThread(STATUS_SUCCESS);
	}

	KdPrint(("[DriverBuddy] Created User Event!\n"));

	WCHAR kernelObjectName[] = L"\\BaseNamedObjects\\Global\\" KERNEL_ID;
	status =
		InitObjectWithUserModeAccess(objectAttributes, kernelObjectName, &pSecurityDescriptor, &pAcl, &tmpUniString);

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[DriverBuddy] Failed to init object with user mode access. Status: 0x%X\n", status));
		PsTerminateSystemThread(STATUS_SUCCESS);
	}

	HANDLE kernelEventHandle;
	status = ZwCreateEvent(&kernelEventHandle, EVENT_ALL_ACCESS, objectAttributes, NotificationEvent, FALSE);

	if (pAcl)
	{
		ExFreePool(pAcl);
	}

	if (pSecurityDescriptor)
	{
		ExFreePool(pSecurityDescriptor);
	}

	if (tmpUniString)
	{
		ExFreePool(tmpUniString);
	}

	if (!NT_SUCCESS(status))
	{
		KdPrint(("[DriverBuddy] Failed to create kernel event. Status: 0x%X\n", status));
		PsTerminateSystemThread(STATUS_SUCCESS);
	}

	KdPrint(("[DriverBuddy] Created Kernel Event!\n"));
	KAPC_STATE apcState;
	while (TRUE)
	{
		// listen for signal from user mode
		ZwWaitForSingleObject(userEventHandle, TRUE, NULL);
		KdPrint(("[DriverBuddy] We received a signal from UM!\n"));

		if (!g_sharedBuff)
		{
			g_sharedBuff = InitSharedMemory();
			if (!g_sharedBuff)
			{
				KdPrint(
					("[DriverBuddy] Listener Thread: Failed to init shared mem.  g_sharedBuff is 0, terminating!\n"));
				PsTerminateSystemThread(STATUS_SUCCESS);
			}
			KdPrint(("[DriverBuddy] Listener Thread: g_sharedBuff is: 0x%p\n", g_sharedBuff));
		}

		// r/w shared buffer per command
		switch (g_sharedBuff->cmd)
		{
			case BUDDY_CMD_EXECUTE:
			{
				if (!g_kaceProc)
				{
					KdPrint(("[DriverBuddy] No KACE process!\n"));
					break;
				}

				// g_pSharedCtx is a usermode address in Kace which holds a PCONTEXT
				if (!g_pSharedCtx)
				{
					PCONTEXT** ppCtx = (PCONTEXT**)(g_sharedBuff->data);
					g_pSharedCtx = *ppCtx;
				}

				if (!attached)
				{
					KdPrint(("[DriverBuddy] Attaching to KACE process: 0x%p\n", g_kaceProc));
					KeStackAttachProcess(g_kaceProc, &apcState);
					attached = 1;
				}

				PCONTEXT ctx = *g_pSharedCtx;

				// could remove apcState later for optimization...

				KdPrint(("[DriverBuddy] Executing RIP: 0x%p\n", ctx->Rip));
				ExecAddressWithCtx(ctx);
				KeUnstackDetachProcess(&apcState);
				attached = 0;
				break;
			}
			default:
				KdPrint(("[DriverBuddy] Listener Thread: g_sharedBuff->cmd is: 0x%d\n", g_sharedBuff->cmd));
				break;
		}

		// convert HANDLE to a pointer to KEVENT
		PKEVENT pEvent = NULL;
		status = ObReferenceObjectByHandle(
			userEventHandle, EVENT_MODIFY_STATE, *ExEventObjectType, KernelMode, (PVOID*)&pEvent, NULL);
		if (NT_SUCCESS(status))
		{
			// reset the event state to non-signaled
			KeClearEvent(pEvent);
			ObDereferenceObject(pEvent);
		}
		else
		{
			KdPrint(("[DriverBuddy] Unable to get event object! status: (0x%08X)\n", status));
			PsTerminateSystemThread(STATUS_SUCCESS);
		}

		// signal complete to user mode
		KdPrint(("[DriverBuddy] Signaling to UM!\n"));
		ZwSetEvent(kernelEventHandle, NULL);
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}
