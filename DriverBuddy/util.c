#include "util.h"
#include "main.h"

NTSTATUS InitObjectWithUserModeAccess(OBJECT_ATTRIBUTES*	objectAttributes,
									  WCHAR*				objectName,
									  PSECURITY_DESCRIPTOR* pSecurityDescriptor,
									  PACL*					pAcl,
									  PUNICODE_STRING*		unicodeName)
{
	NTSTATUS status;
	ULONG	 aclSize;

	*pSecurityDescriptor =
		(PSECURITY_DESCRIPTOR)ExAllocatePoolWithTag(PagedPool, sizeof(SECURITY_DESCRIPTOR), BUDDY_TAG);

	// Initialize the security descriptor
	status = RtlCreateSecurityDescriptor(*pSecurityDescriptor, SECURITY_DESCRIPTOR_REVISION);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[DriverBuddy] Failed to create security descriptor. Status: 0x%X\n", status));
		return status;
	}

	// Define the ACL size and create the ACL
	aclSize = sizeof(ACL) + sizeof(ACCESS_ALLOWED_ACE) + RtlLengthSid(SeExports->SeWorldSid) - sizeof(ULONG);
	*pAcl = (PACL)ExAllocatePoolWithTag(PagedPool, aclSize, BUDDY_TAG);

	if (!*pAcl)
	{
		KdPrint(("[DriverBuddy] Failed to allocate pool for Acl: size: %d \n", aclSize));
		return status;
	}

	status = RtlCreateAcl(*pAcl, aclSize, ACL_REVISION);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[DriverBuddy] Failed to create Acl\n"));
		return status;
	}

	// Add an ACE to the ACL that allows both kernel and user-mode access
	status = RtlAddAccessAllowedAce(*pAcl, ACL_REVISION, EVENT_ALL_ACCESS, SeExports->SeWorldSid);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[DriverBuddy] Failed to modify Acl: 0x%X\n", status));
		return status;
	}

	// Set the security descriptor's DACL
	status = RtlSetDaclSecurityDescriptor(*pSecurityDescriptor, TRUE, *pAcl, FALSE);
	if (!NT_SUCCESS(status))
	{
		KdPrint(("[DriverBuddy] Failed to set security descriptor: 0x%X\n", status));
		return status;
	}

	*unicodeName = (PUNICODE_STRING)ExAllocatePoolWithTag(PagedPool, sizeof(UNICODE_STRING), BUDDY_TAG);

	RtlInitUnicodeString(*unicodeName, objectName);

	InitializeObjectAttributes(objectAttributes, *unicodeName, OBJ_CASE_INSENSITIVE, NULL, *pSecurityDescriptor);

	return status;
}

void SetCET(int enable)
{
	unsigned long long cr4_value = __readcr4();
	if (enable)
	{
		cr4_value |= (1ULL << 23);	// Set CET flag to enable
	}
	else
	{
		cr4_value &= ~(1ULL << 23);	 // Clear CET flag to disable
	}
	__writecr4(cr4_value);
}

// this will cause a critical structure corruption BSOD
void SetSMAP(int enable)
{
	unsigned long long cr4_value = __readcr4();
	if (enable)
	{
		DbgPrint("[DriverBuddy] Enabling SMAP...original cr4: 0x%llX\n", cr4_value);
		cr4_value |= (1ULL << 21);
	}
	else
	{
		DbgPrint("[DriverBuddy] Disabling SMAP...original cr4: 0x%llX\n", cr4_value);
		cr4_value &= ~(1ULL << 21);
	}
	__writecr4(cr4_value);
	DbgPrint("[DriverBuddy] new cr4: 0x%llX\n", cr4_value);
}

void ClearWP()
{
	DbgPrint("[DriverBuddy] Clearing write protection bit\n");
	_disable();
	unsigned long long cr0_value = __readcr0();
	cr0_value &= ~(1ULL << 16);
	__writecr0(cr0_value);
}

void SetWP()
{
	DbgPrint("[DriverBuddy] Setting write protection bit\n");
	unsigned long long cr0_value = __readcr0();
	cr0_value |= (1ULL << 16);
	__writecr0(cr0_value);
	_enable();
}

void GenerateAsmForMe(PCONTEXT ctx)
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

	reg1 = reg1 + reg2 + reg3 + reg4 + reg5 + reg6 + reg7 + reg8 + reg9 + reg10 + reg11 + reg12 + reg13 + reg14 +
		   reg15 + reg16 + reg17;
}
