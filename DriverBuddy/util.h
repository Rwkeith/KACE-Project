#pragma once
#include <intrin.h>
#include <ntifs.h>

EXTERN_C_START
NTSTATUS InitObjectWithUserModeAccess(OBJECT_ATTRIBUTES*	objectAttributes,
									  WCHAR*				objectName,
									  PSECURITY_DESCRIPTOR* pSecurityDescriptor,
									  PACL*					pAcl,
									  PUNICODE_STRING*		unicodeName);
void	 SetSMAP(int enable);
void	 SetCET(int enable);
void	 SetWP();
void	 ClearWP();
void	 GenerateAsmForMe(PCONTEXT ctx);
EXTERN_C_END
