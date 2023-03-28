#include "util.h"
#include <intrin.h>

void set_cet(int enable)
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

void set_smap(int enable)
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
