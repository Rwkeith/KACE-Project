#include "util.h"

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