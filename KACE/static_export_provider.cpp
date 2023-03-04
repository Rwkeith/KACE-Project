
#include "static_export_provider.h"

#include <PEMapper/pefile.h>

#include <SymParser/symparser.hpp>

#include "environment.h"
#include "ntoskrnl_provider.h"
#include "provider.h"

namespace ntoskrnl_export
{
	void Initialize()
	{
		InitializeExport();
	}

	void InitializeObjectType()
	{
		PsProcessType = (_OBJECT_TYPE*)MemoryTracker::AllocateVariable(sizeof(_OBJECT_TYPE) * 2);
		PsProcessType->TotalNumberOfObjects = 1;
		MemoryTracker::TrackVariable(
			(uint64_t)PsProcessType, sizeof(_OBJECT_TYPE) * 2, (char*)"NTOSKRNL.PsProcessType");
		PsThreadType = (_OBJECT_TYPE*)MemoryTracker::AllocateVariable(sizeof(_OBJECT_TYPE) * 2);
		PsThreadType->TotalNumberOfObjects = 1;
		MemoryTracker::TrackVariable((uint64_t)PsThreadType, sizeof(_OBJECT_TYPE) * 2, (char*)"NTOSKRNL.PsThreadType");
	}

	void InitializePsLoadedModuleList()
	{
		PsLoadedModuleList = Environment::PsLoadedModuleList;
	}

	// Can be used to find KeDescriptorTable by walking KiSystemCall64 and finding the LEA instr referencing it.  From
	// there, it's dereferenced to get KiServiceTable, which is a table of offsets.
	void InitKeDescriptorTable()
	{
		auto sym = symparser::find_symbol(Environment::ntoskrnl_path, "KiServiceTable");
		if (sym && sym->rva)
		{
			auto pe_file = PEFile::FindModule("ntoskrnl.exe");
			KeServiceDescriptorTable = (uint64_t)(pe_file->GetMappedImageBase() + sym->rva);  // KiServiceTable;
			Logger::Log("Address of KeServiceDescriptorTable: %p\n", KeServiceDescriptorTable);
		}
		else
		{
			Logger::Log("Failed to find KeServiceDescriptorTable");
		}
	}

	void InitializeExport()
	{
		PsInitialSystemProcess = (uint64_t)&FakeSystemProcess;

		ntoskrnl_export::InitializeObjectType();
		ntoskrnl_export::InitializePsLoadedModuleList();

		Provider::AddDataImpl("NtBuildNumber", &NtBuildNumber, sizeof(NtBuildNumber));
		Provider::AddDataImpl("SeExports", (PVOID)SeExport, sizeof(SeExport));
		Provider::AddDataImpl("KdDebuggerNotPresent", &KdDebuggerNotPresent, sizeof(KdDebuggerNotPresent));
		Provider::AddDataImpl("KdDebuggerEnabled", &KdDebuggerEnabled, sizeof(KdDebuggerEnabled));
		Provider::AddDataImpl("KdEnteredDebugger", &KdEnteredDebugger, sizeof(KdEnteredDebugger));
		Provider::AddDataImpl("PsInitialSystemProcess", &PsInitialSystemProcess, sizeof(PsInitialSystemProcess));
		Provider::AddDataImpl("PsLoadedModuleList", &PsLoadedModuleList, sizeof(PsLoadedModuleList));
		Provider::AddDataImpl("PsProcessType", &PsProcessType, sizeof(PsProcessType));
		Provider::AddDataImpl("PsThreadType", &PsThreadType, sizeof(PsThreadType));
		Provider::AddDataImpl("InitSafeBootMode", &InitSafeBootMode, sizeof(InitSafeBootMode));
		Provider::AddDataImpl("MmSystemRangeStart", &MmSystemRangeStart, sizeof(MmSystemRangeStart));
		Provider::AddDataImpl("MmUserProbeAddress", &MmUserProbeAddress, sizeof(MmUserProbeAddress));
		Provider::AddDataImpl("MmHighestUserAddress", &MmHighestUserAddress, sizeof(MmHighestUserAddress));

		InitKeDescriptorTable();
		Provider::AddDataImpl("KeServiceDescriptorTable", &KeServiceDescriptorTable, sizeof(KeServiceDescriptorTable));
	}
}  // namespace ntoskrnl_export
