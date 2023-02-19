
#include "static_export_provider.h"
#include "ntoskrnl_provider.h"
#include "provider.h"
#include "environment.h"
#include <SymParser/symparser.hpp>
#include <PEMapper/pefile.h>

namespace ntoskrnl_export {
    void Initialize() { InitializeExport(); }

    void InitializeObjectType() {
        PsProcessType = (_OBJECT_TYPE*)MemoryTracker::AllocateVariable(sizeof(_OBJECT_TYPE) * 2);
        PsProcessType->TotalNumberOfObjects = 1;
        MemoryTracker::TrackVariable((uint64_t)PsProcessType, sizeof(_OBJECT_TYPE) * 2, (char*)"NTOSKRNL.PsProcessType");
        PsThreadType = (_OBJECT_TYPE*)MemoryTracker::AllocateVariable(sizeof(_OBJECT_TYPE) * 2);
        PsThreadType->TotalNumberOfObjects = 1;
        MemoryTracker::TrackVariable((uint64_t)PsThreadType, sizeof(_OBJECT_TYPE) * 2, (char*)"NTOSKRNL.PsThreadType");
    }

    void InitializePsLoadedModuleList() {
        PsLoadedModuleList = Environment::PsLoadedModuleList;
    }

    void InitKiServiceTable() {
        auto sym = symparser::find_symbol(Environment::ntoskrnl_path, "KiServiceTable"); //"KiServiceTable");

        if (sym && sym->rva) {
            auto pe_file = PEFile::FindModule("ntoskrnl.exe");
            KiServiceTable = (uint64_t)(pe_file->GetMappedImageBase() + sym->rva);
            auto fake_ssdt = _aligned_malloc(0x1000, 0x1000);
            memset(fake_ssdt, 1, 0x1000);
            // KiServiceTable = // (uint64_t)fake_ssdt;
            Logger::Log("Address of KiServiceTable: %p\n", KiServiceTable);
            Logger::Log("KiServiceTable first 2 entries: %p\n", *(uint64_t*)KiServiceTable);

            

            // *(uint32_t*)KiServiceTable = 0;
            // Logger::Log("New value of KiServiceTable entry 0,1: %p", *(uint64_t*)KiServiceTable);
        } else {
            Logger::Log("Failed to find KiServiceTable");
        }
    }

    void InitKeDescriptorTable() {

        auto sym = symparser::find_symbol(Environment::ntoskrnl_path, "KeServiceDescriptorTable"); //"KiServiceTable");

        if (sym && sym->rva) {
            auto pe_file = PEFile::FindModule("ntoskrnl.exe");
            KeServiceDescriptorTable = KiServiceTable; // 0x0102030405060708;  // (uint64_t)(pe_file->GetMappedImageBase() + sym->rva);
            // *(uint64_t*)KeServiceDescriptorTable = 0;  // 0xDEADB00FF00FB00F; // KiServiceTable;
            Logger::Log("Address of KeServiceDescriptorTable: %p\n", KeServiceDescriptorTable);
            // Logger::Log("Set Value of KeServiceDescriptorTable to KiServiceTable: %p\n", *(uint64_t*)KeServiceDescriptorTable);
        } else {
            Logger::Log("Failed to find KeServiceDescriptorTable");
        }
    }

    void InitializeExport() {
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

        InitKiServiceTable();
        // Provider::AddDataImpl("KiServiceTable", &KiServiceTable, 0x4000);

        InitKeDescriptorTable();
        Provider::AddDataImpl("KeServiceDescriptorTable", &KeServiceDescriptorTable, sizeof(KeServiceDescriptorTable));

    }
} // namespace ntoskrnl_export
