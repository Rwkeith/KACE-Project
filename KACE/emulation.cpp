#include "emulation.h"
#include "static_export_provider.h"
#include <Logger/Logger.h>
#include <MemoryTracker/memorytracker.h>
#include <PEMapper/pefile.h>
#include <Zydis/Zydis.h>
#include <SymParser/symparser.hpp>

#include <assert.h>
#include "environment.h"
#include "paging_emulation.h"
#include "provider.h"

namespace VCPU {
    static ZydisDecoder decoder;
   

    uint64_t VCPU::CR0 = 0x80050033;
    uint64_t VCPU::CR3 = 0x1ad002;
    uint64_t VCPU::CR4 = 0x370678;
    uint64_t VCPU::CR8 = 0;

    //MSRs
    uint64_t LSTAR = 0x1000;




    namespace MSRContext {
        std::unordered_map<uint32_t, std::pair<uint64_t, std::string>> MSRData;

        void InitializeMSR() {

            auto sym = symparser::find_symbol(Environment::ntoskrnl_path, "KiSystemCall64");

            if (sym && sym->rva) {
                auto pe_file = PEFile::FindModule("ntoskrnl.exe");
                LSTAR = (uint64_t)(pe_file->GetMappedImageBase() + sym->rva);
                Logger::Log("LSTAR contains %p which points to data: %p\n", LSTAR, *(uint64_t*)LSTAR);
            } else {
                Logger::Log("Failed to find KiSystemCall64");
            }
        }

        bool Initialize() 
        {
            InitializeMSR();

            MSRData.insert(std::pair(0x1D9, std::pair(0, "DBGCTL_MSR")));
            MSRData.insert(std::pair(0x122, std::pair(0,"IA32_TSX_CTRL MSR")));
            MSRData.insert(std::pair(0x1DB, std::pair(0, "MSRLASTBRANCH-_FROM_IP_MSR")));
            MSRData.insert(std::pair(0x680, std::pair(0, "LastBranchFromIP_MSR")));
            MSRData.insert(std::pair(0x1c9, std::pair(0, "MSR_LASTBRANCH_TOS")));
            MSRData.insert(std::pair(0, std::pair(0xFFF, "MSR_0_P5_IP_ADDR")));
            MSRData.insert(std::pair(0xc0000082, std::pair(LSTAR, "MSR_LSTAR")));
            MSRData.insert(std::pair(0x1B, std::pair(0xfee00800, "IA32_APIC_BASE")));
           

            return true;
        }
    } // namespace MSRContext

    void Initialize() {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
        MemoryTracker::AddMapping(KUSD_MIN, 0x1000, KUSD_USERMODE);
        

        
        MSRContext::Initialize();
    }

    bool Decode(PCONTEXT context, ZydisDecodedInstruction *instr) {
        ZyanU64 runtime_address = context->Rip;
        auto status = ZydisDecoderDecodeBuffer(&decoder, (PVOID)context->Rip, ZYDIS_MAX_INSTRUCTION_LENGTH, instr);
        return ZYAN_SUCCESS(status);
    }

    static uint32_t GRegIndex(ZydisRegister Reg) {

        PCONTEXT resolver = 0;

        if (Reg == ZYDIS_REGISTER_RIP)
            return (uint32_t)(&resolver->Rip) / 8;
        if (Reg == ZYDIS_REGISTER_EFLAGS)
            return (uint32_t)(&resolver->EFlags) / 8;

        auto lookup = (uint32_t)&resolver->Rax;
        auto zydis_rax = ZYDIS_REGISTER_RAX;

        auto zydis_gr64_lookup = ZydisRegisterGetLargestEnclosing(ZYDIS_MACHINE_MODE_LONG_64, Reg);
        auto index = zydis_gr64_lookup - zydis_rax;

        if (index < 0 || index > 15)
            return 0;

        lookup += index * sizeof(uint64_t);

        return lookup / 8;
    }

    // looks up xmm0 to xmm31
    static uint32_t XmmRegIndex(ZydisRegister Reg) {
        
        PCONTEXT resolver = 0;

        auto lookup = (uint32_t)&resolver->Xmm0;
        auto zydis_xmm0 = ZYDIS_REGISTER_XMM0;

        auto index = Reg - zydis_xmm0;

        if (index < 0 || index > 31)
            return 0;

        lookup += index * sizeof(M128A);

        return lookup / 16;  // 16 bytes, 128 bit regs
    }

    static uint64_t ReadRegisterValue(PCONTEXT ctx, ZydisRegister reg) {
        uint64_t* context_lookup = (uint64_t*)ctx;
        auto reg_class = ZydisRegisterGetClass(reg);
        auto ret = context_lookup[GRegIndex(reg)];

        if (reg_class == ZYDIS_REGCLASS_GPR64) { //Read the whole64bit register
            return ret;
        } else if (reg_class == ZYDIS_REGCLASS_GPR32) { //32 lower bytes
            return ret & 0xFFFFFFFF;
        } else if (reg_class == ZYDIS_REGCLASS_GPR16) { //16 llower bytes
            return ret & 0xFFFF;
        } else if (reg_class == ZYDIS_REGCLASS_GPR8) {
            if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) { //8 upper byte
                return (ret & 0xFF00) >> 8;
            } else { //8 lower bytes
                return ret & 0xFF;
            }
        } else {
            DebugBreak();
        }

        return 0;
    }

    static bool SkipToNext(PCONTEXT ctx, ZydisDecodedInstruction *instr) {
        ctx->Rip += instr->length;
        return true;
    }

    namespace PrivilegedInstruction {
        bool Parse(PCONTEXT context) {
            ZydisDecodedInstruction instr;
            
            if (!Decode(context, &instr))
                return false;

            if (instr.mnemonic == ZYDIS_MNEMONIC_CLI) {
                Logger::Log("Clearing Interrupts\n");
                return SkipToNext(context, &instr);
            } else if (instr.mnemonic == ZYDIS_MNEMONIC_STI) {
                Logger::Log("Restoring Interrupts\n");
                return SkipToNext(context, &instr);
            } else if (instr.mnemonic == ZYDIS_MNEMONIC_MOV) {
                EmulatePrivilegedMOV(context, &instr);
                return SkipToNext(context, &instr);
            } else if (instr.mnemonic == ZYDIS_MNEMONIC_WRMSR) {
                if (WriteMSR(context, &instr))
                    return SkipToNext(context, &instr);
                else
                    return false;
            }
            else if (instr.mnemonic == ZYDIS_MNEMONIC_RDMSR) {
                if (ReadMSR(context, &instr))
                    return SkipToNext(context, &instr);
                else
                    return false;
            }
            
            else if (instr.mnemonic == ZYDIS_MNEMONIC_INVLPG) {
                Logger::Log("Invalidating cache\n");
                return SkipToNext(context, &instr);
            } 
            else if (instr.mnemonic == ZYDIS_MNEMONIC_OUT) {
                WritePIO(context, &instr);
                return SkipToNext(context, &instr);
            } else if (instr.mnemonic == ZYDIS_MNEMONIC_IN) {
                ReadPIO(context, &instr);
                return SkipToNext(context, &instr);
            }

            else {
                DebugBreak();
                return false;
            }
        }

        bool EmulatePrivilegedMOV(PCONTEXT context, ZydisDecodedInstruction *instr) {
            uint64_t* context_lookup = (uint64_t*)context;

            auto reg_to_write = GRegIndex(instr->operands[0].reg.value);
            auto reg_to_read = GRegIndex(instr->operands[1].reg.value);

            if (instr->operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || instr->operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER) {
                DebugBreak();
            }

            if (!reg_to_read && !reg_to_write) {
                DebugBreak();
            }

            if (instr->operands[0].reg.value == ZYDIS_REGISTER_CR0) { //Write CR0
                Logger::Log("Writing %llx to CR0\n", context_lookup[reg_to_read]);
                VCPU::CR0 = context_lookup[reg_to_read];
            } else if (instr->operands[1].reg.value == ZYDIS_REGISTER_CR0) { //Read CR0
                Logger::Log("Reading CR0\n");
                context_lookup[reg_to_write] = VCPU::CR0;
            } else if (instr->operands[0].reg.value == ZYDIS_REGISTER_CR3) { //Write CR3
                Logger::Log("Writing %llx to CR3\n", context_lookup[reg_to_read]);
                VCPU::CR3 = context_lookup[reg_to_read];
            } else if (instr->operands[1].reg.value == ZYDIS_REGISTER_CR3) { //Read CR3
                Logger::Log("Reading CR3\n");
                context_lookup[reg_to_write] = VCPU::CR3;
            } else if (instr->operands[0].reg.value == ZYDIS_REGISTER_CR4) { //Read CR4
                Logger::Log("Writing %llx to CR4\n", context_lookup[reg_to_read]);
                VCPU::CR4 = context_lookup[reg_to_read];
            } else if (instr->operands[1].reg.value == ZYDIS_REGISTER_CR4) { //Read CR4
                Logger::Log("Reading CR4\n");
                context_lookup[reg_to_write] = VCPU::CR4;
            } else if (instr->operands[0].reg.value == ZYDIS_REGISTER_CR8) { //Write CR8
                Logger::Log("Writing %llx to CR8\n", context_lookup[reg_to_read]);
                VCPU::CR8 = context_lookup[reg_to_read];
            } else if (instr->operands[1].reg.value == ZYDIS_REGISTER_CR8) { //Read CR8
                Logger::Log("Reading CR8\n");
                context_lookup[reg_to_write] = VCPU::CR8;
            }
            else if (instr->operands[0].reg.value == ZYDIS_REGISTER_DR7) { //Read CR8
                Logger::Log("Writing %llx to DR7\n", context_lookup[reg_to_read]);
                context->Dr7 = context_lookup[reg_to_read];
            }
            else if (instr->operands[1].reg.value == ZYDIS_REGISTER_DR6) { //Read DR6
                Logger::Log("Reading DR6\n");
                context_lookup[reg_to_write] = context->Dr6;
            }
            else if (instr->operands[1].reg.value == ZYDIS_REGISTER_DR7) { //Read DR6
                Logger::Log("Reading DR7\n");
                context_lookup[reg_to_write] = context->Dr7;
            }
            else {
                DebugBreak();
            }

            return true;
        }

        /*
		Reads the contents of a 64-bit model specific register (MSR) specified in the ECX register into registers EDX:EAX. (On processors that support the Intel 64 architecture, the high-order 32 bits of RCX are ignored.) The EDX register is loaded with the high-order 32 bits of the MSR and the EAX register is loaded with the low-order 32 bits. (On processors that support the Intel 64 architecture, the high-order 32 bits of each of RAX and RDX are cleared.) If fewer than 64 bits are implemented in the MSR being read, the values returned to EDX:EAX in unimplemented bit locations are undefined.

		This instruction must be executed at privilege level 0 or in real-address mode; otherwise, a general protection exception #GP(0) will be generated. Specifying a reserved or unimplemented MSR address in ECX will also cause a general protection exception.
		*/

        bool ReadMSR(PCONTEXT context, ZydisDecodedInstruction* instr) {
            uint32_t ECX = context->Rcx & 0xFFFFFFFF;

            if (!MSRContext::MSRData.contains(ECX)) {
                Logger::Log("Reading from unsupported MSR : %llx\n", ECX);
                return false;
            }

            auto ReadData = MSRContext::MSRData[ECX];
            auto MSRValue = ReadData.first;
            auto MSRName = ReadData.second;
            context->Rdx = (MSRValue >> 32) & 0xFFFFFFFF;
            context->Rax = (MSRValue)&0xFFFFFFFF;
            Logger::Log("Reading MSR %s : %llx\n", MSRName.c_str(), MSRValue);
            return true;
        }

        bool WriteMSR(PCONTEXT context, ZydisDecodedInstruction*  instr) {
            uint32_t ECX = context->Rcx & 0xFFFFFFFF;

            if (!MSRContext::MSRData.contains(ECX)) { //GP(0) If the value in ECX specifies a reserved or unimplemented MSR address
                Logger::Log("Writing to unsupported MSR : %llx\n", ECX);
                return false;
            }

            auto ReadData = MSRContext::MSRData[ECX];
            auto MSRValue = ReadData.first;
            auto MSRName = ReadData.second;

            auto NewMSRValue = (context->Rdx << 32) | (context->Rax) & 0xFFFFFFFF;

            MSRContext::MSRData[ECX] = std::pair(NewMSRValue, MSRName);

            Logger::Log("Writing MSR %s : %llx\n", MSRName.c_str(), NewMSRValue);
            return true;
        }

        bool ReadPIO(PCONTEXT context, ZydisDecodedInstruction* instr) {
            // ex:   in  eax, dx    <- eax <= result , dx = addr to read
            // just handle first case, later can fully emulate if necessary.
            context->Rax = 0;
            return true;
        }

        bool WritePIO(PCONTEXT context, ZydisDecodedInstruction* instr) {
            // DriverBuddy coming soon....
            return true;
        }



    } // namespace PrivilegedInstruction

    namespace MemoryWrite {
        bool Parse(uintptr_t addr, PCONTEXT context) {
            ZydisDecodedInstruction instr;

            if (!Decode(context,&instr))
                return false;

            if (auto exportImpl = Provider::FindDataImpl(addr)) {
                return EmulateWrite(exportImpl, context, &instr);
            }

            if (auto HVA = MemoryTracker::GetHVA(addr)) {
                if (MemoryTracker::isTracked(HVA)) {
                    DebugBreak();
                }
                else if (MemoryTracker::isTracked(addr)) {
                    auto nameVar = MemoryTracker::getName(addr);
                    auto offset = MemoryTracker::getStart(nameVar);
                    Logger::Log("Emulating write to %s+%08x\n", nameVar.c_str(), addr - offset);
                }
                else if (KUSD_MIN <= addr && addr <= KUSD_MAX) {
                    Logger::Log("Emulating write to %s+%08x\n", "KUSER_SHARED_DATA", addr - KUSD_MIN);
                    DebugBreak();
                }
                else {
                    auto pe_file = PEFile::FindModule(addr);
                    if (!pe_file) {
                        Logger::Log("Emulating write to %llx translated to %llx\n", addr, HVA);
                        DebugBreak();
                    }
                    else
                        Logger::Log("Emulating write to %s:+%08x\n", pe_file->name.c_str(), addr - pe_file->GetMappedImageBase());
                    // DebugBreak();
                }

                return EmulateWrite(HVA, context, &instr);
            } else {
                if (addr == 0xffffffffffffffff)
                    return false;
                Environment::CheckPtr(addr);
                Logger::Log("Logging from a memory that has no usermode mapping : %llx\n", addr);
                fflush(stdout);
                return false;
            }
        }

        bool EmulateWrite(uintptr_t addr, PCONTEXT context, ZydisDecodedInstruction* instr) { //We return true if we emulated it

            if (instr->mnemonic == ZYDIS_MNEMONIC_MOV) {
                if (instr->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    InstrEmu::WritePtr::EmulateMOV(context, instr->operands[1].reg.value, addr, instr);
                    return SkipToNext(context, instr);
                } else if (instr->operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    // not implemented
                    DebugBreak();
                    //InstrEmu::WritePtr::EmulateMOV(context, instr->operands[1].imm.value.u, addr, instr);
                    //return SkipToNext(context, instr);
                }
                else {
                    Logger::Log("This should never happen, please investigate\n");
                    ZydisFormatter formatter;
                    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
                    char buffer[256];
                    ZydisFormatterFormatInstruction(&formatter, instr, buffer, sizeof(buffer), ZYDIS_RUNTIME_ADDRESS_NONE);
                    Logger::Log("Instruction: %s\n", buffer);
                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_OR) {
                if (instr->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    InstrEmu::WritePtr::EmulateOR(context, instr->operands[1].reg.value, addr, instr);
                    return SkipToNext(context, instr);
                } else {

                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_XOR) {
                if (instr->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    InstrEmu::WritePtr::EmulateXOR(context, instr->operands[1].reg.value, addr, instr);
                    return SkipToNext(context, instr);
                } else {

                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_AND) {
                if (instr->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    InstrEmu::WritePtr::EmulateAND(context, instr->operands[1].reg.value, addr, instr);
                    return SkipToNext(context, instr);
                } else {
                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_STOSQ) {
                if (instr->operand_count == 5 && instr->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && instr->operands[0].element_size == 64) {
                    auto EF = __readeflags();
                    __writeeflags(context->EFlags);
                    __stosq((PDWORD64)addr, context->Rax, context->Rcx);
                    __writeeflags(EF);
                    context->Rcx = 0;
                    return SkipToNext(context, instr);
                } else {
                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_MOVUPS || instr->mnemonic == ZYDIS_MNEMONIC_MOVAPS) {
                if (instr->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY
                    && instr->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) { // movups [reg], reg128
                    InstrEmu::WritePtr::EmulateMOVUPS(context, instr->operands[1].reg.value, addr, instr->operands[0].size, instr);
                    return SkipToNext(context, instr);
                }
            } else {
                ZydisFormatter formatter;
                ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
                char buffer[256];
                ZydisFormatterFormatInstruction(&formatter, instr, buffer, sizeof(buffer), ZYDIS_RUNTIME_ADDRESS_NONE);
                Logger::Log("Unhandled instruction in write emulation: %s\n", buffer);
                DebugBreak();
                return false;
            }
            return false;
        }

    } // namespace MemoryWrite

    namespace MemoryRead {

        bool Parse(uintptr_t addr, PCONTEXT context) {
            ZydisDecodedInstruction instr;
            if (!Decode(context, &instr))
                return false;

            if (auto exportImpl = Provider::FindDataImpl(addr)) {
                return EmulateRead(exportImpl, context, &instr);
            }

            if (auto HVA = MemoryTracker::GetHVA(addr)) {
                if (MemoryTracker::isTracked(addr))  {
                    auto nameVar = MemoryTracker::getName(addr);
                    auto offset = MemoryTracker::getStart(nameVar);
                    Logger::Log("Emulating read from %s+%08x\n", nameVar.c_str(), addr-offset);
                }
                else if (KUSD_MIN <= addr && addr <= KUSD_MAX) {
                    Logger::Log("Emulating read from %s+%08x\n", "KUSER_SHARED_DATA", addr - KUSD_MIN);
                }
                else {
                    auto pe_file = PEFile::FindModule(addr);
                    if (!pe_file) {
                        Logger::Log("Emulating read from %llx translated to %llx\n", addr, HVA);
                        DebugBreak();
                    }
                    else
                        Logger::Log("Emulating read from %s:+%08x\n", pe_file->name.c_str(), addr - pe_file->GetMappedImageBase());
                   // DebugBreak();
                }
                
                return EmulateRead(HVA, context, &instr);
            } else {
                if (addr == 0xffffffffffffffff) {
                    return false;
                }
                if (addr) {
                    uint16_t PML4E = (uint16_t)((addr >> 39) & 0x1FF); //<! PML4 Entry Index
                    uint16_t PDPTE = (uint16_t)((addr >> 30) & 0x1FF); //<! Page-Directory-Pointer Table Index
                    uint16_t PDTE = (uint16_t)((addr >> 21) & 0x1FF); //<! Page Directory Table Index
                    uint16_t PTE = (uint16_t)((addr >> 12) & 0x1FF);
                    uint16_t Offset = addr & 0xFFF;
                    if (PML4E == 481) {
                        //Logger::Log("CR3 operation\n");
                        if (PTE == 481 && PDPTE == 481 && PDTE == 481) {
                            //Logger::Log("Getting entry %d for PML4\n", Offset/8);
                            _PML4E* pml4e1 = PagingEmulation::GetPML4();
                            pml4e1[Offset / 8].Present = 0;
                            if (Offset / 8 == 481)
                                pml4e1[Offset / 8].PageFrameNumber = 0x1AD;
                            else
                                pml4e1[Offset / 8].PageFrameNumber = 0x401D9E;
                            return EmulateRead((uintptr_t)PagingEmulation::GetPML4()+Offset, context, &instr);
                        }
                        else {
                            if (PDPTE == 481 && PDTE == 481 && PTE != 481) {
                                auto translatedAddr = ((UINT64)0x0000 << 48) |
                                    ((UINT64)PTE << 39) |
                                    ((UINT64)Offset / 8 << 30) |
                                    ((UINT64)0 << 21) |
                                    ((UINT64)0 << 12) |
                                    ((UINT64)0);
                               // Logger::Log("Getting physical PFN for %llx\n", translatedAddr);
                                _PML4E* pml4e1 = PagingEmulation::GetPML4();
                                
                                pml4e1[Offset / 8].Present = 1;
                                pml4e1[Offset / 8].PageFrameNumber = translatedAddr/0x1000;
                                return EmulateRead((uintptr_t)PagingEmulation::GetPML4() + Offset, context, &instr);
                            } else  if (PDPTE == 481 && PDTE != 481 && PTE != 481) {
                                auto translatedAddr = ((UINT64)0x0000 << 48) |
                                    ((UINT64)PDTE << 39) |
                                    ((UINT64)PTE << 30) |
                                    ((UINT64)Offset/8 << 21) |
                                    ((UINT64)0 << 12) |
                                    ((UINT64)0);
                               // Logger::Log("Getting physical PFN for %llx\n", translatedAddr);
                                _PML4E* pml4e1 = PagingEmulation::GetPML4();
                                pml4e1[Offset / 8].Present = 1;
                                pml4e1[Offset / 8].PageFrameNumber = translatedAddr / 0x1000;
                                return EmulateRead((uintptr_t)PagingEmulation::GetPML4() + Offset, context, &instr);
                            }
                            else {
                                auto translatedAddr = ((UINT64)0x0000 << 48) |
                                    ((UINT64)PDPTE << 39) |
                                    ((UINT64)PDTE << 30) |
                                    ((UINT64)PTE << 21) |
                                    ((UINT64)Offset / 8 << 12) |
                                    ((UINT64)0);
                                //Logger::Log("Getting physical PFN for %llx\n", translatedAddr);
                                _PML4E* pml4e1 = PagingEmulation::GetPML4();
                                pml4e1[Offset / 8].Present = 0;
                                pml4e1[Offset / 8].PageFrameNumber = 0x555;
                                return EmulateRead((uintptr_t)PagingEmulation::GetPML4() + Offset, context, &instr);
                            }
                        }
                    }
                    else {
                        Environment::CheckPtr(addr);
                        Logger::Log("Logging from a memory that has no usermode mapping : %llx\n", addr);
                        fflush(stdout);
                        return false;
                    }
                } else {
                    Environment::CheckPtr(addr);
                    Logger::Log("Logging from a memory that has no usermode mapping : %llx\n", addr);
                    fflush(stdout);
                    return false;
                }
            }
        }

        bool EmulateRead(uintptr_t addr, PCONTEXT context, ZydisDecodedInstruction* instr) { //We return true if we emulated it
            // Logger::Log("Trying to emulate read on addr %p which contains %p\n", addr, *(uint64_t*)addr);
            if (instr->mnemonic == ZYDIS_MNEMONIC_MOV) {
                if (instr->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    InstrEmu::ReadPtr::EmulateMOV(context, instr->operands[0].reg.value, addr, instr);
                    return SkipToNext(context, instr);
                } else {
                    Logger::Log("This should never happen, please investigate\n");
                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_OR) {
                if (instr->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    InstrEmu::ReadPtr::EmulateOR(context, instr->operands[0].reg.value, addr, instr);
                    return SkipToNext(context, instr);
                } else {

                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_XOR) {
                if (instr->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                    InstrEmu::ReadPtr::EmulateXOR(context, instr->operands[0].reg.value, addr, instr);
                    return SkipToNext(context,instr);
                } else {

                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_AND) {
                if (instr->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {

                    InstrEmu::ReadPtr::EmulateAND(context, instr->operands[0].reg.value, addr, instr);
                    return SkipToNext(context, instr);
                } else {

                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_SUB) {
                if (instr->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {

                    InstrEmu::ReadPtr::EmulateSUB(context, instr->operands[0].reg.value, addr, instr);
                    return SkipToNext(context, instr);
                } else {

                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_ADD) {
                if (instr->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {

                    InstrEmu::ReadPtr::EmulateADD(context, instr->operands[0].reg.value, addr, instr);
                    return SkipToNext(context, instr);
                } else {

                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_CMP) {
                if (instr->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && instr->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) { //cmp [memory], reg
                    InstrEmu::EmulateCMPSourcePtr(context, instr->operands[1].reg.value, addr, instr);
                    return SkipToNext(context, instr);
                } else if (instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
                    && instr->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) { //cmp reg, [memory]
                    InstrEmu::EmulateCMPDestPtr(context, instr->operands[0].reg.value, addr, instr);
                    return SkipToNext(context, instr);
                } else if (instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
                    && instr->operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) { //cmp reg, [memory]
                    InstrEmu::EmulateCMPImm(context, instr->operands[0].imm.value.s, addr, instr->operands[1].element_size, instr);
                    return SkipToNext(context, instr);
                } else if (instr->operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                    && instr->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) { //cmp reg, [memory]
                    InstrEmu::EmulateCMPImm(context, instr->operands[1].imm.value.s, addr, instr->operands[0].element_size, instr);
                    return SkipToNext(context, instr);
                } else {
                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_TEST) {
                if (instr->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY && instr->operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER) { //cmp [memory], reg
                    InstrEmu::EmulateTestSourcePtr(context, instr->operands[1].reg.value, addr, instr);
                    return SkipToNext(context, instr);
                } else if (instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
                    && instr->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) { //cmp reg, [memory]
                    InstrEmu::EmulateTestDestPtr(context, instr->operands[0].reg.value, addr, instr);
                    return SkipToNext(context, instr);
                } else if (instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
                    && instr->operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) { //cmp reg, [memory]
                    InstrEmu::EmulateTestImm(context, instr->operands[0].imm.value.s, addr, instr->operands[1].element_size, instr);
                    return SkipToNext(context, instr);
                } else if (instr->operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                    && instr->operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) { //cmp reg, [memory]
                    InstrEmu::EmulateTestImm(context, instr->operands[1].imm.value.s, addr, instr->operands[0].element_size, instr);
                    return SkipToNext(context, instr);
                } else {
                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_MOVZX) {
                if (instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && instr->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) { //movzx reg, [memory]
                    InstrEmu::ReadPtr::EmulateMOVZX(context, instr->operands[0].reg.value, addr, instr->operands[1].size, instr);
                    return SkipToNext(context, instr);
                } else {
                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_MOVSXD) {
                if (instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY && instr->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER) { //movsxd reg, [memory]
                    InstrEmu::ReadPtr::EmulateMOVSX(context, instr->operands[0].reg.value, addr, instr->operands[1].size, instr);
                    return SkipToNext(context, instr);
                } else {
                    DebugBreak();
                }
            } else if (instr->mnemonic == ZYDIS_MNEMONIC_MOVUPS || instr->mnemonic == ZYDIS_MNEMONIC_MOVAPS) {
                if (instr->operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
                    && instr->operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY) { // movups reg, [reg]
                    InstrEmu::ReadPtr::EmulateMOVUPS(context, instr->operands[0].reg.value, addr, instr->operands[1].size, instr);
                    return SkipToNext(context, instr);
                } else {
                    DebugBreak();
                }
            }

            else {
                ZydisFormatter formatter;
                ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
                char buffer[256];
                ZydisFormatterFormatInstruction(&formatter, instr, buffer, sizeof(buffer), ZYDIS_RUNTIME_ADDRESS_NONE);
                Logger::Log("Unhandled instruction in read emulation: %s\n", buffer);
                DebugBreak();
                return false;
            }
            return false;
        }

    } // namespace MemoryRead

    namespace InstrEmu {

        bool EmulateCMPSourcePtr(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //Emulates cmp [ptr], reg // cmp reg, [ptr]

            uint64_t* context_lookup = (uint64_t*)ctx;
            auto reg_class = ZydisRegisterGetClass(reg);
            auto reg_value = ReadRegisterValue(ctx, reg);

            if (reg_class == ZYDIS_REGCLASS_GPR64) {
                ctx->EFlags = u_cmp_64_sp(ctx->EFlags, ptr, reg_value);
            } else if (reg_class == ZYDIS_REGCLASS_GPR32) {
                ctx->EFlags = u_cmp_32_sp(ctx->EFlags, ptr, reg_value);
            } else if (reg_class == ZYDIS_REGCLASS_GPR16) {
                ctx->EFlags = u_cmp_16_sp(ctx->EFlags, ptr, reg_value);

            } else if (reg_class == ZYDIS_REGCLASS_GPR8) {
                ctx->EFlags = u_cmp_8_sp(ctx->EFlags, ptr, reg_value);
            } else {
                DebugBreak();
            }
            return true;
        }

        bool EmulateCMPDestPtr(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //Emulates cmp [ptr], reg // cmp reg, [ptr]

            uint64_t* context_lookup = (uint64_t*)ctx;
            auto reg_class = ZydisRegisterGetClass(reg);
            auto reg_value = ReadRegisterValue(ctx, reg);

            if (reg_class == ZYDIS_REGCLASS_GPR64) {
                ctx->EFlags = u_cmp_64_dp(ctx->EFlags, ptr, reg_value);
            } else if (reg_class == ZYDIS_REGCLASS_GPR32) {
                ctx->EFlags = u_cmp_32_dp(ctx->EFlags, ptr, reg_value);
            } else if (reg_class == ZYDIS_REGCLASS_GPR16) {
                ctx->EFlags = u_cmp_16_dp(ctx->EFlags, ptr, reg_value);

            } else if (reg_class == ZYDIS_REGCLASS_GPR8) {
                ctx->EFlags = u_cmp_8_dp(ctx->EFlags, ptr, reg_value);
            } else {
                DebugBreak();
            }
            return true;
        }

        bool EmulateCMPImm(PCONTEXT ctx, int32_t imm, uint64_t ptr, size_t size, ZydisDecodedInstruction* instr) { //Emulates cmp [ptr], reg // cmp reg, [ptr]

            uint64_t* context_lookup = (uint64_t*)ctx;

            if (size == 64) {
                ctx->EFlags = u_cmp_64_sp(ctx->EFlags, ptr, imm);
            } else if (size == 32) {
                ctx->EFlags = u_cmp_32_sp(ctx->EFlags, ptr, imm);
            } else if (size == 16) {
                ctx->EFlags = u_cmp_16_sp(ctx->EFlags, ptr, imm);

            } else if (size == 8) {
                ctx->EFlags = u_cmp_8_sp(ctx->EFlags, ptr, imm);
            } else {
                DebugBreak();
            }
            return true;
        }

        bool EmulateTestSourcePtr(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //Emulates cmp [ptr], reg // cmp reg, [ptr]

            uint64_t* context_lookup = (uint64_t*)ctx;
            auto reg_class = ZydisRegisterGetClass(reg);
            auto reg_value = ReadRegisterValue(ctx, reg);

            if (reg_class == ZYDIS_REGCLASS_GPR64) {
                ctx->EFlags = u_test_64_sp(ctx->EFlags, ptr, reg_value) | 0x10000;
            } else if (reg_class == ZYDIS_REGCLASS_GPR32) {
                ctx->EFlags = u_test_32_sp(ctx->EFlags, ptr, reg_value) | 0x10000;
            } else if (reg_class == ZYDIS_REGCLASS_GPR16) {
                ctx->EFlags = u_test_16_sp(ctx->EFlags, ptr, reg_value) | 0x10000;

            } else if (reg_class == ZYDIS_REGCLASS_GPR8) {
                ctx->EFlags = u_test_8_sp(ctx->EFlags, ptr, reg_value) | 0x10000;
            } else {
                DebugBreak();
            }
            return true;
        }

        bool EmulateTestDestPtr(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //Emulates cmp [ptr], reg // cmp reg, [ptr]

            uint64_t* context_lookup = (uint64_t*)ctx;
            auto reg_class = ZydisRegisterGetClass(reg);
            auto reg_value = ReadRegisterValue(ctx, reg);

            if (reg_class == ZYDIS_REGCLASS_GPR64) {
                ctx->EFlags = u_test_64_dp(ctx->EFlags, ptr, reg_value) | 0x10000;
            } else if (reg_class == ZYDIS_REGCLASS_GPR32) {
                ctx->EFlags = u_test_32_dp(ctx->EFlags, ptr, reg_value) | 0x10000;
            } else if (reg_class == ZYDIS_REGCLASS_GPR16) {
                ctx->EFlags = u_test_16_dp(ctx->EFlags, ptr, reg_value) | 0x10000;

            } else if (reg_class == ZYDIS_REGCLASS_GPR8) {
                ctx->EFlags = u_test_8_dp(ctx->EFlags, ptr, reg_value) | 0x10000;
            } else {
                DebugBreak();
            }
            return true;
        }

        bool EmulateTestImm(PCONTEXT ctx, int32_t imm, uint64_t ptr, size_t size, ZydisDecodedInstruction* instr) { //Emulates cmp [ptr], reg // cmp reg, [ptr]

            uint64_t* context_lookup = (uint64_t*)ctx;

            if (size == 64) {
                ctx->EFlags = u_test_64_sp(ctx->EFlags, ptr, imm) | 0x10000;
            } else if (size == 32) {
                ctx->EFlags = u_test_32_sp(ctx->EFlags, ptr, imm) | 0x10000;
            } else if (size == 16) {
                ctx->EFlags = u_test_16_sp(ctx->EFlags, ptr, imm) | 0x10000;

            } else if (size == 8) {
                ctx->EFlags = u_test_8_sp(ctx->EFlags, ptr, imm) | 0x10000;
            } else {
                DebugBreak();
            }
            return true;
        }

        namespace ReadPtr {
            bool EmulateMOV(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //X86-compliant MOV R64, [...] emulation

                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);
                auto orig_value = context_lookup[GRegIndex(reg)];

                if (reg_class == ZYDIS_REGCLASS_GPR64) { //We replace the whole register
                    context_lookup[GRegIndex(reg)] = *(uint64_t*)ptr;

                } else if (reg_class == ZYDIS_REGCLASS_GPR32) { //We replace the whole register
                    context_lookup[GRegIndex(reg)] = *(uint32_t*)ptr;
                } else if (reg_class == ZYDIS_REGCLASS_GPR16) { // 16/8bits operation do not overwrite the rest of the register
                    context_lookup[GRegIndex(reg)] = (orig_value & 0xFFFFFFFFFFFF0000) | (*(uint16_t*)ptr);

                } else if (reg_class == ZYDIS_REGCLASS_GPR8) { // 16/8bits operation do not overwrite the rest of the register
                    if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
                        context_lookup[GRegIndex(reg)] = (orig_value & 0xFFFFFFFFFFFF00FF) | (*(uint8_t*)ptr) << 8;
                    } else { // 16/8bits operation do not overwrite the rest of the register
                        context_lookup[GRegIndex(reg)] = (orig_value & 0xFFFFFFFFFFFFFF00) | (*(uint8_t*)ptr);
                    }
                } else {
                    DebugBreak();
                }
                return true;
            }

            bool EmulateSUB(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //X86-compliant MOV R64, [...] emulation
                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);

                if (reg_class == ZYDIS_REGCLASS_GPR64) {
                    context_lookup[GRegIndex(reg)] -= *(uint64_t*)ptr;

                } else if (reg_class == ZYDIS_REGCLASS_GPR32) { //r32/m32 removes upper byte
                    context_lookup[GRegIndex(reg)] = (context_lookup[GRegIndex(reg)] & 0xFFFFFFFF) - *(uint32_t*)ptr;
                } else if (reg_class == ZYDIS_REGCLASS_GPR16) {
                    context_lookup[GRegIndex(reg)] -= (*(uint16_t*)ptr);

                } else if (reg_class == ZYDIS_REGCLASS_GPR8) {
                    if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
                        context_lookup[GRegIndex(reg)] -= (*(uint8_t*)ptr) << 8;
                    } else {
                        context_lookup[GRegIndex(reg)] -= (*(uint8_t*)ptr);
                    }
                } else {
                    DebugBreak();
                }
                return true;
            }

            bool EmulateADD(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //X86-compliant MOV R64, [...] emulation
                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);

                if (reg_class == ZYDIS_REGCLASS_GPR64) {
                    context_lookup[GRegIndex(reg)] += *(uint64_t*)ptr;

                } else if (reg_class == ZYDIS_REGCLASS_GPR32) { //r32/m32 removes upper byte
                    context_lookup[GRegIndex(reg)] = (context_lookup[GRegIndex(reg)] & 0xFFFFFFFF) + *(uint32_t*)ptr;
                } else if (reg_class == ZYDIS_REGCLASS_GPR16) {
                    context_lookup[GRegIndex(reg)] += (*(uint16_t*)ptr);

                } else if (reg_class == ZYDIS_REGCLASS_GPR8) {
                    if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
                        context_lookup[GRegIndex(reg)] += (*(uint8_t*)ptr) << 8;
                    } else {
                        context_lookup[GRegIndex(reg)] += (*(uint8_t*)ptr);
                    }
                } else {
                    DebugBreak();
                }
                return true;
            }

            bool EmulateOR(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //X86-compliant MOV R64, [...] emulation
                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);

                if (reg_class == ZYDIS_REGCLASS_GPR64) {
                    context_lookup[GRegIndex(reg)] |= *(uint64_t*)ptr;

                } else if (reg_class == ZYDIS_REGCLASS_GPR32) { //r32/m32 removes upper byte
                    context_lookup[GRegIndex(reg)] = (context_lookup[GRegIndex(reg)] & 0xFFFFFFFF) | *(uint32_t*)ptr;
                } else if (reg_class == ZYDIS_REGCLASS_GPR16) {
                    context_lookup[GRegIndex(reg)] |= (*(uint16_t*)ptr);

                } else if (reg_class == ZYDIS_REGCLASS_GPR8) {
                    if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
                        context_lookup[GRegIndex(reg)] |= (*(uint8_t*)ptr) << 8;
                    } else {
                        context_lookup[GRegIndex(reg)] |= (*(uint8_t*)ptr);
                    }
                } else {
                    DebugBreak();
                }
                return true;
            }

            bool EmulateXOR(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //X86-compliant MOV R64, [...] emulation
                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);

                if (reg_class == ZYDIS_REGCLASS_GPR64) {
                    context_lookup[GRegIndex(reg)] ^= *(uint64_t*)ptr;

                } else if (reg_class == ZYDIS_REGCLASS_GPR32) { //r32/m32 removes upper byte
                    context_lookup[GRegIndex(reg)] = (context_lookup[GRegIndex(reg)] & 0xFFFFFFFF) ^ *(uint32_t*)ptr;
                } else if (reg_class == ZYDIS_REGCLASS_GPR16) {
                    context_lookup[GRegIndex(reg)] ^= (*(uint16_t*)ptr);

                } else if (reg_class == ZYDIS_REGCLASS_GPR8) {
                    if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
                        context_lookup[GRegIndex(reg)] ^= (*(uint8_t*)ptr) << 8;
                    } else {
                        context_lookup[GRegIndex(reg)] ^= (*(uint8_t*)ptr);
                    }
                } else {
                    DebugBreak();
                }
                return true;
            }

            bool EmulateAND(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //X86-compliant MOV R64, [...] emulation
                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);

                if (reg_class == ZYDIS_REGCLASS_GPR64) {
                    context_lookup[GRegIndex(reg)] &= *(uint64_t*)ptr;
                } else if (reg_class == ZYDIS_REGCLASS_GPR32) { //r32/m32 removes upper byte
                    context_lookup[GRegIndex(reg)] = (context_lookup[GRegIndex(reg)] & 0xFFFFFFFF) & *(uint32_t*)ptr;
                } else if (reg_class == ZYDIS_REGCLASS_GPR16) {
                    context_lookup[GRegIndex(reg)] &= (*(uint16_t*)ptr);
                } else if (reg_class == ZYDIS_REGCLASS_GPR8) {
                    if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
                        context_lookup[GRegIndex(reg)] &= (*(uint8_t*)ptr) << 8;
                    } else {
                        context_lookup[GRegIndex(reg)] &= (*(uint8_t*)ptr);
                    }
                } else {
                    DebugBreak();
                }
                return true;
            }

            bool EmulateMOVZX(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, uint32_t size, ZydisDecodedInstruction* instr) { //X86-compliant MOVZX R32/16, 8/16[PTR] emulation

                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);
                auto orig_value = context_lookup[GRegIndex(reg)];

                if (reg_class == ZYDIS_REGCLASS_GPR32) { //We replace the whole register
                    if (size == 16) {
                        context_lookup[GRegIndex(reg)] = *(uint16_t*)ptr;
                    } else if (size == 8) {
                        context_lookup[GRegIndex(reg)] = *(uint8_t*)ptr;
                    } else {
                        DebugBreak();
                    }

                } else if (reg_class == ZYDIS_REGCLASS_GPR16) { // 16/8bits operation do not overwrite the rest of the register
                    if (size == 8) {
                        context_lookup[GRegIndex(reg)] = *(uint8_t*)ptr;
                    } else {
                        DebugBreak();
                    }

                } else {
                    DebugBreak();
                }
                return true;
            }

            bool EmulateMOVSX(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, uint32_t size, ZydisDecodedInstruction* instr) { //X86-compliant MOVZX R32/16, 8/16[PTR] emulation

                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);
                auto orig_value = context_lookup[GRegIndex(reg)];

                if (size == 64) {
                    context_lookup[GRegIndex(reg)] = *(int64_t*)ptr;
                } else if (size == 32) {
                    context_lookup[GRegIndex(reg)] = *(int32_t*)ptr;
                }

                else if (size == 16) {
                    context_lookup[GRegIndex(reg)] = *(int16_t*)ptr;
                } else if (size == 8) {
                    context_lookup[GRegIndex(reg)] = *(int8_t*)ptr;
                }

                else {
                    DebugBreak();
                }
                return true;
            }


            // DO NOT TURN ON COMPILER OPTIMIZATIONS, THERE BE DRAGONS
            bool EmulateMOVUPS(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, uint32_t size, ZydisDecodedInstruction* instr) { // MOVUPS R128, 8/16[PTR] emulation
                M128A* context_lookup = (M128A*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);
                auto orig_value = context_lookup[XmmRegIndex(reg)];

                if (size == 128) {
                    context_lookup[XmmRegIndex(reg)] = *(M128A*)ptr;
                } else {
                    DebugBreak();   // this can happen?
                }

                return true;
            }

        } // namespace ReadPtr

        namespace WritePtr {

            bool EmulateMOV(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //X86-compliant MOV R64, [...] emulation

                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);
                auto orig_value = context_lookup[GRegIndex(reg)];

                if (reg_class == ZYDIS_REGCLASS_GPR64) { //We replace the whole register
                    *(uint64_t*)ptr = context_lookup[GRegIndex(reg)];

                } else if (reg_class == ZYDIS_REGCLASS_GPR32) { //We replace the whole register
                    *(uint32_t*)ptr = context_lookup[GRegIndex(reg)];
                } else if (reg_class == ZYDIS_REGCLASS_GPR16) { // 16/8bits operation do not overwrite the rest of the register
                    *(uint16_t*)ptr = context_lookup[GRegIndex(reg)];

                } else if (reg_class == ZYDIS_REGCLASS_GPR8) { // 16/8bits operation do not overwrite the rest of the register
                    if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
                        *(uint8_t*)ptr = context_lookup[GRegIndex(reg)] >> 8;
                    } else { // 16/8bits operation do not overwrite the rest of the register
                        *(uint8_t*)ptr = context_lookup[GRegIndex(reg)];
                    }
                } else {
                    DebugBreak();
                }
                return true;
            }

            bool EmulateMOV(PCONTEXT ctx, ZyanU64 value, uint64_t ptr,
                ZydisDecodedInstruction* instr) { //X86-compliant MOV [ADDR], imm emulation
                /*
                if (reg_class == ZYDIS_REGCLASS_GPR64) { //We replace the whole register
                    *(uint64_t*)ptr = context_lookup[GRegIndex(reg)];

                } else if (reg_class == ZYDIS_REGCLASS_GPR32) { //We replace the whole register
                    *(uint32_t*)ptr = context_lookup[GRegIndex(reg)];
                } else if (reg_class == ZYDIS_REGCLASS_GPR16) { // 16/8bits operation do not overwrite the rest of the register
                    *(uint16_t*)ptr = context_lookup[GRegIndex(reg)];

                } else if (reg_class == ZYDIS_REGCLASS_GPR8) { // 16/8bits operation do not overwrite the rest of the register
                    if (reg == ZYDIS_REGISTER_AH || reg == ZYDIS_REGISTER_BH || reg == ZYDIS_REGISTER_CH || reg == ZYDIS_REGISTER_DH) {
                        *(uint8_t*)ptr = context_lookup[GRegIndex(reg)] >> 8;
                    } else { // 16/8bits operation do not overwrite the rest of the register
                        *(uint8_t*)ptr = context_lookup[GRegIndex(reg)];
                    }
                } else {
                    DebugBreak();
                }*/
                return true;
            }

            bool EmulateSUB(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //X86-compliant MOV R64, [...] emulation
                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);

                DebugBreak();
                return true;
            }

            bool EmulateADD(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //X86-compliant MOV R64, [...] emulation
                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);

                DebugBreak();
                return true;
            }

            bool EmulateOR(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //X86-compliant MOV R64, [...] emulation
                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);

                DebugBreak();
                return true;
            }

            bool EmulateXOR(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //X86-compliant MOV R64, [...] emulation
                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);

                DebugBreak();
                return true;
            }

            bool EmulateAND(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, ZydisDecodedInstruction* instr) { //X86-compliant MOV R64, [...] emulation
                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);

                DebugBreak();
                return true;
            }

            bool EmulateMOVZX(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, uint32_t size, ZydisDecodedInstruction* instr) { //X86-compliant MOVZX R32/16, 8/16[PTR] emulation

                uint64_t* context_lookup = (uint64_t*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);
                auto orig_value = context_lookup[GRegIndex(reg)];

                DebugBreak();
                return true;
            }

            // DO NOT TURN ON COMPILER OPTIMIZATIONS, THERE BE DRAGONS
            bool EmulateMOVUPS(PCONTEXT ctx, ZydisRegister reg, uint64_t ptr, uint32_t size, ZydisDecodedInstruction* instr) { // MOVUPS [ADDR], R128 emulation
                M128A* context_lookup = (M128A*)ctx;
                auto reg_class = ZydisRegisterGetClass(reg);
                auto orig_value = context_lookup[XmmRegIndex(reg)];

                if (size == 128) {
                    *(M128A*)ptr = context_lookup[XmmRegIndex(reg)];
                } else {
                    DebugBreak(); // this can happen?
                }

                return true;
            }

        } // namespace WritePtr
    } // namespace InstrEmu
} // namespace VCPU
