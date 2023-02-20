#include <ntddk.h>
#include "ida_defs.h"
#include "main.h"

char send_pci_device_info();

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = SampleUnload;
    DbgPrint("Driver Entry ran!\n");
    send_pci_device_info();
    return STATUS_SUCCESS;
}

void SampleUnload(_In_ PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("Driver Unload ran!\n");
}

BYTE get_pci_data(unsigned __int8* in_device_info, unsigned int bus, _BYTE* out_reg_data, int command) {
    DbgPrint("get_pci_data()\n");
    BOOL succeeded; // ebx
    unsigned __int16 some_register_addr; // r10
    unsigned __int32 v7; // eax
    unsigned __int16 v8; // ax
    unsigned __int8 v9; // al

    succeeded = 1;
    some_register_addr = bus | ((in_device_info[1] | 0xC0) << 8);
    if (bus >= 0x100 || in_device_info[1] >= 0x10u)
        return 0i64;
    _mm_lfence();
    __outbyte(0xCF8u, 2 * (in_device_info[2] | 0xF8)); // specify which device
    __outbyte(0xCFAu, *in_device_info); // 0xCFA Configuration Data register
    switch (command) {
    case 1:
        v9 = __inbyte(some_register_addr);
        *out_reg_data = v9;
        break;
    case 2:
        v8 = __inword(some_register_addr);
        *(_WORD*)out_reg_data = v8;
        break;
    case 4:
        v7 = __indword(some_register_addr);
        *(_DWORD*)out_reg_data = v7;
        break;
    default:
        _mm_lfence();
        DbgPrint("get_pci_data(): TRIED TO GO DOWN PATH THAT'S NOT IMPLEMENTED :|\n");
        //succeeded = sub_14034B545((__int64)in_device_info, (unsigned int)bus, (__int64)out_reg_data, command,
        //    (unsigned int(__fastcall*)(__int64, __int64, __int64, __int64))((char*)&qword_14000CB78[1839] + 4));
        succeeded = 0;
        break;
    }
    __outbyte(0xCF8u, 0);
    return succeeded;
}


// sign flag
int8 SETS(int x) {
     return x < 0;
}

// assumes x and y are equal size
int8 OFADD(int x, int y) {
        int y2 = y;
    int8 sx = SETS(x);
        return ((1 ^ sx) ^ SETS(y2)) & (sx ^ SETS(x + y2));
}

BYTE __fastcall alternate_pci_get_data(unsigned __int8* a1, unsigned int a2, _BYTE* a3, int a4) {
    DbgPrint("alternate_pci_get_data(a1, %i, a3, %i)\n", a2, a4);
    int v4; // er10
    BOOL v5; // ebx
    char v6; // cc
    unsigned __int16 v7; // r10
    unsigned __int32 v9; // eax
    unsigned __int16 v10; // ax
    unsigned __int8 v11; // al

    v4 = a2 & 3;
    v5 = 1;
    v6 = (v4 + 3324 < 0) ^ OFADD(3324, v4);
    v7 = v4 + 3324;
    if (!v6)
        return 0i64;
    _mm_lfence();
    __outdword(0xCF8u, ((a1[2] & 7 | (8 * ((32 * *a1) | a1[1] & 0x1F))) << 8) | a2 & 0xFFFFFFFC | 0x80000000);
    switch (a4) {
    case 1:
        v11 = __inbyte(v7);
        *a3 = v11;
        break;
    case 2:
        v10 = __inword(v7);
        *(_WORD*)a3 = v10;
        break;
    case 4:
        v9 = __indword(v7);
        *(_DWORD*)a3 = v9;
        break;
    default:
        DbgPrint("alternate_pci_get_data(): TRIED TO GO DOWN PATH NOT IMPLEMENTED\n");
        // v5 = sub_14034B545((__int64)a1, a2, (__int64)a3, a4,
        //    (unsigned int(__fastcall*)(__int64, __int64, __int64, __int64))((char*)&qword_14000CB78[1816] + 4));
        break;
    }
    return v5;
}

__int64 sub_14034E34D(int a1) {
    DbgPrint("sub_14034E34D(%i)\n", a1);
    __int16 v3; // [rsp+38h] [rbp+18h] BYREF
    __int16 v4; // [rsp+40h] [rbp+20h] BYREF
    __int16 v5; // [rsp+48h] [rbp+28h] BYREF
    char v6; // [rsp+4Ah] [rbp+2Ah]

    v5 = 0;
    v6 = 0;
    while (1) {
        if (a1) {
            if (!get_pci_data((unsigned __int8*)&v5, 10, &v3, 2))
                goto LABEL_6;
        } else if (!alternate_pci_get_data((unsigned __int8*)&v5, 0xAu, &v3, 2)) {
            goto LABEL_6;
        }
        if (v3 == 1536 || v3 == 768)
            return 1i64;
    LABEL_6:
        if (a1) {
            if (!get_pci_data((unsigned __int8*)&v5, 0, &v4, 2))
                goto LABEL_10;
        } else if (!alternate_pci_get_data((unsigned __int8*)&v5, 0, &v4, 2)) {
            goto LABEL_10;
        }
        if (v4 == -32634 || v4 == 3601)
            return 1i64;
    LABEL_10:
        if (++HIBYTE(v5) >= 0x20u)
            return 0i64;
    }
}


unsigned __int8 enumerate_pci_and_send_data(unsigned int flag_is_1, __int64 config_space_info, int is_0) {
    unsigned __int8 result; // al
    char iterator; // cl
    int v7; // edi
    char v8; // cl
    bool v9; // zf
    int v10; // eax
    BOOL v11; // eax
    int v12; // ecx
    int size; // edx
    char* bytes_to_send; // rcx
    char v15; // al
    BOOL pci_data; // eax
    char device_info; // [rsp+20h] [rbp-E0h] BYREF
    char current_iteration; // [rsp+21h] [rbp-DFh]
    char v19; // [rsp+22h] [rbp-DEh]
    char v20; // [rsp+24h] [rbp-DCh] BYREF
    unsigned __int8 v21; // [rsp+25h] [rbp-DBh] BYREF
    char v22[2]; // [rsp+26h] [rbp-DAh] BYREF
    int v23; // [rsp+28h] [rbp-D8h] BYREF
    int v24; // [rsp+2Ch] [rbp-D4h] BYREF
    int out_device_data; // [rsp+30h] [rbp-D0h] BYREF
    char v26[4]; // [rsp+38h] [rbp-C8h] BYREF
    int v27; // [rsp+3Ch] [rbp-C4h]
    int v28; // [rsp+40h] [rbp-C0h]
    char v29; // [rsp+44h] [rbp-BCh]
    int v30; // [rsp+45h] [rbp-BBh]
    char v31[4]; // [rsp+50h] [rbp-B0h] BYREF
    __int16 v32; // [rsp+54h] [rbp-ACh]
    char v33; // [rsp+58h] [rbp-A8h]
    int v34; // [rsp+70h] [rbp-90h]
    __int16 v35; // [rsp+74h] [rbp-8Ch]
    char v36[4]; // [rsp+80h] [rbp-80h] BYREF
    char v37[268]; // [rsp+84h] [rbp-7Ch] BYREF

    v32 = 0;
    v33 = 0;
    v34 = 0;
    v35 = 0;


    result = is_0;
    if (!*(_BYTE*)(is_0 + config_space_info)) {
        device_info = is_0;
        iterator = 0;
        current_iteration = 0;
        *(_BYTE*)(is_0 + config_space_info) = 1;
        do {
            v7 = 0;
            for (result = 0;; result = v15 + 1) {
                v19 = result;
                if (result) {
                    if (!v7 || result >= 8u)
                        break;
                }
                if (flag_is_1) {
                    if (!get_pci_data((unsigned __int8*)&device_info, 0, &out_device_data, 4))
                        goto some_fail;
                } else if (!alternate_pci_get_data((unsigned __int8*)&device_info, 0, &out_device_data, 4)) {
                    goto some_fail;
                }
                if (flag_is_1) {
                    if (!get_pci_data((unsigned __int8*)&device_info, 0xE, &v20, 1))
                        goto some_fail;
                } else if (!alternate_pci_get_data((unsigned __int8*)&device_info, 0xEu, &v20, 1)) {
                    goto some_fail;
                }
                v8 = v20;
                if (v20 == -1)
                    goto LABEL_30;
                if (flag_is_1) {
                    if (!get_pci_data((unsigned __int8*)&device_info, 0x34, &v21, 1))
                        goto LABEL_52;
                } else if (!alternate_pci_get_data((unsigned __int8*)&device_info, 0x34u, &v21, 1)) {
                    goto LABEL_52;
                }
                if (v21 == 0xFF)
                    goto LABEL_52;
                v21 &= 0xFCu;
                if (flag_is_1) {
                    if (!get_pci_data((unsigned __int8*)&device_info, v21, v31, 0x26))
                        goto LABEL_52;
                } else if (!alternate_pci_get_data((unsigned __int8*)&device_info, v21, v31, 0x26)) {
                    goto LABEL_52;
                }
                if (v31[0] != 1 || v31[2] != 3 || v32 != 8 || v33 != 5 || v34 != 131088) {
                LABEL_52:
                    if (out_device_data != 0x66610EE)
                        goto LABEL_49;
                    goto LABEL_46;
                }
                if (v31[3] == 120 && v35 == -28702) {
                    if (flag_is_1) {
                        v9 = !get_pci_data((unsigned __int8*)&device_info, 8, &v23, 4);
                        v10 = v23;
                        if (v9)
                            goto LABEL_43;
                    } else {
                        v9 = !alternate_pci_get_data((unsigned __int8*)&device_info, 8u, &v23, 4);
                        v10 = v23;
                        if (!v9)
                            goto LABEL_26;
                    LABEL_43:
                        v10 = -1;
                    }
                LABEL_26:
                    v23 = v10;
                    if (flag_is_1) {
                        pci_data = get_pci_data((unsigned __int8*)&device_info, 44, &v24, 4);
                        v12 = v24;
                        v26[0] = 26;
                        if (!pci_data)
                            goto LABEL_40;
                    } else {
                        v11 = alternate_pci_get_data((unsigned __int8*)&device_info, 0x2Cu, &v24, 4);
                        v12 = v24;
                        v26[0] = 26;
                        if (v11)
                            goto LABEL_28;
                    LABEL_40:
                        v12 = -1;
                    }
                LABEL_28:
                    size = 0x11;
                    v26[1] = device_info;
                    v26[2] = current_iteration;
                    v26[3] = v19;
                    v27 = out_device_data;
                    v28 = v23;
                    v24 = v12;
                    v30 = v12;
                    bytes_to_send = v26;
                    v29 = v20;
                send_to_mothership:
                    DbgPrint("enc_bytes_and_send_to_mothership(bytes_to_send, size);\n");
                    // enc_bytes_and_send_to_mothership(bytes_to_send, size);
                    v8 = v20;
                    goto LABEL_30;
                }
            LABEL_46:
                if (flag_is_1) {
                    if (get_pci_data((unsigned __int8*)&device_info, 0, v37, 0x100)) {
                    LABEL_48:
                        bytes_to_send = v36;
                        v36[1] = current_iteration;
                        size = 260;
                        v36[2] = current_iteration;
                        v36[3] = v19;
                        v36[0] = 26;
                        goto send_to_mothership;
                    }
                } else if (alternate_pci_get_data((unsigned __int8*)&device_info, 0, v37, 0x100)) {
                    goto LABEL_48;
                }
            LABEL_49:
                v8 = v20;
            LABEL_30:
                v15 = v19;
                if (!v19)
                    v7 = v8 & 0x80;
                v20 = v8 & 0x7F;
                if ((unsigned __int8)((v8 & 0x7F) - 1) <= 1u) {
                    if (flag_is_1) {
                        if (get_pci_data((unsigned __int8*)&device_info, 25, v22, 1)) {
                        LABEL_35:
                            enumerate_pci_and_send_data(flag_is_1, config_space_info, (unsigned __int8)v22[0]);
                            v15 = v19;
                            goto skip_to_next;
                        }
                    } else if (alternate_pci_get_data((unsigned __int8*)&device_info, 0x19u, v22, 1)) {
                        goto LABEL_35;
                    }
                some_fail:
                    v15 = v19;
                }
            skip_to_next:
                iterator = current_iteration;
            }
            DbgPrint("current_iteration: %i\n", current_iteration);
            current_iteration = ++iterator;
        } while ((unsigned __int8)iterator < 0x20u);
    }
    return result;
}

char send_pci_device_info() {
    DbgPrint("send_pci_device_info()\n");
    unsigned int flag; // ebx
    unsigned __int32 v1; // eax
    unsigned int v2; // er8
    unsigned __int32 v3; // eax
    int v4; // eax
    M128A config_space_info[16]; // [rsp+20h] [rbp-118h] BYREF

    flag = 0;
    __outbyte(0xCFBu, 1u); // 0xCF8 ==  DWORD r/w register named: CONFIG_ADDRESS
    v1 = __indword(0xCF8u);
    v2 = v1;
    __outdword(0xCF8u, 0x80000000);
    v3 = __indword(0xCF8u);
    __outdword(0xCF8u, v2);
    if (v3 == 0x80000000 && (unsigned int)sub_14034E34D(0))
        goto LABEL_7;
    __outbyte(0xCFBu, 0);
    __outbyte(0xCF8u, 0);
    __outbyte(0xCFAu, 0);
    LOBYTE(v4) = __inbyte(0xCF8u);
    if (!(_BYTE)v4) {
        LOBYTE(v4) = __inbyte(0xCFAu);
        if (!(_BYTE)v4) {
            v4 = sub_14034E34D(1);
            if (v4) {
                flag = 1; // set to 1 on success?
            LABEL_7:
                memset(config_space_info, 0, sizeof(config_space_info));
                LOBYTE(v4) = enumerate_pci_and_send_data(flag, (__int64)config_space_info, 0);
            }
        }
    }
    return v4;
}