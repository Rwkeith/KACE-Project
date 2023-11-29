![alt text](https://drive.google.com/uc?export=view&id=1qgfpXdotNpEWSKo2I_O2puZFFBchPjrG)

# Driver Buddy

## Foundational Credits

Continuation of the original KACE project from waryas and friends

## What has changed / been added from the original Kace project

## *Original Method*
The original Kace project mapped kernel modules into usermode space such as ntos, fltrmgr, win32k, etc.  Then instrumented/emulated driver is then mapped in, where all these mappings are set with `NO_ACCESS` protection so the registered custom exception handler can take control and CPU emulate each instruction with Zydis.  The handler instrument's the Driver and the developer can add handler functions for ntos or other imports used by the instrumented driver.  This version of Kace fully emulated BEDaisy in usermode before moving towards the new approach (some core issues were fixed).

## New Method

* A helper driver is loaded first *DriverBuddy(tm)*
  - Intercepts driver loading with a registered load handler and patches DriverEntry temporarily to skip kernel exeuction
  - Modifies PTE entries of loaded driver to be usermode pages 

* The 'emulated' kernel driver is now legitimately loaded into kernel memory.
  - This allows the kernel structures of the driver to now be created normally.
  - Driver now has real kernel addresses.  This circumvents checks to see if it's running in userland by checking $RIP

* Imports are mapped to the real kernel functions.
  - Again circumvents checks that could be made by the Driver to infer the environment it's running in.

* DriverEntry to be emulated is patched to return before it's instrumented by us.
  - In order to instrument the loaded kernel driver with Kace, the PTE's of the driver are changed to usermode.

* Bug fixes and improvements
  - Some improvements to reimplementations of Nt/ZwSystemQueryInfo which allows you to filter out/hide your other loaded driver's (implemented with old method, but filtering will be needed later on again for new method)

## What needs to be done

* Forward the emulated driver calls to exports from other kernel images and return/filter data accordingly.
  - In the exception handler, when a kernel import is determined to being called, forward the args and address to DriverBuddy through an ioctl. *Could you do this dynamically? Describe call with struct telling # of args, data types for DriverBuddy*
* Filter data you don't want the emulated driver to see (e.g. DriverBuddy when NtSysQueryInfo is called)
* Handle side-channel attacks (timing, kernel vs. usermode thread struct differences)

## Functional Diagram
![alt text](https://drive.google.com/uc?export=view&id=1yxhjL3jBhpJIJbLO9AvpUxS4kEja9qJs)


## Developer Guide

### Requirements Setup
Note: May be preferred to run in VM during some kernel related debugging and development.  (Will run MUCH slower depending on HW)

OS: Windows 10 22H2 Build 19045 (some builds may have issues finding symbols from msft servers, which Kace depends on for logging)
IDE: VS2022, Windows 10 SDK 10.0.22621.0
Dependecies:  [WDK 10.0.22621](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk)

*Make sure Visual Studio is always ran as administrator when running Kace through VS's debugger!*



### VCPKG configuration
Make sure you have vcpkg included in VS2022 installation (should be installed by default)

Note: If you go into Kace project configuration properties and there isn't an option for vcpkg, then run `vcpkg integrate install` in Developer Powershell and restart VS.

1. In Developer Powershell, root project directory `vcpkg x-update-baseline --add-initial-baseline`, then `vcpkg install`

You should now be able to `Build Solution`

## Development and Debugging

You may need to go into Exception Settings and enable Win32 Exceptions->0xc0000005 Access Violation to catch going into the ExceptionHandler.
All other questions, should probably ask Keith.

## General Usage
Specify a path for driver you want to emulate.  Optional flag `load_only_emu_mods` will only load modules in `C:\emu\` folder.
```shell
.\KACE.exe <path_to_driver>  [load_only_emu_mods]
```

When running in VS Debugger, in Exception Settings disable `0xc000005 Access Violation` else the debugger will break on access violations to variables that are tracked.

Use an up to date Windows 10 Build.  Tested on Build 19044.
