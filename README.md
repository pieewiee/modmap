# Module Extending Manual Mapper

DLL manual mapper that will forcefully extend the size of a pre-existing module and map itself there.

## Procedure

1. Pick a module.
2. If there will be no conflicts, forcefully allocate memory immediately after the module's end.
3. Extend the size of the module in its LDR entry to match.
4. Map the DLL into this created region.

## changes
  1. Updated patterns for MiAllocateVad, MiInsertVadCharges, MiInsertVad (compatible with Windows 11 23H2 build: 22631)
  2. Updated structs for MMVAD and MMVAD_FLAGS for windows 11
  3. Driver now uses IOCTL instead of EnumerateDebuggingDevicesOriginal (yeah i know)

## Usage

1. Load the driver
2. change the proccess module and dll in the source code
3.  `modmap`
    - For example: `modmap `

## Note

This was only tested on Windows 10 1803, 1809, 1903, 1909 and is intended for a x64 target process and DLL.

## todo 
 - fix shellcode execution