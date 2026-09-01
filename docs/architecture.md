# Architecture

## Verified test inputs

The supported official Ventoy Win10Based v3.0 image has SHA-256:

```text
6161D63520EB72BD1D5CB99AA9A771CC8B93AD9718DE637B7D2195911DD224EF
```

The verified Windows test disks include fixed and dynamic VHD1 files
(`conectix` footer, disk types 2 and 3). Source images are inspected read-only;
boot tests use recoverable copies.

## Legacy and UEFI paths are different

The ISO root contains:

```text
BOOTMGR
boot/bootvhd.dll
boot/BCD
efi.img
efi/microsoft/boot/BCD
```

`boot/bootvhd.dll` is a 32-bit Windows Boot Application DLL and is relevant to
the Legacy BIOS path. It exports only `VhdFileDeviceOpen`.

The UEFI El Torito image contains a single 64-bit `EFI/BOOT/bootx64.efi`:

```text
File version: 10.0.10240.16384
PDB:          bootmgfw.pdb
PDB GUID:     141D8719-4A66-402C-9357-588E9E421864
PDB age:      2
```

VHD/VHDX support, NTFS, BitLocker, and the Windows boot libraries are linked
directly into this image. The implementation therefore targets this UEFI image
and its matching Microsoft public symbols directly.

## VHD1 parser table

For this exact BOOTMGR build, Microsoft's public symbols and the PE layout give:

```text
Vhd1Parser RVA  0x00002CF8

+0x00  VhdOpen   -> image+0x0003BED0
+0x08  VhdClose  -> image+0x0003BEB0
+0x10  VhdRead   -> image+0x0003BF90
+0x18  VhdWrite  -> image+0x0003BFC0
```

The table contains relocated absolute pointers at runtime. Updating entries
`+0x10` and `+0x18` avoids relocating those VHD routines and avoids depending
on the closed `bootvhd.dll` export ABI. Reads are transformed when VeraCrypt is
active. Writes are rejected until `veracrypt.sys` owns the system disk; on the
empty-password path both callbacks retain stock semantics.

The two BCD paths in the stock ISO share one physical ISO extent. Ventoy patches
`/boot/BCD` in memory before chainloading; UEFI then observes the same bytes via
`/efi/microsoft/boot/BCD`. Derived images must preserve this hard-link layout.
Independent BCD copies fail with status `0xc000000e`.

The inferred VHD1 I/O signature on x64 is:

```c
NTSTATUS VhdReadWrite(
    void *vhd_context,
    uint64_t byte_offset,
    void *buffer,
    uint32_t byte_count,
    uint32_t flags
);
```

This must be confirmed by a pass-through hook before enabling decryption.

## Winload parser and authenticated child launch

Windows Boot Manager does not keep using its own VHD parser after it starts a
boot application. Windows 10 and Windows 11 `winload.efi` contain a separate
copy. Public symbols were used to establish the following independent samples:

```text
Release/version            Vhd1Parser  Open     Close    Read     Write
LTSC 2019 / 17763.292       0x15DCF0    0x45E00  0x45DE0  0x45EC8  0x45EF8
1909 / 18362.1593           0x16B590    0x5A6A0  0x5A680  0x5A760  0x5A790
21H2 / 19041.3086           0x17B580    0x5EFC8  0x5EFA4  0x5F080  0x5F0B0
22H2 / 19041.5608, .6456    0x1805E0    0x60614  0x605F0  0x606CC  0x606FC
```

Across all four families, the read wrapper has the same 48-byte instruction
shape except for its relative `call` displacement, and the analogous write
wrapper starts exactly `0x30` bytes later. The runtime locator parses the PE32+
headers, scans only initialized readable non-executable sections, and accepts
a candidate only when:

- all four table entries point into executable sections of the same image;
- the write pointer equals the read pointer plus `0x30`;
- both wrapper instruction shapes match, excluding only their relative call
  displacements; and
- exactly one candidate exists.

Unknown Windows 10 and Windows 11 x64 builds are therefore not rejected by
version number, but an absent or ambiguous structure is left untouched. If
VeraCrypt is active, failure to validate one Winload parser aborts the child
launch rather than continuing without decryption.

The preloader hooks Boot Manager's `ImgArchEfiStartBootApplication` at RVA
`0x0006B468`. This boundary is late enough that Boot Manager has already loaded
and authenticated Winload. The wrapper validates the loaded image
structurally, changes only the relocated read/write entries in RAM, and then
invokes the original function through a register-preserving trampoline.

## Intended handoff

```text
Ventoy
  -> Encrypted VHD Boot Bridge (EFI/BOOT/bootx64.efi)
      -> UEFI LoadImage(original BOOTMGR)
      -> patch relocated BOOTMGR Vhd1Parser read/write pointers
      -> UEFI StartImage(original BOOTMGR)
          -> bootvhd VHD parser
              -> VeraCrypt header/authentication
              -> sector transform and BootArguments
          -> authenticated child-launch hook
              -> locate and patch winload Vhd1Parser read/write pointers
              -> decrypt Winload VHD reads
              -> reject encrypted pre-kernel VHD writes
          -> Windows kernel
              -> veracrypt.sys takes over
```

The VeraCrypt EFI code is open source. The implementation reuses its volume
header, password, XTS, and `BootArguments` code while replacing the
`EFI_BLOCK_IO_PROTOCOL` backend with the saved raw `VhdRead` callback. The
Windows VeraCrypt driver consumes the standard handoff after kernel startup.

After a non-empty password, the preloader accepts an optional decimal system
PIM in the VeraCrypt boot range `0..65535`. An empty field is represented by
`0`. The same value is used for `ReadVolumeHeader` and encoded in the upper
16 bits of `BootArguments.Flags`, matching VeraCrypt-DCS and the Windows
driver. Password and PIM fields are masked on the UEFI console. A short input
flush after Enter follows VeraCrypt-DCS behavior and prevents a firmware key-up
event from confirming the next prompt.

`F5` redraws the current password or PIM field in visible or masked form while
preserving the buffered value. On password submission, the rendered field is
erased and replaced by one `*`, hiding both the password and its length before
the PIM prompt is displayed. `Esc` deliberately differs from empty password
submission: it clears the buffered secret and requests an UEFI cold reset. A
simple EFI application return cannot serve as cancellation here because the
tested Ventoy vhdboot chain immediately launches the same VHD again. Cold
reset reliably returns to the normal firmware/Ventoy boot sequence.

The preloader registers an `EVT_SIGNAL_EXIT_BOOT_SERVICES` callback before
starting Boot Manager. That callback uses no boot services: it volatile-wipes
the private expanded-key workspace and partial-sector bounce buffer, then
invalidates the preloader's crypto pointers. It deliberately does not erase the
fixed VeraCrypt `BootArguments`/`BOOT_CRYPTO_HEADER` page at this boundary,
because the boot-start `veracrypt.sys` driver consumes and burns it later.

## Validation status

The supported Boot Manager profile and structural Winload locator have been
validated with encrypted Windows 10 LTSC 2019, 1909, 21H2 and 22H2 systems and
Windows 11 25H2, an unencrypted Windows 10 22H2 system, fixed and dynamic VHD1,
default and custom PIM values, and several cipher and PRF combinations. The
Windows 11 test system was fully decrypted with `manage-bde -off C:` before
VeraCrypt system encryption. Persistent file changes and recovery after abrupt
power removal were also tested on physical x64 UEFI hardware. `F5` visibility
toggling and `Esc` cancellation by cold reboot are included in the validated
path.

Future work is expected to broaden virtual-disk format coverage.

## Current non-goals

- Secure Boot support;
- Legacy BIOS;
- VHDX;
- arbitrary BOOTMGR versions;
- implementing encrypted pre-kernel VHD writes; they fail closed as
  write-protected. Native-VHD Windows disables hibernation in the tested
  configuration, so no resume path is currently reachable.
