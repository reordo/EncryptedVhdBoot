/** @file
  Loads the original Windows Boot Manager, replaces its relocated VHD1 I/O
  callbacks in memory, and starts it. When a VeraCrypt system header is
  accepted, VHD reads are decrypted and writes are rejected until the Windows
  VeraCrypt boot driver takes over.

  Copyright (c) 2026, Keishin Senzaki. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <IndustryStandard/PeImage.h>
#include <Protocol/LoadedImage.h>

#include "EvbVeraCrypt.h"

#define EVB_ORIGINAL_BOOT_MANAGER_PATH  L"\\EFI\\BOOT\\bootmgfw.original.efi"

// Profile for bootmgfw.efi 10.0.10240.16384, public PDB
// 141D8719-4A66-402C-9357-588E9E421864 age 2.
#define EVB_BOOTMGR_MINIMUM_SIZE        0x00156000U
#define EVB_VHD1_PARSER_RVA             0x00002CF8U
#define EVB_VHD_OPEN_RVA                0x0003BED0U
#define EVB_VHD_CLOSE_RVA               0x0003BEB0U
#define EVB_VHD_READ_RVA                0x0003BF90U
#define EVB_VHD_WRITE_RVA               0x0003BFC0U

#define EVB_VHD_OPEN_INDEX              0U
#define EVB_VHD_CLOSE_INDEX             1U
#define EVB_VHD_READ_INDEX              2U
#define EVB_VHD_WRITE_INDEX             3U

// bootmgfw.efi 10.0.10240.16384 transfers control to child boot applications
// through ImgArchEfiStartBootApplication.  Hooking that boundary lets us patch
// winload only after BOOTMGR has loaded and authenticated its PE image.
#define EVB_BOOT_APP_START_RVA          0x0006B468U
#define EVB_BOOT_APP_HOOK_SIZE          15U
#define EVB_ABSOLUTE_JUMP_SIZE          14U

#define EVB_VHD_WRAPPER_SIZE             0x30U
#define EVB_VHD_WRAPPER_PAIR_SIZE        (2U * EVB_VHD_WRAPPER_SIZE)
#define EVB_STATUS_UNSUCCESSFUL          ((INT32)0xC0000001)
#define EVB_STATUS_MEDIA_WRITE_PROTECTED ((INT32)0xC00000A2)

typedef INT32 (EFIAPI *EVB_BOOT_APPLICATION_START)(
  IN VOID    *BootApplicationParameters,
  IN VOID    *ImageBase,
  IN UINT32  ImageSize,
  IN UINT32  Flags,
  IN VOID    *StartContext
  );

STATIC EVB_VHD_IO  mOriginalVhdRead;
STATIC EVB_VHD_IO  mOriginalVhdWrite;
STATIC EVB_VHD_IO  mOriginalWinloadVhdRead;
STATIC EVB_VHD_IO  mOriginalWinloadVhdWrite;
STATIC UINTN        *mVhd1Parser;
STATIC UINTN        *mWinloadVhd1Parser;
STATIC UINT8        *mBootApplicationHookTarget;
STATIC UINT8        mBootApplicationHookOriginal[EVB_BOOT_APP_HOOK_SIZE];
STATIC VOID         *mBootApplicationTrampoline;
STATIC EVB_BOOT_APPLICATION_START  mOriginalBootApplicationStart;
STATIC BOOLEAN      mVeraCryptChecked;

typedef struct {
  UINT8                     *Base;
  UINT32                    ImageSize;
  EFI_IMAGE_SECTION_HEADER  *Sections;
  UINT16                    SectionCount;
} EVB_PE_IMAGE;

// Exact 15-byte ImgArchEfiStartBootApplication prologue covered by the
// trampoline. Refuse to patch if a nominally similar BOOTMGR has different
// instructions at the public-symbol RVA.
STATIC CONST UINT8  mBootApplicationHookPrologue[EVB_BOOT_APP_HOOK_SIZE] = {
  0x48, 0x8B, 0xC4,
  0x48, 0x89, 0x58, 0x10,
  0x44, 0x89, 0x48, 0x20,
  0x44, 0x89, 0x40, 0x18
};

// Winload's VHD1 read/write wrappers have remained structurally identical
// across the tested Windows 10 and Windows 11 releases. The relative call
// displacement is the only variable field; the write wrapper immediately
// follows the read wrapper.
STATIC CONST UINT8  mVhdReadWrapperPrefix[] = {
  0x48, 0x83, 0xEC, 0x48, 0x33, 0xC0, 0x45, 0x85,
  0xC9, 0x74, 0x1F, 0x48, 0x89, 0x44, 0x24, 0x30,
  0x8B, 0x44, 0x24, 0x70, 0x89, 0x44, 0x24, 0x28,
  0x44, 0x89, 0x4C, 0x24, 0x20, 0x4D, 0x8B, 0xC8,
  0x4C, 0x8B, 0xC2, 0x33, 0xD2, 0xE8
};

STATIC CONST UINT8  mVhdWriteWrapperPrefix[] = {
  0x48, 0x83, 0xEC, 0x48, 0x33, 0xC0, 0x45, 0x85,
  0xC9, 0x74, 0x1F, 0x48, 0x89, 0x44, 0x24, 0x30,
  0x8B, 0x44, 0x24, 0x70, 0x89, 0x44, 0x24, 0x28,
  0x44, 0x89, 0x4C, 0x24, 0x20, 0x4D, 0x8B, 0xC8,
  0x4C, 0x8B, 0xC2, 0xB2, 0x01, 0xE8
};

STATIC CONST UINT8  mVhdWrapperSuffix[] = {
  0x48, 0x83, 0xC4, 0x48, 0xC3, 0xCC
};

STATIC
BOOLEAN
EvbParsePeImage (
  IN  VOID           *ImageBase,
  IN  UINT32         ImageSize,
  OUT EVB_PE_IMAGE  *Image
  )
{
  UINT8                   *Base;
  EFI_IMAGE_DOS_HEADER    *Dos;
  EFI_IMAGE_NT_HEADERS64  *Nt;
  UINTN                   NtOffset;
  UINTN                   SectionOffset;
  UINTN                   SectionBytes;

  if ((ImageBase == NULL) || (Image == NULL) ||
      (ImageSize < sizeof (EFI_IMAGE_DOS_HEADER)))
  {
    return FALSE;
  }

  Base = (UINT8 *)ImageBase;
  Dos  = (EFI_IMAGE_DOS_HEADER *)Base;
  if (Dos->e_magic != EFI_IMAGE_DOS_SIGNATURE) {
    return FALSE;
  }

  NtOffset = Dos->e_lfanew;
  if ((NtOffset > ImageSize) ||
      ((ImageSize - NtOffset) < sizeof (EFI_IMAGE_NT_HEADERS64)))
  {
    return FALSE;
  }

  Nt = (EFI_IMAGE_NT_HEADERS64 *)(Base + NtOffset);
  if ((Nt->Signature != EFI_IMAGE_NT_SIGNATURE) ||
      (Nt->OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC) ||
      (Nt->FileHeader.Machine != IMAGE_FILE_MACHINE_X64) ||
      (Nt->FileHeader.NumberOfSections == 0) ||
      (Nt->FileHeader.SizeOfOptionalHeader < sizeof (EFI_IMAGE_OPTIONAL_HEADER64)) ||
      (Nt->OptionalHeader.SizeOfImage > ImageSize))
  {
    return FALSE;
  }

  SectionOffset = NtOffset + sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER) +
                  Nt->FileHeader.SizeOfOptionalHeader;
  SectionBytes = (UINTN)Nt->FileHeader.NumberOfSections *
                 sizeof (EFI_IMAGE_SECTION_HEADER);
  if ((SectionOffset > ImageSize) ||
      (SectionBytes > (ImageSize - SectionOffset)))
  {
    return FALSE;
  }

  Image->Base         = Base;
  Image->ImageSize    = Nt->OptionalHeader.SizeOfImage;
  Image->Sections     = (EFI_IMAGE_SECTION_HEADER *)(Base + SectionOffset);
  Image->SectionCount = Nt->FileHeader.NumberOfSections;
  return TRUE;
}

STATIC
BOOLEAN
EvbRangeInSection (
  IN CONST EVB_PE_IMAGE  *Image,
  IN UINTN                Address,
  IN UINTN                Length,
  IN BOOLEAN              Executable
  )
{
  UINTN   Index;
  UINT32  SectionSize;
  UINTN   Start;
  UINTN   End;

  if ((Image == NULL) || (Length == 0) || (Address > (MAX_UINTN - Length))) {
    return FALSE;
  }

  End = Address + Length;
  for (Index = 0; Index < Image->SectionCount; ++Index) {
    if (((Image->Sections[Index].Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) != 0) !=
        Executable)
    {
      continue;
    }

    SectionSize = Image->Sections[Index].Misc.VirtualSize;
    if (SectionSize < Image->Sections[Index].SizeOfRawData) {
      SectionSize = Image->Sections[Index].SizeOfRawData;
    }
    if ((Image->Sections[Index].VirtualAddress > Image->ImageSize) ||
        (SectionSize > (Image->ImageSize - Image->Sections[Index].VirtualAddress)))
    {
      continue;
    }

    Start = (UINTN)(Image->Base + Image->Sections[Index].VirtualAddress);
    if (Start > (MAX_UINTN - SectionSize)) {
      continue;
    }
    if ((Address >= Start) && (End <= (Start + SectionSize))) {
      return TRUE;
    }
  }

  return FALSE;
}

STATIC
BOOLEAN
EvbMatchesVhdWrapperPair (
  IN CONST EVB_PE_IMAGE  *Image,
  IN UINTN                ReadAddress
  )
{
  UINT8  *Read;
  UINT8  *Write;

  if (!EvbRangeInSection (
         Image,
         ReadAddress,
         EVB_VHD_WRAPPER_PAIR_SIZE,
         TRUE
         ))
  {
    return FALSE;
  }

  Read  = (UINT8 *)ReadAddress;
  Write = Read + EVB_VHD_WRAPPER_SIZE;
  return (BOOLEAN)(
           (CompareMem (Read, mVhdReadWrapperPrefix, sizeof (mVhdReadWrapperPrefix)) == 0) &&
           (CompareMem (Read + 42, mVhdWrapperSuffix, sizeof (mVhdWrapperSuffix)) == 0) &&
           (CompareMem (Write, mVhdWriteWrapperPrefix, sizeof (mVhdWriteWrapperPrefix)) == 0) &&
           (CompareMem (Write + 42, mVhdWrapperSuffix, sizeof (mVhdWrapperSuffix)) == 0)
           );
}

STATIC
UINTN *
EvbFindVhd1Parser (
  IN VOID    *ImageBase,
  IN UINT32  ImageSize
  )
{
  EVB_PE_IMAGE  Image;
  UINTN          SectionIndex;
  UINT32         SectionSize;
  UINTN          Offset;
  UINTN          *Candidate;
  UINTN          *Match;

  if (!EvbParsePeImage (ImageBase, ImageSize, &Image)) {
    return NULL;
  }

  Match = NULL;
  for (SectionIndex = 0; SectionIndex < Image.SectionCount; ++SectionIndex) {
    if (((Image.Sections[SectionIndex].Characteristics & EFI_IMAGE_SCN_MEM_READ) == 0) ||
        ((Image.Sections[SectionIndex].Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) != 0) ||
        ((Image.Sections[SectionIndex].Characteristics & EFI_IMAGE_SCN_CNT_INITIALIZED_DATA) == 0))
    {
      continue;
    }

    SectionSize = Image.Sections[SectionIndex].Misc.VirtualSize;
    if (SectionSize < Image.Sections[SectionIndex].SizeOfRawData) {
      SectionSize = Image.Sections[SectionIndex].SizeOfRawData;
    }
    if ((Image.Sections[SectionIndex].VirtualAddress > Image.ImageSize) ||
        (SectionSize > (Image.ImageSize - Image.Sections[SectionIndex].VirtualAddress)) ||
        (SectionSize < (4 * sizeof (UINTN))))
    {
      continue;
    }

    for (Offset = 0; Offset <= (SectionSize - (4 * sizeof (UINTN))); Offset += sizeof (UINTN)) {
      Candidate = (UINTN *)(Image.Base + Image.Sections[SectionIndex].VirtualAddress + Offset);
      if ((Candidate[EVB_VHD_WRITE_INDEX] !=
           (Candidate[EVB_VHD_READ_INDEX] + EVB_VHD_WRAPPER_SIZE)) ||
          !EvbMatchesVhdWrapperPair (&Image, Candidate[EVB_VHD_READ_INDEX]) ||
          !EvbRangeInSection (&Image, Candidate[EVB_VHD_OPEN_INDEX], 1, TRUE) ||
          !EvbRangeInSection (&Image, Candidate[EVB_VHD_CLOSE_INDEX], 1, TRUE))
      {
        continue;
      }

      if (Match != NULL) {
        return NULL;
      }
      Match = Candidate;
    }
  }

  return Match;
}

STATIC
INT32
EFIAPI
EvbWinloadVhdRead (
  IN VOID    *VhdContext,
  IN UINT64  ByteOffset,
  IN VOID    *Buffer,
  IN UINT32  ByteCount,
  IN UINT32  Flags
  )
{
  EFI_STATUS  CryptoStatus;
  INT32       Status;

  Status = mOriginalWinloadVhdRead (
             VhdContext,
             ByteOffset,
             Buffer,
             ByteCount,
             Flags
             );
  if ((Status != 0) || !EvbVeraCryptIsActive ()) {
    return Status;
  }

  CryptoStatus = EvbVeraCryptDecryptRead (
                   mOriginalWinloadVhdRead,
                   VhdContext,
                   Flags,
                   ByteOffset,
                   Buffer,
                   ByteCount
                   );
  if (EFI_ERROR (CryptoStatus)) {
    return EVB_STATUS_UNSUCCESSFUL;
  }
  return Status;
}

STATIC
INT32
EFIAPI
EvbWinloadVhdWrite (
  IN VOID    *VhdContext,
  IN UINT64  ByteOffset,
  IN VOID    *Buffer,
  IN UINT32  ByteCount,
  IN UINT32  Flags
  )
{
  if (EvbVeraCryptIsActive ()) {
    return EVB_STATUS_MEDIA_WRITE_PROTECTED;
  }

  return mOriginalWinloadVhdWrite (
           VhdContext,
           ByteOffset,
           Buffer,
           ByteCount,
           Flags
           );
}

STATIC
BOOLEAN
EvbHookWinloadVhdParser (
  IN VOID    *ImageBase,
  IN UINT32  ImageSize
  )
{
  UINTN  *Parser;

  Parser = EvbFindVhd1Parser (ImageBase, ImageSize);
  if (Parser == NULL) {
    return FALSE;
  }

  mWinloadVhd1Parser        = Parser;
  mOriginalWinloadVhdRead   = (EVB_VHD_IO)Parser[EVB_VHD_READ_INDEX];
  mOriginalWinloadVhdWrite  = (EVB_VHD_IO)Parser[EVB_VHD_WRITE_INDEX];
  Parser[EVB_VHD_READ_INDEX]  = (UINTN)EvbWinloadVhdRead;
  Parser[EVB_VHD_WRITE_INDEX] = (UINTN)EvbWinloadVhdWrite;
  MemoryFence ();

  if ((Parser[EVB_VHD_READ_INDEX] != (UINTN)EvbWinloadVhdRead) ||
      (Parser[EVB_VHD_WRITE_INDEX] != (UINTN)EvbWinloadVhdWrite))
  {
    Parser[EVB_VHD_READ_INDEX]  = (UINTN)mOriginalWinloadVhdRead;
    Parser[EVB_VHD_WRITE_INDEX] = (UINTN)mOriginalWinloadVhdWrite;
    MemoryFence ();
    mWinloadVhd1Parser       = NULL;
    mOriginalWinloadVhdRead  = NULL;
    mOriginalWinloadVhdWrite = NULL;
    return FALSE;
  }

  return TRUE;
}

STATIC
VOID
EvbRestoreWinloadVhdParser (
  VOID
  )
{
  if ((mWinloadVhd1Parser != NULL) &&
      (mOriginalWinloadVhdRead != NULL) &&
      (mOriginalWinloadVhdWrite != NULL))
  {
    mWinloadVhd1Parser[EVB_VHD_READ_INDEX] = (UINTN)mOriginalWinloadVhdRead;
    mWinloadVhd1Parser[EVB_VHD_WRITE_INDEX] = (UINTN)mOriginalWinloadVhdWrite;
    MemoryFence ();
  }

  mWinloadVhd1Parser       = NULL;
  mOriginalWinloadVhdRead  = NULL;
  mOriginalWinloadVhdWrite = NULL;
}

STATIC
INT32
EFIAPI
EvbStartBootApplication (
  IN VOID    *BootApplicationParameters,
  IN VOID    *ImageBase,
  IN UINT32  ImageSize,
  IN UINT32  Flags,
  IN VOID    *StartContext
  )
{
  BOOLEAN  Hooked;
  INT32    Status;

  Hooked = EvbHookWinloadVhdParser (ImageBase, ImageSize);
  if (!Hooked && EvbVeraCryptIsActive ()) {
    Print (L"[EVB] Refusing encrypted boot: Winload VHD1 parser was not uniquely validated.\r\n");
    return EVB_STATUS_UNSUCCESSFUL;
  }

  Status = mOriginalBootApplicationStart (
             BootApplicationParameters,
             ImageBase,
             ImageSize,
             Flags,
             StartContext
             );
  if (Hooked) {
    EvbRestoreWinloadVhdParser ();
  }

  return Status;
}

STATIC
VOID
EvbWriteAbsoluteJump (
  OUT UINT8  *Destination,
  IN  UINTN  Target
  )
{
  // jmp qword ptr [rip+0] followed by the absolute destination.  Unlike a
  // mov-rax/jmp-rax sequence this preserves every register used by the copied
  // ImgArchEfiStartBootApplication prologue.
  Destination[0] = 0xFF;
  Destination[1] = 0x25;
  WriteUnaligned32 ((UINT32 *)(Destination + 2), 0);
  WriteUnaligned64 ((UINT64 *)(Destination + 6), (UINT64)Target);
}

STATIC
EFI_STATUS
EvbInstallBootApplicationHook (
  IN UINT8  *BootManagerBase
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  TrampolineAddress;
  UINT8                 *Trampoline;

  if (CompareMem (
        BootManagerBase + EVB_BOOT_APP_START_RVA,
        mBootApplicationHookPrologue,
        sizeof (mBootApplicationHookPrologue)
        ) != 0)
  {
    return EFI_COMPROMISED_DATA;
  }

  TrampolineAddress = 0;
  Status = gBS->AllocatePages (
                  AllocateAnyPages,
                  EfiLoaderCode,
                  1,
                  &TrampolineAddress
                  );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Trampoline                    = (UINT8 *)(UINTN)TrampolineAddress;
  mBootApplicationHookTarget    = BootManagerBase + EVB_BOOT_APP_START_RVA;
  mBootApplicationTrampoline    = Trampoline;
  mOriginalBootApplicationStart = (EVB_BOOT_APPLICATION_START)Trampoline;

  CopyMem (
    mBootApplicationHookOriginal,
    mBootApplicationHookTarget,
    EVB_BOOT_APP_HOOK_SIZE
    );
  CopyMem (
    Trampoline,
    mBootApplicationHookOriginal,
    EVB_BOOT_APP_HOOK_SIZE
    );
  EvbWriteAbsoluteJump (
    Trampoline + EVB_BOOT_APP_HOOK_SIZE,
    (UINTN)(mBootApplicationHookTarget + EVB_BOOT_APP_HOOK_SIZE)
    );

  EvbWriteAbsoluteJump (
    mBootApplicationHookTarget,
    (UINTN)EvbStartBootApplication
    );
  SetMem (
    mBootApplicationHookTarget + EVB_ABSOLUTE_JUMP_SIZE,
    EVB_BOOT_APP_HOOK_SIZE - EVB_ABSOLUTE_JUMP_SIZE,
    0x90
    );
  MemoryFence ();
  return EFI_SUCCESS;
}

STATIC
VOID
EvbRestoreBootApplicationHook (
  VOID
  )
{
  if (mBootApplicationHookTarget != NULL) {
    CopyMem (
      mBootApplicationHookTarget,
      mBootApplicationHookOriginal,
      EVB_BOOT_APP_HOOK_SIZE
      );
    MemoryFence ();
    mBootApplicationHookTarget = NULL;
  }

  if (mBootApplicationTrampoline != NULL) {
    gBS->FreePages ((EFI_PHYSICAL_ADDRESS)(UINTN)mBootApplicationTrampoline, 1);
    mBootApplicationTrampoline    = NULL;
    mOriginalBootApplicationStart = NULL;
  }
}

STATIC
INT32
EFIAPI
EvbVhdReadPassThrough (
  IN VOID    *VhdContext,
  IN UINT64  ByteOffset,
  IN VOID    *Buffer,
  IN UINT32  ByteCount,
  IN UINT32  Flags
  )
{
  INT32  Status;

  Status = mOriginalVhdRead (VhdContext, ByteOffset, Buffer, ByteCount, Flags);

  if (Status != 0) {
    return Status;
  }

  if (!mVeraCryptChecked) {
    EFI_STATUS  CryptoStatus;

    CryptoStatus       = EvbVeraCryptInitialize (mOriginalVhdRead, VhdContext, Flags);
    mVeraCryptChecked  = TRUE;
    if (CryptoStatus == EFI_NOT_FOUND) {
      Print (L"[EVB] Empty password: continuing without VeraCrypt.\r\n");
    } else if (EFI_ERROR (CryptoStatus)) {
      Print (L"[EVB] VeraCrypt initialization failed: %r\r\n", CryptoStatus);
      return EVB_STATUS_UNSUCCESSFUL;
    }
  }

  if (EvbVeraCryptIsActive ()) {
    EFI_STATUS  CryptoStatus;

    CryptoStatus = EvbVeraCryptDecryptRead (
                     NULL,
                     VhdContext,
                     Flags,
                     ByteOffset,
                     Buffer,
                     ByteCount
                     );
    if (EFI_ERROR (CryptoStatus)) {
      return EVB_STATUS_UNSUCCESSFUL;
    }


  }

  return Status;
}

STATIC
INT32
EFIAPI
EvbVhdWritePassThrough (
  IN VOID    *VhdContext,
  IN UINT64  ByteOffset,
  IN VOID    *Buffer,
  IN UINT32  ByteCount,
  IN UINT32  Flags
  )
{
  if (!mVeraCryptChecked) {
    EFI_STATUS  CryptoStatus;

    CryptoStatus      = EvbVeraCryptInitialize (mOriginalVhdRead, VhdContext, Flags);
    mVeraCryptChecked = TRUE;
    if (CryptoStatus == EFI_NOT_FOUND) {
      Print (L"[EVB] Empty password: continuing without VeraCrypt.\r\n");
    } else if (EFI_ERROR (CryptoStatus)) {
      Print (L"[EVB] VeraCrypt initialization failed: %r\r\n", CryptoStatus);
      return EVB_STATUS_UNSUCCESSFUL;
    }
  }

  if (EvbVeraCryptIsActive ()) {
    return EVB_STATUS_MEDIA_WRITE_PROTECTED;
  }

  return mOriginalVhdWrite (
           VhdContext,
           ByteOffset,
           Buffer,
           ByteCount,
           Flags
           );
}

STATIC
EFI_STATUS
EvbValidateAndHookBootManager (
  IN EFI_LOADED_IMAGE_PROTOCOL  *BootManager
  )
{
  EFI_STATUS  Status;
  UINT8  *Base;
  UINTN  ExpectedOpen;
  UINTN  ExpectedClose;
  UINTN  ExpectedRead;
  UINTN  ExpectedWrite;

  if ((BootManager == NULL) || (BootManager->ImageBase == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  if (BootManager->ImageSize < EVB_BOOTMGR_MINIMUM_SIZE) {
    return EFI_UNSUPPORTED;
  }

  Base          = (UINT8 *)BootManager->ImageBase;
  mVhd1Parser   = (UINTN *)(Base + EVB_VHD1_PARSER_RVA);
  ExpectedOpen  = (UINTN)(Base + EVB_VHD_OPEN_RVA);
  ExpectedClose = (UINTN)(Base + EVB_VHD_CLOSE_RVA);
  ExpectedRead  = (UINTN)(Base + EVB_VHD_READ_RVA);
  ExpectedWrite = (UINTN)(Base + EVB_VHD_WRITE_RVA);

  if ((mVhd1Parser[EVB_VHD_OPEN_INDEX] != ExpectedOpen) ||
      (mVhd1Parser[EVB_VHD_CLOSE_INDEX] != ExpectedClose) ||
      (mVhd1Parser[EVB_VHD_READ_INDEX] != ExpectedRead) ||
      (mVhd1Parser[EVB_VHD_WRITE_INDEX] != ExpectedWrite))
  {
    return EFI_COMPROMISED_DATA;
  }

  mOriginalVhdRead  = (EVB_VHD_IO)mVhd1Parser[EVB_VHD_READ_INDEX];
  mOriginalVhdWrite = (EVB_VHD_IO)mVhd1Parser[EVB_VHD_WRITE_INDEX];

  mVhd1Parser[EVB_VHD_READ_INDEX]  = (UINTN)EvbVhdReadPassThrough;
  mVhd1Parser[EVB_VHD_WRITE_INDEX] = (UINTN)EvbVhdWritePassThrough;
  MemoryFence ();

  if ((mVhd1Parser[EVB_VHD_READ_INDEX] != (UINTN)EvbVhdReadPassThrough) ||
      (mVhd1Parser[EVB_VHD_WRITE_INDEX] != (UINTN)EvbVhdWritePassThrough))
  {
    mVhd1Parser[EVB_VHD_READ_INDEX]  = (UINTN)mOriginalVhdRead;
    mVhd1Parser[EVB_VHD_WRITE_INDEX] = (UINTN)mOriginalVhdWrite;
    MemoryFence ();
    mOriginalVhdRead  = NULL;
    mOriginalVhdWrite = NULL;
    return EFI_WRITE_PROTECTED;
  }

  Status = EvbInstallBootApplicationHook (Base);
  if (EFI_ERROR (Status)) {
    mVhd1Parser[EVB_VHD_READ_INDEX]  = (UINTN)mOriginalVhdRead;
    mVhd1Parser[EVB_VHD_WRITE_INDEX] = (UINTN)mOriginalVhdWrite;
    MemoryFence ();
    mOriginalVhdRead  = NULL;
    mOriginalVhdWrite = NULL;
  }

  return Status;
}

STATIC
VOID
EvbRestoreBootManager (
  VOID
  )
{
  EvbRestoreWinloadVhdParser ();
  EvbRestoreBootApplicationHook ();

  if ((mVhd1Parser != NULL) &&
      (mOriginalVhdRead != NULL) &&
      (mOriginalVhdWrite != NULL))
  {
    mVhd1Parser[EVB_VHD_READ_INDEX]  = (UINTN)mOriginalVhdRead;
    mVhd1Parser[EVB_VHD_WRITE_INDEX] = (UINTN)mOriginalVhdWrite;
    MemoryFence ();
  }

  mVhd1Parser       = NULL;
  mOriginalVhdRead  = NULL;
  mOriginalVhdWrite = NULL;

  EvbVeraCryptCleanup ();
}

EFI_STATUS
EFIAPI
UefiMain (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_STATUS                 Status;
  EFI_STATUS                 ExitStatus;
  EFI_HANDLE                 BootManagerHandle;
  EFI_LOADED_IMAGE_PROTOCOL  *Self;
  EFI_LOADED_IMAGE_PROTOCOL  *BootManager;
  EFI_DEVICE_PATH_PROTOCOL   *BootManagerPath;
  UINTN                      ExitDataSize;
  CHAR16                     *ExitData;

  (VOID)SystemTable;

  BootManagerHandle = NULL;
  BootManager        = NULL;
  BootManagerPath    = NULL;
  ExitDataSize       = 0;
  ExitData           = NULL;

  Status = gBS->HandleProtocol (
                  ImageHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&Self
                  );
  if (EFI_ERROR (Status)) {
    Print (L"[EVB] Cannot inspect the preloader image: %r\r\n", Status);
    return Status;
  }

  BootManagerPath = FileDevicePath (
                      Self->DeviceHandle,
                      EVB_ORIGINAL_BOOT_MANAGER_PATH
                      );
  if (BootManagerPath == NULL) {
    Print (L"[EVB] Cannot construct the original BOOTMGR path.\r\n");
    return EFI_OUT_OF_RESOURCES;
  }

  Status = gBS->LoadImage (
                  FALSE,
                  ImageHandle,
                  BootManagerPath,
                  NULL,
                  0,
                  &BootManagerHandle
                  );
  FreePool (BootManagerPath);
  BootManagerPath = NULL;

  if (EFI_ERROR (Status)) {
    Print (
      L"[EVB] Cannot load %s: %r\r\n",
      EVB_ORIGINAL_BOOT_MANAGER_PATH,
      Status
      );
    return Status;
  }

  Status = gBS->HandleProtocol (
                  BootManagerHandle,
                  &gEfiLoadedImageProtocolGuid,
                  (VOID **)&BootManager
                  );
  if (EFI_ERROR (Status)) {
    Print (L"[EVB] Cannot inspect the original BOOTMGR: %r\r\n", Status);
    gBS->UnloadImage (BootManagerHandle);
    return Status;
  }

  // Preserve any chainloader-provided options. Most Ventoy configurations do
  // not require them, but dropping them here would make the wrapper subtly
  // different from launching the original image directly.
  BootManager->LoadOptions     = Self->LoadOptions;
  BootManager->LoadOptionsSize = Self->LoadOptionsSize;

  Status = EvbValidateAndHookBootManager (BootManager);
  if (EFI_ERROR (Status)) {
    Print (
      L"[EVB] Unsupported or protected BOOTMGR image: %r\r\n",
      Status
      );
    gBS->UnloadImage (BootManagerHandle);
    return Status;
  }

  // BOOTMGR snapshots the UEFI memory map while initializing its own physical
  // allocator. Reserve VeraCrypt's fixed handoff page before StartImage so a
  // later password prompt only fills existing memory and cannot invalidate
  // BOOTMGR's view of available pages.
  Status = EvbVeraCryptReserveBootParams ();
  if (EFI_ERROR (Status)) {
    Print (L"[EVB] Cannot reserve VeraCrypt boot-parameter memory: %r\r\n", Status);
    EvbRestoreBootManager ();
    gBS->UnloadImage (BootManagerHandle);
    return Status;
  }

  Print (L"[EVB] BOOTMGR validated; starting with VeraCrypt-aware VHD hooks.\r\n");
  ExitStatus = gBS->StartImage (BootManagerHandle, &ExitDataSize, &ExitData);

  EvbRestoreBootManager ();
  if (ExitData != NULL) {
    Print (L"[EVB] BOOTMGR returned: %r: %s\r\n", ExitStatus, ExitData);
    FreePool (ExitData);
  } else {
    Print (L"[EVB] BOOTMGR returned: %r\r\n", ExitStatus);
  }
  gBS->UnloadImage (BootManagerHandle);
  return ExitStatus;
}
