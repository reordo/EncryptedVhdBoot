/** @file
  VeraCrypt authentication, sector transformation, and Windows driver boot
  arguments for a VHD-backed system disk.

  The cryptographic primitives and on-disk structures are supplied by the
  upstream VeraCrypt and VeraCrypt-DCS submodules.

  Copyright (c) 2026, Keishin Senzaki. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "EvbVeraCrypt.h"

#include <Uefi.h>

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <common/Tcdefs.h>
#include <BootCommon.h>
#include <common/Crc.h>
#include <common/Crypto.h>
#include <common/Password.h>
#include <common/Volumes.h>

#define EVB_SECTOR_SIZE                  512U
#define EVB_SYSTEM_HEADER_OFFSET         (62U * EVB_SECTOR_SIZE)
#define EVB_MBR_SIGNATURE_OFFSET         0x1B8U
#define EVB_NT_SUCCESS                   0
#define EVB_MAX_PASSWORD_RETRIES         3U
#define EVB_MAX_PIM_DIGITS               5U
#define EVB_INPUT_FLUSH_DELAY_100NS       100000U

#define EVB_CRYPTO_WORKSPACE_PAGES         512U
#define EVB_CRYPTO_ALLOCATION_ALIGNMENT    16U
#define EVB_BOUNCE_BUFFER_SIZE              EVB_SECTOR_SIZE

#pragma pack(1)
typedef struct {
  CHAR8                  Offset[TC_BOOT_LOADER_ARGS_OFFSET];
  BootArguments          BootArgs;
  BOOT_CRYPTO_HEADER     BootCryptoInfo;
  UINT16                 Padding;
  SECREGION_BOOT_PARAMS  SecRegion;
} EVB_BOOT_PARAMS;
#pragma pack()

STATIC PCRYPTO_INFO     mCryptoInfo;
STATIC EVB_BOOT_PARAMS *mBootParams;
STATIC UINT64           mEncryptedStart;
STATIC UINT64           mEncryptedEnd;
STATIC BOOLEAN          mActive;
STATIC EVB_VHD_IO      mRawRead;
STATIC VOID             *mVhdContext;
STATIC UINT32           mReadFlags;
STATIC UINT8            *mCryptoWorkspace;
STATIC UINTN            mCryptoWorkspaceUsed;
STATIC UINTN            mCryptoWorkspaceSize;
// Keep persistent crypto state inside the preloader image.  Child Windows boot
// applications inherit mappings for the active parent image, whereas separate
// UEFI allocations may either be reclaimed or omitted from the child page map.
STATIC UINT8            mCryptoWorkspaceStorage[
                          EFI_PAGES_TO_SIZE (EVB_CRYPTO_WORKSPACE_PAGES)
                          ];
STATIC UINT8            mBounceBuffer[EVB_BOUNCE_BUFFER_SIZE];
STATIC EFI_EVENT        mExitBootServicesEvent;
STATIC BOOLEAN          mExitBootServicesSignaled;
STATIC BOOLEAN          mAttributionBannerDisplayed;

// These fixed regions are the locations searched by the Windows VeraCrypt
// boot driver. Keep the order used by current VeraCrypt-DCS UEFI builds.
STATIC CONST UINTN mBootArgsRegions[] = {
  0x100000,  0x200000,  0x300000,  0x400000,
  0x500000,  0x600000,  0x700000,  0x800000,
  0x900000,  0xA00000,  0xB00000,  0xC00000,
  0xD00000,  0xE00000,  0xF00000,  0x1000000,
  0x90000,   0x88000,   0x80000
};

STATIC
VOID
EvbSecureWipe (
  IN VOID   *Buffer,
  IN UINTN  Size
  )
{
  volatile UINT8  *Cursor;

  Cursor = (volatile UINT8 *)Buffer;
  while (Size-- != 0) {
    *Cursor++ = 0;
  }
  MemoryFence ();
}

STATIC
VOID
EFIAPI
EvbExitBootServices (
  IN EFI_EVENT  Event,
  IN VOID       *Context
  )
{
  (VOID)Event;
  (VOID)Context;

  // The Windows VeraCrypt driver receives its own copy in mBootParams. The
  // preloader's expanded key schedules and decrypted-sector scratch space are
  // no longer needed once firmware boot services are being left.
  mExitBootServicesSignaled  = TRUE;
  EvbSecureWipe (mBounceBuffer, sizeof (mBounceBuffer));
  EvbSecureWipe (mCryptoWorkspaceStorage, sizeof (mCryptoWorkspaceStorage));
  mCryptoInfo          = NULL;
  mCryptoWorkspace     = NULL;
  mCryptoWorkspaceUsed = 0;
  mCryptoWorkspaceSize = 0;
  mRawRead             = NULL;
  mVhdContext          = NULL;
  mReadFlags           = 0;
  mEncryptedStart      = 0;
  mEncryptedEnd        = 0;
  mActive              = FALSE;
}

STATIC
VOID
EvbFlushRepeatedKey (
  VOID
  )
{
  EFI_STATUS     Status;
  EFI_EVENT      Events[2];
  EFI_INPUT_KEY  Key;
  UINTN          EventIndex;

  Events[0] = gST->ConIn->WaitForKey;
  Status = gBS->CreateEvent (EVT_TIMER, 0, NULL, NULL, &Events[1]);
  if (EFI_ERROR (Status)) {
    return;
  }

  Status = gBS->SetTimer (
                  Events[1],
                  TimerRelative,
                  EVB_INPUT_FLUSH_DELAY_100NS
                  );
  if (EFI_ERROR (Status)) {
    gBS->CloseEvent (Events[1]);
    return;
  }

  for (;;) {
    Status = gBS->WaitForEvent (ARRAY_SIZE (Events), Events, &EventIndex);
    if (EFI_ERROR (Status) || (EventIndex == 1)) {
      break;
    }

    (VOID)gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
  }

  gBS->CloseEvent (Events[1]);
}

STATIC
VOID
EvbPrintAttributionBanner (
  VOID
  )
{
  if (mAttributionBannerDisplayed) {
    return;
  }

  // Some Windows Boot Manager/firmware combinations erase the glyphs drawn
  // before StartImage without restoring the UEFI text cursor. Normalize both
  // the display and cursor so the authentication UI starts at the first row.
  (VOID)gST->ConOut->ClearScreen (gST->ConOut);
  (VOID)gST->ConOut->SetCursorPosition (gST->ConOut, 0, 0);

  Print (
    L"\r\n"
    L"Encrypted VHD Boot Bridge\r\n"
    L"Author: Keishin Senzaki (reorder)\r\n"
    L"Email:  riodaa@proton.me\r\n"
    L"GitHub: https://github.com/reordo\r\n"
    L"Source: https://github.com/reordo/EncryptedVhdBoot\r\n"
    L"Based on TrueCrypt,\r\n"
    L"freely available at http://www.truecrypt.org/.\r\n"
    L"\r\n"
    );
  mAttributionBannerDisplayed = TRUE;
}

STATIC
VOID
EvbRedrawPassword (
  IN CONST Password  *VcPassword,
  IN BOOLEAN         Visible
  )
{
  UINTN  Index;

  for (Index = 0; Index < VcPassword->Length; ++Index) {
    Print (L"\b");
  }

  for (Index = 0; Index < VcPassword->Length; ++Index) {
    Print (L"%c", Visible ? (CHAR16)VcPassword->Text[Index] : L'*');
  }
}

STATIC
VOID
EvbCollapsePasswordDisplay (
  IN CONST Password  *VcPassword
  )
{
  UINTN  Index;

  for (Index = 0; Index < VcPassword->Length; ++Index) {
    Print (L"\b \b");
  }

  if (VcPassword->Length != 0) {
    Print (L"*");
  }
}

STATIC
VOID
EvbRedrawPim (
  IN CONST CHAR16  *Digits,
  IN UINTN         DigitCount,
  IN BOOLEAN       Visible
  )
{
  UINTN  Index;

  for (Index = 0; Index < DigitCount; ++Index) {
    Print (L"\b");
  }

  for (Index = 0; Index < DigitCount; ++Index) {
    Print (L"%c", Visible ? Digits[Index] : L'*');
  }
}

STATIC
VOID
EvbCancelBoot (
  VOID
  )
{
  Print (L"[EVB] Boot cancelled; rebooting.\r\n");
  gRT->ResetSystem (EfiResetCold, EFI_ABORTED, 0, NULL);
  CpuDeadLoop ();
}

// VeraCrypt's UEFI port obtains allocation and fatal-error services from its
// consumer. Authentication needs allocation; header creation/randomness is not
// used by this read-only boot path.
VOID *
VeraCryptMemAlloc (
  IN UINTN Size
  )
{
  UINTN  AlignedSize;
  VOID   *Allocation;

  if (mCryptoWorkspace != NULL) {
    AlignedSize = ALIGN_VALUE (Size, EVB_CRYPTO_ALLOCATION_ALIGNMENT);
    if ((AlignedSize < Size) ||
        (AlignedSize > (mCryptoWorkspaceSize - mCryptoWorkspaceUsed)))
    {
      return NULL;
    }

    Allocation = mCryptoWorkspace + mCryptoWorkspaceUsed;
    mCryptoWorkspaceUsed += AlignedSize;
    ZeroMem (Allocation, AlignedSize);
    return Allocation;
  }

  return AllocateZeroPool (Size);
}

VOID
VeraCryptMemFree (
  IN VOID *Pointer
  )
{
  if ((Pointer != NULL) &&
      !((mCryptoWorkspace != NULL) &&
        ((UINT8 *)Pointer >= mCryptoWorkspace) &&
        ((UINT8 *)Pointer < (mCryptoWorkspace + mCryptoWorkspaceSize))))
  {
    FreePool (Pointer);
  }
}

VOID
ThrowFatalException (
  IN INT32 Line
  )
{
  Print (L"[EVB] VeraCrypt fatal error at source line %d.\r\n", Line);
  CpuDeadLoop ();
}

BOOL
RandgetBytes (
  OUT unsigned char *Buffer,
  IN int             Length,
  IN BOOL            ForceSlowPoll
  )
{
  (VOID)Buffer;
  (VOID)Length;
  (VOID)ForceSlowPoll;
  return FALSE;
}

// Upstream cpu.c probes SHA-NI through TrySHA256(), while Sha2Intel.c omits
// that probe in UEFI builds. Software SHA-256 remains available and is the
// conservative choice during pre-boot authentication.
INT32
TrySHA256 (
  VOID
  )
{
  return 0;
}

STATIC
EFI_STATUS
EvbReadPassword (
  OUT Password *VcPassword
  )
{
  EFI_STATUS     Status;
  EFI_INPUT_KEY  Key;
  UINTN          EventIndex;
  BOOLEAN        Visible;

  ZeroMem (VcPassword, sizeof (*VcPassword));
  Visible = FALSE;
  // BOOTMGR may clear the UEFI console after StartImage. Draw the banner in
  // the same phase as the prompt so it remains visible during authentication.
  EvbPrintAttributionBanner ();
  Print (
    L"\r\n[EVB] VeraCrypt password "
    L"(empty = unencrypted; F5 = show/hide; Esc = reboot): "
    );

  for (;;) {
    Status = gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &EventIndex);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    Status = gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
    if (EFI_ERROR (Status)) {
      continue;
    }

    if (Key.ScanCode == SCAN_ESC) {
      EvbFlushRepeatedKey ();
      ZeroMem (VcPassword, sizeof (*VcPassword));
      Print (L"\r\n");
      EvbCancelBoot ();
      return EFI_ABORTED;
    }

    if (Key.ScanCode == SCAN_F5) {
      EvbFlushRepeatedKey ();
      Visible = (BOOLEAN)!Visible;
      EvbRedrawPassword (VcPassword, Visible);
      continue;
    }

    if (Key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
      EvbFlushRepeatedKey ();
      EvbCollapsePasswordDisplay (VcPassword);
      Print (L"\r\n");
      return EFI_SUCCESS;
    }

    if ((Key.UnicodeChar == CHAR_BACKSPACE) && (VcPassword->Length != 0)) {
      --VcPassword->Length;
      VcPassword->Text[VcPassword->Length] = 0;
      Print (L"\b \b");
      continue;
    }

    if ((Key.UnicodeChar >= 0x20) && (Key.UnicodeChar <= 0x7E) &&
        (VcPassword->Length < MAX_PASSWORD))
    {
      VcPassword->Text[VcPassword->Length++] = (UINT8)Key.UnicodeChar;
      Print (L"%c", Visible ? Key.UnicodeChar : L'*');
    }
  }
}

STATIC
EFI_STATUS
EvbReadPim (
  OUT INT32  *Pim
  )
{
  EFI_STATUS     Status;
  EFI_INPUT_KEY  Key;
  UINTN          EventIndex;
  UINTN          DigitCount;
  UINT32         Value;
  BOOLEAN        Visible;
  CHAR16         Digits[EVB_MAX_PIM_DIGITS + 1];

  if (Pim == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  for (;;) {
    Print (
      L"[EVB] VeraCrypt PIM "
      L"(empty = default; F5 = show/hide; Esc = reboot): "
      );
    DigitCount = 0;
    Value      = 0;
    Visible    = FALSE;
    ZeroMem (Digits, sizeof (Digits));

    for (;;) {
      Status = gBS->WaitForEvent (1, &gST->ConIn->WaitForKey, &EventIndex);
      if (EFI_ERROR (Status)) {
        return Status;
      }

      Status = gST->ConIn->ReadKeyStroke (gST->ConIn, &Key);
      if (EFI_ERROR (Status)) {
        continue;
      }

      if (Key.ScanCode == SCAN_ESC) {
        EvbFlushRepeatedKey ();
        ZeroMem (Digits, sizeof (Digits));
        Print (L"\r\n");
        EvbCancelBoot ();
        return EFI_ABORTED;
      }

      if (Key.ScanCode == SCAN_F5) {
        EvbFlushRepeatedKey ();
        Visible = (BOOLEAN)!Visible;
        EvbRedrawPim (Digits, DigitCount, Visible);
        continue;
      }

      if (Key.UnicodeChar == CHAR_CARRIAGE_RETURN) {
        EvbFlushRepeatedKey ();
        Print (L"\r\n");
        if ((DigitCount == 0) || (Value <= MAX_BOOT_PIM_VALUE)) {
          *Pim = (INT32)Value;
          ZeroMem (Digits, sizeof (Digits));
          return EFI_SUCCESS;
        }

        Print (L"[EVB] PIM must be between 0 and %u. Try again.\r\n", MAX_BOOT_PIM_VALUE);
        ZeroMem (Digits, sizeof (Digits));
        break;
      }

      if ((Key.UnicodeChar == CHAR_BACKSPACE) && (DigitCount != 0)) {
        --DigitCount;
        Digits[DigitCount] = 0;
        Value /= 10;
        Print (L"\b \b");
        continue;
      }

      if ((Key.UnicodeChar >= L'0') && (Key.UnicodeChar <= L'9') &&
          (DigitCount < EVB_MAX_PIM_DIGITS))
      {
        Value = (Value * 10) + (UINT32)(Key.UnicodeChar - L'0');
        Digits[DigitCount] = Key.UnicodeChar;
        ++DigitCount;
        Print (L"%c", Visible ? Key.UnicodeChar : L'*');
      }
    }
  }
}

STATIC
EFI_STATUS
EvbAllocateBootParams (
  VOID
  )
{
  EFI_STATUS            Status;
  EFI_PHYSICAL_ADDRESS  Address;
  UINTN                 Index;
  UINTN                 Pages;

  Pages = EFI_SIZE_TO_PAGES (sizeof (*mBootParams));
  for (Index = 0; Index < ARRAY_SIZE (mBootArgsRegions); ++Index) {
    Address = mBootArgsRegions[Index];
    Status = gBS->AllocatePages (
                    AllocateAddress,
                    EfiMemoryMappedIO,
                    Pages,
                    &Address
                    );
    if (!EFI_ERROR (Status)) {
      mBootParams = (EVB_BOOT_PARAMS *)(UINTN)Address;
      ZeroMem (mBootParams, EFI_PAGES_TO_SIZE (Pages));
      Print (L"[EVB] VeraCrypt boot-parameter page reserved at 0x%Lx.\r\n", Address);
      return EFI_SUCCESS;
    }
  }

  return EFI_OUT_OF_RESOURCES;
}

EFI_STATUS
EvbVeraCryptReserveBootParams (
  VOID
  )
{
  EFI_STATUS  Status;

  if (mBootParams != NULL) {
    return EFI_ALREADY_STARTED;
  }

  Status = EvbAllocateBootParams ();
  if (EFI_ERROR (Status)) {
    return Status;
  }

  mCryptoWorkspace     = mCryptoWorkspaceStorage;
  mCryptoWorkspaceUsed = 0;
  mCryptoWorkspaceSize = EFI_PAGES_TO_SIZE (EVB_CRYPTO_WORKSPACE_PAGES);
  ZeroMem (mCryptoWorkspace, mCryptoWorkspaceSize);

  if (mExitBootServicesEvent == NULL) {
    Status = gBS->CreateEvent (
                    EVT_SIGNAL_EXIT_BOOT_SERVICES,
                    TPL_NOTIFY,
                    EvbExitBootServices,
                    NULL,
                    &mExitBootServicesEvent
                    );
    if (EFI_ERROR (Status)) {
      EvbSecureWipe (mCryptoWorkspaceStorage, sizeof (mCryptoWorkspaceStorage));
      mCryptoWorkspace     = NULL;
      mCryptoWorkspaceSize = 0;
      return Status;
    }
  }

  Print (
    L"[EVB] Crypto workspace reserved at 0x%Lx (0x%x bytes).\r\n",
    (UINT64)(UINTN)mCryptoWorkspace,
    mCryptoWorkspaceSize
    );
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EvbPrepareBootParams (
  IN CONST Password  *VcPassword,
  IN INT32           Pim,
  IN CONST UINT8     *Header,
  IN CONST UINT8     *Mbr
  )
{
  EFI_STATUS     Status;
  BootArguments  *Args;
  UINT32         SecRegionCrc;

  if (mBootParams == NULL) {
    Status = EvbAllocateBootParams ();
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  ZeroMem (mBootParams, EFI_PAGE_SIZE);

  Args = &mBootParams->BootArgs;
  TC_SET_BOOT_ARGUMENTS_SIGNATURE (Args->Signature);
  Args->BootLoaderVersion          = VERSION_NUM;
  Args->CryptoInfoOffset           = (UINT16)OFFSET_OF (EVB_BOOT_PARAMS, BootCryptoInfo);
  Args->CryptoInfoLength           = (UINT16)(sizeof (BOOT_CRYPTO_HEADER) + sizeof (UINT16) + sizeof (SECREGION_BOOT_PARAMS));
  Args->HeaderSaltCrc32            = GetCrc32 ((UINT8 *)Header, PKCS5_SALT_SIZE);
  CopyMem (&Args->BootPassword, VcPassword, sizeof (Args->BootPassword));
  Args->HiddenSystemPartitionStart = 0;
  Args->DecoySystemPartitionStart  = 0;
  Args->Flags                      = (UINT32)Pim << 16;
  CopyMem (&Args->BootDriveSignature, Mbr + EVB_MBR_SIGNATURE_OFFSET, sizeof (Args->BootDriveSignature));
  Args->BootArgumentsCrc32 = GetCrc32 (
                              (UINT8 *)Args,
                              (INT32)OFFSET_OF (BootArguments, BootArgumentsCrc32)
                              );

  mBootParams->BootCryptoInfo.ea    = (UINT16)mCryptoInfo->ea;
  mBootParams->BootCryptoInfo.mode  = (UINT16)mCryptoInfo->mode;
  mBootParams->BootCryptoInfo.pkcs5 = (UINT16)mCryptoInfo->pkcs5;
  mBootParams->SecRegion.Ptr        = 0;
  mBootParams->SecRegion.Size       = 0;
  Status = gBS->CalculateCrc32 (
                  &mBootParams->SecRegion,
                  sizeof (mBootParams->SecRegion) - sizeof (mBootParams->SecRegion.Crc),
                  &SecRegionCrc
                  );
  mBootParams->SecRegion.Crc = SecRegionCrc;
  return Status;
}

EFI_STATUS
EvbVeraCryptInitialize (
  IN EVB_VHD_IO  RawRead,
  IN VOID         *VhdContext,
  IN UINT32       Flags
  )
{
  EFI_STATUS  Status;
  Password    VcPassword;
  UINT8       Header[EVB_SECTOR_SIZE];
  UINT8       Mbr[EVB_SECTOR_SIZE];
  INT32       IoStatus;
  INT32       VcStatus;
  INT32       Pim;
  UINTN       Attempt;
  UINT8       Probe[EVB_SECTOR_SIZE];
  CHAR8       ProbeOem[9];
  UINT64_STRUCT ProbeDataUnit;

  if ((RawRead == NULL) || (VhdContext == NULL)) {
    return EFI_INVALID_PARAMETER;
  }

  mRawRead     = RawRead;
  mVhdContext  = VhdContext;
  mReadFlags   = Flags;

  IoStatus = RawRead (VhdContext, 0, Mbr, sizeof (Mbr), Flags);
  if (IoStatus != EVB_NT_SUCCESS) {
    return EFI_DEVICE_ERROR;
  }

  IoStatus = RawRead (
               VhdContext,
               EVB_SYSTEM_HEADER_OFFSET,
               Header,
               sizeof (Header),
               Flags
               );
  if (IoStatus != EVB_NT_SUCCESS) {
    return EFI_DEVICE_ERROR;
  }

  for (Attempt = 0; Attempt < EVB_MAX_PASSWORD_RETRIES; ++Attempt) {
    Status = EvbReadPassword (&VcPassword);
    if (EFI_ERROR (Status)) {
      return Status;
    }

    if (VcPassword.Length == 0) {
      ZeroMem (&VcPassword, sizeof (VcPassword));
      return EFI_NOT_FOUND;
    }

    Status = EvbReadPim (&Pim);
    if (EFI_ERROR (Status)) {
      ZeroMem (&VcPassword, sizeof (VcPassword));
      return Status;
    }

    VcStatus = ReadVolumeHeader (
                 TRUE,
                 Header,
                 &VcPassword,
                 0,
                 Pim,
                 &mCryptoInfo,
                 NULL
                 );
    if (VcStatus == 0) {
      Status = EvbPrepareBootParams (&VcPassword, Pim, Header, Mbr);
      ZeroMem (&VcPassword, sizeof (VcPassword));
      if (EFI_ERROR (Status)) {
        crypto_close (mCryptoInfo);
        mCryptoInfo = NULL;
        return Status;
      }

      mEncryptedStart = mCryptoInfo->EncryptedAreaStart.Value;
      mEncryptedEnd   = mEncryptedStart + mCryptoInfo->EncryptedAreaLength.Value;
      if ((mEncryptedEnd < mEncryptedStart) ||
          ((mEncryptedStart % EVB_SECTOR_SIZE) != 0) ||
          ((mEncryptedEnd % EVB_SECTOR_SIZE) != 0))
      {
        crypto_close (mCryptoInfo);
        mCryptoInfo = NULL;
        return EFI_COMPROMISED_DATA;
      }

      mActive = TRUE;
      IoStatus = RawRead (
                   VhdContext,
                   mEncryptedStart,
                   Probe,
                   sizeof (Probe),
                   Flags
                   );
      if (IoStatus != EVB_NT_SUCCESS) {
        EvbVeraCryptCleanup ();
        return EFI_DEVICE_ERROR;
      }

      ProbeDataUnit.Value = mEncryptedStart / EVB_SECTOR_SIZE;
      DecryptDataUnits (Probe, &ProbeDataUnit, 1, mCryptoInfo);
      CopyMem (ProbeOem, Probe + 3, 8);
      ProbeOem[8] = 0;
      Print (
        L"[EVB] VeraCrypt header accepted: encrypted 0x%Lx..0x%Lx, EA=%d, PRF=%d.\r\n"
        L"[EVB] Decrypted first-sector OEM field: '%a' (%s).\r\n",
        mEncryptedStart,
        mEncryptedEnd,
        mCryptoInfo->ea,
        mCryptoInfo->pkcs5,
        ProbeOem,
        (CompareMem (ProbeOem, "NTFS    ", 8) == 0) ? L"valid NTFS" : L"NOT NTFS"
        );
      if (CompareMem (ProbeOem, "NTFS    ", 8) != 0) {
        EvbVeraCryptCleanup ();
        return EFI_COMPROMISED_DATA;
      }

      return EFI_SUCCESS;
    }

    ZeroMem (&VcPassword, sizeof (VcPassword));
    Print (L"[EVB] Incorrect password or unsupported VeraCrypt header (%d).\r\n", VcStatus);
  }

  return EFI_ACCESS_DENIED;
}

EFI_STATUS
EvbVeraCryptDecryptRead (
  IN EVB_VHD_IO  BounceRead OPTIONAL,
  IN VOID      *VhdContext,
  IN UINT32    Flags,
  IN UINT64    ByteOffset,
  IN OUT VOID  *Buffer,
  IN UINT32    ByteCount
  )
{
  UINT64         ReadEnd;
  UINT64         IntersectStart;
  UINT64         IntersectEnd;
  UINT64_STRUCT  DataUnit;
  UINT64         Cursor;
  UINT64         MiddleEnd;
  UINT64         SectorStart;
  UINT64         SegmentEnd;
  UINT32         SegmentLength;
  UINT8          *Scratch;
  INT32          IoStatus;
  EVB_VHD_IO    EffectiveRead;
  VOID           *EffectiveContext;
  UINT32         EffectiveFlags;

  if (!mActive) {
    return EFI_SUCCESS;
  }

  if ((VhdContext == NULL) || (Buffer == NULL) || (ByteCount == 0)) {
    return EFI_INVALID_PARAMETER;
  }

  ReadEnd = ByteOffset + ByteCount;
  if (ReadEnd < ByteOffset) {
    return EFI_BAD_BUFFER_SIZE;
  }

  IntersectStart = (ByteOffset > mEncryptedStart) ? ByteOffset : mEncryptedStart;
  IntersectEnd   = (ReadEnd < mEncryptedEnd) ? ReadEnd : mEncryptedEnd;
  if (IntersectStart >= IntersectEnd) {
    return EFI_SUCCESS;
  }

  EffectiveRead    = (BounceRead != NULL) ? BounceRead : mRawRead;
  EffectiveContext = (BounceRead != NULL) ? VhdContext : mVhdContext;
  EffectiveFlags   = (BounceRead != NULL) ? Flags : mReadFlags;
  Scratch          = mBounceBuffer;
  Cursor           = IntersectStart;

  // Re-read and decrypt only a partial leading sector.  The aligned interior
  // can be decrypted in place regardless of the total request size.
  if ((Cursor % EVB_SECTOR_SIZE) != 0) {
    SectorStart = Cursor & ~((UINT64)EVB_SECTOR_SIZE - 1);
    IoStatus = EffectiveRead (
                 EffectiveContext,
                 SectorStart,
                 Scratch,
                 EVB_SECTOR_SIZE,
                 EffectiveFlags
                 );
    if (IoStatus != EVB_NT_SUCCESS) {
      return EFI_DEVICE_ERROR;
    }

    DataUnit.Value = SectorStart / EVB_SECTOR_SIZE;
    DecryptDataUnits (Scratch, &DataUnit, 1, mCryptoInfo);
    SegmentEnd = ALIGN_VALUE (Cursor, EVB_SECTOR_SIZE);
    if (SegmentEnd > IntersectEnd) {
      SegmentEnd = IntersectEnd;
    }
    SegmentLength = (UINT32)(SegmentEnd - Cursor);
    CopyMem (
      (UINT8 *)Buffer + (UINTN)(Cursor - ByteOffset),
      Scratch + (UINTN)(Cursor - SectorStart),
      SegmentLength
      );
    Cursor = SegmentEnd;
  }

  MiddleEnd = IntersectEnd & ~((UINT64)EVB_SECTOR_SIZE - 1);
  if (MiddleEnd > Cursor) {
    DataUnit.Value = Cursor / EVB_SECTOR_SIZE;
    DecryptDataUnits (
      (UINT8 *)Buffer + (UINTN)(Cursor - ByteOffset),
      &DataUnit,
      (UINT32)((MiddleEnd - Cursor) / EVB_SECTOR_SIZE),
      mCryptoInfo
      );
    Cursor = MiddleEnd;
  }

  // Finish with at most one partial trailing sector.
  if (Cursor < IntersectEnd) {
    IoStatus = EffectiveRead (
                 EffectiveContext,
                 Cursor,
                 Scratch,
                 EVB_SECTOR_SIZE,
                 EffectiveFlags
                 );
    if (IoStatus != EVB_NT_SUCCESS) {
      return EFI_DEVICE_ERROR;
    }

    DataUnit.Value = Cursor / EVB_SECTOR_SIZE;
    DecryptDataUnits (Scratch, &DataUnit, 1, mCryptoInfo);
    SegmentLength = (UINT32)(IntersectEnd - Cursor);
    CopyMem (
      (UINT8 *)Buffer + (UINTN)(Cursor - ByteOffset),
      Scratch,
      SegmentLength
      );
  }

  return EFI_SUCCESS;
}

BOOLEAN
EvbVeraCryptIsActive (
  VOID
  )
{
  return mActive;
}

VOID
EvbVeraCryptCleanup (
  VOID
  )
{
  if (!mExitBootServicesSignaled && (mExitBootServicesEvent != NULL)) {
    gBS->CloseEvent (mExitBootServicesEvent);
    mExitBootServicesEvent = NULL;
  }

  if (!mExitBootServicesSignaled && (mCryptoInfo != NULL)) {
    crypto_close (mCryptoInfo);
  }

  if (!mExitBootServicesSignaled) {
    EvbSecureWipe (mBounceBuffer, sizeof (mBounceBuffer));
    EvbSecureWipe (mCryptoWorkspaceStorage, sizeof (mCryptoWorkspaceStorage));
    if (mBootParams != NULL) {
      EvbSecureWipe (mBootParams, EFI_PAGE_SIZE);
    }
  }

  mCryptoInfo          = NULL;
  mCryptoWorkspace     = NULL;
  mCryptoWorkspaceUsed = 0;
  mCryptoWorkspaceSize = 0;
  mEncryptedStart      = 0;
  mEncryptedEnd        = 0;
  mActive              = FALSE;
  mRawRead             = NULL;
  mVhdContext          = NULL;
  mReadFlags           = 0;
}
