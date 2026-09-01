/** @file
  VeraCrypt system-volume support for the VHD1 BOOTMGR read hook.

  Copyright (c) 2026, Keishin Senzaki. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#ifndef EVB_VERACRYPT_H_
#define EVB_VERACRYPT_H_

#include <Uefi.h>

typedef INT32 (EFIAPI *EVB_VHD_IO)(
  IN VOID    *VhdContext,
  IN UINT64  ByteOffset,
  IN VOID    *Buffer,
  IN UINT32  ByteCount,
  IN UINT32  Flags
  );

EFI_STATUS
EvbVeraCryptReserveBootParams (
  VOID
  );

EFI_STATUS
EvbVeraCryptInitialize (
  IN EVB_VHD_IO  RawRead,
  IN VOID         *VhdContext,
  IN UINT32       Flags
  );

EFI_STATUS
EvbVeraCryptDecryptRead (
  IN EVB_VHD_IO  BounceRead OPTIONAL,
  IN VOID      *VhdContext,
  IN UINT32    Flags,
  IN UINT64    ByteOffset,
  IN OUT VOID  *Buffer,
  IN UINT32    ByteCount
  );

BOOLEAN
EvbVeraCryptIsActive (
  VOID
  );

VOID
EvbVeraCryptCleanup (
  VOID
  );

#endif
