/** @file
  Read-only detection of a Ventoy marker on an NTFS data partition.

  Ventoy reads NTFS through GRUB, but does not necessarily install an UEFI
  Simple File System protocol for the data partition. This code reads only
  NTFS metadata through Block I/O. Unsupported layouts simply leave the
  normal, visible interface enabled.

  Copyright (c) 2026, Keishin Senzaki. All rights reserved.
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BlockIo.h>

#include "EvbVeraCrypt.h"

#define EVB_NTFS_BUFFER_SIZE       65536U
#define EVB_NTFS_MAX_MFT_BYTES     (256U * 1024U * 1024U)
#define EVB_NTFS_FILE_ATTRIBUTE    0x30U
#define EVB_NTFS_DATA_ATTRIBUTE    0x80U
#define EVB_NTFS_END_ATTRIBUTE     0xFFFFFFFFU
#define EVB_NTFS_FILE_REFERENCE    0x0000FFFFFFFFFFFFULL

STATIC
UINT16
EvbRead16 (
  IN CONST UINT8  *Data
  )
{
  return (UINT16)(Data[0] | (Data[1] << 8));
}

STATIC
UINT32
EvbRead32 (
  IN CONST UINT8  *Data
  )
{
  return (UINT32)Data[0] | ((UINT32)Data[1] << 8) |
         ((UINT32)Data[2] << 16) | ((UINT32)Data[3] << 24);
}

STATIC
UINT64
EvbRead64 (
  IN CONST UINT8  *Data
  )
{
  return (UINT64)EvbRead32 (Data) | ((UINT64)EvbRead32 (Data + 4) << 32);
}

STATIC
BOOLEAN
EvbNtfsNameEquals (
  IN CONST UINT8   *Name,
  IN UINTN         Length,
  IN CONST CHAR16  *Expected
  )
{
  UINTN   Index;
  CHAR16  Actual;
  CHAR16  Wanted;

  for (Index = 0; Index < Length; ++Index) {
    if (Expected[Index] == 0) {
      return FALSE;
    }

    Actual = EvbRead16 (Name + 2 * Index);
    Wanted = Expected[Index];
    if ((Actual >= L'A') && (Actual <= L'Z')) {
      Actual += L'a' - L'A';
    }
    if ((Wanted >= L'A') && (Wanted <= L'Z')) {
      Wanted += L'a' - L'A';
    }
    if (Actual != Wanted) {
      return FALSE;
    }
  }

  return Expected[Length] == 0;
}

typedef struct {
  BOOLEAN  DirectoryFound;
  BOOLEAN  ImageFound;
  BOOLEAN  MarkerFound;
  UINT64   DirectoryId;
  UINT64   ImageParent;
  UINT64   MarkerParent;
} EVB_NTFS_SEARCH;

STATIC
VOID
EvbInspectFileRecord (
  IN CONST UINT8      *Record,
  IN UINTN            RecordSize,
  IN UINT64           RecordId,
  IN OUT EVB_NTFS_SEARCH  *Search
  )
{
  UINTN         Position;
  UINTN         AttributeSize;
  UINTN         ValueOffset;
  UINTN         ValueLength;
  CONST UINT8   *Value;
  UINTN         NameLength;
  UINT64        Parent;
  BOOLEAN       Directory;

  if ((RecordSize < 0x38) || (EvbRead32 (Record) != SIGNATURE_32 ('F', 'I', 'L', 'E')) ||
      ((EvbRead16 (Record + 0x16) & 1U) == 0))
  {
    return;
  }

  Directory = (EvbRead16 (Record + 0x16) & 2U) != 0;
  Position = EvbRead16 (Record + 0x14);
  while ((Position <= RecordSize - 24) &&
         (EvbRead32 (Record + Position) != EVB_NTFS_END_ATTRIBUTE))
  {
    AttributeSize = EvbRead32 (Record + Position + 4);
    if ((AttributeSize < 24) || (AttributeSize > RecordSize - Position)) {
      return;
    }

    if ((EvbRead32 (Record + Position) == EVB_NTFS_FILE_ATTRIBUTE) &&
        (Record[Position + 8] == 0))
    {
      ValueLength = EvbRead32 (Record + Position + 0x10);
      ValueOffset = EvbRead16 (Record + Position + 0x14);
      if ((ValueOffset <= AttributeSize) &&
          (ValueLength <= AttributeSize - ValueOffset) &&
          (ValueLength >= 0x42))
      {
        Value = Record + Position + ValueOffset;
        NameLength = Value[0x40];
        if ((NameLength <= (ValueLength - 0x42) / 2) &&
            (Value[0x41] != 2)) // Ignore the DOS 8.3 alias.
        {
          Parent = EvbRead64 (Value) & EVB_NTFS_FILE_REFERENCE;
          if (Directory && (Parent == 5) &&
              EvbNtfsNameEquals (Value + 0x42, NameLength, L"ventoy"))
          {
            Search->DirectoryFound = TRUE;
            Search->DirectoryId = RecordId;
          } else if (!Directory &&
                     EvbNtfsNameEquals (Value + 0x42, NameLength, L"ventoy_vhdboot.img"))
          {
            Search->ImageFound = TRUE;
            Search->ImageParent = Parent;
          } else if (!Directory &&
                     EvbNtfsNameEquals (Value + 0x42, NameLength, L"ventoy_vhdboot.silent"))
          {
            Search->MarkerFound = TRUE;
            Search->MarkerParent = Parent;
          }
        }
      }
    }

    Position += AttributeSize;
  }
}

STATIC
BOOLEAN
EvbSearchComplete (
  IN CONST EVB_NTFS_SEARCH  *Search
  )
{
  return Search->DirectoryFound && Search->ImageFound && Search->MarkerFound &&
         (Search->ImageParent == Search->DirectoryId) &&
         (Search->MarkerParent == Search->DirectoryId);
}

STATIC
BOOLEAN
EvbScanNtfsVolume (
  IN EFI_BLOCK_IO_PROTOCOL  *BlockIo
  )
{
  EFI_STATUS       Status;
  UINT8            *Buffer;
  UINT32           BlockSize;
  UINT32           Alignment;
  UINT32           ClusterSize;
  UINT32           RecordSize;
  UINT64           MftLcn;
  UINTN            Attribute;
  UINTN            AttributeSize;
  UINTN            RunOffset;
  UINTN            RunEnd;
  UINTN            RunPosition;
  UINTN            LengthBytes;
  UINTN            OffsetBytes;
  UINTN            Index;
  UINT64           RunClusters;
  INT64            RunDelta;
  UINT64           DeltaBits;
  INT64            CurrentLcn;
  UINT64           LogicalOffset;
  UINT64           ValidBytes;
  UINT64           BytesInRun;
  UINT64           RunCursor;
  UINTN            ReadSize;
  UINTN            RecordOffset;
  EVB_NTFS_SEARCH  Search;
  BOOLEAN          Found;

  BlockSize = BlockIo->Media->BlockSize;
  if (!BlockIo->Media->MediaPresent || !BlockIo->Media->LogicalPartition ||
      (BlockSize < 512) || (BlockSize > 4096) ||
      (BlockSize & (BlockSize - 1U)) != 0)
  {
    return FALSE;
  }

  Alignment = BlockIo->Media->IoAlign;
  if (Alignment < EFI_PAGE_SIZE) {
    Alignment = EFI_PAGE_SIZE;
  }
  Buffer = AllocateAlignedPages (EFI_SIZE_TO_PAGES (EVB_NTFS_BUFFER_SIZE), Alignment);
  if (Buffer == NULL) {
    return FALSE;
  }

  Found = FALSE;
  Status = BlockIo->ReadBlocks (BlockIo, BlockIo->Media->MediaId, 0, BlockSize, Buffer);
  if (EFI_ERROR (Status) || (CompareMem (Buffer + 3, "NTFS    ", 8) != 0) ||
      (EvbRead16 (Buffer + 0x0B) != BlockSize))
  {
    goto Done;
  }

  ClusterSize = (UINT32)BlockSize * Buffer[0x0D];
  if ((Buffer[0x0D] == 0) || (ClusterSize > EVB_NTFS_BUFFER_SIZE) ||
      (ClusterSize & (ClusterSize - 1U)) != 0)
  {
    goto Done;
  }

  MftLcn = EvbRead64 (Buffer + 0x30);
  if (Buffer[0x40] & 0x80) {
    if ((256U - Buffer[0x40]) > 12) {
      goto Done;
    }
    RecordSize = 1U << (256U - Buffer[0x40]);
  } else {
    RecordSize = ClusterSize * Buffer[0x40];
  }
  if ((RecordSize < 512) || (RecordSize > 4096) ||
      (ClusterSize % RecordSize != 0) ||
      (MftLcn > BlockIo->Media->LastBlock / (ClusterSize / BlockSize)))
  {
    goto Done;
  }

  Status = BlockIo->ReadBlocks (
                      BlockIo,
                      BlockIo->Media->MediaId,
                      MftLcn * (ClusterSize / BlockSize),
                      ALIGN_VALUE (RecordSize, BlockSize),
                      Buffer
                      );
  if (EFI_ERROR (Status) ||
      (EvbRead32 (Buffer) != SIGNATURE_32 ('F', 'I', 'L', 'E')))
  {
    goto Done;
  }

  Attribute = EvbRead16 (Buffer + 0x14);
  RunOffset = 0;
  RunEnd = 0;
  ValidBytes = 0;
  while (Attribute <= RecordSize - 0x40) {
    if (EvbRead32 (Buffer + Attribute) == EVB_NTFS_END_ATTRIBUTE) {
      break;
    }
    AttributeSize = EvbRead32 (Buffer + Attribute + 4);
    if ((AttributeSize < 0x40) || (AttributeSize > RecordSize - Attribute)) {
      break;
    }
    if ((EvbRead32 (Buffer + Attribute) == EVB_NTFS_DATA_ATTRIBUTE) &&
        (Buffer[Attribute + 8] == 1) && (Buffer[Attribute + 9] == 0))
    {
      RunOffset = Attribute + EvbRead16 (Buffer + Attribute + 0x20);
      RunEnd = Attribute + AttributeSize;
      ValidBytes = EvbRead64 (Buffer + Attribute + 0x38);
      if ((RunOffset < Attribute + 0x40) || (RunOffset >= RunEnd)) {
        RunOffset = 0;
      }
      break;
    }
    Attribute += AttributeSize;
  }
  if ((RunOffset == 0) || (ValidBytes == 0)) {
    goto Done;
  }

  // Copy the runlist before reusing the aligned buffer for MFT data.
  RunEnd -= RunOffset;
  if (RunEnd > RecordSize) {
    goto Done;
  }
  {
    UINT8  Runlist[4096];

    CopyMem (Runlist, Buffer + RunOffset, RunEnd);
    RunPosition = 0;
    CurrentLcn = 0;
    LogicalOffset = 0;
    ZeroMem (&Search, sizeof (Search));
    while ((RunPosition < RunEnd) && (Runlist[RunPosition] != 0) &&
           (LogicalOffset < ValidBytes) &&
           (LogicalOffset < EVB_NTFS_MAX_MFT_BYTES))
    {
      LengthBytes = Runlist[RunPosition] & 0x0F;
      OffsetBytes = Runlist[RunPosition] >> 4;
      if ((LengthBytes == 0) || (LengthBytes > 8) || (OffsetBytes == 0) ||
          (OffsetBytes > 8) ||
          (RunPosition + 1 + LengthBytes + OffsetBytes > RunEnd))
      {
        break;
      }

      RunClusters = 0;
      for (Index = 0; Index < LengthBytes; ++Index) {
        RunClusters |= (UINT64)Runlist[RunPosition + 1 + Index] << (8 * Index);
      }
      DeltaBits = 0;
      for (Index = 0; Index < OffsetBytes; ++Index) {
        DeltaBits |= (UINT64)Runlist[RunPosition + 1 + LengthBytes + Index] << (8 * Index);
      }
      if ((OffsetBytes < 8) &&
          ((Runlist[RunPosition + LengthBytes + OffsetBytes] & 0x80) != 0))
      {
        DeltaBits |= MAX_UINT64 << (8 * OffsetBytes);
      }
      RunDelta = (INT64)DeltaBits;
      RunPosition += 1 + LengthBytes + OffsetBytes;
      if (((RunDelta >= 0) && (CurrentLcn > MAX_INT64 - RunDelta)) ||
          ((RunDelta < 0) &&
           ((UINT64)CurrentLcn < (~(UINT64)RunDelta + 1U))))
      {
        break;
      }
      CurrentLcn += RunDelta;
      if ((RunClusters == 0) || (CurrentLcn < 0) ||
          (RunClusters > MAX_UINT64 / ClusterSize) ||
          ((UINT64)CurrentLcn > BlockIo->Media->LastBlock / (ClusterSize / BlockSize)) ||
          (RunClusters > (BlockIo->Media->LastBlock / (ClusterSize / BlockSize)) -
                         (UINT64)CurrentLcn))
      {
        break;
      }

      BytesInRun = RunClusters * ClusterSize;
      for (RunCursor = 0; (RunCursor < BytesInRun) &&
           (LogicalOffset < ValidBytes) &&
           (LogicalOffset < EVB_NTFS_MAX_MFT_BYTES); RunCursor += ReadSize)
      {
        ReadSize = (UINTN)MIN ((UINT64)EVB_NTFS_BUFFER_SIZE, BytesInRun - RunCursor);
        Status = BlockIo->ReadBlocks (
                            BlockIo,
                            BlockIo->Media->MediaId,
                            (UINT64)CurrentLcn * (ClusterSize / BlockSize) +
                            RunCursor / BlockSize,
                            ReadSize,
                            Buffer
                            );
        if (EFI_ERROR (Status)) {
          goto Done;
        }

        for (RecordOffset = 0; RecordOffset + RecordSize <= ReadSize &&
             LogicalOffset + RecordOffset < ValidBytes; RecordOffset += RecordSize)
        {
          EvbInspectFileRecord (
            Buffer + RecordOffset,
            RecordSize,
            (LogicalOffset + RecordOffset) / RecordSize,
            &Search
            );
        }
        LogicalOffset += ReadSize;
        if (EvbSearchComplete (&Search)) {
          Found = TRUE;
          goto Done;
        }
      }
    }
  }

Done:
  FreeAlignedPages (Buffer, EFI_SIZE_TO_PAGES (EVB_NTFS_BUFFER_SIZE));
  return Found;
}

BOOLEAN
EvbNtfsQuietMarkerExists (
  VOID
  )
{
  EFI_STATUS             Status;
  EFI_HANDLE             *Handles;
  UINTN                  HandleCount;
  UINTN                  Index;
  EFI_BLOCK_IO_PROTOCOL  *BlockIo;
  BOOLEAN                Found;

  Handles = NULL;
  HandleCount = 0;
  Found = FALSE;
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiBlockIoProtocolGuid,
                  NULL,
                  &HandleCount,
                  &Handles
                  );
  if (EFI_ERROR (Status)) {
    return FALSE;
  }

  for (Index = 0; Index < HandleCount; ++Index) {
    Status = gBS->HandleProtocol (
                    Handles[Index],
                    &gEfiBlockIoProtocolGuid,
                    (VOID **)&BlockIo
                    );
    if (!EFI_ERROR (Status) && EvbScanNtfsVolume (BlockIo)) {
      Found = TRUE;
      break;
    }
  }

  FreePool (Handles);
  return Found;
}
