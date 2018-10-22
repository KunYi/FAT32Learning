// FAT32Parser.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

#define IMGNAME ("CF128M.img")
#pragma pack(push)
#pragma pack(1)
typedef struct {
	UCHAR   STATE;
	UCHAR   HEAD_S;
	USHORT  CLU_S;
	UCHAR   FS;
	UCHAR   HEAD_E;
	USHORT  CLU_E;
	ULONG32 SECTOR_RS;
	ULONG32 TOTAL_SECTOR;
} PARTION_TABLE;

typedef struct BIOSPB_TAG
{                            //  Offset    Size
	UCHAR  JMP[3];           //  0         3
	UCHAR  VersionId[8];     //  3         8
	USHORT BytesPerSect;     //  11        2
	UCHAR  SectsPerClust;    //  13        1
	USHORT RsvdSects;        //  14        2
	UCHAR  NumFATs;          //  16        1
	USHORT NumRootEntries;   //  17        2
	USHORT SectsPerPart;     //  19        2
	UCHAR  MediaDesc;        //  21        1
	USHORT SectsPerFAT;      //  22        2
	USHORT SectsPerTrack;    //  24        2
	USHORT NumHeads;         //  26        2
	USHORT NumHiddenSectL;   //  28        4
	USHORT NumHiddenSectH;
	USHORT TotalSectorsL;    //  32        4
	USHORT TotalSectorsH;
	USHORT SectsPerFATL;     //  36        4
	USHORT SectsPerFATH;
	USHORT Flags;            //  40        2
	USHORT FSVersion;        //  42        2
	USHORT RootClusterL;     //  44        4
	USHORT RootClusterH;
	USHORT FSInfo;           //  48        2
	USHORT BackupBootSector; //  50        2
	UCHAR  Reserved[12];     //  52        12
	UCHAR  DriveId;          //  64        1
	UCHAR  Reserved1;        //  65        1
	UCHAR  BootSig;          //  66        1
	USHORT VolumeIdL;        //  67        4
	USHORT VolumeIdH;
	UCHAR  Label[11];        //  71        11
	UCHAR  TypeFAT[8];       //  82        8
} BIOSPB, *PBIOSPB;

typedef struct
{
	UCHAR  FileName[8];
	UCHAR  FileExt[3];
	UCHAR  FATTr;
	ULONG  CreateTime;

	USHORT CreateDate;
	USHORT LAccessDate;
	USHORT FirstClustH;
	USHORT LModTime;
	USHORT LModDate;
	USHORT FirstClustL;
	ULONG  FileSize;
} DIRENTRY, *PDIRENTRY;

typedef struct _LongFileName
{
	UCHAR  sequenceNo;           // Sequence number, 0xe5 for
								 // deleted entry
	USHORT Name1_5[5];    // file name part
	UCHAR  fileattribute;        // File attibute
	UCHAR  reserved1;
	UCHAR  checksum;             // Checksum
	USHORT Name6_11[6];    // WORD reserved_2;
	USHORT reserved2;
	USHORT Name12_13[2];
} LFNENTRY, *PLFN_ENTRY;

typedef struct
{
	UCHAR  Order;         // Order of this entry for long entries associated with the file.
	USHORT Name1[5];      // Characters 1-5 of long name component.
	UCHAR  Attributes;    // ATTR_LONG_NAME
	UCHAR  Type;
	UCHAR  Checksum;
	USHORT Name2[6];      // Characters 6-11 of this long name component.
	USHORT MustZero;      // This is meaningless and must be zero.
	USHORT Name3[2];      // Characters 12-13 of this long name component.
} DIRENTRY32, *PDIRENTRY32;

enum ATTRIBUTE_DIR  {
	READONLY = 1,
	HIDDEN = 2,
	SYSTEM = 4,
	LABEL = 8,
	DIRECTORY = 16,
	ARCHIVE = 32,
	ATTR_LFN = READONLY + HIDDEN + SYSTEM + LABEL, 
	ATTR_MASK = READONLY + HIDDEN + SYSTEM + LABEL + DIRECTORY + ARCHIVE
};

FILE *img = NULL;
ULONG32 DataStartLBA = 0;
PBIOSPB pBPB = NULL;
UCHAR SECTOR_CACHE_START[0x4000];
UCHAR READ_BUFFER_START[0x4000];

#define SECTOR_SIZE (512)

#pragma pack(pop)
struct
{
	ULONG       FATLBA;             // LBA start of FAT (first)
	ULONG       RootDirLBA;         // LBA start of root directory
	ULONG       DataStartLBA;       // LBA start of data area
} g_FATParms;

BOOL IsDataCluster(ULONG Cluster)
{
	Cluster &= 0x0fffffff;
	if (Cluster >= 0x00000002 && Cluster <= 0x0fffffef)
		return(TRUE);

	return(FALSE);
}


BOOL IsRsvdCluster(ULONG Cluster)
{
	Cluster &= 0x0fffffff;
	if (Cluster >= 0x0ffffff0 && Cluster <= 0x0ffffff6)
		return(TRUE);

	return(FALSE);
}


BOOL IsEOFCluster(ULONG Cluster)
{
	Cluster &= 0x0fffffff;
	if (Cluster >= 0x0ffffff8 && Cluster <= 0x0fffffff)
		return(TRUE);

	return(FALSE);
}


BOOL IsBadCluster(ULONG Cluster)
{
	Cluster &= 0x0fffffff;
	if (Cluster == 0x0ffffff7)
		return(TRUE);

	return(FALSE);
}

ULONG Cluster2LBA(ULONG Cluster)
{
	return(g_FATParms.DataStartLBA + (Cluster - 2) * pBPB->SectsPerClust);
}

ULONG LBA2Cluster(ULONG LBA)
{
	return(((LBA - g_FATParms.DataStartLBA) / pBPB->SectsPerClust) + 2);
}

BOOLEAN ReadSectors(UCHAR DriveID,
	ULONG LBA,
	USHORT nSectors,
	PUCHAR pBuffer,
	size_t buffersize)
{
	if (img == NULL)
		return FALSE;
	DriveID = DriveID;

	if (fseek(img, LBA * SECTOR_SIZE, SEEK_SET) != 0)
		return FALSE;

	ULONG32 value = fread_s(pBuffer, buffersize, SECTOR_SIZE, nSectors, img);
	if (value != nSectors)
		return FALSE;
	return TRUE;
}

ULONG GetNextCluster(ULONG Cluster)
{
	ULONG Sector = 0;
	ULONG ByteOffset = 0;
	PUCHAR pSectorCache = (PUCHAR)SECTOR_CACHE_START;   // Sector cache is where the sector used to read the FAT cluster chains lives.
	static ULONG CurrentSector = 0;
	ULONG NextCluster = 0;

	// If we're passed an EOF cluster, return it.
	//
	if (IsEOFCluster(Cluster))
		return(Cluster);

	// Is caller giving us a valid cluster?
	//
	if (!IsDataCluster(Cluster))
	{
		printf("Bad cluster number\n");
		return(0);  // 0 isn't a valid cluster number (at least for our purposes).
	}

	// Compute sector where our FAT entry lives.
	//
	Sector = Cluster * sizeof(ULONG);
	ByteOffset = Sector & (pBPB->BytesPerSect - 1);
	Sector /= pBPB->BytesPerSect;
	Sector += g_FATParms.FATLBA;

	// If the sector we're interested in isn't in our cache, get it.
	//
	if (CurrentSector != Sector)
	{
		if (!ReadSectors(pBPB->DriveId, Sector, 1, pSectorCache, sizeof(SECTOR_CACHE_START)))
		{
			//          TODO: Only a message?
			//          SERPRINT("GetNextCluster - unable to read sector.\r\n");
		}

		CurrentSector = Sector;
	}

	// Locate next cluster number...
	//
	NextCluster = *(PULONG)(pSectorCache + ByteOffset);

	//SERPRINT("GetNextCluster - cluster=0x%x  next cluster=0x%x.\r\n", Cluster, NextCluster);

	// Return the next cluster value.
	//
	return(NextCluster);
}

ULONG NextSector(ULONG Sector)
{
	ULONG Cluster = LBA2Cluster(Sector++);
	ULONG NewCluster = LBA2Cluster(Sector);
	//
	// Just checking to see if we've used all the sectors in the current cluster.
	//
	if (Cluster != NewCluster) {
		NewCluster = GetNextCluster(Cluster);
		if (IsDataCluster(NewCluster) && Cluster != NewCluster)
		{
			return Cluster2LBA(NewCluster);
		}
		else {
			printf("NextSector() - NewCluster %d\n", NewCluster);
			Sector = 0;
		}
	}
	return Sector;
}

static CHAR UNI2STR(USHORT code)
{
	if (code < 128)
		return (CHAR)code;
	return 0;
}

static void FillFileNameBuff(CHAR* buf, PDIRENTRY32 pDirE32)
{
	USHORT i = 0;
	for (i = 0; i < 5; i++)
		buf[i] = UNI2STR(pDirE32->Name1[i]);
	for (i = 0; i < 6; i++)
		buf[i + 5] = UNI2STR(pDirE32->Name2[i]);
	for (i = 0; i < 2; i++)
		buf[i + 11] = UNI2STR(pDirE32->Name3[i]);
}

static ULONG FindDocsDir(void)
{
	USHORT i;
	ULONG DirLBA;
	PUCHAR Sector = READ_BUFFER_START;
	PDIRENTRY pDirEntry = NULL;

	for (DirLBA = g_FATParms.RootDirLBA; DirLBA; DirLBA = NextSector(DirLBA))
	{
		// Read a sector from the root directory.
		if (!ReadSectors(pBPB->DriveId, DirLBA, 1, Sector, sizeof(READ_BUFFER_START)))
		{
			printf("Couldn't read root directory sector (LBA=0x%x)\n", DirLBA);
			return 0UL;
		}

		for (pDirEntry = (PDIRENTRY)Sector, i = 0; i < (pBPB->BytesPerSect / sizeof(DIRENTRY)); i++, pDirEntry++)
		{
			if (pDirEntry->FileName[0] == 0)
				return 0UL;

			if ((pDirEntry->FATTr  & ATTR_MASK) == ATTR_LFN)
			{
				PDIRENTRY32  lfn = (PDIRENTRY32)pDirEntry;
				CHAR BUFF[27] = { 0 };
				UCHAR sno = lfn->Order ^ 0x40;

				if (sno > 20)
					continue;

				if (sno == 2)
				{
					FillFileNameBuff(BUFF + 13, lfn++);
					FillFileNameBuff(BUFF, lfn);
				}

				pDirEntry += sno;
				i += sno;

				if ((sno == 2) && (strcmp("Documents and Settings", (const char*)BUFF) == 0))
				{
					printf("FileName:%s\n", BUFF);
					ULONG Subdir = pDirEntry->FirstClustL + (pDirEntry->FirstClustH << 16);
					return Cluster2LBA(Subdir);
				}
			}
		}
	}
	return 0UL;
}

static ULONG FindDefaultVol(ULONG DirLBA, PDIRENTRY pEntry)
{
	USHORT i;
	PUCHAR Sector = READ_BUFFER_START;
	PDIRENTRY pDirEntry = NULL;

	if (pEntry == NULL)
		return 0UL;

	for (; DirLBA; DirLBA = NextSector(DirLBA))
	{
		// Read a sector from the root directory.
		if (!ReadSectors(pBPB->DriveId, DirLBA, 1, Sector, sizeof(READ_BUFFER_START)))
		{
			printf("Couldn't read root directory sector (LBA=0x%x)\n", DirLBA);
			return 0UL;
		}

		for (pDirEntry = (PDIRENTRY)Sector, i = 0; i < (pBPB->BytesPerSect / sizeof(DIRENTRY)); i++, pDirEntry++)
		{
			if (pDirEntry->FileName[0] == 0)
				return 0UL;

			if ((pDirEntry->FATTr  & ATTR_MASK) == ATTR_LFN)
			{
				PDIRENTRY32  lfn = (PDIRENTRY32)pDirEntry;
				CHAR BUFF[27] = { 0 };
				UCHAR sno = lfn->Order ^ 0x40;

				if (sno > 20)
					continue;

				if (sno == 1)
				{
					FillFileNameBuff(BUFF, lfn);
				}

				pDirEntry += sno;
				i += sno;

				if ((sno == 1) && (strcmp("default.vol", (const char*)BUFF) == 0))
				{
					memcpy(pEntry, pDirEntry, sizeof(DIRENTRY));
					return pDirEntry->FirstClustL + (pDirEntry->FirstClustH << 16);
				}
			}
			if (memcmp("DEFAULT VOL", pDirEntry->FileName, 11) == 0)
			{
				memcpy(pEntry, pDirEntry, sizeof(DIRENTRY));
				return pDirEntry->FirstClustL + (pDirEntry->FirstClustH << 16);
			}
		}
	}
	return 0UL;
}

static void EnumFileCluster(PDIRENTRY pDirEntry, ULONG ClusterSize)
{
	ULONG FCluster = (pDirEntry->FirstClustH << 16) + pDirEntry->FirstClustL;
	ULONG FileSize = pDirEntry->FileSize;
	printf(" default.vol : Cluster:0x%X, Size:%d\r\n", FCluster, pDirEntry->FileSize);
	ULONG Sector;
	ULONG ByteOffset;
	ULONG NumOfCluster = (FileSize / ClusterSize);
	NumOfCluster += (FileSize % ClusterSize) ? 1 : 0;
	UCHAR FATSector[512];
	ULONG NextCluster = FCluster;

	while(NumOfCluster--)
	{
		if (!IsDataCluster(NextCluster))
		{
			printf("Cluster chain broken: 0x%x, Sector:0x%x, ByteOffset:0x%x\r\n",
				NextCluster, Sector, ByteOffset);
			return;
		}
		Sector = NextCluster * sizeof(ULONG);
		ByteOffset = Sector & (pBPB->BytesPerSect - 1);
		Sector /= pBPB->BytesPerSect;
		Sector += g_FATParms.FATLBA;
		printf("    -- FAT Location: Sector:0x%X, ByteOffset:0x%X, Num of Cluster:%d\r\n",
			Sector, ByteOffset, NumOfCluster);
		ReadSectors(0x80, Sector, 1, FATSector, sizeof(FATSector));
		NextCluster = *((PULONG)(FATSector + ByteOffset));
		printf("    --  NextCluster: 0x%X\r\n", NextCluster);
		if (IsEOFCluster(NextCluster))
			return;
	}
}

int main()
{
	UCHAR MBR[512];
	ULONG BPBLBA = 0;
	assert(sizeof(LFNENTRY) == sizeof(DIRENTRY));
		
	fopen_s(&img, IMGNAME, "rb");
	ZeroMemory(MBR, sizeof(MBR));
	fread_s(MBR, sizeof(MBR), sizeof(UCHAR), sizeof(MBR), img);
	PARTION_TABLE *ptrPartiton = (PARTION_TABLE*)&MBR[0x1BE];
	BPBLBA = DataStartLBA = ptrPartiton->SECTOR_RS;

	fseek(img, DataStartLBA*SECTOR_SIZE, SEEK_SET);

	UCHAR FAT32[512];
	ZeroMemory(FAT32, sizeof(FAT32));
	fread_s(FAT32, sizeof(FAT32), sizeof(UCHAR), sizeof(FAT32), img);
	pBPB = (BIOSPB *)FAT32;
	ULONG32 Cluster = pBPB->RootClusterL + (pBPB->RootClusterH << 16);
	// Compute LBA for various disk regions.
	g_FATParms.DataStartLBA = DataStartLBA;
	g_FATParms.RootDirLBA = Cluster2LBA(Cluster);
	ULONG32 SectsPerFAT = pBPB->SectsPerFATL + (pBPB->SectsPerFATH << 16);
	ULONG32 HiddendSects = pBPB->NumHiddenSectL + (pBPB->NumHiddenSectH << 16);
	ULONG32 ClusterSize = (pBPB->SectsPerClust * pBPB->BytesPerSect);
	g_FATParms.RootDirLBA = DataStartLBA + (pBPB->NumFATs * SectsPerFAT) + pBPB->RsvdSects;
	g_FATParms.FATLBA = DataStartLBA + pBPB->RsvdSects;

	UCHAR FATType[9];
	memcpy_s(FATType, sizeof(FATType), pBPB->TypeFAT, 8);
	FATType[8] = '\0';
	if (memcmp(FATType, "FAT32", 5))
	{
		printf("Unknown file system: '%s'\n", FATType);
		goto exit;
	}
	printf("\r\nDrive Info:\r\n");
	printf(" - Drive ID ................... 0x%x\r\n", pBPB->DriveId);
	printf(" - Sector Size ...............  0x%x\r\n\r\n", pBPB->BytesPerSect);
	printf(" - Heads ...................... 0x%x\r\n", pBPB->NumHeads);
	printf(" - Number of Sectors Per Track  0x%x\r\n", pBPB->SectsPerTrack);

	printf("FAT Info:\r\n");
	printf(" - FAT Type ................... %s\r\n", FATType);
	printf(" - DOS BPB Sector LBA ......... 0x%x\r\n", BPBLBA);
	printf(" - Cluster Size ............... 0x%x\r\n", ClusterSize);
	printf(" - Number of FATs ............. 0x%x\r\n", pBPB->NumFATs);
	printf(" - Number of Sectors Per FAT .. 0x%x\r\n", SectsPerFAT);
	printf(" - Number of Hidden Sectors ... 0x%x\r\n", HiddendSects);
	printf(" - Number of Reserved Sectors . 0x%x\r\n\r\n", pBPB->RsvdSects);
	printf(" - FS Info  ................... 0x%x\r\n", (pBPB->FSInfo));
	printf(" - FS Sector .................. 0x%x\r\n", BPBLBA + (pBPB->FSInfo));
	printf(" - Root dir location (LBA) .... 0x%x\r\n", g_FATParms.RootDirLBA);
	printf(" - FAT location (LBA) ......... 0x%x\r\n", g_FATParms.FATLBA);
	g_FATParms.DataStartLBA = BPBLBA + pBPB->RsvdSects + (pBPB->NumFATs * SectsPerFAT);
	printf(" - Data location (LBA) ........ 0x%x\r\n\r\n", g_FATParms.DataStartLBA);
	printf(" - FAT RootDir location (LBA) . 0x%x\r\n\r\n", g_FATParms.RootDirLBA);

	ULONG DirLBA = FindDocsDir();
	DIRENTRY dirEntry;
	ULONG FCluster = FindDefaultVol(DirLBA, &dirEntry);
	if (IsDataCluster(FCluster)) {
		EnumFileCluster(&dirEntry, ClusterSize);
	}
exit:
	fclose(img);
    return 0;
}
