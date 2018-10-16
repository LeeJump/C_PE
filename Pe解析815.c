// study.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "string.h"
#include "stdio.h" 
#include "stdlib.h"
#define False 0
#define True 1
#define OK 1
#define Error 0
#define BYTE unsigned char
#define WORD unsigned short
#define DWORD unsigned int
#define PBYTE  char*
#define PWORD  short* 
#define PDWORD  int*
#define MZ_SIGNATURE 0x5A4D
#define PE_SIGNATURE 0x00004550
#define IMAGE_SIZEOF_SHORT_NAME 8
typedef struct _IMAGE_DOS_HEADERS{
	WORD e_magic;		//0x00
	WORD e_cblp;		//0x02
	WORD e_cp;			//0x04
	WORD e_crlc;		//0x06
	WORD e_cparhdr;		//0x08
	WORD e_minalloc;	//0x0A
	WORD e_maxalloc;	//0x0C
	WORD e_ss;			//0x0E
	WORD e_sp;			//0x10
	WORD e_csum;		//0x12
	WORD e_ip;			//0x14	
	WORD e_cs;			//0x16
	WORD e_lfarlc;		//0x18
	WORD e_ovno;		//0x1a
	WORD e_res[4];		//0x1c
	WORD e_oemid;		//0x24
	WORD e_oeminfo;		//0x26
	WORD e_res2[10];	//0x28
	DWORD e_lfanew;		//0x3C
}IMAGE_DOS_HEADERS,* PIMAGE_DOS_HEADERS;

typedef struct IMAGE_DATA_DIRECTORY{
	DWORD VirtualAddress;	//0x00
	DWORD Size;				//0x04
}IMAGE_DATA_DIRECTORY,PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_EXPORT_DIRECTORY{
	DWORD Characteristics;		//0x00
	DWORD TimeDateStamp;		//0x04
	WORD MajorVersion;			//0x08
	WORD MinorVersion;			//0x10
	DWORD Name;					//0x0C
	DWORD Base;					//0x10
	DWORD NumberOfFunctions;	//0x14
	DWORD NumberOfNames;		//0x18
	DWORD AddressOfFunctions;	//0x1c
	DWORD AddressOfNames;		//0x20
	DWORD AddressOfNameOrdinals;//0x24

}IMAGE_EXPORT_DIRECTORY,*PIMAGE_EXPORT_DIRECTORY;

typedef struct _IMAGE_IMPORT_BY_NAME{
	WORD Hint;
	BYTE Name[1];
}IMAGE_IMPORT_BY_NAME,* PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA{
	union{
		PBYTE ForwarderString;
		PDWORD Function;
		DWORD Ordinal;
		DWORD AddressOfData;
	}ul;
}IMAGE_THUNK_DATA,* PIMAGE_THUNK_DATA;

typedef struct _IMAGE_IMPORT_DESCRIPTOR{
	union{
		DWORD Characteristics;
		DWORD OriginalFirstThunk;
	}u;
	DWORD TimaDataStamp;
	DWORD ForwarderChain;
	DWORD Name;
	DWORD FirstThunk;
}IMAGE_IMPORT_DESCRIPTOR,*PIMAGE_IMPORT_DESCRIPTOR;


typedef struct _IMAGE_BOUND_FOWARDER_REF{
	DWORD TimeDataStamp;
	WORD  OffsetModuleName;
	WORD  Reserved;
}IMAGE_BOUND_FORWARDER_REF,*PIMAGE_BOUND_FORWARDER_REF;

typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR{
	DWORD TimeDataStamp;
	WORD  OffsetModuleName;
	WORD  NumberOfModuleForwarderRefs;
}IMAGE_BOUND_IMPORT_FORWARDER_REF,*PIMAGE_BOUND_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_BASE_RELOCATION{
	DWORD VitualAddress;
	DWORD SizeOfBlock;
}IMAGE_BASE_RELOCATION,*PIMAGE_BASE_RELOCATION;

typedef struct _IMAGE_FILE_HEADERS{
	WORD Machine;				//0x00
	WORD NumberOfSections;		//0x02
	DWORD TimeDateStamp;		//0x04
	DWORD PointerToSymbolTable; //0x08
	DWORD NumberOfSymbols;		//0x0C
	WORD SizeOfOptionalHeaders; //0x10
	WORD Characteristics;		//0x12
}IMAGE_FILE_HEADERS,* PIMAGE_FILE_HEADERS;

typedef struct _IMAGE_OPTIONAL_HEADERS{
	WORD Magic;							//0x00		
	BYTE MajorLinkerVersion;			//0x02
	BYTE MinorLinkerVersion;			//0x03
	DWORD SizeOfCode;					//0x04
	DWORD SizeOfInitializedData;		//0x08
	DWORD SizeOfUninitializedData;		//0x0C
	DWORD AddressOfEntryPoint;			//0x10
	DWORD BaseOfCode;					//0x14
	DWORD BaseOfData;					//0x18
	DWORD ImageBase;					//0x1C
	DWORD SectionAlignment;				//0x20
	DWORD FileAlignment;				//0x24
	WORD MajorOperatingSystemVersion;	//0x28
	WORD MinorOperatingSystemVersion;	//0x2a
	WORD MajorImageVersion;				//0x2c
	WORD MinorImageVersion;				//0x2e
	WORD MajorSubsystemVersion;			//0x30
	WORD MinorSubsystemVersion;			//0x32
	DWORD Win32VersionValue;			//0x34
	DWORD SizeOfImage;					//0x38
	DWORD SizeOfHeaders;				//0x3c
	DWORD CheckSum;						//0x40
	WORD Subsystem;						//0x44
	WORD DLLCharacteristics;			//0x46
	DWORD SizeOfStackReserve;			//0x48
	DWORD SizeOfStackCommit;			//0x4c
	DWORD SizeOfHeapReserve;			//0x50
	DWORD SizeOfHeapCommit;				//0x54
	DWORD LoaderFlags;					//0x58
	DWORD NumberOfRvaAndSizes;			//0x5c
	IMAGE_DATA_DIRECTORY DataDirectory[16];	//0x60

}IMAGE_OPTIONAL_HEADERS,* PIMAGE_OPTIONAL_HEADERS;

typedef struct _IMAGE_NT_HEADERS{
	DWORD Signature;
	IMAGE_FILE_HEADERS FileHeaders;
	IMAGE_OPTIONAL_HEADERS OptionalHeaders;
}IMAGE_NT_HEADERS,* PIMAGE_NT_HEADERS;

typedef struct _IMAGE_SECTION_HEADERS{
	BYTE Name[IMAGE_SIZEOF_SHORT_NAME];
	union{
		DWORD PhysicalAddress;
		DWORD VirtualSize;
	}Misc;
	DWORD VirtualAddress;
	DWORD SizeOfRawData;
	DWORD PointerToRawData;
	DWORD PointerToRelocations;
	DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;			
    WORD  NumberOfLinenumbers;	
	DWORD Characteristics;

}IMAGE_SECTION_HEADERS,* PIMAGE_SECTION_HEADERS;

DWORD getFileSize(FILE* fp)
{//return FileSize
	
	int size;
	if(fp)
	{
		fseek(fp,0L,2);
		size=ftell(fp);
		//remeber to rewind file index pointer.
		rewind(fp);
		return size;
	}
	else
		return Error;
}
BYTE FileToFileBuffer(FILE* fp,PBYTE* buffer,DWORD* size)
{//return Buffer
	if(fp)
	{
		*size=getFileSize(fp);
		*buffer=(PBYTE)malloc(*size);
		memset(*buffer,0,*size);
		if(*buffer)
		{
			memset(*buffer,0,*size);
			fread(*buffer,1,*size,fp);
			return OK;
		}
		printf("malloc error!\n");
		return Error;

	}
	return Error;
	
}
BYTE BufferToFile(PBYTE stream,DWORD size,PBYTE path)
{
	FILE* fp=fopen(path,"wb");
	if(fp && stream)
	{
		fwrite(stream,1,size,fp);
		fclose(fp);				//save and close
		return 1;
	}
	else
	{
		printf("create file error\n");
		return Error;
	}
}
BYTE BufferPEInit(PBYTE buffer,PIMAGE_DOS_HEADERS* pDosHeaders,PIMAGE_NT_HEADERS* pNTHeaders,PIMAGE_SECTION_HEADERS* pSectionHeaders)
{
	PIMAGE_DOS_HEADERS pDosH;
	PIMAGE_NT_HEADERS pNTH;
	PIMAGE_SECTION_HEADERS pSecH;
	int i;
	char name[9]={0};
	pDosH=(PIMAGE_DOS_HEADERS)buffer;
	*pDosHeaders=pDosH; //para 2
	if(pDosH->e_magic==MZ_SIGNATURE)
		{	
			printf("***********DosHeader**********\n");
			printf("find MZ sign in Dos Header !..\n");
			printf("pDosHeaders->e_lfanew : 0x%x\n",pDosH->e_lfanew);
			printf("\n");
			pNTH=(PIMAGE_NT_HEADERS)((PBYTE)pDosH+pDosH->e_lfanew);
			*pNTHeaders=pNTH; //para 3
			if(pNTH->Signature==PE_SIGNATURE)
			{
				
				printf("***********NTHeader**********\n");
				printf("fine PE sign in NT Header..\n");
				printf("\n");
				printf("***********FileHeader**********\n");
				printf("FileHeaders.NumberOfSections : 0x%x\n",pNTH->FileHeaders.NumberOfSections);
				printf("FileHeaders.SizeOfOptionalHeaders : 0x%x\n",pNTH->FileHeaders.SizeOfOptionalHeaders);
				printf("FileHeaders.Characteristics : 0x%x\n",pNTH->FileHeaders.Characteristics);
				printf("\n");
				printf("***********OpthionalHeader**********\n");
				printf("OptionalHeaders.Magic : 0x%x\n",pNTH->OptionalHeaders.Magic);
				printf("OptionalHeaders.SizeOfCode : 0x%x\n",pNTH->OptionalHeaders.SizeOfCode);
				printf("OptionalHeaders.AddressOfEntryPoint  : 0x%x\n",pNTH->OptionalHeaders.AddressOfEntryPoint);
				printf("OptionalHeaders.ImageBase   : 0x%x\n",pNTH->OptionalHeaders.ImageBase );
				printf("OptionalHeaders.SectionAlignment   : 0x%x\n",pNTH->OptionalHeaders.SectionAlignment  );
				printf("OptionalHeaders.FileAlignment   : 0x%x\n",pNTH->OptionalHeaders.FileAlignment );
				printf("OptionalHeaders.SizeOfImage    : 0x%x\n",pNTH->OptionalHeaders.SizeOfImage  );
				printf("OptionalHeaders.SizeOfHeaders    : 0x%x\n",pNTH->OptionalHeaders.SizeOfHeaders  );
				printf("\n");
				printf("***********OpthionalHeader**********\n");
				pSecH=(PIMAGE_SECTION_HEADERS)((PBYTE)(&(pNTH->FileHeaders)+1)+pNTH->FileHeaders.SizeOfOptionalHeaders);
				*pSectionHeaders=pSecH;//para 4
				for(i=0;i<pNTH->FileHeaders.NumberOfSections;i++)
				{
					printf("num : %d(from 0 to N)\n",i);
					memcpy(name,(pSecH+i)->Name,8);
					printf("name: %s\n",name);
					printf("Misc : 0x%x\n",(pSecH+i)->Misc);
					printf("VirtualAddress : 0x%x\n",(pSecH+i)->VirtualAddress);
					printf("SizeOfRawData : 0x%x\n",(pSecH+i)->SizeOfRawData);
					printf("PointerToRawData : 0x%x\n",(pSecH+i)->PointerToRawData);
					printf("Characteristics : 0x%x\n",(pSecH+i)->Characteristics);
					printf("----------------------------------\n");
				}
				
				
			}
			else
			{
				printf("no PE SIGN!...\n");
				return Error;
			}
			printf("***********PeCheck Finished!**********\n");
			printf("remeber to free buffer!\n");
			printf("-----------------------------------------------\n");
			printf("\n");
			return True;
		}
		else 
		{
			*pDosHeaders=NULL;
			*pNTHeaders=NULL;
			printf("no mz sign!..\n");
			return Error;
		}
}

DWORD RVA_To_FOA(DWORD rva,PIMAGE_SECTION_HEADERS pSectionHeaders,DWORD numOfSec)
{
	DWORD i;
	DWORD foa,sRVA,sFOA,sVS;
	for(i=0;i<numOfSec;i++)
	{
		sRVA=(pSectionHeaders+i)->VirtualAddress;
		sFOA=(pSectionHeaders+i)->PointerToRawData;
		sVS=(pSectionHeaders+i)->Misc.VirtualSize;
		if(rva>=sRVA && rva<=(sRVA+sVS))
		{
			foa=rva-sRVA+sFOA;
			printf(" rva in No.%d(from 0 to n) Section..\n",i);
			printf("RVA -> FOA : 0x%x\n",foa);
			printf("RVA -> FOA Finished..!\n");
			return foa;
		}
			
	}
	printf("RVA -> FOA error!..\n");
	system("pause");
	return Error;
}
DWORD FOA_To_RVA(DWORD foa,PIMAGE_SECTION_HEADERS pSectionHeaders,DWORD numOfSec)
{
	DWORD i;
	DWORD sfoa,secSize,srva,rva;
	PIMAGE_SECTION_HEADERS pSec;

	for(i=0;i<numOfSec;i++)
	{
		pSec=pSectionHeaders+i;
		sfoa=pSec->PointerToRawData;
		srva=pSec->VirtualAddress;
		secSize=pSec->SizeOfRawData;
		if(foa>sfoa && foa< sfoa+secSize)
		{
			rva=foa-sfoa+srva;
			printf(" sva in No.%d(from 0 to n) Section..\n",i);
			printf("FOA -> RVA : 0x%x\n",rva);
			printf("FOA -> RVA Finished..!\n");
			return rva;
		}
	}
	printf("FOA -> RVA error!..\n");
	system("pause");
	return Error;
}

PBYTE RVA_To_FPtr(DWORD rva,PIMAGE_SECTION_HEADERS pSectionHeaders,DWORD numOfSec,PBYTE fileBuffer)
{
	DWORD i;
	DWORD foa,srva,diff,fPtr;
	PIMAGE_SECTION_HEADERS pSec;

	for(i=0;i<numOfSec;i++)
	{
		pSec=pSectionHeaders+i;
		srva=pSec->VirtualAddress;
		if(rva>srva && rva<srva+pSec->Misc.VirtualSize)
		{
			diff=rva-srva;
			foa=pSec->PointerToRawData+diff;
			fPtr=foa+(DWORD)fileBuffer;
		//	printf("FOA -> fPtr Finished, fPtr = 0x%x\n",fPtr);
			return (PBYTE)fPtr;
		}
	}
	printf("FOA -> fPtr Error..\n");
	system("pause");
	return Error;
}

int PrintExportDir(PBYTE fileBuffer)
{
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir=NULL;

	DWORD numOfFun,numOfName;
	DWORD numOfSec;

	DWORD foaExportDir;
	DWORD foaFunDir;
	DWORD foaNameDir;
	DWORD foaNameOrdDir;

	PDWORD pFunDir;
	PDWORD pNameDir;
	PWORD  pNameOrdDir;

	DWORD i;
	DWORD desNameAddr;

	if(BufferPEInit(fileBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
	{
		// 1, find exportDir RVA and RVA to FOA
		//  remeber all FOA are fiileOffset , have to + fileBuffer
		numOfSec=pNTHeaders->FileHeaders.NumberOfSections;

		foaExportDir=RVA_To_FOA(pNTHeaders->OptionalHeaders.DataDirectory[0].VirtualAddress,pSectionHeaders,numOfSec);
		// 2, FOA+FileBuffer
		pExportDir=(PIMAGE_EXPORT_DIRECTORY)(foaExportDir+(DWORD)fileBuffer);
		// 3, assign exportDir Info 
		numOfFun=pExportDir->NumberOfFunctions;
		numOfName=pExportDir->NumberOfNames;

		// 4, Assign and RVA TO FOA
		foaFunDir=RVA_To_FOA(pExportDir->AddressOfFunctions,pSectionHeaders,numOfSec);
		foaNameDir=RVA_To_FOA(pExportDir->AddressOfNames,pSectionHeaders,numOfSec);
		foaNameOrdDir=RVA_To_FOA(pExportDir->AddressOfNameOrdinals,pSectionHeaders,numOfSec);
		// 5, FOA+FileBuffer
		pFunDir=(PDWORD)(foaFunDir+(DWORD)fileBuffer);
		pNameDir=(PDWORD)(foaNameDir+(DWORD)fileBuffer);
		pNameOrdDir=(PWORD)(foaNameOrdDir+(DWORD)fileBuffer);


		// 5, print info

		printf("************ExportDir Info:***************\n");
		printf("Name : %s\n",pExportDir->Name+(DWORD)fileBuffer);
		printf("Base : 0x%x\n",pExportDir->Base);
		printf("NumberOfFunctions : 0x%x\n",numOfFun);
		printf("NumberOfNameFunctions : 0x%x\n",numOfName);
		printf("AddressOfFunctions : 0x%x\n",pExportDir->AddressOfFunctions);
		printf("AddressOfNameOrdinals : 0x%x\n",pExportDir->AddressOfNameOrdinals);
		printf("AddressOfNames : 0x%x\n",pExportDir->AddressOfNames);

		printf("*****FunDir*****\n");
		for(i=0;i<numOfFun;i++)
		{
			printf("0x%x\n",*(pFunDir+i));
		}
		printf("*****NameDir*****\n");
		for(i=0; i<numOfName;i++)
		{
			desNameAddr=RVA_To_FOA(*(pNameDir+i),pSectionHeaders,numOfSec)+(DWORD)fileBuffer;
			printf("%s\n",desNameAddr);
		}
		printf("*****NameOrdDir*****\n");
		for(i=0; i<numOfName;i++)
		{
			printf("0x%x\n",*(pNameOrdDir+i));
		}



		return OK;
	}
	else
	{
		printf("PE Init Error...!\n");
		system("pause");
		return Error;
	}
}
int PrintBaseRelocation(PBYTE fileBuffer)
{
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_BASE_RELOCATION pBaseRelc=NULL;

	DWORD numOfSec;
	DWORD foaBaseRelc;
	DWORD i,j;

	DWORD rvaBlockBase;
	DWORD blockSize;
	DWORD ct;
	PWORD pIndex;

	if(BufferPEInit(fileBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
	{
		// 1, rvaBaseRelc -> foa -> pBaseRelc
		numOfSec=pNTHeaders->FileHeaders.NumberOfSections;
		foaBaseRelc=RVA_To_FOA(pNTHeaders->OptionalHeaders.DataDirectory[5].VirtualAddress,pSectionHeaders,numOfSec);
		pBaseRelc=(PIMAGE_BASE_RELOCATION)(foaBaseRelc+(DWORD)fileBuffer);
		// 2,
		blockSize=0;
		for(i=0;;i++)
		{
			pBaseRelc=(PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelc+blockSize);
			rvaBlockBase=pBaseRelc->VitualAddress;
			blockSize=pBaseRelc->SizeOfBlock;
			ct=(blockSize-8)/2;
			if(!rvaBlockBase && !blockSize)
			{
				printf("**************end**************\n");
				break;
			}
			printf("**********No.%d block**********\n",i);
			printf("VitualAddress(rva): 0x%x\n",rvaBlockBase);
			printf("SizeOfBlock : 0x%x\n",blockSize);
			printf("_________index info___________");
			printf("ct : %d pieces.\n");

			pIndex=(PWORD)(pBaseRelc+1);
			for(j=0;j<ct;j++)
			{
				printf("index BaseOffsetAddress : 0x%x ,",*(pIndex+j) & 0x0FFF);
				printf("charectors: 0x%x .\n",(*(pIndex+j) & 0xF000) >>12);
			}
			
		}
		return OK;
		
		
	}
	else
	{
		printf("PE Init Error.\n");
		system("pause");
		return Error;
	}
}

DWORD PrintImportDescriptor(PBYTE fileBuffer)
{
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_IMPORT_DESCRIPTOR pImportDscp=NULL;

	PIMAGE_THUNK_DATA pOrgThunkData=NULL;
	PIMAGE_THUNK_DATA pThunkData=NULL;

	PIMAGE_IMPORT_BY_NAME pImportByName=NULL;

	DWORD numOfSec;

	DWORD rvaImportDscp,rvaDllName,rvaOrgThunkData,rvaThunkData;
	PBYTE pDllName;
	

	DWORD i,j;
	// 1, PeInit and find first importDescriptor
	if(BufferPEInit(fileBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
	{
		
		numOfSec=pNTHeaders->FileHeaders.NumberOfSections;
		rvaImportDscp=pNTHeaders->OptionalHeaders.DataDirectory[1].VirtualAddress;
		pImportDscp=(PIMAGE_IMPORT_DESCRIPTOR)RVA_To_FPtr(rvaImportDscp,pSectionHeaders,numOfSec,fileBuffer);
		
	// 2, iterate to print the importDescriptor
		for(i=0;;i++,pImportDscp+=1)
		{
			
			if(pImportDscp->u.OriginalFirstThunk==0 && pImportDscp->FirstThunk==0)
			{
				printf("************dll End************\n");
				break;
			}
			// (1) get Pname
			rvaDllName=pImportDscp->Name;
			pDllName=RVA_To_FPtr(rvaDllName,pSectionHeaders,numOfSec,fileBuffer);
			// (2) Print dll name 
			printf("************index: %d(from 0 to n)************\n",i);
			printf("************dll Name: %s************\n",pDllName);

			// (3) iterate the Original First Thunk
			rvaOrgThunkData=(DWORD)pImportDscp->u.OriginalFirstThunk;
			pOrgThunkData=(PIMAGE_THUNK_DATA)RVA_To_FPtr(rvaOrgThunkData,pSectionHeaders,numOfSec,fileBuffer);
			printf("****************** OriginalFirstThunk *******************\n");
			printf(" 0x%x-> 0x%x\n",pOrgThunkData,*pOrgThunkData);
			for(j=0;;j++,pOrgThunkData+=1)
			{
				if(pOrgThunkData->ul.AddressOfData==0)
				{
					printf("function count : %d\n",j);
					printf("****************** OriginalFirstThunk End *******************\n");
					break;
				}
				// (1) check if the Highest Position equal to 1
				if(pOrgThunkData->ul.Ordinal >> 31 ==1)
				{
					// is ordinal
					printf("function import By Ordinal : 0x %x \n",pOrgThunkData->ul.Ordinal & 0x7FFFFFFF);

				}
				else
				{
					// is ImportByNameRVA
					pImportByName=(PIMAGE_IMPORT_BY_NAME)RVA_To_FPtr((DWORD)pOrgThunkData->ul.AddressOfData,pSectionHeaders,numOfSec,fileBuffer);
					// don't need to 
					printf("Function import By Name : %s\n",pImportByName->Name);

				}
			}
		

			// (4) Iterate First Thunk
			rvaThunkData=pImportDscp->FirstThunk;
			pThunkData=(PIMAGE_THUNK_DATA)RVA_To_FPtr(rvaThunkData,pSectionHeaders,numOfSec,fileBuffer);
			printf(" 0x%x-> 0x%x\n",pThunkData,*pThunkData);
			printf("****************** FirstThunk *******************\n");
			for(j=0;;j++,pThunkData+=1)
			{
				
				if(pThunkData->ul.AddressOfData==0)
				{
					printf("function count : %d\n",j);
					printf("****************** FirstThunk End *******************\n");
					break;
				}
				// (1) check if the Highest Position equal to 1
				printf("Function import address : 0x%x\n",pThunkData->ul.AddressOfData);
				/*
				if(pThunkData->ul.Ordinal >> 31 ==1)
				{
					// is ordinal
					printf("function import By Ordinal : 0x %x \n",pThunkData->ul.Ordinal & 0x7FFFFFFF);

				}
				else
				{
					// is ImportByNameRVA
					pImportByName=(PIMAGE_IMPORT_BY_NAME)RVA_To_FPtr((DWORD)pThunkData->ul.AddressOfData,pSectionHeaders,numOfSec,fileBuffer);
				
					printf("Function import By Name : %s\n",pThunkData->ul.AddressOfData);

				}
				*/
			}

		}
		printf("Print Import Description Finnished..\n");
		system("pause");
		return OK;
	}
	else
	{
		printf("fileBuffer PE init Error..!\n");
		system("pause");
		return Error;
	}



}

DWORD PrintBoundImportDescriptor(PBYTE fileBuffer)
{
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_BOUND_IMPORT_DESCRIPTOR pBoundImpDescrpt=NULL;
	PIMAGE_BOUND_FORWARDER_REF pBoundRef=NULL; 

	PIMAGE_BOUND_IMPORT_DESCRIPTOR firstPBoundImpDescrpt;
	DWORD numOfSec,numOfRef;
	DWORD rvaBoundImpDescrpt;
	DWORD i,j;


	if(BufferPEInit(fileBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
	{
		numOfSec=pNTHeaders->FileHeaders.NumberOfSections;
		rvaBoundImpDescrpt=pNTHeaders->OptionalHeaders.DataDirectory[11].VirtualAddress;
		// check  rva  in headers or in the sections
		if(rvaBoundImpDescrpt<pSectionHeaders->PointerToRawData)
			pBoundImpDescrpt=(PIMAGE_BOUND_IMPORT_DESCRIPTOR)(rvaBoundImpDescrpt+(DWORD)fileBuffer);
			
		else
			pBoundImpDescrpt=(PIMAGE_BOUND_IMPORT_DESCRIPTOR)RVA_To_FPtr(rvaBoundImpDescrpt,pSectionHeaders,numOfSec,fileBuffer);
		firstPBoundImpDescrpt=pBoundImpDescrpt;
		// Iterate to print pBoundImpDescrpt
		for(i=0;;i++)
		{	
			// (1) print pBoundImpDescrpt
			if(pBoundImpDescrpt->TimeDataStamp==0 && pBoundImpDescrpt->OffsetModuleName==0)
			{
				printf("**********************BoundImportDescriptor End*************************\n");
				break;
			}

			numOfRef=pBoundImpDescrpt->NumberOfModuleForwarderRefs;
			printf("*******BoundImportDescriptor No.%d(from 0 to n)*******\n",i);
			printf("TimeDataStamp : 0x%x\n",pBoundImpDescrpt->TimeDataStamp);
			printf("ModuleName : %s\n",pBoundImpDescrpt->OffsetModuleName+(DWORD)firstPBoundImpDescrpt);
			printf("NumberOfModuleForwarderRefs : %d\n",numOfRef);
			
			// (2) print pBountForwarderRefs
			pBoundRef=(PIMAGE_BOUND_FORWARDER_REF)(pBoundImpDescrpt+1);
			for(j=0;j<numOfRef;j++)
			{
				pBoundRef+=j;
				printf("*******BoundForwarderRefs No.%d(from 0 to n)*******\n",j);
				printf("TimeDataStamp : 0x%x\n",pBoundRef->TimeDataStamp);
				printf("ModuleName : %s\n",pBoundRef->OffsetModuleName+(DWORD)firstPBoundImpDescrpt);
				printf("*******BoundForwarderRef End*******\n");
		
			}

			
			pBoundImpDescrpt+=(numOfRef+1);

		}
		printf("Function :PrintBoundImportDescriptor Finished..\n");
		return OK;

	}
	else
	{
		printf("fileBuffer PE Init Error!..\n");
		free(fileBuffer);
		system("pause");
		return Error;
	}
}

DWORD GetFunctionAddrByNmOdrFromFileBuffer(PBYTE fileBuffer , char* str)
{
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir=NULL;

	DWORD foaPExportDir;
	DWORD foaPAddressDir;
	DWORD foaPNameDir;
	DWORD foaPNameOrdDir;

	DWORD numOfSec;
	DWORD numOfAddr;
	DWORD numOfName;
	DWORD ordBase;

	PDWORD pAddressDir;
	PDWORD pNameDir;
	PWORD pNameOrdDir;

	DWORD i;
	WORD order;
	DWORD desNameAddr;

	

	if(BufferPEInit(fileBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
	{
		// 1, find pExportDir
			// (1), get ExportDir rva ,and RVA to FOA
		numOfSec=pNTHeaders->FileHeaders.NumberOfSections;
		foaPExportDir=RVA_To_FOA(pNTHeaders->OptionalHeaders.DataDirectory[0].VirtualAddress,pSectionHeaders,numOfSec);
			// (2), pExportDir = FOA + FileBuffer
		pExportDir=(PIMAGE_EXPORT_DIRECTORY)(foaPExportDir+fileBuffer);

		// 2, find addDir,nameDir,numOrdDir from pExportDir
			// (1) get rva , and rva to FOA
		foaPAddressDir=RVA_To_FOA(pExportDir->AddressOfFunctions,pSectionHeaders,numOfSec);
		foaPNameDir=RVA_To_FOA(pExportDir->AddressOfNames,pSectionHeaders,numOfSec);
		foaPNameOrdDir=RVA_To_FOA(pExportDir->AddressOfNameOrdinals,pSectionHeaders,numOfSec);
			// (2) p = FOA+FileBuffer
		pAddressDir=(PDWORD)(foaPAddressDir+(DWORD)fileBuffer);
		pNameDir=(PDWORD)(foaPNameDir+(DWORD)fileBuffer);
		pNameOrdDir=(PWORD)(foaPNameOrdDir+(DWORD)fileBuffer);

		// 3, check  str name or order
		ordBase=pExportDir->Base;
			// (1) check if str[0] is numerical
		if(*str>='0' && *str <='9')
		{
			order = (WORD)atoi(str); //str to int
			order -= ordBase;
			numOfAddr=pExportDir->NumberOfFunctions;
			if(order<numOfAddr)
			{
				printf("the funAddress offset in Image : 0x%x\n",*(pAddressDir+order));
				return OK;
			}
			else
			{
				printf("order overflow!..\n");
				system("pause");
				return Error;
			}
		}
		else
		{
			numOfName=pExportDir->NumberOfNames;
			for(i=0;i<numOfName;i++)
			{
				//find name RVA -> FOA -> FOA+fileBuffer
				desNameAddr=RVA_To_FOA( *(pNameDir+i) ,pSectionHeaders,numOfSec)+(DWORD)fileBuffer;
				if(!strcmp(str,(char*)desNameAddr))
				{
					printf("find name in nameDir..\n");
					order=(int)*(pNameOrdDir+i);
					printf("the funAddress  offset in Image : 0x%x\n",*(pAddressDir+order));
					return OK;
				}
			}
			printf("not find name in nameDir!...\n");
			system("pause");
			return Error;
		}
	}
	else
	{
		printf("PE init Error..!\n");
		system("pause");
		return Error;
	}
}

BYTE FileBufferToImageBuffer(PBYTE fileBuffer,PBYTE* imageBuffer,DWORD* SizeImageBuffer)
{	//dilivery filebuffer & imagebuffer
	
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	//DWORD fileSize,imageSize;
	
	PBYTE image_buffer=NULL;
	PBYTE imageBase;
	PBYTE des;
	PBYTE src;
	
	
	int i;
	
	
	// 1, file to filebuffer
	if(fileBuffer)
	{
		
		// 2, buffer PE Init
		if(BufferPEInit(fileBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
		{
			// 3, fileBuffer extend to imageBuffer
			//  (1)	malloc imageBuffer
			*SizeImageBuffer=pNTHeaders->OptionalHeaders.SizeOfImage;   //delivery SizeImageBuffer
			if(image_buffer=(PBYTE)malloc(*SizeImageBuffer))
			{
				memset(image_buffer,0,*SizeImageBuffer);
				*imageBuffer=image_buffer;
				//	(2) cpy headers
				memcpy(image_buffer,fileBuffer,pNTHeaders->OptionalHeaders.SizeOfHeaders);
				//	(3) cpy sections
				imageBase=(PBYTE)pNTHeaders->OptionalHeaders.ImageBase;
				for(i=0;i<pNTHeaders->FileHeaders.NumberOfSections;i++)
				{
					//des
					des=(PBYTE)((pSectionHeaders+i)->VirtualAddress+image_buffer);
					//src
					src=(PBYTE)((pSectionHeaders+i)->PointerToRawData+fileBuffer);
					memcpy(des,src,(pSectionHeaders+i)->Misc.VirtualSize);
					
				}
				printf("FileBufferToImageBuffer finished!\n please free filebuffer and imagebuffer after using\n");
				printf("-----------------------------------------------\n");
				printf("\n");
				return OK;
				
			}
			else
			{
				printf("imageBuffer malloc error!\n");
				system("pause");
				return Error;
			}
			
		}
		else
		{
			printf("Buffer PE Init Error!..\n");
			system("pause");
			return Error;
		}
	}
	else
	{
		printf("Error Filebuffer !\n");
		system("pause");
		return Error;
	}
}


BYTE ImageBufferToFileBuffer(PBYTE imageBuffer,PBYTE* fileBuffer,DWORD* sizeFileBuffer)
{
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_SECTION_HEADERS lastPSecH;
	
	PBYTE file_buffer=NULL;

	PBYTE des;
	PBYTE src;
	DWORD i,fileBufferSize;

	// 1, imageBuffer PE Init..
	if(BufferPEInit(imageBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
	{
		// 2, malloc file_buffer
			// (1) caculate file size
		lastPSecH=pSectionHeaders+pNTHeaders->FileHeaders.NumberOfSections-1;
		fileBufferSize=lastPSecH->PointerToRawData+lastPSecH->SizeOfRawData;
		*sizeFileBuffer=fileBufferSize;			//delivery filebuffer size;
			// (1) malloc file buffer
		file_buffer=(PBYTE)malloc(fileBufferSize);
		memset(file_buffer,0,fileBufferSize);
		if(file_buffer)
		{
			// 2, cpy image buffer to file buffer
				// (1) cpy headers
			*fileBuffer=file_buffer;
			memcpy(file_buffer,imageBuffer,pNTHeaders->OptionalHeaders.SizeOfHeaders);
				// (2) cpy sections
			for(i=0;i<pNTHeaders->FileHeaders.NumberOfSections;i++)
			{
				//des
				des=file_buffer+(pSectionHeaders+i)->PointerToRawData;
				//src
				src=imageBuffer+(pSectionHeaders+i)->VirtualAddress;
				memcpy(des,src,(pSectionHeaders+i)->SizeOfRawData);
			}
			printf("ImageBufferToFileBuffer finishd...\n");
			printf("-----------------------------------------------\n");
			printf("\n");
			return OK;
		}
		else
		{
			printf(" file buffer malloc error!..\n");
			system("pause");
			return Error;
		}

	}
	else
	{
		printf("Buffer PE Init Error..\n");
		system("pause");

		return Error;
	}
	
}
int FindMaxIndex(int* arr,int len)
{
	int max=*arr,max_index=0;
	for(int i=1; i<len; i++)
		if(*(arr+i)>max)
		{
			max=*(arr+i);
			max_index=i;
		}
	return max_index;
}
int FindSpaceSignSection(PBYTE buffer,int* space,int* index,int sign)
{

	// if sign=-1,find max SpaceSec, 
	// if sign=0,1,2,3 ... index=sign
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSecH=NULL;
	int i,secNum;
	int* spaceList;
	// 1, PE Init
	if(BufferPEInit(buffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
	{
		// 2, section num and malloc spaceValuelist
		secNum=pNTHeaders->FileHeaders.NumberOfSections;
		spaceList=(int*)malloc(secNum*sizeof(DWORD));
		memset(spaceList,0,secNum*sizeof(DWORD));
		// 3, traverse sections and save into list
		for(i=0;i<secNum;i++)
		{
			pSecH=pSectionHeaders+i;
			*(spaceList+i)=pSecH->SizeOfRawData-pSecH->Misc.VirtualSize;
			printf("No.%d , space : 0x%x\n",i,*(spaceList+i));
		}
		// 4, check if sign = 0 , and find max SpaceSec
		if(sign==-1)
		{
			*index=FindMaxIndex(spaceList,secNum);
			*space=*(spaceList+*index);
			printf("--------------------------------\n");
			printf("find max index : %d\n,",*index);
			printf(" max space : 0x%x\n",*space);
		}
		else
		{
			*index=sign;
			*space=*(spaceList+*index);
			printf(" index : %d\n,",*index);
			printf(" space : 0x%x\n",*space);
		}
		free(spaceList);
		return OK;

	}
	else
	{
		printf("PE Init Error!..\n");
		system("pause");
	
		return Error;
	}
}
//funaddress-(imageBase+callFunOffset+5)
int AppendCallFunctionCode(DWORD funAddress,PBYTE pCallFun,DWORD callFunOffset,DWORD imageBase)
{
	// append call desAddressOffset
	// algorith funAddress-(imageBase+callFunOffset+5);
	BYTE call;
	DWORD desAddressOffset;
		// 1, append call
	call=0xE8;
	*pCallFun=call;
		// 2, append desAddressOffset
	desAddressOffset=funAddress-(imageBase+callFunOffset+5);
	*(PDWORD)(pCallFun+1)=desAddressOffset;
	return OK;
}
int AppendAndAlterOEP(PBYTE pJmpOEP,DWORD jmpOEPOffset,PDWORD pOEP,DWORD codeStartOffset)
{

	// append jmp OEP
	// // algorith *pOEP-(jmpOEPOffset+5);
	if(pJmpOEP && pOEP)
	{
		BYTE jmp;
		DWORD desAddressOffset;
		// 1, assign jmp
		jmp=0xE9;
		*pJmpOEP=jmp;
		// 2, assign addressOffset
		desAddressOffset=*pOEP-(jmpOEPOffset+5);
		*(PDWORD)(pJmpOEP+1)=desAddressOffset;
		// 3, assign oep
		*pOEP=codeStartOffset;
		return OK;
	}
	else 
	{
		printf("para in  error!\n");
		return Error;
	}
}
DWORD getLeftSecHSpace(PIMAGE_DOS_HEADERS pDosHeaders,DWORD SizeOfHeaders,PIMAGE_SECTION_HEADERS pSectionHeaders,DWORD numOfSecH)
{
	DWORD leftSecHSpace;
	leftSecHSpace=SizeOfHeaders-((DWORD)(pSectionHeaders+numOfSecH)-(DWORD)pDosHeaders);
	printf("leftSecHSpace : 0x%x...\n",leftSecHSpace);
	return leftSecHSpace;

}
int AddSectionFromFileBufferToNewFileBuffer(PBYTE fileBuffer,DWORD fileSize,char* name,int lengthFactor,PBYTE* newFileBuffer,DWORD* newFileBufferSize)
{
	// para name' size must be 8 
	// lengthFactor : length = imageAlign * lengthFactor
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_SECTION_HEADERS pNewSecH=NULL;

	

	DWORD  leftSecHSpace;
	DWORD  numOfSecH;
	DWORD  sizeOfSecH;
	DWORD  sizeOfHeaders;
	DWORD  sizeOfImageAlign;
	DWORD  sizeOfImage ;
	// 1, PE init
	if(BufferPEInit(fileBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
	{
		// 2, check if enough left sectionHeaders space
			// (1) get left SecH Space
		numOfSecH=pNTHeaders->FileHeaders.NumberOfSections;
		sizeOfHeaders=pNTHeaders->OptionalHeaders.SizeOfHeaders;
		leftSecHSpace=getLeftSecHSpace(pDosHeaders,sizeOfHeaders,pSectionHeaders,numOfSecH);
			// (2) check if enough
		sizeOfSecH=sizeof(*pSectionHeaders);
		if( leftSecHSpace >= (sizeOfSecH*2) )
		{
			printf("leftSecHSpace enough!...\n");
			// 3, add a new section
				// (1) cpy From No0 sec To new Sec
			pNewSecH=pSectionHeaders+numOfSecH;
			
			memcpy(pNewSecH,pSectionHeaders,sizeOfSecH);
				// (2) modify info Of newSecH
			memcpy(pNewSecH->Name,name,8);		//name
			sizeOfImageAlign=pNTHeaders->OptionalHeaders.SectionAlignment;
			pNewSecH->Misc.VirtualSize=sizeOfImageAlign*lengthFactor;	//Misc
			pNewSecH->SizeOfRawData=sizeOfImageAlign*lengthFactor;      //sizeOfRawData
			sizeOfImage=pNTHeaders->OptionalHeaders.SizeOfImage;
			pNewSecH->VirtualAddress=sizeOfImage;					//VirtualOffset
			pNewSecH->PointerToRawData=(pNewSecH-1)->PointerToRawData+(pNewSecH-1)->SizeOfRawData; //fileOffset
				// (3) modify numOfSec
			pNTHeaders->FileHeaders.NumberOfSections+=1;
				// (4) modify sizeOfImage
			pNTHeaders->OptionalHeaders.SizeOfImage+=pNewSecH->Misc.VirtualSize;
			printf("***********newSectionHeader has added successfully*************\n");
			// printf info of new section header
			pNewSecH=pSectionHeaders+pNTHeaders->FileHeaders.NumberOfSections-1;
			printf("***********newSectionHeader info as follows*************\n");
			printf("******** name : %s, ********\n",pNewSecH->Name);
			printf("******** Misc : 0x%x, ********\n",pNewSecH->Misc);
			printf("******** VirtualAddress : 0x%x, ********\n",pNewSecH->VirtualAddress);
			printf("******** SizeOfRawData : 0x%x, ********\n",pNewSecH->SizeOfRawData);
			printf("******** PointerToRawData : 0x%x, ********\n",pNewSecH->PointerToRawData);
			printf("******** Characteristics : 0x%x, ********\n",pNewSecH->Characteristics);

			// 4, create newFileBuffer(enlarge the filelength for new Section)
			*newFileBufferSize=fileSize+pNewSecH->SizeOfRawData;
			printf("newFileBufferSize : 0x%x..\n",*newFileBufferSize);
			*newFileBuffer=(PBYTE)malloc(*newFileBufferSize);
			memset(*newFileBuffer,0,*newFileBufferSize);  //memory clear to set 0 to new section

			
			// 5, cpy fileBuffer to newFileBuffer
			memcpy(*newFileBuffer,fileBuffer,fileSize);
			memset((PBYTE)(pNewSecH->PointerToRawData+(DWORD)(*newFileBuffer)),0,pNewSecH->SizeOfRawData);
			printf("newFileBuffer generate successfully...\n");
			return OK;


		}
		else
		{
			printf("no enough space for add section!\n");
			system("pause");
			
			return Error;
		}
	}
	else
	{
		printf("PE init Error!...\n");
		system("pause");
		
		return Error;
	}
	// 1, check if enough  section headers space
}
DWORD  InsertCodeIntoSignSection(PBYTE imageBuffer,char* code,int sizeOfCode,int sign)
{
	//InsertCodeIntoSignSection
	// sign = -1: max 
	// sign=0,1,2,3,4: add to No 1,2,3,4
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSecH=NULL;
	
	PBYTE pCodeStart=NULL;
	PBYTE src=NULL;

	
	DWORD codeStartOffset,jmpOEPOffset;
	int space=0,index=-1;
	PDWORD pOEP=NULL;
	PBYTE pJmpOEP;
	
	// 1, PE Init
	if(BufferPEInit(imageBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
	{
		// 2, find expective section space and index

		FindSpaceSignSection(imageBuffer,&space,&index,sign);
	
		
		if(index!=-1)
		{
			// 3, check if space enough
			if(space>0 && space-sizeOfCode-20>0)
			{	
				// 4, append code to section 
					// (1) append code
				
				pSecH=pSectionHeaders+index;
				//des from code+8
				codeStartOffset=pSecH->VirtualAddress+pSecH->Misc.VirtualSize+8;
				pCodeStart=imageBuffer+codeStartOffset;
				//src
				src=code;
				memcpy(pCodeStart,src,sizeOfCode);
					// (2)Append And Alter OEP
				pJmpOEP=pCodeStart+sizeOfCode;
				jmpOEPOffset=pJmpOEP-imageBuffer;

				pOEP=(PDWORD)&(pNTHeaders->OptionalHeaders.AddressOfEntryPoint);
				AppendAndAlterOEP(pJmpOEP,jmpOEPOffset,pOEP,codeStartOffset);

				// 5, alter this section characters finished
				DWORD x=pSecH->Characteristics;
				DWORD y=pSectionHeaders->Characteristics;
				pSecH->Characteristics=x|y;
				printf("******alter this section characters finished*******\n");
				return OK;

			}
			else
			{
				printf("no enough space to Insert code in MaxSpace!!\n");
				system("pause");
				
				return Error;
			}
		}
		else
		{
			printf("FindMaxSpeceSection Error!\n");
			system("pause");
		
			return Error;
		}
		
	}
	else
	{
		printf("PE Init Error!..\n");
		system("pause");
		
		return Error;
	}
	
}
DWORD  InsertFunctionIntoSignSection(PBYTE imageBuffer,char* paraCode,int sizeOfParaCode,DWORD funAddress,int sign,int signShellCodeSec)
{
	//append para -> call function -> jmp oep -> alter oep.
	// sign = -1: max 
	// sign=0,1,2,3,4: add to No 1,2,3,4
	// signOfShellSec=1 , add to my shellcode section
	// signOfShellSec=0 , add to ultral section
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSecH=NULL;
	
	PBYTE pCodeStart=NULL;
	PBYTE src=NULL;

	
	DWORD codeStartOffset,jmpOEPOffset,callFunOffset;
	DWORD imageBase;
	int space=0,index=-1;
	PDWORD pOEP=NULL;
	PBYTE pJmpOEP;
	PBYTE pCallFun;
	
	
	// 1, PE Init
	if(BufferPEInit(imageBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
	{
		// 2, find expective Section Space and Index

		FindSpaceSignSection(imageBuffer,&space,&index,sign);

		if(index!=-1||signShellCodeSec)
		{
			// 3, check if space enough
			if( (space>0 && space-sizeOfParaCode-0x20>0) || signShellCodeSec )
			{	
				// 4, append code to section 
					// (1) append paracode
				
				pSecH=pSectionHeaders+index;
				//des from code+8
				if(!signShellCodeSec)
				{
					codeStartOffset=pSecH->VirtualAddress+pSecH->Misc.VirtualSize+0x8;
				}
				else
				{
					codeStartOffset=pSecH->VirtualAddress+0x8;
				}
				
				printf("shellcode will append in Ultralcode Adress+8...\n");
				pCodeStart=imageBuffer+codeStartOffset;
				//src
				src=paraCode;
				memcpy(pCodeStart,src,sizeOfParaCode);
				printf("******append paracode finished*******\n");
					// (2) Append call function
				pCallFun=pCodeStart+sizeOfParaCode;
				callFunOffset=pCallFun-imageBuffer;
				imageBase=pNTHeaders->OptionalHeaders.ImageBase;
				AppendCallFunctionCode(funAddress,pCallFun,callFunOffset,imageBase);
				printf("******append callFun finished*******\n");




					// (3) Append And Alter OEP
				pJmpOEP=pCodeStart+sizeOfParaCode+5;
				jmpOEPOffset=pJmpOEP-imageBuffer;

				pOEP=(PDWORD)&(pNTHeaders->OptionalHeaders.AddressOfEntryPoint);
				AppendAndAlterOEP(pJmpOEP,jmpOEPOffset,pOEP,codeStartOffset);
				printf("******Append And Alter OEP finished*******\n");
				// 5, alter this section characters
				DWORD x=pSecH->Characteristics;
				DWORD y=pSectionHeaders->Characteristics;
				pSecH->Characteristics=x|y;
				printf("******alter this section characters finished*******\n");
				return OK;
				

			}
			else
			{
				printf("no enough space to Insert code in MaxSpace!!\n");
				system("pause");
				
				return Error;
			}
		}
		else
		{
			printf("FindMaxSpeceSection Error!\n");
			system("pause");
			
			return Error;
		}
		
	}
	else
	{
		printf("PE Init Error!..\n");
		system("pause");
	
		return Error;
	}
	
}

void TestFileToFile(char* srcPath,char * desPath)
{
	//File -> FileBuffer -> ImageBuffer -> newFileBuffer -> newFile
	//free 3 buffers
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_SECTION_HEADERS lastPSecH;
	PBYTE fileBuffer;
	PBYTE imageBuffer;
	PBYTE newFileBuffer;
	DWORD fileSize,imageSize;
	FILE* fp=fopen(srcPath,"rb");
	if(fp)
	{
		FileToFileBuffer(fp,&fileBuffer,&fileSize);
		FileBufferToImageBuffer(fileBuffer,&imageBuffer,&imageSize);
		ImageBufferToFileBuffer(imageBuffer,&newFileBuffer,&fileSize);
		BufferPEInit(newFileBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders);
		lastPSecH=pSectionHeaders+pNTHeaders->FileHeaders.NumberOfSections-1;
		BufferToFile(newFileBuffer,lastPSecH->PointerToRawData+lastPSecH->SizeOfRawData,desPath);

		free(fileBuffer);
		free(imageBuffer);
		free(newFileBuffer);
		fclose(fp);
		printf("free OK!!\n");
		printf("FileToFile Finished!!\n");
	}
}
void TestAppendShellcode(char* srcPath,char * desPath)
{
	//File -> FileBuffer -> ImageBuffer -> insert shell code -> newFileBuffer -> newFile
	//free 3 buffers
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_SECTION_HEADERS lastPSecH;
	PBYTE fileBuffer;
	PBYTE imageBuffer;
	PBYTE newFileBuffer;
	DWORD fileSize,imageSize;
	char paraCode[8]={0x6a,0x00,0x6a,0x00,0x6a,0x00,0x6a,0x00};
	int sizeOfParaCode=8;
	DWORD funAddress=0x77D5050B;
	int sign=4,signShellCodeSec=1;
	FILE* fp=fopen(srcPath,"rb");
	if(fp)
	{
		FileToFileBuffer(fp,&fileBuffer,&fileSize);
		FileBufferToImageBuffer(fileBuffer,&imageBuffer,&imageSize);
		InsertFunctionIntoSignSection(imageBuffer,paraCode,sizeOfParaCode,funAddress,sign,signShellCodeSec);
		

		ImageBufferToFileBuffer(imageBuffer,&newFileBuffer,&fileSize);
		BufferPEInit(newFileBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders);
		lastPSecH=pSectionHeaders+pNTHeaders->FileHeaders.NumberOfSections-1;
		BufferToFile(newFileBuffer,lastPSecH->PointerToRawData+lastPSecH->SizeOfRawData,desPath);

		free(fileBuffer);
		free(imageBuffer);
		free(newFileBuffer);
		fclose(fp);
		printf("free OK!!\n");
		printf("FileToFile Finished!!\n");
	}
}

DWORD MovFileExportDir(char* sPath,char *dPath)
{
	// 1, file to fileBuffer -> add ExportSection -> newBuffer -> mov ExportDir
	FILE *fp;
	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_EXPORT_DIRECTORY pExportDir=NULL;

	PIMAGE_EXPORT_DIRECTORY desPExportDir=NULL;
	

	PBYTE fileBuffer=NULL;
	PBYTE newFileBuffer=NULL;
	PBYTE pExportSec=NULL;
	
	
	DWORD fileSize;
	DWORD newFileSize;
	DWORD foaExportDir;
	DWORD foaAddressDir;
	DWORD foaNameOrdDir;

	DWORD foaNameDir,foaDesPName;
	DWORD foaPName,rvaDesPName;

	DWORD foaDesPAddressDir,rvaDesPAddressDir;
	DWORD foaDesPNameOrdDir,rvaDesPNameOrdDir;
	DWORD foaDesPNameDir,rvaDesPNameDir;

	PDWORD pAddressDir;
	PDWORD desPAddressDir;
	PWORD  pNameOrdDir;
	PWORD  desPNameOrdDir;
	PDWORD pNameDir;
	PDWORD desPNameDir;
	PBYTE pName;
	PBYTE desPName;
	

	DWORD numOfAddress;
	DWORD numOfName;
	DWORD lenOfName;
	
	DWORD sizeOfExportDir;

	
	char secName[8]="export";
	DWORD numOfSec;
	DWORD i;


	fp=fopen(sPath,"rb");
	if(fp)
	{	
		// add ExportSection
		FileToFileBuffer(fp,&fileBuffer,&fileSize);
		if(AddSectionFromFileBufferToNewFileBuffer(fileBuffer,fileSize,secName,2,&newFileBuffer,&newFileSize))
		{
			// 2, write to newFileBuffer
			fclose(fp);
			fp=fopen(dPath,"wb");
			fwrite(newFileBuffer,1,newFileSize,fp);
			free(fileBuffer);
			printf("free(fileBuffer)\n..");
			if(BufferPEInit(newFileBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
			{
				// 3, cpy srcExportDir to desExportDir
				numOfSec=pNTHeaders->FileHeaders.NumberOfSections;
				pExportSec=(PBYTE)((pSectionHeaders+numOfSec-1)->PointerToRawData+(DWORD)newFileBuffer);
				desPExportDir=(PIMAGE_EXPORT_DIRECTORY)pExportSec;
				// cpy exportDir
				foaExportDir=RVA_To_FOA(pNTHeaders->OptionalHeaders.DataDirectory[0].VirtualAddress,pSectionHeaders,numOfSec);
				pExportDir= (PIMAGE_EXPORT_DIRECTORY)(foaExportDir+(DWORD)newFileBuffer);

				sizeOfExportDir=sizeof(IMAGE_EXPORT_DIRECTORY);
				memcpy(desPExportDir,pExportDir,sizeOfExportDir);

				// 4, cpy 3 SrcDir to 3 DesDir.. 

				foaAddressDir=RVA_To_FOA(pExportDir->AddressOfFunctions,pSectionHeaders,numOfSec);
				foaNameOrdDir=RVA_To_FOA(pExportDir->AddressOfNameOrdinals,pSectionHeaders,numOfSec);
				foaNameDir=RVA_To_FOA(pExportDir->AddressOfNames,pSectionHeaders,numOfSec);

				pAddressDir=(PDWORD)(foaAddressDir+(DWORD)newFileBuffer);
				pNameOrdDir=(PWORD)(foaNameOrdDir+(DWORD)newFileBuffer);
				pNameDir=(PDWORD)(foaNameDir+(DWORD)newFileBuffer);

				numOfAddress=pExportDir->NumberOfFunctions;
				numOfName=pExportDir->NumberOfNames;

				desPAddressDir=(PDWORD)((PIMAGE_EXPORT_DIRECTORY)desPExportDir+1);
				desPNameOrdDir=(PWORD)(desPAddressDir+numOfAddress);
				desPNameDir=(PDWORD)(desPNameOrdDir+numOfName);

				// cpy adreessDir,NameOrdDir,NameDir

				memcpy(desPAddressDir,pAddressDir,numOfAddress*4);
				memcpy(desPNameOrdDir,pNameOrdDir,numOfName*2);
				memcpy(desPNameDir,pNameDir,numOfName*4);

				// cpy name of nameDir
				
				desPName=(PBYTE)(desPNameDir+numOfName);
				for(i=0;i<numOfName;i++)
				{
					
					foaPName=RVA_To_FOA(*(pNameDir+i),pSectionHeaders,numOfSec);
					pName=(PBYTE)(foaPName+(DWORD)newFileBuffer);
					lenOfName=strlen(pName);
					

					// assign rva to desNameDir
					foaDesPName=(DWORD)desPName-(DWORD)newFileBuffer;
					rvaDesPName=FOA_To_RVA(foaDesPName,pSectionHeaders,numOfSec);
					*(desPNameDir+i)=rvaDesPName;

			

					memcpy(desPName,pName,lenOfName);
					desPName+=(lenOfName+1);
				}
				



				// alter 3 dir address
				foaDesPAddressDir=(DWORD)desPAddressDir-(DWORD)newFileBuffer;
				foaDesPNameOrdDir=(DWORD)desPNameOrdDir-(DWORD)newFileBuffer;
				foaDesPNameDir=(DWORD)desPNameDir-(DWORD)newFileBuffer;

				rvaDesPAddressDir=FOA_To_RVA(foaDesPAddressDir,pSectionHeaders,numOfSec);
				rvaDesPNameOrdDir=FOA_To_RVA(foaDesPNameOrdDir,pSectionHeaders,numOfSec);
				rvaDesPNameDir=FOA_To_RVA(foaDesPNameDir,pSectionHeaders,numOfSec);


				desPExportDir->AddressOfFunctions=rvaDesPAddressDir;
				desPExportDir->AddressOfNameOrdinals=rvaDesPNameOrdDir;
				desPExportDir->AddressOfNames=rvaDesPNameDir;

				//alter pNTHeaders->OptionalHeaders.DataDirectory[0].VirtualAddress

				pNTHeaders->OptionalHeaders.DataDirectory[0].VirtualAddress=(pSectionHeaders+numOfSec-1)->VirtualAddress;
				(pSectionHeaders+numOfSec-1)->Characteristics=0x40000040;
			
				BufferToFile(newFileBuffer,newFileSize,dPath);
				free(newFileBuffer);
				printf(" mov ExportDir finished..!!\n");
				system("pause");
				return OK;



			}
			else
			{
				printf("newFileBuffer PE INIT error!\n");
				free(newFileBuffer);
				fclose(fp);
				system("pause");
				return Error;
			}
			
		}
		else
		{
			printf("Section ADD Error !..\n");
			fclose(fp);
			free(fileBuffer);
			system("pause");
			return Error;

		}

	}	
	else
	{
		printf("fopen error!..\n");
		system("pause");
		return Error;
	}
}

DWORD MovFileBaseRelocDir(char* srcPath,char* desPath)
{

	// file -> fileBuffer -> addSection -> newFileBuffer -> movRelcDir -> savaNewFile
	FILE* fp;

	PBYTE fileBuffer=NULL;
	PBYTE newFileBuffer=NULL;
	

	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSecH=NULL;
	PIMAGE_BASE_RELOCATION pBaseRelocDir=NULL;
	PIMAGE_BASE_RELOCATION desPBaseRelocDir=NULL;
	char secName[8]="reloc";

	PBYTE pSec;

	DWORD fileSize;
	DWORD newFileSize;
	DWORD numOfSec;
	DWORD i;
	DWORD sizeOfBlock;

	

	DWORD foaBaseRelocDir,rvaBaseRelocDir;
	
	fp=fopen(srcPath,"rb");
	if(fp)
	{
		if(FileToFileBuffer(fp,&fileBuffer,&fileSize))
		{
			if(AddSectionFromFileBufferToNewFileBuffer(fileBuffer,fileSize,secName,20,&newFileBuffer,&newFileSize))
			{
				free(fileBuffer);
				if(BufferPEInit(newFileBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
				{
					numOfSec=pNTHeaders->FileHeaders.NumberOfSections;
					pSecH=pSectionHeaders+numOfSec-1;
					pSec=(PBYTE)(pSecH->PointerToRawData+(DWORD)newFileBuffer);

					// cpy baseRelocDir
					rvaBaseRelocDir=pNTHeaders->OptionalHeaders.DataDirectory[5].VirtualAddress;
					foaBaseRelocDir=RVA_To_FOA(rvaBaseRelocDir,pSectionHeaders,numOfSec);
					pBaseRelocDir=(PIMAGE_BASE_RELOCATION)(foaBaseRelocDir+(DWORD)newFileBuffer);

					desPBaseRelocDir=(PIMAGE_BASE_RELOCATION)pSec;

					for(i=0;;i++)
					{
						if(!(pBaseRelocDir->VitualAddress) && !(pBaseRelocDir->SizeOfBlock))
							break;
						sizeOfBlock=pBaseRelocDir->SizeOfBlock;

						memcpy(desPBaseRelocDir,pBaseRelocDir,sizeOfBlock);

						pBaseRelocDir=(PIMAGE_BASE_RELOCATION)((DWORD)pBaseRelocDir+sizeOfBlock);
						desPBaseRelocDir=(PIMAGE_BASE_RELOCATION)((DWORD)desPBaseRelocDir+sizeOfBlock);

					}

					// alter address

					pNTHeaders->OptionalHeaders.DataDirectory[5].VirtualAddress=(DWORD)pSecH->VirtualAddress;

					fclose(fp);
					BufferToFile(newFileBuffer,newFileSize,desPath);

					
					free(newFileBuffer);
					printf("MovFileBaseRelocDir finished!\n");
					system("pause");
					return Error;

					
					

				}
				else
				{
					printf("newFileBuffer PE Init Error!..\n");
					free(newFileBuffer);
					system("pause");
					return Error;
				}
			}
			else
			{
				printf("addSection Error..\n");
				free(fileBuffer);
				fclose(fp);
				system("pause");
				return Error;
			}
		}
		else
		{
			printf("File to fileBuffer Error!..\n");
			fclose(fp);
			system("pause");
			return Error;
		}
	}
	else
	{
		printf("fopen Error!..\n");
		system("pause");
		return Error;
	}
}


DWORD AmendAddrInRelocDir(char *sPath,char *dPath,DWORD diff)
{
	FILE* fp;

	PIMAGE_DOS_HEADERS pDosHeaders=NULL;
	PIMAGE_NT_HEADERS pNTHeaders=NULL;
	PIMAGE_SECTION_HEADERS pSectionHeaders=NULL;
	PIMAGE_BASE_RELOCATION pRelocDir=NULL;
	
	PBYTE fileBuffer;

	DWORD rvaRelocDir,foaRelocDir;
	DWORD i,j;
	
	DWORD fileSize;
	DWORD numOfSec;

	DWORD foaBase,rvaBase;
	PWORD pIndex;

	DWORD base;
	DWORD offset;
	DWORD ct;

	PDWORD desAddr;


	fp=fopen(sPath,"rb");
	if(fp)
	{
		if(FileToFileBuffer(fp,&fileBuffer,&fileSize))
		{
			fclose(fp);
			if(BufferPEInit(fileBuffer,&pDosHeaders,&pNTHeaders,&pSectionHeaders))
			{
				// amend
				numOfSec=pNTHeaders->FileHeaders.NumberOfSections;
				rvaRelocDir=pNTHeaders->OptionalHeaders.DataDirectory[5].VirtualAddress;
				foaRelocDir=RVA_To_FOA(rvaRelocDir,pSectionHeaders,numOfSec);
				pRelocDir=(PIMAGE_BASE_RELOCATION)(foaRelocDir+(DWORD)fileBuffer);

				for(i=0;;i++)
				{
					if(!(pRelocDir->SizeOfBlock) && !(pRelocDir->VitualAddress))
						break;
					rvaBase=pRelocDir->VitualAddress;
					foaBase=RVA_To_FOA(rvaBase,pSectionHeaders,numOfSec);
					base=foaBase+(DWORD)fileBuffer;

					ct=(pRelocDir->SizeOfBlock-8)/2;

					pIndex=(PWORD)(pRelocDir+1);
					for(j=0;j<ct;j++)
					{
						// restore every address..
						
						if( *(pIndex+j) & 0xF000  == 0x3000)
						{
							offset=0;
							offset=(DWORD)(*(pIndex+i) & 0x0FFF);
							desAddr=(PDWORD)(base+offset);
							*(desAddr)+=diff;
						}
					}
					pRelocDir=(PIMAGE_BASE_RELOCATION)((DWORD)pRelocDir+(DWORD)pRelocDir->SizeOfBlock);

					
					
				}

				BufferToFile(fileBuffer,fileSize,dPath);
				free(fileBuffer);
				printf("amend Reloc VitualAddress Finished..\n");
				return OK;

			}
			else
			{
				printf("file Buffer PE init Error!\n");
				free(fileBuffer);
				system("pause");
				return Error;
			
			}
		}
		else
		{
			printf("file to fileBuffer Error;!!\n");
			system("pause");
			return Error;
		}
	}
	else
	{
		printf("fopen Error!\n");
		system("pause");
		return Error;
	}
}
void TestAddSectionInFileBuffer(char* spath,char* dpath)
{
	FILE* fp;
	PBYTE fileBuffer;
	PBYTE newFileBuffer;
	char name[8]={'a','b','c','g'};
	DWORD fileSize;
	DWORD newFileSize;
	DWORD lengthFact=2;
	if(fp=fopen(spath,"rb"))
	{
		FileToFileBuffer(fp,&fileBuffer,&fileSize);
		
		AddSectionFromFileBufferToNewFileBuffer(fileBuffer,fileSize,name,lengthFact,&newFileBuffer,&newFileSize);
		BufferToFile(newFileBuffer,newFileSize,dpath);
		free(fileBuffer);
		free(newFileBuffer);
		fclose(fp);
		printf("file generate finished!....\n");
	
		
	}
	else
	{
		fclose(fp);
		printf("fopen Error!\n");
		system("pause");
		
	
	}
}
void TestPrintExportDir(char* path)
{
	FILE* fp;
	PBYTE fileBuffer=NULL;
	DWORD fileSize;
	if(fp=fopen(path,"rb"))
	{
		if(FileToFileBuffer(fp,&fileBuffer,&fileSize))
		{
			PrintExportDir(fileBuffer);
			fclose(fp);
			free(fileBuffer);
		}
		else
		{
			printf("file to file buffer Error!..\n");
			fclose(fp);
			free(fileBuffer);
			system("pause");
		}
	}
	else
	{
		printf("fopen Error !..\n");
		system("pause");
	}
}
void TestGetFunAddress(char* path,char* str)
{
	FILE* fp;
	PBYTE fileBuffer=NULL;
	DWORD fileSize;
	if(fp=fopen(path,"rb"))
	{
		if(FileToFileBuffer(fp,&fileBuffer,&fileSize))
		{
			GetFunctionAddrByNmOdrFromFileBuffer(fileBuffer,str);
			fclose(fp);
			free(fileBuffer);
		}
		else
		{
			printf("file to file buffer Error!..\n");
			fclose(fp);
			free(fileBuffer);
			system("pause");
		}
	}
	else
	{
		printf("fopen Error !..\n");
		system("pause");
	}
}
void TestPrintBaseRelocation(char* path)
{
	FILE* fp;
	PBYTE fileBuffer=NULL;
	DWORD fileSize;
	if(fp=fopen(path,"rb"))
	{
		if(FileToFileBuffer(fp,&fileBuffer,&fileSize))
		{
			PrintBaseRelocation(fileBuffer);
			fclose(fp);
			free(fileBuffer);
		}
		else
		{
			printf("file to file buffer Error!..\n");
			fclose(fp);
			free(fileBuffer);
			
			system("pause");
		}
	}
	else
	{
		printf("fopen Error !..\n");
		system("pause");
	}
}
void TestMovFileExportDir()
{
	char* spath="C:/hideDll.dll";
	char* dpath="C:/new.dll";
	MovFileExportDir(spath,dpath);
	
}

void TestMovFileBaseRelocDir()
{
	char* spath="C:/hideDll.dll";
	char* dpath="C:/new.dll";
	MovFileBaseRelocDir(spath,dpath);
}

void TestAmendRelocDir()
{
	char* spath="C:/new.dll";
	char* dpath="C:/amendNew.dll";
	AmendAddrInRelocDir(spath,dpath,0x10000000);
}

void TestPrintImportDescriptor()
{
	char* path="C:/Newnotepad.exe";
	FILE* fp;
	PBYTE fileBuffer;
	DWORD fileSize=0;
	if(fp=fopen(path,"rb"))
	{
		FileToFileBuffer(fp,&fileBuffer,&fileSize);
		PrintImportDescriptor(fileBuffer);
		free(fileBuffer);

	}
}
void TestPrintBoundImportDescriptor()
{
	char* path="C:/Newnotepad.exe";
	FILE* fp;
	PBYTE fileBuffer;
	DWORD fileSize=0;
	if(fp=fopen(path,"rb"))
	{
		FileToFileBuffer(fp,&fileBuffer,&fileSize);
		PrintBoundImportDescriptor(fileBuffer);
		free(fileBuffer);

	}
}
int main(int argc, char* argv[])
{
	
	//char* spath="C:/WINDOWS/system32/notepad.exe";
	//char* spath="C:/hideDll.dll";
	//char* dpath="C:/new.dll";
	//TestAddSectionInFileBuffer(spath,dpath);
	//char* path="C:/hideDll.dll";
	//char* str="12";
	//TestAppendShellcode(spath,dpath);
	
	//TestGetFunAddress(path,str);
	//TestPrintBaseRelocation(path);
	//TestMovFileExportDir();
	//TestPrintExportDir(dpath);
	//TestMovFileBaseRelocDir();
	//TestAmendRelocDir();
	//TestPrintImportDescriptor();
	TestPrintBoundImportDescriptor();

	




	

	
	system("pause");
	return 1;

}
