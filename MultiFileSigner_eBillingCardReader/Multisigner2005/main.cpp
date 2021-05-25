#include "main.h"


int RSA_KEY = 1;
int ECDSA_KEY = 2;

int main()
{
	CK_RV           rv				=	CKR_OK;
	CK_ULONG        count			=	0;
	CK_SLOT_ID_PTR  pSlots			=	NULL;
	CK_ULONG        i				=	0;
	CK_INFO         info;
	CK_TOKEN_INFO   tokenInfo;
	//char			sLibraryName[]	=	"asignp11.dll";
	//char sLibraryName[] = "C:\\WINDOWS\\system32\\asignp11.dll";
	LPCWSTR sLibraryName = L"asignp11.dll";
	HINSTANCE		hinstLib = NULL;


	printf("Multi Signer Test (eBilling Kartenleser)\n");
	printf("========================================\n\n");


	// load PKCS11 DLL

	//if ((hinstLib = LoadLibrary((LPCWSTR)sLibraryName)) == NULL)
	if ((hinstLib = LoadLibrary(sLibraryName)) == NULL)
	{
		printf("could not load library %s.\n", sLibraryName);
		return(0);
	}

	// get procedure names

	if ((Proc_C_Initialize = (Type_C_Initialize *)GetProcAddress(hinstLib, "C_Initialize")) == NULL)
	{
		printf("ERROR: invalid DLL.\n");
		return(0);
	}

	// for all other proc's, omit pointer check
	Proc_C_GetSlotList		= (Type_C_GetSlotList *)	GetProcAddress(hinstLib, "C_GetSlotList");
	Proc_C_WaitForSlotEvent	= (Type_C_WaitForSlotEvent *) GetProcAddress(hinstLib, "C_WaitForSlotEvent");
	Proc_C_GetTokenInfo		= (Type_C_GetTokenInfo *)	GetProcAddress(hinstLib, "C_GetTokenInfo");
	Proc_C_OpenSession		= (Type_C_OpenSession *)	GetProcAddress(hinstLib, "C_OpenSession");
	Proc_C_CloseSession		= (Type_C_CloseSession *)	GetProcAddress(hinstLib, "C_CloseSession");
	Proc_C_DigestInit		= (Type_C_DigestInit *)		GetProcAddress(hinstLib, "C_DigestInit");
	Proc_C_DigestUpdate		= (Type_C_DigestUpdate *)	GetProcAddress(hinstLib, "C_DigestUpdate");
	Proc_C_DigestFinal		= (Type_C_DigestFinal *)	GetProcAddress(hinstLib, "C_DigestFinal");
	Proc_C_Login			= (Type_C_Login *)			GetProcAddress(hinstLib, "C_Login");
	Proc_C_Logout			= (Type_C_Logout *)			GetProcAddress(hinstLib, "C_Logout");
	Proc_C_FindObjectsInit	= (Type_C_FindObjectsInit *)GetProcAddress(hinstLib, "C_FindObjectsInit");
	Proc_C_FindObjects		= (Type_C_FindObjects *)	GetProcAddress(hinstLib, "C_FindObjects");
	Proc_C_FindObjectsFinal = (Type_C_FindObjectsFinal *)GetProcAddress(hinstLib, "C_FindObjectsFinal");
	Proc_C_SignInit			= (Type_C_SignInit *)		GetProcAddress(hinstLib, "C_SignInit");
	Proc_C_Sign				= (Type_C_Sign *)			GetProcAddress(hinstLib, "C_Sign");
	Proc_C_VerifyInit		= (Type_C_VerifyInit *)		GetProcAddress(hinstLib, "C_VerifyInit");
	Proc_C_Verify			= (Type_C_Verify *)			GetProcAddress(hinstLib, "C_Verify");
	Proc_C_GenerateKey		= (Type_C_GenerateKey *)	GetProcAddress(hinstLib, "C_GenerateKey");
	Proc_C_EncryptInit		= (Type_C_EncryptInit *)	GetProcAddress(hinstLib, "C_EncryptInit");
	Proc_C_EncryptUpdate	= (Type_C_EncryptUpdate *)	GetProcAddress(hinstLib, "C_EncryptUpdate");
	Proc_C_Encrypt			= (Type_C_Encrypt *)		GetProcAddress(hinstLib, "C_Encrypt");
	Proc_C_EncryptFinal		= (Type_C_EncryptFinal *)	GetProcAddress(hinstLib, "C_EncryptFinal");
	Proc_C_WrapKey			= (Type_C_WrapKey *)		GetProcAddress(hinstLib, "C_WrapKey");
	Proc_C_UnwrapKey		= (Type_C_UnwrapKey *)		GetProcAddress(hinstLib, "C_UnwrapKey");
	Proc_C_DecryptInit		= (Type_C_DecryptInit *)	GetProcAddress(hinstLib, "C_DecryptInit");
	Proc_C_DecryptUpdate	= (Type_C_DecryptUpdate *)	GetProcAddress(hinstLib, "C_DecryptUpdate");
	Proc_C_Decrypt			= (Type_C_Decrypt *)		GetProcAddress(hinstLib, "C_Decrypt");
	Proc_C_DecryptFinal		= (Type_C_DecryptFinal *)	GetProcAddress(hinstLib, "C_DecryptFinal");
	Proc_C_GetAttributeValue= (Type_C_GetAttributeValue *)GetProcAddress(hinstLib, "C_GetAttributeValue");
	Proc_C_DestroyObject	= (Type_C_DestroyObject *)	GetProcAddress(hinstLib, "C_DestroyObject");
	Proc_C_CreateObject		= (Type_C_CreateObject *)	GetProcAddress(hinstLib, "C_CreateObject");
	Proc_C_SetPIN			= (Type_C_SetPIN *)			GetProcAddress(hinstLib, "C_SetPIN");
	Proc_C_SetAttributeValue= (Type_C_SetAttributeValue *)GetProcAddress(hinstLib, "C_SetAttributeValue");
	Proc_C_GetInfo			= (Type_C_GetInfo *)		GetProcAddress(hinstLib, "C_GetInfo");
	Proc_C_Finalize			= (Type_C_Finalize *)		GetProcAddress(hinstLib, "C_Finalize");



	if ((rv = Proc_C_Initialize(NULL)) != CKR_OK)
	{
		printf("Failed to initialize PKCS#11 Library %s, rv = 0x%x\n", sLibraryName, rv);
		return 0;
	}

	if ((rv = Proc_C_GetInfo(&info)) != CKR_OK)
	{
		printf("Failed to initialize Cryptographic Library, rv = 0x%x\n", rv);
		return 0;
	}

	printf("\nManufacturer: %.*s\n", 32, info.manufacturerID);
	printf("Description : %.*s\n", 32, info.libraryDescription);
	printf("Version     : %d.%d\n\n", info.libraryVersion.major, info.libraryVersion.minor);
		
	if ((rv = Proc_C_GetSlotList(TRUE, NULL, &count)) != CKR_OK)
	{
		printf("Failed to get slot list, rv = 0x%x\n", rv);
		return 0;
	}

	pSlots = new CK_SLOT_ID[count];

	if ((rv = Proc_C_GetSlotList(TRUE, pSlots, &count)) != CKR_OK)
	{
		printf("Failed to get slot list, rv = 0x%x\n", rv);
		return 0;
	}

	for (i=0; i<count; i++)
	{
		if ((rv = Proc_C_GetTokenInfo(pSlots[i], &tokenInfo)) != CKR_OK)
		{
			printf("Failed to get token info for slot %d, rv = 0x%x\n", pSlots[i], rv);
			return 0;
		}
		printf("   Slot %4d: %.*s\n", pSlots[i], 32, tokenInfo.label);
	}

	signingfiles();

	if ((rv = Proc_C_Finalize(NULL)) != CKR_OK)
	{
		printf("Failed to finalize PKCS#11 Library, rv = 0x%x\n", rv);
		return 0;
	}


	delete pSlots;
	printf("\n\ncontinue with enter key\n");
	getch();

	return 0;
}


CK_RV GetSlot(CK_SLOT_ID_PTR pSlot)
{
	CK_RV          rv     = CKR_OK;
	CK_ULONG       count  = 0;
	CK_SLOT_ID_PTR pSlots = NULL;
	CK_ULONG       i      = 0;
	CK_TOKEN_INFO  tokenInfo;
	char           ach[10];

	if ((rv = Proc_C_GetSlotList(TRUE, NULL, &count)) != CKR_OK)
	{
		printf("Failed to get slot list, rv = 0x%x\n", rv);
		return rv;
	}

	pSlots = new CK_SLOT_ID[count];

	if ((rv = Proc_C_GetSlotList(TRUE, pSlots, &count)) != CKR_OK)
	{
		printf("Failed to get slot list, rv = 0x%x\n", rv);
		return 0;
	}

	printf("\n");
	for (i=0; i<count; i++)
	{
		if ((rv = Proc_C_GetTokenInfo(pSlots[i], &tokenInfo)) != CKR_OK)
		{
			printf("Failed to get token info for slot %d, rv = 0x%x\n", pSlots[i], rv);
			return 0;
		}
		printf("   %d: Slot %4d: %.*s\n", i, pSlots[i], 32, tokenInfo.label);
	}

	printf("\nWhich slot would you like to use (0->%d)? ", count-1);
	gets(ach);
	printf("\n");

	if ((CK_ULONG)atoi(ach) >= count)
	{
		printf("\nIllegal choice!!!\n", count-1);
		return CKR_GENERAL_ERROR;
	}

	*pSlot = pSlots[atoi(ach)];

	delete pSlots;

	return CKR_OK;
}


void signingfiles()
{
	bool					ret = true;
	char					path[_MAX_PATH];
	struct _finddata_t		sfiles[max_file];
	CK_SLOT_ID				slot= 0;
	CK_RV					rv = CKR_OK;
	struct signPara			paras[max_file];

// Daten abfragen
	int ifiles = GetFilesFromDir(path,sfiles);

	
	if ((rv = GetSlot(&slot)) != CKR_OK)
	{
		printf("Failed to get slot\n", rv);
		return;
	}

// dateien vorbereiten und hashen
	for(int i =0; i < ifiles; i++)
	{
		sprintf(paras[i].input,"%s%s",path,sfiles[i].name);
		sprintf(paras[i].output,"%s%s.sig",path,sfiles[i].name);
		

		paras[i].hashsize = sizeof(paras[i].hash);
		ret = hashFile(paras[i].input,paras[i].hash,&paras[i].hashsize, slot);
		if(ret == false)
		{
			return;
		}
	}


// signieren

	CK_SESSION_HANDLE		hSession = 0;
	CK_OBJECT_HANDLE		handle = -1;
	CK_MECHANISM			mechanism;

	if ((rv = Proc_C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &hSession)) != CKR_OK)
	{
		printf("Failed to open session with CryptoToken, rv = 0x%x\n", rv);
		return;
	}

	int key=-1;
	handle = FindPrivateKey(hSession,key);
	if (handle== -1)
	{
		Proc_C_CloseSession(hSession);
		return;
	}

	if (key == RSA_KEY)
		mechanism.mechanism      = CKM_SHA1_RSA_PKCS;
	else if(key == ECDSA_KEY)
		mechanism.mechanism      = CKM_ECDSA_SHA1;
	else
	{
		printf("Unknown Keytype");
		return;
	}
	mechanism.pParameter     = NULL_PTR;
	mechanism.ulParameterLen = 0;


	printf("\n\nsigning %d files\n",ifiles);
	printf("=================\n\n");

	for(int j = 0; j < ifiles; j++)
	{

		
		if ((rv = Proc_C_SignInit(hSession, &mechanism, handle)) != CKR_OK)
		{
			printf("Failed to init sign, rv = 0x%x\n", rv);
			Proc_C_CloseSession(hSession);
			return;
		}
		paras[j].signaturesize = sizeof(paras[j].signature);
		if ((rv = Proc_C_Sign(hSession, paras[j].hash, paras[j].hashsize, paras[j].signature, &paras[j].signaturesize )) != CKR_OK)
		{
			paras[j].success = false;
			printf("Failed to sign, rv = 0x%x\n", rv);
			continue;
		}
		else
		{
			printf("Success signing file!\n");
			paras[j].success = true;
		}
	}
	Proc_C_CloseSession(hSession);

// Signatur abspeichern

	FILE* file = NULL;

	for (int k=0; k < ifiles; k++)
	{
		if (paras[k].success)
		{
			if ((file = fopen(paras[k].output, "wb")) == NULL)
			{
				printf("Failed to open file %s\n", paras[k].output);
				continue;
			}
			
			if (fwrite(paras[k].signature, 1, paras[k].signaturesize, file) != paras[k].signaturesize)
			{
				fclose(file);
				printf("Failed to write file %s\n", paras[k].output);
				continue;
			}
			
			fclose(file);
		}
	}
}



CK_OBJECT_HANDLE FindPrivateKey(CK_SESSION_HANDLE hSession,int &key)
{
	CK_ATTRIBUTE			attributes[2];
	CK_ULONG				ul1 = 0;
	CK_ULONG				ul2 = 0;
	CK_ULONG				ul3 = 0;
	CK_ULONG				count_rsa = 0;
	CK_ULONG				count_ecdsa = 0;
	CK_CHAR					ach1[256];
	CK_CHAR					ach2[256];
	int						j=0;
	int						k=0;
	CK_OBJECT_HANDLE		handles_RSA[10];
	CK_OBJECT_HANDLE		handles_ECDSA[10];
	CK_RV					rv = CKR_OK;
	

// RSA KEY
	ul1 = CKO_PRIVATE_KEY;
	ul2 = CKK_RSA;
	attributes[0].type       = CKA_CLASS;
	attributes[0].pValue     = &ul1;
	attributes[0].ulValueLen = sizeof(ul1);
	attributes[1].type       = CKA_KEY_TYPE;
	attributes[1].pValue     = &ul2;
	attributes[1].ulValueLen = sizeof(ul2);


	if ((rv = Proc_C_FindObjectsInit(hSession, attributes, 2)) != CKR_OK)
	{
		printf("Failed to init find operation, rv = 0x%x\n", rv);
		return -1;
	}

	if ((rv = Proc_C_FindObjects(hSession, handles_RSA, 10, &count_rsa)) != CKR_OK)
	{
		printf("Failed to find objects, rv = 0x%x\n", rv);
		return -1;
	}

	if ((rv = Proc_C_FindObjectsFinal(hSession)) != CKR_OK)
	{
		printf("Failed to final find operation, rv = 0x%x\n", rv);
		return -1;
	}

	for (j=0; j<count_rsa; j++)
	{
		attributes[0].type       = CKA_LABEL;
		attributes[0].pValue     = &ach1;
		attributes[0].ulValueLen = sizeof(ach1);
		attributes[1].type       = CKA_ID;
		attributes[1].pValue     = &ach2;
		attributes[1].ulValueLen = sizeof(ach2);

		if (Proc_C_GetAttributeValue(hSession, handles_RSA[j], attributes, 2) == CKR_OK)
		{
			printf("%d: %.*s :", j, attributes[0].ulValueLen, attributes[0].pValue);
			for (k=0; k<attributes[1].ulValueLen; ++k)
		 		printf(" %02X", ach2[k]);
		}

		printf("\n");

	}

// ECDSA KEY
	ul1 = CKO_PRIVATE_KEY;
	ul2 = CKK_ECDSA;
	attributes[0].type       = CKA_CLASS;
	attributes[0].pValue     = &ul1;
	attributes[0].ulValueLen = sizeof(ul1);
	attributes[1].type       = CKA_KEY_TYPE;
	attributes[1].pValue     = &ul2;
	attributes[1].ulValueLen = sizeof(ul2);


	if ((rv = Proc_C_FindObjectsInit(hSession, attributes, 2)) != CKR_OK)
	{
		printf("Failed to init find operation, rv = 0x%x\n", rv);
		return -1;
	}

	if ((rv = Proc_C_FindObjects(hSession, handles_ECDSA, 10, &count_ecdsa)) != CKR_OK)
	{
		printf("Failed to find objects, rv = 0x%x\n", rv);
		return -1;
	}

	if ((rv = Proc_C_FindObjectsFinal(hSession)) != CKR_OK)
	{
		printf("Failed to final find operation, rv = 0x%x\n", rv);
		return -1;
	}

	for (j=0; j<count_ecdsa; j++)
	{
		attributes[0].type       = CKA_LABEL;
		attributes[0].pValue     = &ach1;
		attributes[0].ulValueLen = sizeof(ach1);
		attributes[1].type       = CKA_ID;
		attributes[1].pValue     = &ach2;
		attributes[1].ulValueLen = sizeof(ach2);

		if (Proc_C_GetAttributeValue(hSession, handles_ECDSA[j], attributes, 2) == CKR_OK)
		{
			printf("%d: %.*s :", (count_rsa+j), attributes[0].ulValueLen, attributes[0].pValue);
			for (k=0; k<attributes[1].ulValueLen; ++k)
		 		printf(" %02X", ach2[k]);
		}

		printf("\n");
	}


	if ( (count_rsa + count_ecdsa) == 0)
	{
		return -1;
	}

	printf("%d private keys found.\n\n", (count_rsa + count_ecdsa) );

	printf("Which key (0->x) ? ");
	gets((char*)ach1);
	printf("\n");


	j = atoi((char*)ach1);

	if (j < count_rsa)
	{
		key = RSA_KEY;
		return handles_RSA[j];
	}

	key = ECDSA_KEY;
	j -= count_rsa;
	return handles_ECDSA[j];
}


bool hashFile(const char* filename,CK_CHAR* hash,CK_ULONG* size,CK_SLOT_ID slot)
{
	CK_SESSION_HANDLE hSession  = 0;
	CK_MECHANISM mechanism;	
	CK_CHAR	buffer[256];
	CK_RV rv = CKR_OK;
	FILE *file;
	int	ret = 0;

	mechanism.mechanism      = CKM_SHA_1;
	mechanism.pParameter     = NULL_PTR;
	mechanism.ulParameterLen = 0;

	if ((file = fopen(filename, "rb")) == NULL)
	{
		printf("Error reading file %s\n",filename);
		return false;
	}

	if ((rv = Proc_C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &hSession)) != CKR_OK)
	{
		printf("Failed to open session with CryptoToken, rv = 0x%x\n", rv);
		return false;
	}

	if ((rv = Proc_C_DigestInit(hSession, &mechanism)) != CKR_OK)
	{
		printf("Failed to init digest, rv = 0x%x\n", rv);
		Proc_C_CloseSession(hSession);
		return false;
	}

	while ((ret = fread(buffer, 1, sizeof(buffer), file)) == sizeof(buffer))
	{
		if ((rv = Proc_C_DigestUpdate(hSession, buffer, ret)) != CKR_OK)
		{
			fclose(file);
			printf("Failed to digest update, rv = 0x%x\n", rv);
			Proc_C_CloseSession(hSession);
			return false;
		}
	}


	if ((rv = Proc_C_DigestUpdate(hSession, buffer, ret)) != CKR_OK)
	{
		printf("Failed to digest update, rv = 0x%x\n", rv);
		Proc_C_CloseSession(hSession);
		return false;
	}

	if ((rv = Proc_C_DigestFinal(hSession, hash, size)) != CKR_OK)
	{
		printf("Failed to digest final, rv = 0x%x\n", rv);
		Proc_C_CloseSession(hSession);
		return false;
	}

	Proc_C_CloseSession(hSession);
	return true;
}

int GetFilesFromDir(char* path,_finddata_t* sfiles)
{
	int ifiles = 0;
	int	hFile;
	char findpath[_MAX_PATH+10];


	printf("\nDirectory for filesigning (max. %d files): ",max_file);
	gets((char*)path);
	printf("\n");

	int len = strlen(path);
	if(path[0] == '"')
	{
		// Zeichenkette mit Anführungszeichen
		char *p =  strtok(path, "\"");
		strcpy(path,p);

	}
	if(path[len] != '\\')
		sprintf(path,"%s\\",path);

	sprintf(findpath,"%s*.*",path);


	if ( (hFile = _findfirst(findpath, &sfiles[ifiles])) == -1 )
	{
		printf("No file in Directory");
		return 0;
	}
	else
	{
		
		do
		{
			if ( !(sfiles[ifiles].attrib &_A_SUBDIR) ) 
			{
				printf("found: %s\n",sfiles[ifiles].name);
				ifiles++;
			}
		}while( (_findnext( hFile, &sfiles[ifiles] ) == 0 ) && (ifiles < 10));
		_findclose( hFile );
	}

	return ifiles;
}

