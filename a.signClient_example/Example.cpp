#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <string.h>

#ifndef ULONG_PTR
#define ULONG_PTR unsigned long *
#endif

#include <windows.h>


#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
   returnType __declspec(dllexport) name

#define CK_DECLARE_FUNCTION(returnType, name) \
   returnType __declspec(dllimport) name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
   returnType __declspec(dllimport) (* name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
   returnType (* name)

#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#pragma pack(push, cryptoki, 1)
#include "pkcs11.h"
#pragma pack(pop, cryptoki)



typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_Initialize)		(
  CK_VOID_PTR   pInitArgs
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_GetSlotList)		(
  CK_BBOOL       tokenPresent,  /* only slots with tokens? */
  CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
  CK_ULONG_PTR   pulCount       /* receives number of slots */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_WaitForSlotEvent)		(
  CK_FLAGS flags,        /* blocking/nonblocking flag */
  CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
  CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_GetTokenInfo)		(
  CK_SLOT_ID        slotID,  /* ID of the token's slot */
  CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_OpenSession)		(
  CK_SLOT_ID            slotID,        /* the slot's ID */
  CK_FLAGS              flags,         /* from CK_SESSION_INFO */
  CK_VOID_PTR           pApplication,  /* passed to callback */
  CK_NOTIFY             Notify,        /* callback function */
  CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_CloseSession)		(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_DigestInit)		(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_DigestUpdate)		(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_BYTE_PTR       pPart,     /* data to be digested */
  CK_ULONG          ulPartLen  /* bytes of data to be digested */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_DigestFinal)		(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_BYTE_PTR       pDigest,      /* gets the message digest */
  CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_Login)			(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_USER_TYPE      userType,  /* the user type */
  CK_CHAR_PTR       pPin,      /* the user's PIN */
  CK_ULONG          ulPinLen   /* the length of the PIN */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_Logout)			(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_FindObjectsInit)	(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
  CK_ULONG          ulCount     /* attrs in search template */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_FindObjects)		(
 CK_SESSION_HANDLE    hSession,          /* session's handle */
 CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
 CK_ULONG             ulMaxObjectCount,  /* max handles to get */
 CK_ULONG_PTR         pulObjectCount     /* actual # returned */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_FindObjectsFinal)	(
  CK_SESSION_HANDLE hSession  /* the session's handle */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_SignInit)			(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of signature key */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_Sign)				(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_BYTE_PTR       pData,           /* the data to sign */
  CK_ULONG          ulDataLen,       /* count of bytes to sign */
  CK_BYTE_PTR       pSignature,      /* gets the signature */
  CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_VerifyInit)		(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
  CK_OBJECT_HANDLE  hKey         /* verification key */ 
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_Verify)			(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pData,          /* signed data */
  CK_ULONG          ulDataLen,      /* length of signed data */
  CK_BYTE_PTR       pSignature,     /* signature */
  CK_ULONG          ulSignatureLen  /* signature length*/
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_GenerateKey)			(
  CK_SESSION_HANDLE    hSession,    /* the session's handle */
  CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
  CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
  CK_ULONG             ulCount,     /* # of attrs in template */
  CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_EncryptInit)			(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_EncryptUpdate)			(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pPart,              /* the plaintext data */
  CK_ULONG          ulPartLen,          /* plaintext data len */
  CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_Encrypt)			(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pData,               /* the plaintext data */
  CK_ULONG          ulDataLen,           /* bytes of plaintext */
  CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
  CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_EncryptFinal)			(
  CK_SESSION_HANDLE hSession,                /* session handle */
  CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
  CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_WrapKey)			(
  CK_SESSION_HANDLE hSession,        /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
  CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
  CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
  CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
  CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_UnwrapKey)			(
  CK_SESSION_HANDLE    hSession,          /* session's handle */
  CK_MECHANISM_PTR     pMechanism,        /* unwrapping mech. */
  CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
  CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
  CK_ULONG             ulWrappedKeyLen,   /* wrapped key len */
  CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
  CK_ULONG             ulAttributeCount,  /* template length */
  CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_DecryptInit)			(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
  CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_DecryptUpdate)			(
  CK_SESSION_HANDLE hSession,            /* session's handle */
  CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
  CK_ULONG          ulEncryptedPartLen,  /* input length */
  CK_BYTE_PTR       pPart,               /* gets plaintext */
  CK_ULONG_PTR      pulPartLen           /* p-text size */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_Decrypt)			(
  CK_SESSION_HANDLE hSession,           /* session's handle */
  CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
  CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
  CK_BYTE_PTR       pData,              /* gets plaintext */
  CK_ULONG_PTR      pulDataLen          /* gets p-text size */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_DecryptFinal)			(
  CK_SESSION_HANDLE hSession,       /* the session's handle */
  CK_BYTE_PTR       pLastPart,      /* gets plaintext */
  CK_ULONG_PTR      pulLastPartLen  /* p-text size */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_GetAttributeValue)			(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs; gets vals */
  CK_ULONG          ulCount     /* attributes in template */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_DestroyObject)			(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_OBJECT_HANDLE  hObject    /* the object's handle */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_CreateObject)			(
  CK_SESSION_HANDLE hSession,    /* the session's handle */
  CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
  CK_ULONG          ulCount,     /* attributes in template */
  CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_SetPIN)			(
  CK_SESSION_HANDLE hSession,  /* the session's handle */
  CK_CHAR_PTR       pOldPin,   /* the old PIN */
  CK_ULONG          ulOldLen,  /* length of the old PIN */
  CK_CHAR_PTR       pNewPin,   /* the new PIN */
  CK_ULONG          ulNewLen   /* length of the new PIN */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_SetAttributeValue)			(
  CK_SESSION_HANDLE hSession,   /* the session's handle */
  CK_OBJECT_HANDLE  hObject,    /* the object's handle */
  CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attrs and values */
  CK_ULONG          ulCount     /* attributes in template */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_GetInfo)			(
  CK_INFO_PTR   pInfo  /* location that receives information */
);
typedef CK_DECLARE_FUNCTION(CK_RV, Type_C_Finalize)			(
  CK_VOID_PTR   pReserved  /* reserved.  Should be NULL_PTR */
);


Type_C_Initialize		(*(Proc_C_Initialize));
Type_C_GetSlotList		(*(Proc_C_GetSlotList));
Type_C_WaitForSlotEvent	(*(Proc_C_WaitForSlotEvent));
Type_C_GetTokenInfo		(*(Proc_C_GetTokenInfo));
Type_C_OpenSession		(*(Proc_C_OpenSession));
Type_C_CloseSession		(*(Proc_C_CloseSession));
Type_C_DigestInit		(*(Proc_C_DigestInit));
Type_C_DigestUpdate		(*(Proc_C_DigestUpdate));
Type_C_DigestFinal		(*(Proc_C_DigestFinal));
Type_C_Login			(*(Proc_C_Login));
Type_C_Logout			(*(Proc_C_Logout));
Type_C_FindObjectsInit	(*(Proc_C_FindObjectsInit));
Type_C_FindObjects	(*(Proc_C_FindObjects));
Type_C_FindObjectsFinal (*(Proc_C_FindObjectsFinal));
Type_C_SignInit			(*(Proc_C_SignInit));
Type_C_Sign				(*(Proc_C_Sign));
Type_C_VerifyInit		(*(Proc_C_VerifyInit));
Type_C_Verify			(*(Proc_C_Verify));
Type_C_GenerateKey		(*(Proc_C_GenerateKey));
Type_C_EncryptInit		(*(Proc_C_EncryptInit));
Type_C_EncryptUpdate	(*(Proc_C_EncryptUpdate));
Type_C_Encrypt			(*(Proc_C_Encrypt));
Type_C_EncryptFinal		(*(Proc_C_EncryptFinal));
Type_C_WrapKey			(*(Proc_C_WrapKey));
Type_C_UnwrapKey		(*(Proc_C_UnwrapKey));
Type_C_DecryptInit		(*(Proc_C_DecryptInit));
Type_C_DecryptUpdate	(*(Proc_C_DecryptUpdate));
Type_C_Decrypt			(*(Proc_C_Decrypt));
Type_C_DecryptFinal		(*(Proc_C_DecryptFinal));
Type_C_GetAttributeValue	(*(Proc_C_GetAttributeValue));
Type_C_DestroyObject	(*(Proc_C_DestroyObject));
Type_C_CreateObject		(*(Proc_C_CreateObject));
Type_C_SetPIN			(*(Proc_C_SetPIN));
Type_C_SetAttributeValue	(*(Proc_C_SetAttributeValue));
Type_C_GetInfo			(*(Proc_C_GetInfo));
Type_C_Finalize			(*(Proc_C_Finalize));



/*********************************************************************
/* Show some info for each slot with a token present and let the user 
/* choose one
/********************************************************************/
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

/*********************************************************************
/* Find objects
/********************************************************************/
void FindObjects(CK_ULONG ulObjectType)
{
	CK_RV             rv        = CKR_OK;
	CK_ULONG          count     = 0;
	CK_SLOT_ID_PTR    pSlots    = NULL;
	CK_ULONG          i         = 0;
	CK_ULONG          j         = 0;
	CK_ULONG          k         = 0;
	CK_ULONG          ul        = 0;
	CK_TOKEN_INFO     tokenInfo;
	CK_SESSION_HANDLE hSession  = 0;
	CK_SLOT_ID        slot      = 0;
	CK_CHAR           ach[256];
	CK_CHAR           ach2[256];
	CK_CHAR           ach3[256];
	CK_CHAR           cert[2048];
	CK_ATTRIBUTE      attributes[4];
	CK_OBJECT_HANDLE  hObjects[10];
	CK_OBJECT_HANDLE  nObjects  = 0;
	FILE              *hFile    = NULL;

	if ((rv = Proc_C_GetSlotList(TRUE, NULL, &count)) != CKR_OK)
	{
		printf("Failed to get slot list, rv = 0x%x\n", rv);
		return;
	}

	pSlots = new CK_SLOT_ID[count];

	if ((rv = Proc_C_GetSlotList(TRUE, pSlots, &count)) != CKR_OK)
	{
		printf("Failed to get slot list, rv = 0x%x\n", rv);
		return;
	}

	printf("\n");
	printf("Slot:Object: Token Label : Object Label : Object ID\n");
	printf("----------------------------------------------------------------\n");

	for (i=0; i<count; i++) 
	{
		ul = ulObjectType;
		attributes[0].type       = CKA_CLASS;
		attributes[0].pValue     = &ul;	
		attributes[0].ulValueLen = sizeof(ul);

		if ((rv = Proc_C_GetTokenInfo(pSlots[i], &tokenInfo)) != CKR_OK)
			;
		else if (Proc_C_OpenSession(pSlots[i], CKF_SERIAL_SESSION, NULL, NULL, &hSession) != CKR_OK)
			;
		else if (Proc_C_FindObjectsInit(hSession, attributes, 1) != CKR_OK)
			;
		else if (Proc_C_FindObjects(hSession, hObjects, 10, &nObjects) != CKR_OK)
			;
		else if (Proc_C_FindObjectsFinal(hSession) != CKR_OK)
			;
		else 
		{
			for (j=0; j<nObjects; j++)
			{
				printf(" %02d :  %02d  : %.*s", i, j, 32, tokenInfo.label);

				attributes[0].type       = CKA_LABEL;
				attributes[0].pValue     = &ach;
				attributes[0].ulValueLen = sizeof(ach);
				attributes[1].type       = CKA_ID;
				attributes[1].pValue     = &ach2;
				attributes[1].ulValueLen = sizeof(ach2);
				attributes[2].type       = CKA_ISSUER;
				attributes[2].pValue     = &ach3;
				attributes[2].ulValueLen = sizeof(ach3);
				if (Proc_C_GetAttributeValue(hSession, hObjects[j], attributes, 3) == CKR_OK)
				{
					printf(" : %.*s :", attributes[0].ulValueLen, attributes[0].pValue);
					for (k=0; k<attributes[1].ulValueLen; ++k)
						printf(" %02X", ach2[k]);
					printf(" : Issuer:");
					for (k=0; k<attributes[2].ulValueLen; ++k)
						printf(" %02X", ach3[k]);
//					printf(" : %.*s", attributes[2].ulValueLen, attributes[2].pValue);
				}

				printf("\n");

			}
		}
		Proc_C_CloseSession(hSession);
	}

	printf("\nWhich slot (0->%d) ? ", count-1);
	gets((char*)ach);
	printf("\n");

	if (ach[0] == 0) return;

	i = atoi((char*)ach);

	printf("Which object (0->x) ? ");
	gets((char*)ach);
	printf("\n");

	if (ach[0] == 0) return;

	j = atoi((char*)ach);

	ul = ulObjectType;
	attributes[0].type       = CKA_CLASS;
	attributes[0].pValue     = &ul;	
	attributes[0].ulValueLen = sizeof(ul);
	
	if (Proc_C_OpenSession(pSlots[i], CKF_SERIAL_SESSION, NULL, NULL, &hSession) != CKR_OK)
		;
	else if (Proc_C_FindObjectsInit(hSession, attributes, 1) != CKR_OK)
		;
	else if (Proc_C_FindObjects(hSession, hObjects, 10, &nObjects) != CKR_OK)
		;
	else if (Proc_C_FindObjectsFinal(hSession) != CKR_OK)
		;
	else	
	{
		attributes[0].type       = CKA_VALUE;
		attributes[0].pValue     = &cert;
		attributes[0].ulValueLen = sizeof(cert);
		Proc_C_GetAttributeValue(hSession, hObjects[j], attributes, 1);
			
	}

	Proc_C_CloseSession(hSession);

	printf("Name of target file? ");
	gets((char*)ach);
	printf("\n");

	if ((hFile = fopen((char*)ach, "wb")) == NULL)
	{
		printf("Failed to open file %s\n", ach);
		return;
	}
	fwrite(attributes[0].pValue, 1, attributes[0].ulValueLen, hFile);
	fclose(hFile);

	delete pSlots;

	return;
}




/*********************************************************************
/* Sign a file. Generate a MD5 hash value of the file, sign the hash 
/* with the chosen private key, write the signature file to disk
/********************************************************************/
void SignFile()
{
	CK_RV             rv        = CKR_OK;
	CK_SESSION_HANDLE hSession  = 0;
	CK_SLOT_ID        slot      = 0;
	CK_CHAR           ach[256];
	CK_CHAR           ach1[256];
	CK_CHAR           ach2[256];
	CK_ATTRIBUTE      attributes[2];
	CK_ULONG          count     = 0;
	CK_ULONG          ul1       = 0;
	CK_ULONG          ul2       = 0;
	CK_ULONG          ul3       = 0;
	CK_ULONG          j         = 0;
	CK_ULONG          k         = 0;
	CK_OBJECT_HANDLE  handles[10];
	CK_MECHANISM      mechanism;
	FILE              *hFile    = NULL;


	if ((rv = GetSlot(&slot)) != CKR_OK)
	{
		printf("Failed to get slot\n", rv);
		return;
	}

	if ((rv = Proc_C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &hSession)) != CKR_OK)
	{
		printf("Failed to open session with CryptoToken, rv = 0x%x\n", rv);
		return;
	}
	
	printf("Enter data file name: ");
	gets((char*)ach1);
	printf("\n");
	
	if ((hFile = fopen((char*)ach1, "rb")) == NULL)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to open file %s\n", ach1);
		return;
	}

	mechanism.mechanism      = CKM_SHA_1;
	mechanism.pParameter     = NULL_PTR;
	mechanism.ulParameterLen = 0;

	if ((rv = Proc_C_DigestInit(hSession, &mechanism)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to init digest, rv = 0x%x\n", rv);
		return;
	}

	while ((ul1 = fread(ach1, 1, sizeof(ach1), hFile)) == sizeof(ach1))
	{
		if ((rv = Proc_C_DigestUpdate(hSession, ach1, ul1)) != CKR_OK)
		{
			fclose(hFile);
			Proc_C_CloseSession(hSession);
			printf("Failed to digest update, rv = 0x%x\n", rv);
			return;
		}
	}

	fclose(hFile);

	if ((rv = Proc_C_DigestUpdate(hSession, ach1, ul1)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to digest update, rv = 0x%x\n", rv);
		return;
	}

	ul1 = sizeof(ach1);
	if ((rv = Proc_C_DigestFinal(hSession, ach1, &ul1)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to digest final, rv = 0x%x\n", rv);
		return;
	}

	Proc_C_CloseSession(hSession);

	if ((rv = Proc_C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &hSession)) != CKR_OK)
	{
		printf("Failed to open session with CryptoToken, rv = 0x%x\n", rv);
		return;
	}
	
/*	printf("Enter PIN: ");
	gets((char*)ach2);
	printf("\n");

	if ((rv = Proc_C_Login(hSession, CKU_USER, ach2, strlen((char*)ach2))) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to logon session, rv = 0x%x\n", rv);
		return;
	} */
	
	ul2 = CKO_PRIVATE_KEY;
	ul3 = CKK_RSA;
	attributes[0].type       = CKA_CLASS;
	attributes[0].pValue     = &ul2;
	attributes[0].ulValueLen = sizeof(ul2);
	attributes[1].type       = CKA_KEY_TYPE;
	attributes[1].pValue     = &ul3;
	attributes[1].ulValueLen = sizeof(ul3);

	if ((rv = Proc_C_FindObjectsInit(hSession, attributes, 2)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to init find operation, rv = 0x%x\n", rv);
		return;
	}

	if ((rv = Proc_C_FindObjects(hSession, handles, 10, &count)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to find objects, rv = 0x%x\n", rv);
		return;
	}

	if ((rv = Proc_C_FindObjectsFinal(hSession)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to final find operation, rv = 0x%x\n", rv);
		return;
	}

	
	printf("%d private keys found.\n", count);

	j=0;

	if (count == 0)
	{
		return;
	}
	if (count > 1)
	{
		for (j=0; j<count; j++)
		{
			attributes[0].type       = CKA_LABEL;
			attributes[0].pValue     = &ach;
			attributes[0].ulValueLen = sizeof(ach);
			attributes[1].type       = CKA_ID;
			attributes[1].pValue     = &ach2;
			attributes[1].ulValueLen = sizeof(ach2);
			if (Proc_C_GetAttributeValue(hSession, handles[j], attributes, 2) == CKR_OK)
			{
				printf("%d: %.*s :", j, attributes[0].ulValueLen, attributes[0].pValue);
				for (k=0; k<attributes[1].ulValueLen; ++k)
					printf(" %02X", ach2[k]);
			}

			printf("\n");

		}

		printf("Which key (0->x) ? ");
		gets((char*)ach);
		printf("\n");

		if (ach[0] == 0) return;

		j = atoi((char*)ach);

	}	
	
	
	
	mechanism.mechanism      = CKM_SHA1_RSA_PKCS;
	mechanism.pParameter     = NULL_PTR;
	mechanism.ulParameterLen = 0;

	if ((rv = Proc_C_SignInit(hSession, &mechanism, handles[j])) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to init sign, rv = 0x%x\n", rv);
		return;
	}

	ul2 = sizeof(ach2);
	if ((rv = Proc_C_Sign(hSession, ach1, ul1, ach2, &ul2)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to sign, rv = 0x%x\n", rv);
		return;
	}

	printf("Enter signature file name: ");
	gets((char*)ach1);
	printf("\n");
	
	if ((hFile = fopen((char*)ach1, "wb")) == NULL)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to open file %s\n", ach1);
		return;
	}

	if (fwrite(ach2, 1, ul2, hFile) != ul2)
	{
		fclose(hFile);
		Proc_C_CloseSession(hSession);
		printf("Failed to write file %s\n", ach1);
		return;
	}

	fclose(hFile);
/*	Proc_C_Logout(hSession); */
	Proc_C_CloseSession(hSession);

	return;
}




/*********************************************************************
/* Verify a signed file. Generate the hash value of the file, read 
/* the signature file and let the user choose the verify key
/********************************************************************/
void VerifyFile()
{
	CK_RV             rv        = CKR_OK;
	CK_SESSION_HANDLE hSession  = 0;
	CK_SLOT_ID        slot      = 0;
	CK_CHAR           ach[256];
	CK_CHAR           ach1[256];
	CK_CHAR           ach2[256];
	CK_ATTRIBUTE      attributes[2];
	CK_ULONG          count     = 0;
	CK_ULONG          ul1       = 0;
	CK_ULONG          ul2       = 0;
	CK_ULONG          ul3       = 0;
	CK_ULONG          j         = 0;
	CK_ULONG          k         = 0;
	CK_OBJECT_HANDLE  handles[10];
	CK_MECHANISM      mechanism;
	FILE              *hFile    = NULL;

	if ((rv = GetSlot(&slot)) != CKR_OK)
	{
		printf("Failed to get slot\n", rv);
		return;
	}

	if ((rv = Proc_C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &hSession)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to open session with CryptoToken, rv = 0x%x\n", rv);
		return;
	}
	
	printf("Enter data file name: ");
	gets((char*)ach1);
	printf("\n");
	
	if ((hFile = fopen((char*)ach1, "rb")) == NULL)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to open file %s\n", ach1);
		return;
	}

	mechanism.mechanism      = CKM_SHA_1;
	mechanism.pParameter     = NULL_PTR;
	mechanism.ulParameterLen = 0;

	if ((rv = Proc_C_DigestInit(hSession, &mechanism)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to init digest, rv = 0x%x\n", rv);
		return;
	}

	while ((ul1 = fread(ach1, 1, sizeof(ach1), hFile)) == sizeof(ach1))
	{
		if ((rv = Proc_C_DigestUpdate(hSession, ach1, ul1)) != CKR_OK)
		{
			fclose(hFile);
			Proc_C_CloseSession(hSession);
			printf("Failed to digest update, rv = 0x%x\n", rv);
			return;
		}
	}

	fclose(hFile);

	if ((rv = Proc_C_DigestUpdate(hSession, ach1, ul1)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to digest update, rv = 0x%x\n", rv);
		return;
	}

	ul1 = sizeof(ach1);
	if ((rv = Proc_C_DigestFinal(hSession, ach1, &ul1)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to digest final, rv = 0x%x\n", rv);
		return;
	}

	Proc_C_CloseSession(hSession);

	if ((rv = Proc_C_OpenSession(slot, CKF_SERIAL_SESSION, NULL, NULL, &hSession)) != CKR_OK)
	{
		printf("Failed to open session, rv = 0x%x\n", rv);
		return;
	}
	
	ul2 = CKO_PUBLIC_KEY;
	ul3 = CKK_RSA;
	attributes[0].type       = CKA_CLASS;
	attributes[0].pValue     = &ul2;
	attributes[0].ulValueLen = sizeof(ul2);
	attributes[1].type       = CKA_KEY_TYPE;
	attributes[1].pValue     = &ul3;
	attributes[1].ulValueLen = sizeof(ul3);

	if ((rv = Proc_C_FindObjectsInit(hSession, attributes, 2)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to init find operation, rv = 0x%x\n", rv);
		return;
	}

	if ((rv = Proc_C_FindObjects(hSession, handles, 10, &count)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to find objects, rv = 0x%x\n", rv);
		return;
	}

	if ((rv = Proc_C_FindObjectsFinal(hSession)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to final find operation, rv = 0x%x\n", rv);
		return;
	}



	printf("%d public keys found.\n", count);

	j=0;

	if (count == 0)
	{
		return;
	}
	if (count > 1)
	{
		for (j=0; j<count; j++)
		{
			attributes[0].type       = CKA_LABEL;
			attributes[0].pValue     = &ach;
			attributes[0].ulValueLen = sizeof(ach);
			attributes[1].type       = CKA_ID;
			attributes[1].pValue     = &ach2;
			attributes[1].ulValueLen = sizeof(ach2);
			if (Proc_C_GetAttributeValue(hSession, handles[j], attributes, 2) == CKR_OK)
			{
				printf("%d: %.*s :", j, attributes[0].ulValueLen, attributes[0].pValue);
				for (k=0; k<attributes[1].ulValueLen; ++k)
					printf(" %02X", ach2[k]);
			}

			printf("\n");

		}

		printf("Which key (0->x) ? ");
		gets((char*)ach);
		printf("\n");

		if (ach[0] == 0) return;

		j = atoi((char*)ach);

	}	
	
	




	printf("Enter signature file name: ");
	gets((char*)ach2);
	printf("\n");

	if ((hFile = fopen((char*)ach2, "rb")) == NULL)
	{
		printf("Failed to open file %s\n", ach1);
		return;
	}

	ul2 = fread(ach2, 1, sizeof(ach2), hFile);

	mechanism.mechanism      = CKM_SHA1_RSA_PKCS;
	mechanism.pParameter     = NULL_PTR;
	mechanism.ulParameterLen = 0;

	if ((rv = Proc_C_VerifyInit(hSession, &mechanism, handles[j])) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to init sign, rv = 0x%x\n", rv);
		return;
	}

	if ((rv = Proc_C_Verify(hSession, ach1, ul1, ach2, ul2)) != CKR_OK)
	{
		Proc_C_CloseSession(hSession);
		printf("Failed to verify, rv = 0x%x\n", rv);
		return;
	}

	Proc_C_CloseSession(hSession);

	printf("Signature OK\n", rv);

	return;
}





/*********************************************************************
/* Check for a inserted card 
/********************************************************************/
void CheckForCard()
{
	CK_RV             rv        = CKR_OK;
	CK_FLAGS		  flags		= CKF_DONT_BLOCK;
	CK_SLOT_ID		  slot;


	printf("Hit any key to abort.\n");

	do
	{

		rv = Proc_C_WaitForSlotEvent(flags,
										&slot,
										NULL_PTR);
		printf("C_WaitForSlotEvent returns 0x%x, slot is %d\n", rv, slot);

		if (kbhit())
			return;

	} while ((rv == CKR_OK) || (rv == CKR_NO_EVENT));

	return;
}













int main()
{
	CK_RV           rv				=	CKR_OK;
	CK_ULONG        count			=	0;
	CK_SLOT_ID_PTR  pSlots			=	NULL;
	CK_ULONG        i				=	0;
	CK_INFO         info;
	CK_TOKEN_INFO   tokenInfo;
	char            ach[10];
	char			sLibraryName[]	=	"asignp11.dll";
	HINSTANCE		hinstLib = NULL;


	printf("PKCS-Test\n");
	printf("=========\n\n");


	// load PKCS11 DLL

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

	while (1)
	{
		printf("\n");
		printf("1. Find Data Objects\n");
		printf("2. Find Certificate Objects\n");
		printf("3. Find Public Key Objects\n");
		printf("4. Find Private Key Objects\n");
		printf("5. Sign File\n");
		printf("6. Verify File\n");
		printf("7. Check for Card\n");

		printf("q. Quit\n");
		printf("\n\n? ");

		gets(ach);

		if (ach[0] == 'q')
			break;

		switch (atoi(ach))
		{
			case 1 : FindObjects(CKO_DATA);			break;
			case 2 : FindObjects(CKO_CERTIFICATE);	break;
			case 3 : FindObjects(CKO_PUBLIC_KEY);	break;
			case 4 : FindObjects(CKO_PRIVATE_KEY);	break;
			case 5 : SignFile();                    break;
			case 6 : VerifyFile();                  break;
			case 7 : CheckForCard();                break;
		}
	}

	if ((rv = Proc_C_Finalize(NULL)) != CKR_OK)
	{
		printf("Failed to finalize PKCS#11 Library, rv = 0x%x\n", rv);
		return 0;
	}

	return 0;
}
