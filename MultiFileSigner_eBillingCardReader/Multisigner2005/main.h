#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <string.h>
#include <io.h>

#define max_file 64

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




// FUNKTIONEN
CK_RV				GetSlot(CK_SLOT_ID_PTR pSlot);
void				signingfiles();
int					GetFilesFromDir(char* path,_finddata_t* sfiles);
bool				hashFile(const char* file,CK_CHAR* hash,CK_ULONG* size,CK_SLOT_ID slot);
CK_OBJECT_HANDLE	FindPrivateKey(CK_SESSION_HANDLE hSession,int &key);

struct signPara
{
	char				input[_MAX_PATH];
	char				output[_MAX_PATH];
	CK_CHAR				hash[256];
	CK_ULONG			hashsize;

	CK_CHAR				signature[256];
	CK_ULONG			signaturesize;

	bool				success;
};