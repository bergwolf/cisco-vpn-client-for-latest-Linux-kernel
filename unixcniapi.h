#ifndef UNIXCNIAPI_H
#define UNIXCNIAPI_H

#define CNI_SIGNATURE        "@CNI" 
#define CNI_SIGNATURESIZE    4  

typedef struct  
{  
    uint32 blockSize;
#ifdef _LP64
    uint32 pad1;
    uint32 pad2;
#endif
    /* signature is last, because that is the area most likely to be smashed.*/
    char Signature[CNI_SIGNATURESIZE]; // not a null terminated string!  
} BLOCKINFO, *LPBLOCKINFO;  
  
  
typedef struct  
{  
    PVOID  lpFragmentData;  
    UINT   uiFragmentDataSize;  
    struct FRAGMENTBUFFER * lpPrevious;  
    struct FRAGMENTBUFFER * lpNext;  
}FRAGMENTBUFFER, *LPFRAGMENTBUFFER;  
  
typedef struct  
{  
    char Signature[CNI_SIGNATURESIZE];  
      
    UINT uiPacketSize;  
    UINT uiFragmentCount;  
      
    LPFRAGMENTBUFFER lpHead;  
    LPFRAGMENTBUFFER lpTail;  
} PACKETDESCRIPTOR, *LPPACKETDESCRIPTOR;

#endif //UNIXCNIAPI_H
