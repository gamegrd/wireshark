/* packet-xbox.h
 *
 */
#include <Windows.h>


 //#define PBYTE   guint8*
#define bool    gint8
#define true    1
#define false   0


typedef bool(_stdcall* Type_NewXbox)();
typedef int(_stdcall* Type_DecryptCC00)(PBYTE pRand, PBYTE pInData, int nInputSize, PBYTE pOutBuff);
typedef int(_stdcall* Type_DecryptCC01)(PBYTE pRand, PBYTE pInData, int nInputSize, PBYTE pOutBuff);
typedef int(_stdcall* Type_DecryptD00D)(PBYTE pBegin, PBYTE pInData, int nInputSize, PBYTE pOutBuff);

extern Type_NewXbox     m_pNewXbox;
extern Type_DecryptCC00 m_pDecryptCC00;
extern Type_DecryptCC01 m_pDecryptCC01;
extern Type_DecryptD00D m_pDecryptD00D;
