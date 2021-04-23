#include "config.h"

#include <epan/packet.h>
#include <stdio.h>
#include <stdlib.h>





extern gint ett_xbox_head;
extern gint ett_xbox_data;


typedef void(_stdcall* Type_BaoDebugOutputA)(const char* szmsg);

typedef void(_stdcall*Type_DataFile_Close)();
typedef void(_stdcall*Type_DataFile_WriteAppend)(const guint8* pdata, int nsize);
typedef guint(_stdcall*Type_DataFile_Create)(const char* szfile);

extern Type_BaoDebugOutputA m_pDebugOutputA;
extern Type_DataFile_Close m_pDataFile_Close;
extern Type_DataFile_WriteAppend m_pDataFile_WriteAppend;
extern Type_DataFile_Create m_pDataFile_Create;


enum eChannelType
{
    ChannelType_Video = 0,
    ChannelType_Audio,
    ChannelType_ChatAudio,
    ChannelType_Control,
    ChannelType_Input,
    ChannelType_InputFeedback,
    ChannelType_TcpBase,
    ChannelType_Unknow
};

typedef struct tagChannelNode {
    enum eChannelType   nType;
    guint32             nConnectID;
    guint16             nPayLoadLen;
    guint8              bPayloadData[0x100];
} *tagChannelNodePtr;


typedef struct tagXboxTcpHead {
    guint32 flags_version;
    guint32 flags_padding;
    guint32 flags_extension;
    guint32 flags_csrccount;
    guint32 flags_marker;
    guint32 flags_payloadtype;
    guint32 seq;
    guint32 time;
    guint32 connectid;
    guint32 channelid;
} tagXboxTcpHeadNode;

const char* Channel_GetDiscForType(enum eChannelType   nType);
void Channel_Init();
tagChannelNodePtr Channel_GetForID(guint32 nid);
tagChannelNodePtr Channel_GetForType(enum eChannelType nType);
void Channel_Append(enum eChannelType nChannelType, guint32 nid);
void Channel_SetPayloadDataForID(guint32 nid, guint16 nPayLoadLen, guint8* pPayloadData);



int dissect_xboxtcp_Control_Streamer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle);
int dissect_xboxudp_Control_Streamer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle);

int dissect_xboxudp_Udp_Handshake(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle);




