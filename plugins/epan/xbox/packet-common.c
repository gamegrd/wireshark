#include "config.h"
#include "packet-common.h"

gint ett_xbox_head = -1;
gint ett_xbox_data = -1;

Type_BaoDebugOutputA m_pDebugOutputA = NULL;
Type_DataFile_Close m_pDataFile_Close = NULL;
Type_DataFile_WriteAppend m_pDataFile_WriteAppend = NULL;
Type_DataFile_Create m_pDataFile_Create = NULL;



struct tagChannelNode m_channelList[ChannelType_Unknow];


//-------------
const char* Channel_GetDiscForType(enum eChannelType   nType)
{
    switch (nType)
    {
    case ChannelType_Video:
        return "Video";
        break;
    case ChannelType_Audio:
        return "Audio";
        break;
    case ChannelType_ChatAudio:
        return "ChatAudio";
        break;
    case ChannelType_Control:
        return "Control";
        break;
    case ChannelType_Input:
        return "Input";
        break;
    case ChannelType_InputFeedback:
        return "InputFeedback";
        break;
    case ChannelType_TcpBase:
        return "TcpBase";
        break;
    case ChannelType_Unknow:
        return "<Unknow1>";
        break;
    default:
        return "<Unknow2>";
        break;
    }
}

void Channel_Init()
{
    memset(&m_channelList, 0, sizeof(struct tagChannelNode) * ChannelType_Unknow);
}

tagChannelNodePtr Channel_GetForID(guint32 nid)
{
    for (int i = ChannelType_Video;i < ChannelType_Unknow;i++)
    {
        if (m_channelList[i].nConnectID == nid)
            return &m_channelList[i];
    }
    if (nid == 0x404)
    {
        m_channelList[ChannelType_Input].nConnectID = 0x404;
        m_channelList[ChannelType_Input].nType = ChannelType_Input;
        return &m_channelList[ChannelType_Input];
    }
    return NULL;
}

tagChannelNodePtr Channel_GetForType(enum eChannelType nType)
{
    return &m_channelList[nType];
}

void Channel_Append(enum eChannelType nChannelType, guint32 nid)
{
    char szbuff[0x100];
    if (nChannelType == ChannelType_Unknow)
    {
        sprintf(szbuff, "ChannelAppend:%d=%X [Unknow]", nChannelType, nid);
        m_pDebugOutputA(szbuff);
        return;
    }

    m_channelList[nChannelType].nType = nChannelType;
    m_channelList[nChannelType].nConnectID = nid;
    m_channelList[nChannelType].nPayLoadLen = 0;
}

void Channel_SetPayloadDataForID(guint32 nid, guint16 nPayLoadLen, guint8* pPayloadData)
{
    if (nPayLoadLen > 0)
    {
        tagChannelNodePtr pct = Channel_GetForID(nid);
        if (pct == NULL)
            return;
        m_channelList[pct->nType].nPayLoadLen = nPayLoadLen;
        memcpy(m_channelList[pct->nType].bPayloadData, pPayloadData, nPayLoadLen);
    }
}





