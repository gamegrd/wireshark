#include "config.h"

#include <epan/packet.h>
#include <stdio.h>
#include <stdlib.h>
#include "packet-xboxudp.h"
#include "packet-common.h"

#define XBOX_UDPPORT 6600


static int proto_xboxudp = -1;

//Head
static gint hf_xboxudp_head = -1;
static gint hf_xboxudp_head_flags = -1;
static gint hf_xboxudp_head_flags_version = -1;
static gint hf_xboxudp_head_flags_padding = -1;
static gint hf_xboxudp_head_flags_extension = -1;
static gint hf_xboxudp_head_flags_csrccount = -1;
static gint hf_xboxudp_head_flags_marker = -1;
static gint hf_xboxudp_head_flags_payloadtype = -1;

#define BIT_xboxudp_head_flags_version      0xC000
#define BIT_xboxudp_head_flags_padding      0x2000
#define BIT_xboxudp_head_flags_extension    0x1000
#define BIT_xboxudp_head_flags_csrccount    0xF00
#define BIT_xboxudp_head_flags_marker       0x80
#define BIT_xboxudp_head_flags_payloadtype  0x7F

static gint hf_xboxudp_head_seq = -1;
static gint hf_xboxudp_head_time = -1;
static gint hf_xboxudp_head_connectid = -1;
static gint hf_xboxudp_head_channelid = -1;

static gint hf_xboxudp_decrypt_data = -1;

static int dissect_xboxudp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);

static const value_string szPayloadTypesudp[] =
{
    {0x23, "Streamer"},
    {0x60, "Control"},
    {0x61, "Channel Control"},
    {0x64, "UDP Handshake"},
    {0, NULL}
};

void proto_register_xboxudp(void)
{
    proto_xboxudp = proto_register_protocol(
        "XBOXUDP Protocol", /* name       */
        "XBOXUDP",      /* short name */
        "xboxudp"       /* abbrev     */
    );

    static hf_register_info hf[] = {
        {
            &hf_xboxudp_head,
            { "xboxudp.head", "xboxudp.head",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------
            &hf_xboxudp_head_flags,
            { "xboxudp.head.flags", "xboxudp.head.flags",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //------------
            &hf_xboxudp_head_flags_version,
            { "xboxudp.head.flags.version", "xboxudp.head.flags.version",
            FT_UINT16, BASE_HEX,
            NULL, BIT_xboxudp_head_flags_version,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_head_flags_padding,
            { "xboxudp.head.flags.padding", "xboxudp.head.flags.padding",
            FT_UINT16, BASE_HEX,
            NULL, BIT_xboxudp_head_flags_padding,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_head_flags_extension,
            { "xboxudp.head.flags.extension", "xboxudp.head.flags.extension",
            FT_UINT16, BASE_HEX,
            NULL, BIT_xboxudp_head_flags_extension,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_head_flags_csrccount,
            { "xboxudp.head.flags.csrccount", "xboxudp.head.flags.csrccount",
            FT_UINT16, BASE_HEX,
            NULL, BIT_xboxudp_head_flags_csrccount,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_head_flags_marker,
            { "xboxudp.head.flags.marker", "xboxudp.head.flags.marker",
            FT_UINT16, BASE_HEX,
            NULL, BIT_xboxudp_head_flags_marker,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_head_flags_payloadtype,
            { "xboxudp.head.flags.payloadtype", "xboxudp.head.flags.payloadtype",
            FT_UINT16, BASE_HEX,
            VALS(szPayloadTypesudp), BIT_xboxudp_head_flags_payloadtype,
            NULL, HFILL }
        },
        //-------------
        {
            &hf_xboxudp_head_seq,
            { "xboxudp.head.seq", "xboxudp.head.seq",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_head_time,
            { "xboxudp.head.time", "xboxudp.head.time",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_head_connectid,
            { "xboxudp.head.connectid", "xboxudp.head.connectid",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_head_channelid,
            { "xboxudp.head.channelid", "xboxudp.head.channelid",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {//--------------------------
            &hf_xboxudp_decrypt_data,
            { "xboxudp.Decrypt.Data", "xboxudp.Decrypt.Data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
         }
    };

    proto_register_field_array(proto_xboxudp, hf, array_length(hf));
}

void proto_reg_handoff_xboxudp(void)
{
    static dissector_handle_t xbox_handle;

    xbox_handle = create_dissector_handle(dissect_xboxudp, proto_xboxudp);
    dissector_add_uint("udp.port", XBOX_UDPPORT, xbox_handle);
}
//
//int dissect_xboxudp_Control_Streamer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, int noffset,struct tagXboxUdpHead *pHead, char *pszTitle)
//{
//    guint offset = noffset;
//    guint nwidth;
//
//    tagChannelNodePtr pcn = Channel_GetForID(pHead->connectid);
//    if (pcn == NULL)
//    {
//        //strcat(pszTitle, "<Unknow.ConnectID>");
//        nwidth = (guint)strlen(pszTitle);
//        sprintf(pszTitle, "<Unknow.CID=%X>", pHead->connectid);
//        return tvb_captured_length(tvb);
//    }
//    else {
//        strcat(pszTitle, ".");
//        strcat(pszTitle, Channel_GetDiscForType(pcn->nType));
//    }
//    //-----
//    nwidth = 4;
//    proto_tree_add_item(tree, hf_xboxtcp_data_Stream_Flags, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
//    offset += nwidth;
//    //-----
//    proto_tree_add_item(tree, hf_xboxtcp_data_Stream_Seq, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
//    offset += nwidth;
//    //-----
//    proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PSeq, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
//    offset += nwidth;
//    //-----
//    nwidth = 4;
//    proto_item* tiPayLoadType = proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PayloadType, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
//    guint32 nPayloadType = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
//    offset += nwidth;
//    //-----
//    proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PayloadLen, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
//    guint32 nPayloadSize = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
//    offset += nwidth;
//
//    switch (pcn->nType)
//    {
//    case ChannelType_Video:
//        switch (nPayloadType)
//        {
//        case PayloadTypeVideoAudio_SeverHandShake:
//            proto_item_append_text(tiPayLoadType, ":SeverHandShake");
//            break;
//        case PayloadTypeVideoAudio_ClientHandShake:
//            proto_item_append_text(tiPayLoadType, ":ClientHandShake");
//            break;
//        case PayloadTypeVideoAudio_Control:
//            proto_item_append_text(tiPayLoadType, ":Control");
//            break;
//        case PayloadTypeVideoAudio_Data:
//            proto_item_append_text(tiPayLoadType, ":Data");
//            break;
//        default:
//            proto_item_append_text(tiPayLoadType, ":Unknow");
//            break;
//        }
//
//        nwidth = offset - noffset;
//        m_pDebugOutputA("      |--Video.begin");
//        nwidth += dissect_xboxtcp_Control_Streamer_Video(tvb, pinfo, tree, data, offset, pHead, pszTitle, nPayloadType, nPayloadSize);
//        m_pDebugOutputA("      |--Video.end");
//        return nwidth;
//        break;
//    case ChannelType_Audio:
//        switch (nPayloadType)
//        {
//        case PayloadTypeVideoAudio_SeverHandShake:
//            proto_item_append_text(tiPayLoadType, ":SeverHandShake");
//            break;
//        case PayloadTypeVideoAudio_ClientHandShake:
//            proto_item_append_text(tiPayLoadType, ":ClientHandShake");
//            break;
//        case PayloadTypeVideoAudio_Control:
//            proto_item_append_text(tiPayLoadType, ":Control");
//            break;
//        case PayloadTypeVideoAudio_Data:
//            proto_item_append_text(tiPayLoadType, ":Data");
//            break;
//        default:
//            proto_item_append_text(tiPayLoadType, ":Unknow");
//            break;
//        }
//
//        nwidth = offset - noffset;
//        m_pDebugOutputA("      |--Audio.begin");
//        nwidth += dissect_xboxtcp_Control_Streamer_Audio(tvb, pinfo, tree, data, offset, pHead, pszTitle, nPayloadType, nPayloadSize);
//        m_pDebugOutputA("      |--Audio.end");
//        return nwidth;
//        break;
//    case ChannelType_ChatAudio:
//        break;
//    case ChannelType_Control:
//        nwidth = offset - noffset;
//        m_pDebugOutputA("      |--Control.begin");
//        nwidth += dissect_xboxtcp_Control_Streamer_Control(tvb, pinfo, tree, data, offset, pHead, pszTitle, nPayloadType, nPayloadSize);
//        m_pDebugOutputA("      |--Control.end");
//        return nwidth;
//
//        break;
//    case ChannelType_Input:
//        switch (nPayloadType)
//        {
//        case PayloadTypeInput_SeverHandShake:
//            proto_item_append_text(tiPayLoadType, ":SeverHandShake");
//            break;
//        case PayloadTypeInput_ClientHandShake:
//            proto_item_append_text(tiPayLoadType, ":ClientHandShake");
//            break;
//        case PayloadTypeInput_FrameAck:
//            proto_item_append_text(tiPayLoadType, ":FrameAck");
//            break;
//        case PayloadTypeInput_Frame:
//            proto_item_append_text(tiPayLoadType, ":Frame");
//            break;
//        default:
//            proto_item_append_text(tiPayLoadType, ":Unknow");
//            break;
//        }
//        nwidth = offset - noffset;
//        m_pDebugOutputA("      |--Input.begin");
//        nwidth += dissect_xboxtcp_Control_Streamer_Input(tvb, pinfo, tree, data, offset, pHead, pszTitle, nPayloadType, nPayloadSize);
//        m_pDebugOutputA("      |--Input.end");
//        return nwidth;
//        break;
//    case ChannelType_InputFeedback:
//        break;
//    case ChannelType_TcpBase:
//        break;
//    default:
//        break;
//    }
//
//    //-----
//    if (nPayloadSize > 0)
//    {
//        nwidth = nPayloadSize;
//        proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PayloadData, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
//        offset += nwidth;
//    }
//    //-----
//    offset += dissect_xboxtcp_Common_PaddingData(tvb, pinfo, tree, data, offset, pHead);
//    //-----
//    nwidth = offset - noffset;
//    //strcat(pszTitle, ".Open");
//    return nwidth;
//}

static int dissect_xboxudp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "XBOXUDP");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);
    //------------------------------------
    //guint16 wcmd = tvb_get_guint16(tvb, 0, ENC_BIG_ENDIAN);
    proto_item* item_top = proto_tree_add_item(tree, proto_xboxudp, tvb, 0, -1, ENC_NA);

    int offset = 0;
    int nwidth;
    proto_item* ti2;
    struct tagXboxTcpHead Head;
    char pszTitle[0X100];
    ////proto_item_append_text(ti, ", Type %s",val_to_str(packet_type, pkt_type_names, "Unknown (0x%02x)"));
    //-----------------------------------------
    nwidth = 2;
    proto_tree* foo_tree_head = proto_item_add_subtree(item_top, ett_xbox_head);
    ti2 = proto_tree_add_item(foo_tree_head, hf_xboxudp_head, tvb, 0, 12, ENC_BIG_ENDIAN);
    proto_item_set_text(ti2, "Head");
    proto_tree* foo_tree_headitems = proto_item_add_subtree(ti2, ett_xbox_head);
    proto_item* ht1 = proto_tree_add_item(foo_tree_headitems, hf_xboxudp_head_flags, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    proto_tree* te2 = proto_item_add_subtree(ht1, ett_xbox_head);
    proto_tree_add_item(te2, hf_xboxudp_head_flags_version, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    proto_tree_add_item(te2, hf_xboxudp_head_flags_padding, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    proto_tree_add_item(te2, hf_xboxudp_head_flags_extension, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    proto_tree_add_item(te2, hf_xboxudp_head_flags_csrccount, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    proto_tree_add_item(te2, hf_xboxudp_head_flags_marker, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    proto_tree_add_item(te2, hf_xboxudp_head_flags_payloadtype, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    Head.flags_payloadtype = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN)& BIT_xboxudp_head_flags_payloadtype;
    Head.flags_padding= tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN) & BIT_xboxudp_head_flags_padding;
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s",val_to_str(Head.flags_payloadtype, szPayloadTypesudp, "(0x%02x)"));
    offset += nwidth;
    //-----
    nwidth = 2;
    proto_tree_add_item(foo_tree_headitems, hf_xboxudp_head_seq, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    //-----
    nwidth = 4;
    proto_tree_add_item(foo_tree_headitems, hf_xboxudp_head_time, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    //-----
    nwidth = 2;
    proto_tree_add_item(foo_tree_headitems, hf_xboxudp_head_channelid, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    Head.channelid = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;
    //-----
    nwidth = 2;
    proto_tree_add_item(foo_tree_headitems, hf_xboxudp_head_connectid, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    Head.connectid = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;
    //-----------------------------------------
    proto_tree* foo_tree_data = proto_item_add_subtree(item_top, ett_xbox_head);
    ti2 = proto_tree_add_item(foo_tree_data, hf_xboxudp_head, tvb, offset, -1, ENC_BIG_ENDIAN);
    proto_item_set_text(ti2, "Data");
    proto_tree* foo_tree_dataitems = proto_item_add_subtree(ti2, ett_xbox_head);
    switch (Head.flags_payloadtype)
    {
    case 0x23:  //Streamer
        strcpy(pszTitle, szPayloadTypesudp[0].strptr);
        nwidth = dissect_xboxudp_Control_Streamer(tvb, pinfo, foo_tree_dataitems,data, offset, &Head, pszTitle);
        proto_item_set_len(ti2, nwidth);
        nwidth += offset;
        proto_item_set_len(item_top, nwidth);
        proto_item_set_text(item_top, pszTitle);
        col_add_fstr(pinfo->cinfo, COL_INFO, pszTitle);
        return nwidth;
        break;
    //case 0x60:  //Control
    //    strcpy(pszTitle, szPayloadTypesudp[1].strptr);
    //    nwidth = dissect_xboxudp_Control_Handshake(tvb, pinfo, foo_tree_dataitems, offset, &Head, pszTitle);
    //    proto_item_set_len(ti2, nwidth);
    //    nwidth += offset;
    //    proto_item_set_len(item_top, nwidth);
    //    proto_item_set_text(item_top, pszTitle);
    //    return nwidth;
    //    break;
    //case 0x61:  //Channel Control
    //    strcpy(pszTitle, szPayloadTypesudp[2].strptr);
    //    nwidth = dissect_xboxudp_Channel_Control(tvb, pinfo, foo_tree_dataitems, offset, &Head, pszTitle);
    //    proto_item_set_len(ti2, nwidth);
    //    nwidth += offset;
    //    proto_item_set_len(item_top, nwidth);
    //    proto_item_set_text(item_top, pszTitle);
    //    return nwidth;
    //    break;
    case 0x64:  //UDP Handshake
        strcpy(pszTitle, szPayloadTypesudp[3].strptr);
        nwidth = dissect_xboxudp_Udp_Handshake(tvb, pinfo, foo_tree_dataitems, data, offset, &Head, pszTitle);
        proto_item_set_len(ti2, nwidth);
        nwidth += offset;
        proto_item_set_len(item_top, nwidth);
        proto_item_set_text(item_top, pszTitle);
        return nwidth;
        break;
    default:
        sprintf(pszTitle, "<Unknow:%x>", Head.flags_payloadtype);
        proto_item_set_text(item_top, pszTitle);
        break;
    }

    col_add_fstr(pinfo->cinfo, COL_INFO, pszTitle);
    //------------------------------------
    return tvb_captured_length(tvb);
}


