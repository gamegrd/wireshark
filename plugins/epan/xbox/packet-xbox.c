#include "config.h"

#include <epan/packet.h>
#include "packet-xbox.h"
#include <stdio.h>
#include <stdlib.h>
#include "packet-common.h"

#define XBOX_PORT 5050

Type_NewXbox     m_pNewXbox=NULL;
Type_DecryptCC00 m_pDecryptCC00=NULL;
Type_DecryptCC01 m_pDecryptCC01 = NULL;
Type_DecryptD00D m_pDecryptD00D = NULL;

static int proto_xbox = -1;

static int hf_xbox_pdu_type = -1;
static int hf_xbox_pdu_size = -1;
static int hf_xbox_pdu_size_subdata = -1;
static int hf_xbox_pdu_size_head = -1;
static int hf_xbox_pdu_size_data = -1;
static int hf_xbox_pdu_ver = -1;
static int hf_xbox_dd00_head_flags = -1;
static int hf_xbox_dd00_head_devtype = -1;

static int hf_xbox_dd00_body_minver= -1;
static int hf_xbox_dd00_body_maxver = -1;

static int hf_xbox_dd01_body_name = -1;
static int hf_xbox_dd01_body_hardware_id = -1;
static int hf_xbox_dd01_body_lasterr = -1;
static int hf_xbox_dd01_body_certificate = -1;
static int hf_xbox_cc00_key_deviceid = -1;
static int hf_xbox_cc00_key_randkey = -1;
static int hf_xbox_cc00_key_pubkey = -1;
static int hf_xbox_cc00_key_keytype = -1;

static int hf_xbox_cc01_body_targetParticipantId = -1;
static int hf_xbox_cc01_body_sourceParticipantId = -1;

static int hf_xbox_d00d_seq = -1;
static int hf_xbox_d00d_tid = -1;
static int hf_xbox_d00d_sid = -1;
static int hf_xbox_d00d_msgtype = -1;
static int hf_xbox_d00d_cid = -1;

static int hf_xbox_d00d_8001_LowWatermark = -1;
static int hf_xbox_d00d_8001_processedListLength = -1;
static int hf_xbox_d00d_8001_ProcessedListItem = -1;
static int hf_xbox_d00d_8001_rejectedListLength = -1;
static int hf_xbox_d00d_8001_rejectedListItem = -1;

static int hf_xbox_d00d_A003_width= -1;
static int hf_xbox_d00d_A003_height = -1;
static int hf_xbox_d00d_A003_dpix = -1;
static int hf_xbox_d00d_A003_dpiy = -1;
static int hf_xbox_d00d_A003_DeviceCapablilities = -1;
static int hf_xbox_d00d_A003_ClientVersion = -1;
static int hf_xbox_d00d_A003_OsMajorVersion = -1;
static int hf_xbox_d00d_A003_OsMinorVersion = -1;
static int hf_xbox_d00d_A003_LOCALNAME = -1;

static int hf_xbox_d00d_A01E_LiveTVProvider = -1;
static int hf_xbox_d00d_A01E_MajorVersion = -1;
static int hf_xbox_d00d_A01E_MinorVersion = -1;
static int hf_xbox_d00d_A01E_BuildNumber = -1;
static int hf_xbox_d00d_A01E_Locale = -1;

static int hf_xbox_d00d_A01E_titlecount = -1;
static int hf_xbox_d00d_A01E_titleid = -1;
static int hf_xbox_d00d_A01E_titleDispostion = -1;
static int hf_xbox_d00d_A01E_ProductID = -1;
static int hf_xbox_d00d_A01E_SandboxID = -1;
static int hf_xbox_d00d_A01E_AumId = -1;

static int hf_xbox_d00d_A026_ChannelRequestId = -1;
static int hf_xbox_d00d_A026_TitleID = -1;
static int hf_xbox_d00d_A026_ServiceUUID = -1;
static int hf_xbox_d00d_A026_ActivityId = -1;

static int hf_xbox_d00d_A027_ChannelRequestId = -1;
static int hf_xbox_d00d_A027_ChannelID = -1;
static int hf_xbox_d00d_A027_Result = -1;


static int hf_xbox_decrypt_data = -1;



static int dissect_xbox(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);


bool InitCryptLib()
{
    if (m_pDecryptCC00 != NULL)
        return true;
    HMODULE hlib = LoadLibraryA("XboxCryptLib.dll");
    if (hlib == NULL)
        return false;
    m_pNewXbox = (Type_NewXbox)GetProcAddress(hlib, "NewXbox");
    m_pDebugOutputA = (Type_BaoDebugOutputA)GetProcAddress(hlib, "BaoDebugOutputA");
    m_pDataFile_Create = (Type_DataFile_Create)GetProcAddress(hlib, "DataFile_Create");
    m_pDataFile_WriteAppend = (Type_DataFile_WriteAppend)GetProcAddress(hlib, "DataFile_WriteAppend");
    m_pDataFile_Close = (Type_DataFile_Close)GetProcAddress(hlib, "DataFile_Close");
    if (m_pNewXbox == NULL)
    {
        return false;
    }
    if (m_pNewXbox() == false)
    {
        return false;
    }
    m_pDecryptCC01 = (Type_DecryptCC01)GetProcAddress(hlib, "DecryptCC01");
    if (m_pDecryptCC01 == NULL)
        return false;
    m_pDecryptD00D = (Type_DecryptD00D)GetProcAddress(hlib, "DecryptD00D");
    m_pDecryptCC00 = (Type_DecryptCC00)GetProcAddress(hlib, "DecryptCC00");

    //m_pDataFile_Create("d:\\receive\\WireShark.Data");

    return true;
}

void proto_register_xbox(void)
{
    proto_xbox = proto_register_protocol(
        "XBOX Protocol", /* name       */
        "XBOX",      /* short name */
        "xbox"       /* abbrev     */
    );

    static hf_register_info hf[] = {
        {
            &hf_xbox_pdu_type,
            { "xbox.type", "xbox.type",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_decrypt_data,
            { "xbox.Decrypt.Data", "xbox.Decrypt.Data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_pdu_size,
            { "xbox.size", "xbox.size",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_pdu_size_head,
            { "xbox.headsize", "xbox.headsize",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_pdu_size_data,
            { "xbox.datasize", "xbox.datasize",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_pdu_size_subdata,
            { "xbox.subsize", "xbox.subsize",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_pdu_ver,
            { "xbox.ver", "xbox.ver",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_dd00_head_flags,
            { "xbox.flags", "xbox.flags",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_dd00_head_devtype,
            { "xbox.devtype", "xbox.devtype",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_dd00_body_minver,
            { "xbox.minver", "xbox.minver",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_dd00_body_maxver,
            { "xbox.maxver", "xbox.maxver",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_dd01_body_name,
            { "xbox.name", "xbox.name",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_dd01_body_hardware_id,
            { "xbox.hardware.id", "xbox.hardware.id",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_dd01_body_lasterr,
            { "xbox.lasterr", "xbox.lasterr",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_dd01_body_certificate,
            { "xbox.certificate", "xbox.certificate",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
         },
        {   //-------------------------------------------------
            &hf_xbox_cc00_key_keytype,
            { "xbox.keytype", "xbox.keytype",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_cc00_key_deviceid,
            { "xbox.deviceid", "xbox.deviceid",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_cc00_key_randkey,
            { "xbox.randkey", "xbox.randkey",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_cc00_key_pubkey,
            { "xbox.pubkey", "xbox.pubkey",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //-------------------------------------------------
            &hf_xbox_cc01_body_targetParticipantId,
            { "xbox.cc01.body.targetParticipantId", "xbox.cc01.body.targetParticipantId",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   
            &hf_xbox_cc01_body_sourceParticipantId,
            { "xbox.cc01.body.sourceParticipantId", "xbox.cc01.body.sourceParticipantId",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {//-------------------------------------------------
            &hf_xbox_d00d_seq,
            { "xbox.d00d.seq", "xbox.d00d.seq",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_tid,
            { "xbox.d00d.tid", "xbox.d00d.tid",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_sid,
            { "xbox.d00d.sid", "xbox.d00d.sid",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_msgtype,
            { "xbox.d00d.msgtype", "xbox.d00d.msgtype",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_cid,
            { "xbox.d00d.cid", "xbox.d00d.cid",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },      
        {   //--------------------------------------------------------------------8001
            &hf_xbox_d00d_8001_LowWatermark,
            { "xbox.d00d.8001.LowWatermark", "xbox.d00d.8001.LowWatermark",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_8001_processedListLength,
            { "xbox.d00d.8001.processedListLength", "xbox.d00d.8001.processedListLength",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_8001_ProcessedListItem,
            { "xbox.d00d.8001.ProcessedListItem", "xbox.d00d.8001.ProcessedListItem",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_8001_rejectedListLength,
            { "xbox.d00d.8001.rejectedListLength", "xbox.d00d.8001.rejectedListLength",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------------------------------------------------A003
            &hf_xbox_d00d_A003_width,
            { "xbox.d00d.A003.width", "xbox.d00d.A003.width",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A003_height,
            { "xbox.d00d.A003.height", "xbox.d00d.A003.height",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A003_dpix,
            { "xbox.d00d.A003.dpix", "xbox.d00d.A003.dpix",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A003_dpiy,
            { "xbox.d00d.A003.dpiy", "xbox.d00d.A003.dpiy",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A003_DeviceCapablilities,
            { "xbox.d00d.A003.DeviceCapablilities", "xbox.d00d.A003.DeviceCapablilities",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A003_ClientVersion,
            { "xbox.d00d.A003.ClientVersion", "xbox.d00d.A003.ClientVersion",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A003_OsMajorVersion,
            { "xbox.d00d.A003.OsMajorVersion", "xbox.d00d.A003.OsMajorVersion",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A003_OsMinorVersion,
            { "xbox.d00d.A003.OsMinorVersion", "xbox.d00d.A003.OsMinorVersion",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A003_LOCALNAME,
            { "xbox.d00d.A003.LOCALNAME", "xbox.d00d.A003.LOCALNAME",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------------------------------------------------A01E
            &hf_xbox_d00d_A01E_titlecount,
            { "xbox.d00d.A01E.count", "xbox.d00d.A01E.count",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   
            &hf_xbox_d00d_A01E_LiveTVProvider,
            { "xbox.d00d.A01E.LiveTVProvider", "xbox.d00d.A01E.LiveTVProvider",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A01E_MajorVersion,
            { "xbox.d00d.A01E.MajorVersion", "xbox.d00d.A01E.MajorVersion",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A01E_MinorVersion,
            { "xbox.d00d.A01E.MinorVersion", "xbox.d00d.A01E.MinorVersion",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A01E_BuildNumber,
            { "xbox.d00d.A01E.BuildNumber", "xbox.d00d.A01E.BuildNumber",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A01E_Locale,
            { "xbox.d00d.A01E.Locale", "xbox.d00d.A01E.Locale",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A01E_titleid,
            { "xbox.d00d.A01E.titleID", "xbox.d00d.A01E.titleID",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A01E_titleDispostion,
            { "xbox.d00d.A01E.titleDispostion", "xbox.d00d.A01E.titleDispostion",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A01E_ProductID,
            { "xbox.d00d.A01E.ProductID", "xbox.d00d.A01E.ProductID",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A01E_SandboxID,
            { "xbox.d00d.A01E.SandboxID", "xbox.d00d.A01E.SandboxID",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A01E_AumId,
            { "xbox.d00d.A01E.AumId", "xbox.d00d.A01E.AumId",
            FT_STRINGZ, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------------------------------------------------A026
            &hf_xbox_d00d_A026_ChannelRequestId,
            { "xbox.d00d.A026.ChannelRequestId", "xbox.d00d.A026.ChannelRequestId",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A026_TitleID,
            { "xbox.d00d.A026.titleID", "xbox.d00d.A026.titleID",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A026_ServiceUUID,
            { "xbox.d00d.A026.ServiceUUID", "xbox.d00d.A026.ServiceUUID",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A026_ActivityId,
            { "xbox.d00d.A026.ActivityId", "xbox.d00d.A026.ActivityId",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------------------------------------------------A027
            &hf_xbox_d00d_A027_ChannelRequestId,
            { "xbox.d00d.A027.ChannelRequestId", "xbox.d00d.A027.ChannelRequestId",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A027_ChannelID,
            { "xbox.d00d.A027.ChannelID", "xbox.d00d.A027.ChannelID",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xbox_d00d_A027_Result,
            { "xbox.d00d.A027.Result", "xbox.d00d.A027.Result",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //------------------------------------------------------------------------
            &hf_xbox_d00d_8001_rejectedListItem,
            { "xbox.d00d.8001.rejectedListItem", "xbox.d00d.8001.rejectedListItem",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        }
    };
    proto_register_field_array(proto_xbox, hf, array_length(hf));

    /* Setup protocol subtree array */
    static gint* ett[] = {
        &ett_xbox_head,
        &ett_xbox_data
    };


    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_xbox(void)
{
    static dissector_handle_t xbox_handle;

    xbox_handle = create_dissector_handle(dissect_xbox, proto_xbox);
    dissector_add_uint("udp.port", XBOX_PORT, xbox_handle);
}

static int dissect_xbox_dd00(proto_item* ti, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    int offset = 0;
    int nwidth = 2;
    proto_item* ti2;

    //-----------------------------------------
    proto_tree* foo_tree_head = proto_item_add_subtree(ti, ett_xbox_head);
    proto_tree* foo_tree_headitems;

    ti2 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, 0, 6, ENC_NA);
    proto_item_set_text(ti2, "Head");
    foo_tree_headitems = proto_item_add_subtree(ti2, ett_xbox_head);
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_type, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_size, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_ver, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;

    //-----------------------------------------
    proto_item* ti3 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, 6, -1, ENC_NA);
    proto_item_set_text(ti3, "Data");
    proto_tree* foo_tree_data = proto_item_add_subtree(ti3, ett_xbox_head);
    nwidth = 4;
    proto_tree_add_item(foo_tree_data, hf_xbox_dd00_head_flags, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 2;
    proto_tree_add_item(foo_tree_data, hf_xbox_dd00_head_devtype, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_dd00_body_minver, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_dd00_body_maxver, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;

    return 0;
}
static int dissect_xbox_dd01(proto_item* ti, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    int offset = 0;
    int nwidth = 2;
    proto_item* ti2;

    //proto_item_append_text(ti, ", Type %s",val_to_str(packet_type, pkt_type_names, "Unknown (0x%02x)"));
    //-----------------------------------------
    proto_tree* foo_tree_head = proto_item_add_subtree(ti, ett_xbox_head);
    proto_tree* foo_tree_headitems;

    ti2 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, 0, 6, ENC_NA);
    proto_item_set_text(ti2, "Head");
    foo_tree_headitems = proto_item_add_subtree(ti2, ett_xbox_head);
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_type, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_size_head, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_ver, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;

    //-----------------------------------------
    proto_item* ti3 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, 6, -1, ENC_NA);
    proto_item_set_text(ti3, "Data");
    proto_tree* foo_tree_data = proto_item_add_subtree(ti3, ett_xbox_head);
    nwidth = 4;
    proto_tree_add_item(foo_tree_data, hf_xbox_dd00_head_flags, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 2;
    proto_tree_add_item(foo_tree_data, hf_xbox_dd00_head_devtype, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    guint16 wlen = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(foo_tree_data, hf_xbox_pdu_size_subdata, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_dd01_body_name, tvb, offset, wlen, ENC_BIG_ENDIAN);
    offset += wlen;
    offset++;
    wlen = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(foo_tree_data, hf_xbox_pdu_size_subdata, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_dd01_body_hardware_id, tvb, offset, wlen, ENC_BIG_ENDIAN);
    offset += wlen;
    offset++;
    nwidth = 4;
    proto_tree_add_item(foo_tree_data, hf_xbox_dd01_body_lasterr, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 2;
    wlen = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    proto_tree_add_item(foo_tree_data, hf_xbox_pdu_size_subdata, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_dd01_body_certificate, tvb, offset, wlen, ENC_BIG_ENDIAN);
    offset += wlen;
    //-----------------------------------------

    return 0;
}

int dissect_xbox_cc00(proto_item* ti, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    int offset = 0;
    int nwidth = 2;
    proto_item* ti2;
    if (InitCryptLib() == false)
    {
        proto_tree* foo_tree_head = proto_item_add_subtree(ti, ett_xbox_head);
        ti2 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, 0, 6, ENC_NA);
        proto_item_set_text(ti2, "Load Xbox DeCrypt Lib.Error");
        return 0;
    }
    //-----------------------------------------
    proto_tree* foo_tree_head = proto_item_add_subtree(ti, ett_xbox_head);
    proto_tree* foo_tree_headitems;
    guint16 wsize_head, wsize_data, wsize_data_ori;

    ti2 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, 0, 8, ENC_NA);
    proto_item_set_text(ti2, "Head");
    foo_tree_headitems = proto_item_add_subtree(ti2, ett_xbox_head);
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_type, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_size_head, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    wsize_head = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_size_data, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    wsize_data = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    wsize_data_ori = wsize_data;
    if ((wsize_data % 16) != 0)
    {
        wsize_data = wsize_data / 16+1;
        wsize_data = wsize_data * 16;
    }
    offset += nwidth;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_ver, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;

    //-----------------------------------------
    proto_item* ti3 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, offset, wsize_head, ENC_NA);
    proto_item_set_text(ti3, "Key");
    proto_tree* foo_tree_data = proto_item_add_subtree(ti3, ett_xbox_head);
    nwidth = 0x10;
    proto_tree_add_item(foo_tree_data, hf_xbox_cc00_key_deviceid, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 2;
    proto_tree_add_item(foo_tree_data, hf_xbox_cc00_key_keytype, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 0x40;
    proto_tree_add_item(foo_tree_data, hf_xbox_cc00_key_pubkey, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 0x10;
    proto_tree_add_item(foo_tree_data, hf_xbox_cc00_key_randkey, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    PBYTE pRandkey= (PBYTE)tvb_get_ptr(tvb, offset,nwidth);
    offset += nwidth;
    //-----------------------------------------
    ti3 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, offset, wsize_data, ENC_NA);
    proto_item_set_text(ti3, "Data");
    foo_tree_data = proto_item_add_subtree(ti3, ett_xbox_head);
    PBYTE pInputData = (PBYTE)tvb_get_ptr(tvb, offset, wsize_data);
    guchar* decrypt_buffer = (guchar*)wmem_alloc(pinfo->pool, wsize_data);
    m_pDecryptCC00(pRandkey, pInputData, wsize_data,decrypt_buffer);
    tvbuff_t *next_tvb = tvb_new_child_real_data(tvb, decrypt_buffer, wsize_data, wsize_data);
    add_new_data_source(pinfo, next_tvb, "DeCrypt Data");
    int offset2 = 0;
    //int nwidth2 = 0;
    proto_tree_add_item(foo_tree_data, hf_xbox_decrypt_data, next_tvb, offset2, -1, ENC_BIG_ENDIAN);

    //-----------------------------------------
    offset += wsize_data;
    ti3 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, offset, -1, ENC_NA);
    proto_item_set_text(ti3, "Hash");

    return 0;
}

int dissect_xbox_cc01_body(proto_item* ti, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    guint32 offset = 0;
    guint32 nwidth;
    //-----------------------------------------
    proto_item* foo_tree_data = proto_item_add_subtree(ti, ett_xbox_head);
    //-----
    nwidth = 4;
    proto_tree_add_item(foo_tree_data, hf_xbox_cc01_body_targetParticipantId, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_cc01_body_sourceParticipantId, tvb, offset, nwidth, ENC_BIG_ENDIAN);

    return 0;
}


int dissect_xbox_cc01(proto_item* ti, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    int offset = 0;
    int nwidth = 2;
    proto_item* ti2;

    //proto_item_append_text(ti, ", Type %s",val_to_str(packet_type, pkt_type_names, "Unknown (0x%02x)"));
    //-----------------------------------------
    proto_tree* foo_tree_head = proto_item_add_subtree(ti, ett_xbox_head);
    proto_tree* foo_tree_headitems;
    guint16 wsize_head, wsize_data, wsize_data_ori;

    ti2 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, 0, 8, ENC_NA);
    proto_item_set_text(ti2, "Head");
    foo_tree_headitems = proto_item_add_subtree(ti2, ett_xbox_head);
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_type, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_size_head, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    wsize_head = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_size_data, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    wsize_data = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    wsize_data_ori = wsize_data;
    if ((wsize_data % 16) != 0)
    {
        wsize_data = wsize_data / 16 + 1;
        wsize_data = wsize_data * 16;
    }
    offset += nwidth;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_ver, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;

    //-----------------------------------------
    proto_item* ti3 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, offset, wsize_head, ENC_NA);
    proto_item_set_text(ti3, "Key");
    proto_tree* foo_tree_data = proto_item_add_subtree(ti3, ett_xbox_head);
    nwidth = 0x10;
    proto_tree_add_item(foo_tree_data, hf_xbox_cc00_key_randkey, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    PBYTE pRandkey = (PBYTE)tvb_get_ptr(tvb, offset, nwidth);
    offset += nwidth;
    //-----------------------------------------
    ti3 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, offset, wsize_data, ENC_NA);
    proto_item_set_text(ti3, "Data");
    foo_tree_data = proto_item_add_subtree(ti3, ett_xbox_head);
    PBYTE pInputData = (PBYTE)tvb_get_ptr(tvb, offset, wsize_data);
    guchar* decrypt_buffer = (guchar*)wmem_alloc(pinfo->pool, wsize_data);
    m_pDecryptCC01(pRandkey, pInputData, wsize_data, decrypt_buffer);
    tvbuff_t* next_tvb = tvb_new_child_real_data(tvb, decrypt_buffer, wsize_data, wsize_data);
    add_new_data_source(pinfo, next_tvb, "DeCrypt Data");
    int offset2 = 0;
    proto_tree_add_item(foo_tree_data, hf_xbox_decrypt_data, next_tvb, offset2, -1, ENC_BIG_ENDIAN);
    dissect_xbox_cc01_body(ti3,next_tvb,pinfo,tree,data);
    //-----------------------------------------
    offset += wsize_data;
    ti3 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, offset, -1, ENC_NA);
    proto_item_set_text(ti3, "Hash");

    return 0;
}

int dissect_xbox_d00d_8001(proto_item* ti, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    guint32 offset = 0;
    guint32 nwidth = 4;
    proto_item* ti2;
    //-----------------------------------------
    proto_tree* foo_tree_headitems;
    guint32 ncount,i;
    guint32 nmaxsize = tvb_captured_length(tvb);
    ti2 = ti;
    foo_tree_headitems = proto_item_add_subtree(ti2, ett_xbox_head);
    proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_8001_LowWatermark, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_8001_processedListLength, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    ncount = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;
    if (nmaxsize <= offset)
        return 0;
    for (i = 0;i < ncount;i++)
    {
        proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_8001_ProcessedListItem, tvb, offset, nwidth, ENC_BIG_ENDIAN);
        offset += nwidth;
        if (nmaxsize <= offset)
            return 0;
    }
    proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_8001_rejectedListLength, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    ncount = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;
    if (nmaxsize <= offset)
        return 0;
    for (i = 0;i < ncount;i++)
    {
        proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_8001_rejectedListItem, tvb, offset, nwidth, ENC_BIG_ENDIAN);
        offset += nwidth;
        if (nmaxsize <= offset)
            return 0;
    }

    return 0;
}
int dissect_xbox_d00d_A003(proto_item* ti, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    guint32 offset = 0;
    guint32 nwidth;
    guint16 nsize;
    //-----------------------------------------
    proto_item* foo_tree_data = proto_item_add_subtree(ti, ett_xbox_head);
    //-----
    nwidth = 2;
    proto_tree_add_item(foo_tree_data, hf_xbox_dd00_head_devtype, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    //-----
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A003_width, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A003_height, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A003_dpix, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A003_dpiy, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 8;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A003_DeviceCapablilities, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 4;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A003_ClientVersion, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A003_OsMajorVersion, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A003_OsMinorVersion, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;

    nwidth = 2;
    proto_tree_add_item(foo_tree_data, hf_xbox_pdu_size_head, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    nsize = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;

    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A003_LOCALNAME, tvb, offset, nsize, ENC_BIG_ENDIAN);
    offset += nwidth;

    return 0;
}
int dissect_xbox_d00d_A01E(proto_item* ti, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    guint32 offset = 0;
    guint32 nwidth;
    guint16 nsize;
    guint16 ncount;
    //-----------------------------------------
    proto_item* foo_tree_data = proto_item_add_subtree(ti, ett_xbox_head);
    //-----
    nwidth = 4;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A01E_LiveTVProvider, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A01E_MajorVersion, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A01E_MinorVersion, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A01E_BuildNumber, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 2;
    proto_tree_add_item(foo_tree_data, hf_xbox_pdu_size_head, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    nsize = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN)+1;
    offset += nwidth;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A01E_Locale, tvb, offset, nsize, ENC_BIG_ENDIAN);
    offset += nsize;

    //-----
    nwidth = 2;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A01E_titlecount, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    ncount = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;
    for (guint16 i = 0;i < ncount;i++)
    {
        nwidth = 4;
        proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A01E_titleid, tvb, offset, nwidth, ENC_BIG_ENDIAN);
        offset += nwidth;
        nwidth = 2;
        proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A01E_titleDispostion, tvb, offset, nwidth, ENC_BIG_ENDIAN);
        offset += nwidth;
        nwidth = 16;
        proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A01E_ProductID, tvb, offset, nwidth, ENC_BIG_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A01E_SandboxID, tvb, offset, nwidth, ENC_BIG_ENDIAN);
        offset += nwidth;
        nwidth = 2;
        proto_tree_add_item(foo_tree_data, hf_xbox_pdu_size_head, tvb, offset, nwidth, ENC_BIG_ENDIAN);
        nsize = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN)+1;
        offset += nwidth;
        proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A01E_AumId, tvb, offset, nsize, ENC_BIG_ENDIAN);
        offset += nsize;
    }

    return 0;
}
int dissect_xbox_d00d_A026(proto_item* ti, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    guint32 offset = 0;
    guint32 nwidth;
    //-----------------------------------------
    proto_item* foo_tree_data = proto_item_add_subtree(ti, ett_xbox_head);
    //-----
    nwidth = 4;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A026_ChannelRequestId, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 4;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A026_TitleID, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 16;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A026_ServiceUUID, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 4;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A026_ActivityId, tvb, offset, nwidth, ENC_BIG_ENDIAN);

    return 0;
}
int dissect_xbox_d00d_A027(proto_item* ti, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    guint32 offset = 0;
    guint32 nwidth;
    //-----------------------------------------
    proto_item* foo_tree_data = proto_item_add_subtree(ti, ett_xbox_head);
    //-----
    nwidth = 4;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A027_ChannelRequestId, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 8;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A027_ChannelID, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 4;
    proto_tree_add_item(foo_tree_data, hf_xbox_d00d_A027_Result, tvb, offset, nwidth, ENC_BIG_ENDIAN);

    return 0;
}
int dissect_xbox_d00d_a001(proto_item* ti, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    guint32 offset = 0;
    guint32 nwidth = 4;
    proto_item* ti2;
    //-----------------------------------------
    proto_tree* foo_tree_headitems;
    guint32 ncount,i;
    guint32 nmaxsize = tvb_captured_length(tvb);
    ti2 = ti;
    foo_tree_headitems = proto_item_add_subtree(ti2, ett_xbox_head);
    proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_8001_LowWatermark, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_8001_processedListLength, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    ncount = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;
    if (nmaxsize <= offset)
        return 0;
    for (i = 0;i < ncount;i++)
    {
        proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_8001_ProcessedListItem, tvb, offset, nwidth, ENC_BIG_ENDIAN);
        offset += nwidth;
        if (nmaxsize <= offset)
            return 0;
    }
    proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_8001_rejectedListLength, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    ncount = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;
    if (nmaxsize <= offset)
        return 0;
    for (i = 0;i < ncount;i++)
    {
        proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_8001_rejectedListItem, tvb, offset, nwidth, ENC_BIG_ENDIAN);
        offset += nwidth;
        if (nmaxsize <= offset)
            return 0;
    }

    return 0;
}

int dissect_xbox_d00d(proto_item* ti, tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    int offset = 0;
    int nwidth = 2;
    proto_item* ti2;

    //proto_item_append_text(ti, ", Type %s",val_to_str(packet_type, pkt_type_names, "Unknown (0x%02x)"));
    //-----------------------------------------
    proto_tree* foo_tree_head = proto_item_add_subtree(ti, ett_xbox_head);
    proto_tree* foo_tree_headitems;
    guint16 wsize_data, wmsgtype;

    ti2 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, 0, 6, ENC_NA);
    proto_item_set_text(ti2, "Head");
    foo_tree_headitems = proto_item_add_subtree(ti2, ett_xbox_head);
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_type, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_pdu_size_data, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    wsize_data = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    if ((wsize_data % 16) != 0)
    {
        wsize_data = wsize_data / 16 + 1;
        wsize_data = wsize_data * 16;
    }

    offset += nwidth;
    nwidth = 4;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_seq, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 4;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_tid, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 4;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_sid, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 2;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_msgtype, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    wmsgtype = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;
    nwidth = 8;
    proto_tree_add_item(foo_tree_headitems, hf_xbox_d00d_cid, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;

    //-----------------------------------------
    proto_item* ti3 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, offset, wsize_data, ENC_NA);
    proto_item_set_text(ti3, "Data");
    proto_tree* foo_tree_data = proto_item_add_subtree(ti3, ett_xbox_head);
    PBYTE pInputData = (PBYTE)tvb_get_ptr(tvb, offset, wsize_data);
    guchar* decrypt_buffer = (guchar*)wmem_alloc(pinfo->pool, wsize_data);
    PBYTE pbegin = (PBYTE)tvb_get_ptr(tvb, 0, 0x10);

    m_pDecryptD00D(pbegin, pInputData, wsize_data, decrypt_buffer);
    tvbuff_t* next_tvb = tvb_new_child_real_data(tvb, decrypt_buffer, wsize_data, wsize_data);
    add_new_data_source(pinfo, next_tvb, "DeCrypt Data");
    int offset2 = 0;
    //int nwidth2 = 0;
    proto_item* ti4 = proto_tree_add_item(foo_tree_data, hf_xbox_decrypt_data, next_tvb, offset2, -1, ENC_BIG_ENDIAN);
    switch (wmsgtype)
    {
    case 0xa001:
        dissect_xbox_d00d_a001(ti4, next_tvb, pinfo, tree, data);
        break;
    case 0x8001:
        dissect_xbox_d00d_8001(ti4, next_tvb, pinfo, tree, data);
        break;
    case 0xA003:
        dissect_xbox_d00d_A003(ti4, next_tvb, pinfo, tree, data);
        break;
    case 0xA01E:
        dissect_xbox_d00d_A01E(ti4, next_tvb, pinfo, tree, data);
        break;
    case 0xA026:
        dissect_xbox_d00d_A026(ti4, next_tvb, pinfo, tree, data);
        break;
    case 0xA027:
        dissect_xbox_d00d_A027(ti4, next_tvb, pinfo, tree, data);
        break;
    default:
        break;
    }

    //-----------------------------------------
    offset += wsize_data;
    ti3 = proto_tree_add_item(foo_tree_head, ett_xbox_head, tvb, offset, -1, ENC_NA);
    proto_item_set_text(ti3, "Hash");
    //-----------------------------------------

    return 0;
}


static int dissect_xbox(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "XBOX");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);
    //------------------------------------
    guint16 wcmd = tvb_get_guint16(tvb, 0, ENC_BIG_ENDIAN);
    proto_item* ti = proto_tree_add_item(tree, proto_xbox, tvb, 0, -1, ENC_NA);


    switch (wcmd)
    {
    case 0xdd00:
        dissect_xbox_dd00(ti,tvb, pinfo, tree, data);
        break;
    case 0xdd01:
        dissect_xbox_dd01(ti, tvb, pinfo, tree, data);
        break;
    case 0xcc00:
        dissect_xbox_cc00(ti, tvb, pinfo, tree, data);
        break;
    case 0xcc01:
        dissect_xbox_cc01(ti, tvb, pinfo, tree, data);
        break;
    case 0xd00d:
        dissect_xbox_d00d(ti, tvb, pinfo, tree, data);
        break;
    default:
        proto_tree_add_item(tree, hf_xbox_pdu_type, tvb, 0, 2, ENC_BIG_ENDIAN);
        break;
    }
    //------------------------------------
    return tvb_captured_length(tvb);
}


