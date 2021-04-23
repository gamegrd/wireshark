#include "config.h"

#include <epan/packet.h>
#include <stdio.h>
#include <stdlib.h>
#include "packet-xboxtcp.h"
#include "packet-common.h"

#define XBOX_TCPPORT 6600

static int proto_xboxtcp = -1;

//Head
static gint hf_xboxtcp_head = -1;
static gint hf_xboxtcp_head_flags1 = -1;
static gint hf_xboxtcp_head_flags2 = -1;
static gint hf_xboxtcp_head_flags_version = -1;
static gint hf_xboxtcp_head_flags_padding = -1;
static gint hf_xboxtcp_head_flags_extension = -1;
static gint hf_xboxtcp_head_flags_csrccount = -1;
static gint hf_xboxtcp_head_flags_marker = -1;
static gint hf_xboxtcp_head_flags_payloadtype = -1;


#define BIT_xboxtcp_head_flags_version      0xC0
#define BIT_xboxtcp_head_flags_padding      0x20
#define BIT_xboxtcp_head_flags_extension    0x10
#define BIT_xboxtcp_head_flags_csrccount    0xF

#define BIT_xboxtcp_head_flags_marker       0x80
#define BIT_xboxtcp_head_flags_payloadtype  0x7F

//-------------
static gint hf_xboxtcp_head_seq= -1;
static gint hf_xboxtcp_head_time= -1;
static gint hf_xboxtcp_head_connectid= -1;
static gint hf_xboxtcp_head_channelid = -1;
static gint hf_xboxtcp_head_unknow = -1;

//-------------
static gint hf_xboxtcp_decrypt_data = -1;

//-------------
static gint hf_xboxtcp_data_Control_Handshake_type = -1;
static gint hf_xboxtcp_data_Control_Handshake_connectid = -1;

static gint hf_xboxudp_data_Handshake_type = -1;
//-------------
static gint hf_xboxtcp_data_Channel_Control_Type = -1;
static gint hf_xboxtcp_data_Channel_Control_Flags = -1;

//-------------
static gint hf_xboxtcp_data_common_string_len = -1;
static gint hf_xboxtcp_data_common_string_buffer = -1;

//-------------
static gint hf_xboxtcp_data_Channel_Control_FlagsLen = -1;
static gint hf_xboxtcp_data_Channel_Control_FlagsData = -1;

//-------------
static gint hf_xboxtcp_data_Stream_Flags=-1;
static gint hf_xboxtcp_data_Stream_Seq = -1;
static gint hf_xboxtcp_data_Stream_PSeq = -1;
static gint hf_xboxtcp_data_Stream_PayloadType = -1;
static gint hf_xboxtcp_data_Stream_PayloadLen = -1;
static gint hf_xboxtcp_data_Stream_PayloadData = -1;
//-------------
static gint hf_xboxtcp_data_Stream_Audio_Channels = -1;
static gint hf_xboxtcp_data_Stream_Audio_SampleRate = -1;
static gint hf_xboxtcp_data_Stream_Audio_AudioCodec = -1;
static gint hf_xboxtcp_data_Stream_Audio_BitDepth = -1;
static gint hf_xboxtcp_data_Stream_Audio_Type = -1;
//-------------
static gint hf_xboxtcp_data_Stream_Video_FPS = -1;
static gint hf_xboxtcp_data_Stream_Video_Width = -1;
static gint hf_xboxtcp_data_Stream_Video_Height = -1;
static gint hf_xboxtcp_data_Stream_Video_VideoCodes = -1;
enum eVideoCodeTypes {
    VideoCode_H264=0,
    VideoCode_YUV,
    VideoCode_RGB
};
static gint hf_xboxtcp_data_Stream_Video_Bpp = -1;
static gint hf_xboxtcp_data_Stream_Video_Bytes = -1;
static gint hf_xboxtcp_data_Stream_Video_RMask = -1;
static gint hf_xboxtcp_data_Stream_Video_GMask = -1;
static gint hf_xboxtcp_data_Stream_Video_BMask = -1;

static gint hf_xboxtcp_data_Stream_Video_InitialFrameId = -1;

static gint hf_xboxtcp_data_Stream_Video_ProtocolVersion = -1;
static gint hf_xboxtcp_data_Stream_Video_ReterenceTimestamp = -1;
static gint hf_xboxtcp_data_Stream_Video_FormatsLength = -1;
static gint hf_xboxtcp_data_Stream_Video_VideoFormats = -1;
static gint hf_xboxtcp_data_Stream_Video_VideoFormatInfo = -1;

static gint hf_xboxtcp_data_Stream_Control_Flag = -1;
enum eVideoControlFlags {
    VideoControlFlag_RequestKeyframe=4,
    VideoControlFlag_StartStream=8,
    VideoControlFlag_StopStream=0x10,
    VideoControlFlag_QueueDepth=0x20,
    VideoControlFlag_LostFreames=0x40,
    VideoControlFlag_LastDisplayedFrame=0x80
};
//-------------
static gint hf_xboxtcp_data_Stream_Input_Key_DPadUp = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_DPadDown = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_DPadLeft = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_DPadRight = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_Start = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_Back = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_Left_thumbsitck = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_Right_thumbsitck = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_Leftshoulder = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_rightshouder = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_Guide = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_Unknow = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_A = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_B = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_X = -1;
static gint hf_xboxtcp_data_Stream_Input_Key_Y = -1;

static gint hf_xboxtcp_data_Stream_Input_Analog_LeftTrigger = -1;
static gint hf_xboxtcp_data_Stream_Input_Analog_RightTrigger = -1;
static gint hf_xboxtcp_data_Stream_Input_Analog_LeftthumbstickX = -1;
static gint hf_xboxtcp_data_Stream_Input_Analog_LeftthumbstickY = -1;
static gint hf_xboxtcp_data_Stream_Input_Analog_RightthumbstickX = -1;
static gint hf_xboxtcp_data_Stream_Input_Analog_RightthumbstickY = -1;
static gint hf_xboxtcp_data_Stream_Input_Analog_LeftRumbleTrigger = -1;
static gint hf_xboxtcp_data_Stream_Input_Analog_RightRumbleTrigger = -1;
static gint hf_xboxtcp_data_Stream_Input_Analog_LeftRumblehandle = -1;
static gint hf_xboxtcp_data_Stream_Input_Analog_RightRumblehandle = -1;

static gint hf_xboxtcp_data_Stream_Input_Extension_Unknow1 = -1;
static gint hf_xboxtcp_data_Stream_Input_Extension_Unknow2 = -1;
static gint hf_xboxtcp_data_Stream_Input_Extension_LeftRumbleTrigger2 = -1;
static gint hf_xboxtcp_data_Stream_Input_Extension_RightRumbleTrigger2 = -1;
static gint hf_xboxtcp_data_Stream_Input_Extension_LeftRumblehandle2 = -1;
static gint hf_xboxtcp_data_Stream_Input_Extension_RightRumblehandle2 = -1;
static gint hf_xboxtcp_data_Stream_Input_Extension_Unknow3 = -1;
static gint hf_xboxtcp_data_Stream_Input_Extension_Unknow4 = -1;
static gint hf_xboxtcp_data_Stream_Input_Extension_Unknow5 = -1;


static gint hf_xboxtcp_data_Stream_Input_ServerHand_ProtocolVer = -1;
static gint hf_xboxtcp_data_Stream_Input_ServerHand_DesktopWidth = -1;
static gint hf_xboxtcp_data_Stream_Input_ServerHand_DesktopHeight = -1;
static gint hf_xboxtcp_data_Stream_Input_ServerHand_MaxTouches = -1;
static gint hf_xboxtcp_data_Stream_Input_ServerHand_InitFrameID = -1;

static gint hf_xboxtcp_data_Stream_Input_ClientHand_MaxTouches = -1;
static gint hf_xboxtcp_data_Stream_Input_ClientHand_ReferenceTimestamp = -1;

static gint hf_xboxtcp_data_Stream_Input_FrameAck_AckedFrame = -1;

static gint hf_xboxtcp_data_Stream_Input_Frame_FrameID = -1;
static gint hf_xboxtcp_data_Stream_Input_Frame_Timestamp = -1;
static gint hf_xboxtcp_data_Stream_Input_Frame_CreatedTimestamp = -1;
static gint hf_xboxtcp_data_Stream_Input_Frame_InputButtonModel = -1;
static gint hf_xboxtcp_data_Stream_Input_Frame_InputAnalogModel = -1;
static gint hf_xboxtcp_data_Stream_Input_Frame_InputExtensionModel = -1;

//-------------
static gint hf_xboxtcp_data_Stream_Control_Head_PSeq = -1;
static gint hf_xboxtcp_data_Stream_Control_Head_Unknow1 = -1;
static gint hf_xboxtcp_data_Stream_Control_Head_Unknow2 = -1;
static gint hf_xboxtcp_data_Stream_Control_Head_PayLoadType = -1;
static gint hf_xboxtcp_data_Stream_Control_Head_PayloadData = -1;

static gint hf_xboxtcp_data_Stream_Control_SessionInit_Unknow = -1;

static gint hf_xboxtcp_data_Stream_Control_SessionCreate_length = -1;
static gint hf_xboxtcp_data_Stream_Control_SessionCreate_Unknow = -1;

static gint hf_xboxtcp_data_Stream_Control_SessionCreateR_Unknow = -1;

static gint hf_xboxtcp_data_Stream_Control_SessionDestory_Unknow1 = -1;
static gint hf_xboxtcp_data_Stream_Control_SessionDestory_Length = -1;
static gint hf_xboxtcp_data_Stream_Control_SessionDestory_Unknow2 = -1;

static gint hf_xboxtcp_data_Stream_Control_VideoStatistics_Unknow = -1;
//-------------
static gint hf_xboxtcp_data_Stream_Control_RealtimeTelemetry_FieldCount = -1;

static gint hf_xboxtcp_data_Stream_Control_RealtimeTelemetry_TelemetryField_key = -1;
static gint hf_xboxtcp_data_Stream_Control_RealtimeTelemetry_TelemetryField_value = -1;

//-------------
static gint hf_xboxtcp_data_Stream_Control_ChangeVideoQuality_Unknow = -1;

static gint hf_xboxtcp_data_Stream_Control_InitiateNetworktest_unknow= -1;

static gint hf_xboxtcp_data_Stream_Control_NetworkInfo_unknow1 = -1;
static gint hf_xboxtcp_data_Stream_Control_NetworkInfo_unknow2 = -1;
static gint hf_xboxtcp_data_Stream_Control_NetworkInfo_unknow3 = -1;

static gint hf_xboxtcp_data_Stream_Control_NetworkTstR_unknow = -1;

static gint hf_xboxtcp_data_Stream_Control_ControllerEvent_Event = -1;
static gint hf_xboxtcp_data_Stream_Control_ControllerEvent_ControllerNumber = -1;
//-------------
static gint hf_xboxudp_video_data_Flags = -1;
static gint hf_xboxudp_video_data_FrameId = -1;
static gint hf_xboxudp_video_data_Timestamp = -1;
static gint hf_xboxudp_video_data_Totalsize = -1;
static gint hf_xboxudp_video_data_Packetcount = -1;
static gint hf_xboxudp_video_data_Offset = -1;
static gint hf_xboxudp_video_data_DataLen = -1;
static gint hf_xboxudp_video_data_Data = -1;
//-------------
static gint hf_xboxtcp_data_common_paddingdata = -1;

//-------------
enum ePayloadTypeVideoAudio {
    PayloadTypeVideoAudio_SeverHandShake=1,
    PayloadTypeVideoAudio_ClientHandShake,
    PayloadTypeVideoAudio_Control,
    PayloadTypeVideoAudio_Data
};
//static const value_string szPayloadTypes_VideoAudio[] =
//{
//    {1, "ServerHandShark"},
//    {2, "ClientHandShark"},
//    {3, "Control"},
//    {4, "Data"},
//    {0, NULL}
//};

enum ePayloadTypeInput {
    PayloadTypeInput_SeverHandShake = 1,
    PayloadTypeInput_ClientHandShake,
    PayloadTypeInput_FrameAck,
    PayloadTypeInput_Frame
};
//static const value_string szPayloadTypes_Input[] =
//{
//    {1, "ServerHandShark"},
//    {2, "ClientHandShark"},
//    {3, "FrameAck"},
//    {4, "Frame"},
//    {0, NULL}
//};

//Control Payload Type
//Type	Value
enum eControlPayloadType {
    CPT_Session_Init = 0x01,
    CPT_Session_Create,
    CPT_Session_Create_Response,
    CPT_Session_Destroy,
    CPT_Video_Statistics,
    CPT_Realtime_Telemetry,
    CPT_Change_Video_Quality,
    CPT_Initiate_Network_Test,
    CPT_Network_Information,
    CPT_Network_Test_Response,
    CPT_Controller_Event
};

//-------------



static int dissect_xboxtcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_);

static const value_string szPayloadTypestcp[] =
{
    {0x23, "Streamer"},
    {0x60, "Control"},
    {0x61, "Channel Control"},
    {0x64, "UDP Handshake"},
    {0, NULL}
};

void proto_register_xboxtcp(void)
{
    proto_xboxtcp = proto_register_protocol(
        "XBOXTCP Protocol", /* name       */
        "XBOXTCP",      /* short name */
        "xboxtcp"       /* abbrev     */
    );

    static hf_register_info hf[] = {
        {
            &hf_xboxtcp_head,
            { "xboxtcp.head", "xboxtcp.head",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_common_paddingdata,
            { "xboxtcp.data.common.paddingdata", "xboxtcp.data.common.paddingdata",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_common_string_len,
            { "xboxtcp.data.string.len", "xboxtcp.data.string.len",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_common_string_buffer,
            { "xboxtcp.data.string.buffer", "xboxtcp.data.string.buffer",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------
            &hf_xboxtcp_head_flags1,
            { "xboxtcp.head.flags1", "xboxtcp.head.flags1",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------
            &hf_xboxtcp_head_flags2,
            { "xboxtcp.head.flags2", "xboxtcp.head.flags2",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //------------
            &hf_xboxtcp_head_flags_version,
            { "xboxtcp.head.flags.version", "xboxtcp.head.flags.version",
            FT_UINT16, BASE_HEX,
            NULL, BIT_xboxtcp_head_flags_version,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_head_flags_padding,
            { "xboxtcp.head.flags.padding", "xboxtcp.head.flags.padding",
            FT_UINT16, BASE_HEX,
            NULL, BIT_xboxtcp_head_flags_padding,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_head_flags_extension,
            { "xboxtcp.head.flags.extension", "xboxtcp.head.flags.extension",
            FT_UINT16, BASE_HEX,
            NULL, BIT_xboxtcp_head_flags_extension,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_head_flags_csrccount,
            { "xboxtcp.head.flags.csrccount", "xboxtcp.head.flags.csrccount",
            FT_UINT16, BASE_HEX,
            NULL, BIT_xboxtcp_head_flags_csrccount,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_head_flags_marker,
            { "xboxtcp.head.flags.marker", "xboxtcp.head.flags.marker",
            FT_UINT16, BASE_HEX,
            NULL, BIT_xboxtcp_head_flags_marker,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_head_flags_payloadtype,
            { "xboxtcp.head.flags.payloadtype", "xboxtcp.head.flags.payloadtype",
            FT_UINT16, BASE_HEX,
            VALS(szPayloadTypestcp), BIT_xboxtcp_head_flags_payloadtype,
            NULL, HFILL }
        },
        //-------------
        {   
            &hf_xboxtcp_head_seq,
            { "xboxtcp.head.seq", "xboxtcp.head.seq",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   
            &hf_xboxtcp_head_time,
            { "xboxtcp.head.time", "xboxtcp.head.time",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   
            &hf_xboxtcp_head_connectid,
            { "xboxtcp.head.connectid", "xboxtcp.head.connectid",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   
            &hf_xboxtcp_head_channelid,
            { "xboxtcp.head.channelid", "xboxtcp.head.channelid",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------    Udp
            &hf_xboxudp_data_Handshake_type,
            { "xboxudp.Handshake.type", "xboxudp.Handshake.type",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------    Control
            &hf_xboxtcp_data_Control_Handshake_type,
            { "xboxtcp.data.Control_Handshake.type", "xboxtcp.data.Control_Handshake.type",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   
            &hf_xboxtcp_data_Control_Handshake_connectid,
            { "xboxtcp.data.Control_Handshake.connectid", "xboxtcp.data.Control_Handshake.connectid",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------    Channel
            &hf_xboxtcp_data_Channel_Control_Type,
            { "xboxtcp.data.Channel.Control.type", "xboxtcp.data.Channel.Control.type",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   
            &hf_xboxtcp_data_Channel_Control_Flags,
            { "xboxtcp.data.Channel.Control.Flags", "xboxtcp.data.Channel.Control.Flags",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   
            &hf_xboxtcp_data_Channel_Control_FlagsLen,
            { "xboxtcp.data.Channel.Control.FlagsLen", "xboxtcp.data.Channel.Control.FlagsLen",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   
            &hf_xboxtcp_data_Channel_Control_FlagsData,
            { "xboxtcp.data.Channel.Control.FlagsData", "xboxtcp.data.Channel.Control.FlagsData",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------    Stream
            &hf_xboxtcp_data_Stream_Flags,
            { "xboxtcp.data.Stream.Flags", "xboxtcp.data.Stream.Flags",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Seq,
            { "xboxtcp.data.Stream.Seq", "xboxtcp.data.Stream.Seq",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_PSeq,
            { "xboxtcp.data.Stream.PSeq", "xboxtcp.data.Stream.PSeq",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_PayloadType,
            { "xboxtcp.data.Stream.PayloadType", "xboxtcp.data.Stream.PayloadType",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_PayloadLen,
            { "xboxtcp.data.Stream.PayloadLen", "xboxtcp.data.Stream.PayloadLen",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_PayloadData,
            { "xboxtcp.data.Stream.PayloadData", "xboxtcp.data.Stream.PayloadData",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------    Stream.Control
            &hf_xboxtcp_data_Stream_Control_ControllerEvent_Event,
            { "xboxtcp.data.Stream.Control.ControllerEvent.Event", "xboxtcp.data.Stream.Control.ControllerEvent.Event",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   
            &hf_xboxtcp_data_Stream_Control_ControllerEvent_ControllerNumber,
            { "xboxtcp.data.Stream.Control.ControllerEvent.ControllerNumber", "xboxtcp.data.Stream.Control.ControllerEvent.ControllerNumber",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------    Stream.Audio
            &hf_xboxtcp_data_Stream_Audio_Channels,
            { "xboxtcp.data.Stream.Audio.Channels", "xboxtcp.data.Stream.Audio.Channels",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Audio_SampleRate,
            { "xboxtcp.data.Stream.Audio.SampleRate", "xboxtcp.data.Stream.Audio.SampleRate",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Audio_AudioCodec,
            { "xboxtcp.data.Stream.Audio.AudioCodec", "xboxtcp.data.Stream.Audio.AudioCodec",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Audio_BitDepth,
            { "xboxtcp.data.Stream.Audio.BitDepth", "xboxtcp.data.Stream.Audio.BitDepth",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Audio_Type,
            { "xboxtcp.data.Stream.Audio.Type", "xboxtcp.data.Stream.Audio.Type",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------    Stream.Video
            &hf_xboxtcp_data_Stream_Video_FPS,
            { "xboxtcp.data.Stream.Video.FPS", "xboxtcp.data.Stream.Video.FPS",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_Width,
            { "xboxtcp.data.Stream.Video.Width", "xboxtcp.data.Stream.Video.Width",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_Height,
            { "xboxtcp.data.Stream.Video.Height", "xboxtcp.data.Stream.Video.Height",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_VideoCodes,
            { "xboxtcp.data.Stream.Video.VideoCodes", "xboxtcp.data.Stream.Video.VideoCodes",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_Bpp,
            { "xboxtcp.data.Stream.Video.Bpp", "xboxtcp.data.Stream.Video.Bpp",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_Bytes,
            { "xboxtcp.data.Stream.Video.Bytes", "xboxtcp.data.Stream.Video.Bytes",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_RMask,
            { "xboxtcp.data.Stream.Video.RMask", "xboxtcp.data.Stream.Video.RMask",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_GMask,
            { "xboxtcp.data.Stream.Video.GMask", "xboxtcp.data.Stream.Video.GMask",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_BMask,
            { "xboxtcp.data.Stream.Video.BMask", "xboxtcp.data.Stream.Video.BMask",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_ProtocolVersion,
            { "xboxtcp.data.Stream.Video.ProtocolVersion", "xboxtcp.data.Stream.Video.ProtocolVersion",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_ReterenceTimestamp,
            { "xboxtcp.data.Stream.Video.ReterenceTimestamp", "xboxtcp.data.Stream.Video.ReterenceTimestamp",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_FormatsLength,
            { "xboxtcp.data.Stream.Video.FormatsLength", "xboxtcp.data.Stream.Video.FormatsLength",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_VideoFormats,
            { "xboxtcp.data.Stream.Video.VideoFormats", "xboxtcp.data.Stream.Video.VideoFormats",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_VideoFormatInfo,
            { "xboxtcp.data.Stream.Video.VideoFormatInfo", "xboxtcp.data.Stream.Video.VideoFormatInfo",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Video_InitialFrameId,
            { "xboxtcp.data.Stream.Video.InitialFrameId", "xboxtcp.data.Stream.Video.InitialFrameId",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
         {   //--------------------------    Stream.Input
            &hf_xboxtcp_data_Stream_Input_Key_DPadUp,
            { "xboxtcp.data.Stream.Input.Key.DPadUp", "xboxtcp.data.Stream.Input.Key.DPadUp",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_DPadDown,
            { "xboxtcp.data.Stream.Input.Key.DPadDown", "xboxtcp.data.Stream.Input.Key.DPadDown",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_DPadLeft,
            { "xboxtcp.data.Stream.Input.Key.DPadLeft", "xboxtcp.data.Stream.Input.Key.DPadLeft",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_DPadRight,
            { "xboxtcp.data.Stream.Input.Key.DPadRight", "xboxtcp.data.Stream.Input.Key.DPadRight",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_Start,
            { "xboxtcp.data.Stream.Input.Key.Start", "xboxtcp.data.Stream.Input.Key.Start",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_Back,
            { "xboxtcp.data.Stream.Input.Key.Back", "xboxtcp.data.Stream.Input.Key.Back",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_Left_thumbsitck,
            { "xboxtcp.data.Stream.Input.Key.Leftthumbstick", "xboxtcp.data.Stream.Input.Key.Leftthumbstick",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_Right_thumbsitck,
            { "xboxtcp.data.Stream.Input.Key.Rightthumbstick", "xboxtcp.data.Stream.Input.Key.Rightthumbstick",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_Leftshoulder,
            { "xboxtcp.data.Stream.Input.Key.Leftshoulder", "xboxtcp.data.Stream.Input.Key.Leftshoulder",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_rightshouder,
            { "xboxtcp.data.Stream.Input.Key.Rightshouder", "xboxtcp.data.Stream.Input.Key.Rightshouder",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_Guide,
            { "xboxtcp.data.Stream.Input.Key.Guide", "xboxtcp.data.Stream.Input.Key.Guide",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_Unknow,
            { "xboxtcp.data.Stream.Input.Key.Unknow", "xboxtcp.data.Stream.Input.Key.Unknow",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_A,
            { "xboxtcp.data.Stream.Input.Key.A", "xboxtcp.data.Stream.Input.Key.A",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_B,
            { "xboxtcp.data.Stream.Input.Key.B", "xboxtcp.data.Stream.Input.Key.B",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_X,
            { "xboxtcp.data.Stream.Input.Key.X", "xboxtcp.data.Stream.Input.Key.X",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Key_Y,
            { "xboxtcp.data.Stream.Input.Key.Y", "xboxtcp.data.Stream.Input.Key.Y",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //-------------------
            &hf_xboxtcp_data_Stream_Input_Analog_LeftTrigger,
            { "xboxtcp.data.Stream.Input.Analog.LeftTrigger", "xboxtcp.data.Stream.Input.Analog.LeftTrigger",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Analog_RightTrigger,
            { "xboxtcp.data.Stream.Input.Analog.RightTrigger", "xboxtcp.data.Stream.Input.Analog.RightTrigger",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Analog_LeftthumbstickX,
            { "xboxtcp.data.Stream.Input.Analog.LeftthumbstickX", "xboxtcp.data.Stream.Input.Analog.LeftthumbstickX",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Analog_LeftthumbstickY,
            { "xboxtcp.data.Stream.Input.Analog.LeftthumbstickY", "xboxtcp.data.Stream.Input.Analog.LeftthumbstickY",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Analog_RightthumbstickX,
            { "xboxtcp.data.Stream.Input.Analog.RightthumbstickX", "xboxtcp.data.Stream.Input.Analog.RightthumbstickX",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Analog_RightthumbstickY,
            { "xboxtcp.data.Stream.Input.Analog.RightthumbstickY", "xboxtcp.data.Stream.Input.Analog.RightthumbstickY",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Analog_LeftRumbleTrigger,
            { "xboxtcp.data.Stream.Input.Analog.LeftRumbleTrigger", "xboxtcp.data.Stream.Input.Analog.LeftRumbleTrigger",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Analog_RightRumbleTrigger,
            { "xboxtcp.data.Stream.Input.Analog.RightRumbleTrigger", "xboxtcp.data.Stream.Input.Analog.RightRumbleTrigger",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Analog_LeftRumblehandle,
            { "xboxtcp.data.Stream.Input.Analog.LeftRumblehandle", "xboxtcp.data.Stream.Input.Analog.LeftRumblehandle",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Analog_RightRumblehandle,
            { "xboxtcp.data.Stream.Input.Analog.RightRumblehandle", "xboxtcp.data.Stream.Input.Analog.RightRumblehandle",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //------------------
            &hf_xboxtcp_data_Stream_Input_Extension_Unknow1,
            { "xboxtcp.data.Stream.Input.Extension.Unknow1", "xboxtcp.data.Stream.Input.Extension.Unknow1",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Extension_Unknow2,
            { "xboxtcp.data.Stream.Input.Extension.Unknow2", "xboxtcp.data.Stream.Input.Extension.Unknow2",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Extension_LeftRumbleTrigger2,
            { "xboxtcp.data.Stream.Input.Extension.LeftRumbleTrigger2", "xboxtcp.data.Stream.Input.Extension.LeftRumbleTrigger2",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Extension_RightRumbleTrigger2,
            { "xboxtcp.data.Stream.Input.Extension.RightRumbleTrigger2", "xboxtcp.data.Stream.Input.Extension.RightRumbleTrigger2",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Extension_LeftRumblehandle2,
            { "xboxtcp.data.Stream.Input.Extension.LeftRumblehandle2", "xboxtcp.data.Stream.Input.Extension.LeftRumblehandle2",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Extension_RightRumblehandle2,
            { "xboxtcp.data.Stream.Input.Extension.RightRumblehandle2", "xboxtcp.data.Stream.Input.Extension.RightRumblehandle2",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Extension_Unknow3,
            { "xboxtcp.data.Stream.Input.Extension.Unknow3", "xboxtcp.data.Stream.Input.Extension.Unknow3",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Extension_Unknow4,
            { "xboxtcp.data.Stream.Input.Extension.Unknow4", "xboxtcp.data.Stream.Input.Extension.Unknow4",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Extension_Unknow5,
            { "xboxtcp.data.Stream.Input.Extension.Unknow5", "xboxtcp.data.Stream.Input.Extension.Unknow5",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },

        {       //----------------------
            &hf_xboxtcp_data_Stream_Input_ServerHand_ProtocolVer,
            { "xboxtcp.data.Stream.Input.ServerHand.ProtocolVer", "xboxtcp.data.Stream.Input.ServerHand.ProtocolVer",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_ServerHand_DesktopWidth,
            { "xboxtcp.data.Stream.Input.ServerHand.DesktopWidth", "xboxtcp.data.Stream.Input.ServerHand.DesktopWidth",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_ServerHand_DesktopHeight,
            { "xboxtcp.data.Stream.Input.ServerHand.DesktopHeight", "xboxtcp.data.Stream.Input.ServerHand.DesktopHeight",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_ServerHand_MaxTouches,
            { "xboxtcp.data.Stream.Input.ServerHand.MaxTouches", "xboxtcp.data.Stream.Input.ServerHand.MaxTouches",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_ClientHand_MaxTouches,
            { "xboxtcp.data.Stream.Input.ClientHand.MaxTouches", "xboxtcp.data.Stream.Input.ClientHand.MaxTouches",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_ClientHand_ReferenceTimestamp,
            { "xboxtcp.data.Stream.Input.ClientHand.ReferenceTimestamp", "xboxtcp.data.Stream.Input.ClientHand.ReferenceTimestamp",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_FrameAck_AckedFrame,
            { "xboxtcp.data.Stream.Input.FrameAck.AckedFrame", "xboxtcp.data.Stream.Input.FrameAck.AckedFrame",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Frame_FrameID,
            { "xboxtcp.data.Stream.Input.Frame.FrameID", "xboxtcp.data.Stream.Input.Frame.FrameID",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Frame_Timestamp,
            { "xboxtcp.data.Stream.Input.Frame.Timestamp", "xboxtcp.data.Stream.Input.Frame.Timestamp",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Frame_CreatedTimestamp,
            { "xboxtcp.data.Stream.Input.Frame.CreatedTimestamp", "xboxtcp.data.Stream.Input.Frame.CreatedTimestamp",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Frame_InputButtonModel,
            { "xboxtcp.data.Stream.Input.Frame.InputButtonModel", "xboxtcp.data.Stream.Input.Frame.InputButtonModel",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Frame_InputAnalogModel,
            { "xboxtcp.data.Stream.Input.Frame.InputAnalogModel", "xboxtcp.data.Stream.Input.Frame.InputAnalogModel",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Input_Frame_InputExtensionModel,
            { "xboxtcp.data.Stream.Input.Frame.InputExtensionModel", "xboxtcp.data.Stream.Input.Frame.InputExtensionModel",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------    Stream.Control
            &hf_xboxtcp_data_Stream_Control_Head_PSeq,
            { "xboxtcp.data.Stream.Control.Head.PSeq", "xboxtcp.data.Stream.Control.Head.PSeq",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Control_Head_Unknow1,
            { "xboxtcp.data.Stream.Control.Head.Unknow1", "xboxtcp.data.Stream.Control.Head.Unknow1",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Control_Head_Unknow2,
            { "xboxtcp.data.Stream.Control.Head.Unknow2", "xboxtcp.data.Stream.Control.Head.Unknow2",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Control_Head_PayLoadType,
            { "xboxtcp.data.Stream.Control.Head.PayLoadType", "xboxtcp.data.Stream.Control.Head.PayLoadType",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Control_Head_PayloadData,
            { "xboxtcp.data.Stream.Control.Head.PayloadData", "xboxtcp.data.Stream.Control.Head.PayloadData",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Control_Flag,
            { "xboxtcp.data.Stream.Control.Flag", "xboxtcp.data.Stream.Control.Flag",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Control_RealtimeTelemetry_FieldCount,
            { "xboxtcp.data.Stream.Control.RealtimeTelemetry.FieldCount", "xboxtcp.data.Stream.Control.RealtimeTelemetry.FieldCount",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Control_RealtimeTelemetry_TelemetryField_key,
            { "xboxtcp.data.Stream.Control.RealtimeTelemetry.TelemetryField.key", "xboxtcp.data.Stream.Control.RealtimeTelemetry.TelemetryField.key",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Control_RealtimeTelemetry_TelemetryField_value,
            { "xboxtcp.data.Stream.Control.RealtimeTelemetry.TelemetryField.value", "xboxtcp.data.Stream.Control.RealtimeTelemetry.TelemetryField.value",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxtcp_data_Stream_Control_ChangeVideoQuality_Unknow,
            { "xboxtcp.data.Stream.Control.ChangeVideoQuality.Unknow", "xboxtcp.data.Stream.Control.ChangeVideoQuality.Unknow",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   //--------------------------    Video.Data
            &hf_xboxudp_video_data_Flags,
            { "xboxudp.video.data.Flags", "xboxudp.video.data.Flags",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {   
            &hf_xboxudp_video_data_FrameId,
            { "xboxudp.video.data.FrameId", "xboxudp.video.data.FrameId",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_video_data_Timestamp,
            { "xboxudp.video.data.Timestamp", "xboxudp.video.data.Timestamp",
            FT_UINT64, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_video_data_Totalsize,
            { "xboxudp.video.data.Totalsize", "xboxudp.video.data.Totalsize",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_video_data_Packetcount,
            { "xboxudp.video.data.Packetcount", "xboxudp.video.data.Packetcount",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_video_data_Offset,
            { "xboxudp.video.data.Offset", "xboxudp.video.data.Offset",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_video_data_DataLen,
            { "xboxudp.video.data.DataLen", "xboxudp.video.data.DataLen",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        {
            &hf_xboxudp_video_data_Data,
            { "xboxudp.video.data.Data", "xboxudp.video.data.Data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

       {//--------------------------
            &hf_xboxtcp_decrypt_data,
            { "xboxtcp.Decrypt.Data", "xboxtcp.Decrypt.Data",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
         }
    };
    Channel_Init();
    proto_register_field_array(proto_xboxtcp, hf, array_length(hf));
}

void proto_reg_handoff_xboxtcp(void)
{
    static dissector_handle_t xbox_handle;

    xbox_handle = create_dissector_handle(dissect_xboxtcp, proto_xboxtcp);
    dissector_add_uint("tcp.port", XBOX_TCPPORT, xbox_handle);
}

int dissect_xboxtcp_common_string(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset,char *pname,gboolean bZero,char *pszResult,int nMaxsize)
{
    int offset = noffset;
    int nwidth;
    guint16 wlen = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    int ntotalsize = wlen + 2;

    if (bZero)
        ntotalsize++;

    proto_item* ti1 = proto_tree_add_item(tree, hf_xboxtcp_head, tvb, noffset, ntotalsize, ENC_LITTLE_ENDIAN);
    proto_item_set_text(ti1, pname);
    proto_tree* foo_tree_headitems1 = proto_item_add_subtree(ti1, ett_xbox_head);

    //-----
    nwidth = 2;
    proto_tree_add_item(foo_tree_headitems1, hf_xboxtcp_data_common_string_len, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    nwidth = wlen;
    proto_tree_add_item(foo_tree_headitems1, hf_xboxtcp_data_common_string_buffer, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    if(nMaxsize>0)
    if (pszResult != NULL)
    {
        if ((guint16)nMaxsize < (wlen-1))
        {
            wlen=(guint16)nMaxsize-1;
        }
        strcpy(pszResult, (char*)tvb_get_ptr(tvb, offset, wlen));
    }
    offset += nwidth;

    return ntotalsize;
}

int dissect_xboxtcp_Common_PaddingData(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead)
{
    //hf_xboxtcp_data_common_paddingdata
    int rn = 0;
    if (pHead->flags_padding)
    {
        int ni, nc = 3;
        guint8 tb;
        for (ni = 0;ni < nc;ni++)
        {
            tb = tvb_get_guint8(tvb, noffset + ni);
            if (tb == 0)
                continue;
            if (tb < 4)
            {
                rn = tb;
                break;
            }
        }
        if (rn > 0)
        {
            proto_tree_add_item(tree, hf_xboxtcp_data_common_paddingdata, tvb, noffset, rn, ENC_LITTLE_ENDIAN);
        }
    }
    return rn;
}

static int dissect_xboxtcp_Control_Handshake(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset,struct tagXboxTcpHead *pHead, char* pszTitle)
{
    int offset = noffset;
    int nwidth;
    //-----
    nwidth = 1;
    proto_tree_add_item(tree, hf_xboxtcp_data_Control_Handshake_type, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    nwidth = 2;
    proto_tree_add_item(tree, hf_xboxtcp_data_Control_Handshake_connectid, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
     //-----
    offset += dissect_xboxtcp_Common_PaddingData(tvb, pinfo, tree, data, offset, pHead);
     //-----
    nwidth = offset - noffset;
    strcat(pszTitle, ".Handshake");

    return nwidth;
}
int dissect_xboxudp_Udp_Handshake(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle)
{
    int offset = noffset;
    int nwidth;
    //-----
    nwidth = 1;
    proto_tree_add_item(tree, hf_xboxudp_data_Handshake_type, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    offset += dissect_xboxtcp_Common_PaddingData(tvb, pinfo, tree, data, offset, pHead);
    //-----
    nwidth = offset - noffset;
    strcat(pszTitle, ".Handshake");

    return nwidth;
}

static int dissect_xboxtcp_Channel_Control_Create(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle)
{
    guint offset = noffset;
    guint nwidth;
    char szbuff[0x80] = {0};
    
    //-----
    offset += dissect_xboxtcp_common_string(tvb, pinfo, tree, data, offset, "Channel Name",FALSE, szbuff,0x80);

    enum eChannelType   nType = ChannelType_Unknow;
    if (_stricmp(szbuff, "Microsoft::Rdp::Dct::Channel::Class::Video") == 0)
    {
        nType = ChannelType_Video;
    }else
    if (_stricmp(szbuff, "Microsoft::Rdp::Dct::Channel::Class::Audio") == 0)
    {
        nType = ChannelType_Audio;
    }
    else
    if (_stricmp(szbuff, "Microsoft::Rdp::Dct::Channel::Class::ChatAudio") == 0)
    {
        nType = ChannelType_ChatAudio;
    }
    else
    if (_stricmp(szbuff, "Microsoft::Rdp::Dct::Channel::Class::Control") == 0)
    {
        nType = ChannelType_Control;
    }
    else
    if (_stricmp(szbuff, "Microsoft::Rdp::Dct::Channel::Class::Input") == 0)
    {
        nType = ChannelType_Input;
    }
    else
    if (_stricmp(szbuff, "Microsoft::Rdp::Dct::Channel::Class::Input Feedback") == 0)
    {
        nType = ChannelType_InputFeedback;
    }
    else
    if (_stricmp(szbuff, "Microsoft::Rdp::Dct::Channel::Class::TcpBase") == 0)
    {
        nType = ChannelType_TcpBase;
    }

    Channel_Append(nType, pHead->connectid);
    //-----
    nwidth = 4;
    proto_tree_add_item(tree, hf_xboxtcp_data_Channel_Control_Flags, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    offset += dissect_xboxtcp_Common_PaddingData(tvb, pinfo, tree, data, offset, pHead);
    //-----
    nwidth = offset - noffset;
    strcat(pszTitle, ".Create");
    return nwidth;
}

static int dissect_xboxtcp_Channel_Control_Open(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle)
{
    guint offset = noffset;
    guint nwidth;
    //-----
    nwidth = 4;
    proto_tree_add_item(tree, hf_xboxtcp_data_Channel_Control_FlagsLen, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    guint32 nsize = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    if (nsize > 0)
    {
        tagChannelNodePtr pn = Channel_GetForID(pHead->connectid);
        if (pn != NULL)
        {
            pn->nPayLoadLen = nsize;
            memcpy(pn->bPayloadData, tvb_get_ptr(tvb, offset, nsize), nsize);
        }
        nwidth = nsize;
        proto_tree_add_item(tree, hf_xboxtcp_data_Channel_Control_FlagsData, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
    }
    //-----
    offset += dissect_xboxtcp_Common_PaddingData(tvb, pinfo, tree, data, offset, pHead);
    //-----
    nwidth = offset - noffset;
    strcat(pszTitle, ".Open");
    return nwidth;
}

static int dissect_xboxtcp_Channel_Control_Close(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle)
{
    guint offset = noffset;
    guint nwidth;
    //-----
    nwidth = 4;
    proto_tree_add_item(tree, hf_xboxtcp_data_Channel_Control_Flags, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    offset += dissect_xboxtcp_Common_PaddingData(tvb, pinfo, tree, data, offset, pHead);
    //-----
    nwidth = offset - noffset;
    strcat(pszTitle, ".Close");
    return nwidth;
}

static int dissect_xboxtcp_Channel_Control(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle)
{
    int offset = noffset;
    int nwidth;
    guint32 ntype;
    //-----
    nwidth = 4;
    proto_tree_add_item(tree, hf_xboxtcp_data_Channel_Control_Type, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    ntype= tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    switch(ntype)
    {
        case 2: //Create
            offset+= dissect_xboxtcp_Channel_Control_Create(tvb, pinfo, tree, data, offset, pHead,pszTitle);
            return (offset - noffset);
            break;
        case 3: //Open
            offset += dissect_xboxtcp_Channel_Control_Open(tvb, pinfo, tree, data, offset, pHead, pszTitle);
            return (offset - noffset);
            break;
        case 4: //Close
            offset += dissect_xboxtcp_Channel_Control_Close(tvb, pinfo, tree, data, offset, pHead, pszTitle);
            return (offset - noffset);
            break;
        default:
            break;
    }

    //-----
    return tvb_captured_length(tvb);
}

int dissect_xboxtcp_Control_Streamer_Audio(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle,guint32 nPayloadType, guint32 nPayloadSize)
{
    guint offset = noffset;
    guint nwidth;

    //-----
    if (nPayloadSize > 0)
    {
        proto_item* item_top =proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PayloadData, tvb, offset, nPayloadSize, ENC_LITTLE_ENDIAN);
        proto_tree* foo_tree= proto_item_add_subtree(item_top, ett_xbox_head);
        guint offset2 = offset;
        //-------
        nwidth = 4;
        proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Audio_Channels, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
        offset2 += nwidth;
        //proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Audio_SampleRate, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
        //offset2 += nwidth;
        //proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Audio_AudioCodec, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
        //offset2 += nwidth;
        //proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Audio_BitDepth, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
        //offset2 += nwidth;
        //proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Audio_Type, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
        //offset2 += nwidth;

        //-------
        offset += nPayloadSize;
    }
    //-----
    offset += dissect_xboxtcp_Common_PaddingData(tvb, pinfo, tree, data, offset, pHead);
    //-----
    nwidth = offset - noffset;
    //strcat(pszTitle, ".Open");
    return nwidth;

}

int dissect_xboxtcp_Control_Streamer_Input(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle,guint32 nPayloadType, guint32 nPayloadSize)
{
    guint offset = noffset;
    guint nwidth;
    //-----
    proto_item* item_top = proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PayloadData, tvb, offset, -1, ENC_LITTLE_ENDIAN);
    proto_tree* foo_tree = proto_item_add_subtree(item_top, ett_xbox_head);

    proto_item* item2;
    proto_tree* tree2;
    switch (nPayloadType)
    {
    case PayloadTypeInput_SeverHandShake:
        //--------- 
        nwidth = 4;
        proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_ServerHand_ProtocolVer, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        //--------- 
        nwidth = 4;
        proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_ServerHand_DesktopWidth, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        //--------- 
        nwidth = 4;
        proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_ServerHand_DesktopHeight, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        //--------- 
        nwidth = 4;
        proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_ServerHand_MaxTouches, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        //--------- 
        nwidth = 4;
        proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_ServerHand_InitFrameID, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;

        break;
    case PayloadTypeInput_ClientHandShake:
        //--------- 
        nwidth = 4;
        proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_ClientHand_MaxTouches, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        //--------- 
        nwidth = 8;
        proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_ClientHand_ReferenceTimestamp, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;

        break;
    case PayloadTypeInput_FrameAck:
        //--------- 
        nwidth = 4;
        proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_FrameAck_AckedFrame, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;

        break;
    case PayloadTypeInput_Frame:
        //--------- 
        nwidth = 4;
        proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_Frame_FrameID, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        //--------- 
        nwidth = 8;
        proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_Frame_Timestamp, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        //--------- 
        nwidth = 8;
        proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_Frame_CreatedTimestamp, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        //--------- 
        nwidth = 16;
        item2 = proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_Frame_InputButtonModel, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        tree2=proto_item_add_subtree(item2, ett_xbox_head);
        nwidth = 1;
        //----
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_DPadUp, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_DPadDown, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_DPadLeft, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_DPadRight, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_Start, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_Back, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_Left_thumbsitck, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_Right_thumbsitck, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_Leftshoulder, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_rightshouder, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_Guide, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_Unknow, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_A, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_B, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_X, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Key_Y, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;

        //--------- 
        nwidth = 14;
        item2 = proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_Frame_InputAnalogModel, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        tree2 = proto_item_add_subtree(item2, ett_xbox_head);
        //----
        nwidth = 1;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Analog_LeftTrigger, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        nwidth = 1;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Analog_RightTrigger, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        nwidth = 2;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Analog_LeftthumbstickX, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        nwidth = 2;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Analog_LeftthumbstickY, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        nwidth = 2;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Analog_RightthumbstickX, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        nwidth = 2;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Analog_RightthumbstickY, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        nwidth = 1;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Analog_LeftRumbleTrigger, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        nwidth = 1;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Analog_RightRumbleTrigger, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        nwidth = 1;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Analog_LeftRumblehandle, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        nwidth = 1;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Analog_RightRumblehandle, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;

        //--------- 
        nwidth = 9;
        item2 = proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Input_Frame_InputExtensionModel, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        tree2 = proto_item_add_subtree(item2, ett_xbox_head);
        //----
        nwidth = 1;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Extension_Unknow1, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Extension_Unknow2, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Extension_LeftRumbleTrigger2, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Extension_RightRumbleTrigger2, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Extension_LeftRumblehandle2, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Extension_RightRumblehandle2, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Extension_Unknow3, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Extension_Unknow4, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        proto_tree_add_item(tree2, hf_xboxtcp_data_Stream_Input_Extension_Unknow5, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;

        break;
    default:

        break;
    }

    //-----
    offset += dissect_xboxtcp_Common_PaddingData(tvb, pinfo, tree, data, offset, pHead);
    //-----
    nwidth = offset - noffset;
    //strcat(pszTitle, ".Open");
    return nwidth;

}

int dissect_xboxtcp_Control_Streamer_Control_RealtimeTelemetry(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle)
{
    guint offset = noffset;
    guint nwidth;
    guint16 ncount,i;
    proto_item* item1;
    //-----
    nwidth = 2;
    item1 = proto_tree_add_item(tree, hf_xboxtcp_data_Stream_Control_RealtimeTelemetry_FieldCount, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    ncount = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    for (i = 0;i < ncount;i++)
    {
        //-----
        nwidth = 2;
        proto_tree_add_item(tree, hf_xboxtcp_data_Stream_Control_RealtimeTelemetry_TelemetryField_key, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        //-----
        nwidth = 8;
        proto_tree_add_item(tree, hf_xboxtcp_data_Stream_Control_RealtimeTelemetry_TelemetryField_value, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
    }
    nwidth = offset - noffset;
    proto_item_set_len(item1, nwidth);
    return nwidth;
}
int dissect_xboxtcp_Control_Streamer_Control_ChangeVideoQuality(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle)
{
    guint offset = noffset;
    guint nwidth;
    guint16 ncount=6, i;
    //-----
    for (i = 0;i < ncount;i++)
    {
        //-----
        nwidth = 4;
        proto_tree_add_item(tree, hf_xboxtcp_data_Stream_Control_ChangeVideoQuality_Unknow, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
    }
    nwidth = offset - noffset;
    return nwidth;
}
int dissect_xboxtcp_Control_Streamer_Control_Event(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle)
{
    guint offset = noffset;
    guint nwidth;
    //-----
    nwidth = 1;
    proto_tree_add_item(tree, hf_xboxtcp_data_Stream_Control_ControllerEvent_Event, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    nwidth = 1;
    proto_tree_add_item(tree, hf_xboxtcp_data_Stream_Control_ControllerEvent_ControllerNumber, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;

    nwidth = offset - noffset;
    return nwidth;
}

int dissect_xboxtcp_Control_Streamer_Control(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle, guint32 nPayloadType, guint32 nPayloadSize)
{
    guint offset = noffset;
    guint nwidth;

    //-----
    nPayloadSize = -1;
    proto_item* item_top = proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PayloadData, tvb, offset, nPayloadSize, ENC_LITTLE_ENDIAN);
    proto_tree* foo_tree = proto_item_add_subtree(item_top, ett_xbox_head);
    //--------- Head

    //----------
    nwidth = 2;
    proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Control_Head_PSeq, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //----------
    nwidth = 1;
    proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Control_Head_Unknow1, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //----------
    nwidth = 1;
    proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Control_Head_Unknow2, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //----------
    nwidth = 2;
    proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Control_Head_PayLoadType, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    guint16 nPayloadType2 = tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //----------
    char szmsg[100];
    switch (nPayloadType2)
    {
    case CPT_Session_Init:
        proto_item_append_text(item_top, ":Session.Init");
        break;
    case CPT_Session_Create:
        proto_item_append_text(item_top, ":Session.Create");
        break;
    case CPT_Session_Create_Response:
        proto_item_append_text(item_top, ":Session.Create.Response");
        break;
    case CPT_Session_Destroy:
        proto_item_append_text(item_top, ":Session.Destroy");
        break;
    case CPT_Video_Statistics:
        proto_item_append_text(item_top, ":Video.Statistics");
        break;
    case CPT_Realtime_Telemetry:
        proto_item_append_text(item_top, ":Realtime.Telemetry");
        offset+=dissect_xboxtcp_Control_Streamer_Control_RealtimeTelemetry(tvb,pinfo,foo_tree,offset,pHead,pszTitle);
        break;
    case CPT_Change_Video_Quality:
        proto_item_append_text(item_top, ":Change.Video.Quality");
        offset += dissect_xboxtcp_Control_Streamer_Control_ChangeVideoQuality(tvb, pinfo, foo_tree, offset, pHead, pszTitle);
        break;
    case CPT_Initiate_Network_Test:
        proto_item_append_text(item_top, ":Initiate.Network.Test");
        break;
    case CPT_Network_Information:
        proto_item_append_text(item_top, ":Network.Information");
        break;
    case CPT_Network_Test_Response:
        proto_item_append_text(item_top, ":Initiate_NetworkTest.Response");
        break;
    case CPT_Controller_Event:
        proto_item_append_text(item_top, ":Controller.Event");
        offset += dissect_xboxtcp_Control_Streamer_Control_Event(tvb, pinfo, foo_tree, offset, pHead, pszTitle);
        break;
    default:
        sprintf(szmsg, ":Unknow:%x",nPayloadType2);
        proto_item_append_text(item_top, szmsg);
        break;
    }

    //-----
    offset += dissect_xboxtcp_Common_PaddingData(tvb, pinfo, tree, data, offset, pHead);
    //-----
    nwidth = offset - noffset;
    //strcat(pszTitle, ".Open");
    return nwidth;

}

int dissect_xboxtcp_Control_Streamer_Video_Format(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, int noffset)
{
    guint offset = noffset;
    guint nwidth;
    //-------
    proto_item* item_1 = proto_tree_add_item(tree, hf_xboxtcp_data_Stream_Video_VideoFormatInfo, tvb, offset, 4 * 4, ENC_LITTLE_ENDIAN);
    proto_tree* foo_tree1 = proto_item_add_subtree(item_1, ett_xbox_head);
    //-------
    nwidth = 4;
    proto_tree_add_item(foo_tree1, hf_xboxtcp_data_Stream_Video_FPS, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-------
    nwidth = 4;
    proto_tree_add_item(foo_tree1, hf_xboxtcp_data_Stream_Video_Width, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-------
    nwidth = 4;
    proto_tree_add_item(foo_tree1, hf_xboxtcp_data_Stream_Video_Height, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-------
    nwidth = 4;
    proto_tree_add_item(foo_tree1, hf_xboxtcp_data_Stream_Video_VideoCodes, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    guint32 nVideoCode = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    
    switch (nVideoCode)
    {
    case VideoCode_H264:
        proto_item_append_text(item_1, ".H264");
        break;
    case VideoCode_RGB:
        proto_item_append_text(item_1, ".RGB");
        //-------
        nwidth = 4;
        proto_tree_add_item(foo_tree1, hf_xboxtcp_data_Stream_Video_Bpp, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        //-------
        nwidth = 4;
        proto_tree_add_item(foo_tree1, hf_xboxtcp_data_Stream_Video_Bytes, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        //-------
        nwidth = 8;
        proto_tree_add_item(foo_tree1, hf_xboxtcp_data_Stream_Video_RMask, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        //-------
        nwidth = 8;
        proto_tree_add_item(foo_tree1, hf_xboxtcp_data_Stream_Video_GMask, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        //-------
        nwidth = 8;
        proto_tree_add_item(foo_tree1, hf_xboxtcp_data_Stream_Video_BMask, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
        break;
    case VideoCode_YUV:
        proto_item_append_text(item_1, ".YUV");
        break;
    default:
        break;
    }
    nwidth=offset - noffset;
    proto_item_set_len(item_1, nwidth);
    return nwidth;
}

int dissect_xboxtcp_Control_Streamer_Video(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle, guint32 nPayloadType, guint32 nPayloadSize)
{
    guint offset = noffset;
    guint nwidth;
    guint32 ncount,i,nflag;
    //-----
    if (nPayloadSize > 0)
    {
        proto_item* item_top = proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PayloadData, tvb, offset, nPayloadSize, ENC_LITTLE_ENDIAN);
        proto_tree* foo_tree = proto_item_add_subtree(item_top, ett_xbox_head);
        proto_item* item_1;
        proto_tree* foo_tree1;
        guint offset2 = offset;
        switch (nPayloadType)
        {
        case PayloadTypeVideoAudio_SeverHandShake:
            //-------
            nwidth = 4;
            proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Video_ProtocolVersion, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            //-------
            nwidth = 4;
            proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Video_Width, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            //-------
            nwidth = 4;
            proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Video_Height, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            //-------
            nwidth = 4;
            proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Video_FPS, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            //-------
            nwidth = 8;
            proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Video_ReterenceTimestamp, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            //-------
            nwidth = 4;
            proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Video_FormatsLength, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            ncount = tvb_get_guint32(tvb, offset2, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            for (i = 0;i < ncount;i++)
            {
                item_1 = proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Video_VideoFormatInfo, tvb, offset2, 4*4, ENC_LITTLE_ENDIAN);
                foo_tree1 = proto_item_add_subtree(item_1, ett_xbox_head);
                //-------
                nwidth = 4;
                proto_tree_add_item(foo_tree1, hf_xboxtcp_data_Stream_Video_FPS, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
                offset2 += nwidth;
                //-------
                nwidth = 4;
                proto_tree_add_item(foo_tree1, hf_xboxtcp_data_Stream_Video_Width, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
                offset2 += nwidth;
                //-------
                nwidth = 4;
                proto_tree_add_item(foo_tree1, hf_xboxtcp_data_Stream_Video_Height, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
                offset2 += nwidth;
                //-------
                nwidth = 4;
                proto_tree_add_item(foo_tree1, hf_xboxtcp_data_Stream_Video_VideoCodes, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
                offset2 += nwidth;

            }

            break;
        case PayloadTypeVideoAudio_ClientHandShake:
            //-------
            nwidth = 4;
            proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Video_InitialFrameId, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            //-------
            offset2 += dissect_xboxtcp_Control_Streamer_Video_Format(tvb, pinfo, foo_tree, offset2);
            break;
        case PayloadTypeVideoAudio_Control:
            //-------
            nwidth = 4;
            item_1 =proto_tree_add_item(foo_tree, hf_xboxtcp_data_Stream_Control_Flag, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            nflag = tvb_get_guint32(tvb, offset2, ENC_LITTLE_ENDIAN);
            if (nflag & VideoControlFlag_RequestKeyframe)
            {
                proto_item_append_text(item_1, ":RequestKeyframe");
            }
            if (nflag & VideoControlFlag_StartStream)
            {
                proto_item_append_text(item_1, ":StartStream");
            }
            if (nflag & VideoControlFlag_StopStream)
            {
                proto_item_append_text(item_1, ":StopStream");
            }
            if (nflag & VideoControlFlag_QueueDepth)
            {
                proto_item_append_text(item_1, ":QueueDepth");
            }
            if (nflag & VideoControlFlag_LostFreames)
            {
                proto_item_append_text(item_1, ":LostFreames");
            }
            if (nflag & VideoControlFlag_LastDisplayedFrame)
            {
                proto_item_append_text(item_1, ":LastDisplayedFrame");
            }

            offset2 += nwidth;
            break;
        case PayloadTypeVideoAudio_Data:
            //m_pDataFile_WriteAppend(tvb_get_ptr(tvb,offset, nPayloadSize), nPayloadSize);
            //-------
            nwidth = 4;
            proto_tree_add_item(foo_tree, hf_xboxudp_video_data_Flags, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            //-------
            nwidth = 4;
            proto_tree_add_item(foo_tree, hf_xboxudp_video_data_FrameId, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            //-------
            nwidth = 8;
            proto_tree_add_item(foo_tree, hf_xboxudp_video_data_Timestamp, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            //-------
            nwidth = 4;
            proto_tree_add_item(foo_tree, hf_xboxudp_video_data_Totalsize, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            //-------
            nwidth = 4;
            proto_tree_add_item(foo_tree, hf_xboxudp_video_data_Packetcount, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            //-------
            nwidth = 4;
            proto_tree_add_item(foo_tree, hf_xboxudp_video_data_Offset, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            //-------
            nwidth = 4;
            proto_tree_add_item(foo_tree, hf_xboxudp_video_data_DataLen, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            ncount = tvb_get_guint32(tvb, offset2, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;
            //-------
            nwidth = ncount;
            proto_tree_add_item(foo_tree, hf_xboxudp_video_data_Data, tvb, offset2, nwidth, ENC_LITTLE_ENDIAN);
            offset2 += nwidth;

            //------- 写入数据文件
            //ncount += 8 * 4;
            //m_pDataFile_WriteAppend(tvb_get_ptr(tvb, offset, ncount), ncount);

            break;
        }


        offset += nPayloadSize;
    }
    //-----
    offset += dissect_xboxtcp_Common_PaddingData(tvb, pinfo, tree, data, offset, pHead);
    //-----
    nwidth = offset - noffset;
    //strcat(pszTitle, ".Open");
    return nwidth;

}


int dissect_xboxtcp_Control_Streamer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle)
{
    guint offset = noffset;
    guint nwidth;

    tagChannelNodePtr pcn = Channel_GetForID(pHead->connectid);
    if (pcn == NULL)
    {
        //strcat(pszTitle, "<Unknow.ConnectID>");
        nwidth = (guint)strlen(pszTitle);
        sprintf(pszTitle, "<Unknow.CID=%X>", pHead->connectid);
        return tvb_captured_length(tvb);
    }
    else {
        strcat(pszTitle, ".");
        strcat(pszTitle, Channel_GetDiscForType(pcn->nType));
    }
    //-----
    nwidth = 4;
    proto_tree_add_item(tree, hf_xboxtcp_data_Stream_Flags, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    proto_tree_add_item(tree, hf_xboxtcp_data_Stream_Seq, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PSeq, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    nwidth = 4;
    proto_item *tiPayLoadType= proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PayloadType, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    guint32 nPayloadType = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PayloadLen, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    guint32 nPayloadSize = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += nwidth;

    switch (pcn->nType)
    {
    case ChannelType_Video:
        switch (nPayloadType)
        {
        case PayloadTypeVideoAudio_SeverHandShake:
            proto_item_append_text(tiPayLoadType, ":SeverHandShake");
            break;
        case PayloadTypeVideoAudio_ClientHandShake:
            proto_item_append_text(tiPayLoadType, ":ClientHandShake");
            break;
        case PayloadTypeVideoAudio_Control:
            proto_item_append_text(tiPayLoadType, ":Control");
            break;
        case PayloadTypeVideoAudio_Data:
            proto_item_append_text(tiPayLoadType, ":Data");
            break;
        default:
            proto_item_append_text(tiPayLoadType, ":Unknow");
            break;
        }

        nwidth = offset - noffset;
        nwidth+= dissect_xboxtcp_Control_Streamer_Video(tvb,pinfo,tree,data,offset,pHead,pszTitle, nPayloadType, nPayloadSize);
        return nwidth;
        break;
    case ChannelType_Audio:
        switch (nPayloadType)
        {
        case PayloadTypeVideoAudio_SeverHandShake:
            proto_item_append_text(tiPayLoadType, ":SeverHandShake");
            break;
        case PayloadTypeVideoAudio_ClientHandShake:
            proto_item_append_text(tiPayLoadType, ":ClientHandShake");
            break;
        case PayloadTypeVideoAudio_Control:
            proto_item_append_text(tiPayLoadType, ":Control");
            break;
        case PayloadTypeVideoAudio_Data:
            proto_item_append_text(tiPayLoadType, ":Data");
            break;
        default:
            proto_item_append_text(tiPayLoadType, ":Unknow");
            break;
        }

        nwidth = offset - noffset;
        nwidth+= dissect_xboxtcp_Control_Streamer_Audio(tvb,pinfo,tree,data,offset,pHead,pszTitle, nPayloadType, nPayloadSize);
        return nwidth;
        break;
    case ChannelType_ChatAudio:
        break;
    case ChannelType_Control:
        nwidth = offset - noffset;
        m_pDebugOutputA("|--Stream.Control.begin");
        nwidth += dissect_xboxtcp_Control_Streamer_Control(tvb, pinfo, tree, data, offset, pHead, pszTitle, nPayloadType, nPayloadSize);
        m_pDebugOutputA("|--Stream.Control.End");
        return nwidth;

        break;
    case ChannelType_Input:
        switch (nPayloadType)
        {
        case PayloadTypeInput_SeverHandShake:
            proto_item_append_text(tiPayLoadType, ":SeverHandShake");
            break;
        case PayloadTypeInput_ClientHandShake:
            proto_item_append_text(tiPayLoadType, ":ClientHandShake");
            break;
        case PayloadTypeInput_FrameAck:
            proto_item_append_text(tiPayLoadType, ":FrameAck");
            break;
        case PayloadTypeInput_Frame:
            proto_item_append_text(tiPayLoadType, ":Frame");
            break;
        default:
            proto_item_append_text(tiPayLoadType, ":Unknow");
            break;
        }
        nwidth = offset - noffset;
        m_pDebugOutputA("      |--Input.begin");
        nwidth += dissect_xboxtcp_Control_Streamer_Input(tvb, pinfo, tree, data, offset, pHead, pszTitle, nPayloadType, nPayloadSize);
        m_pDebugOutputA("      |--Input.end");
        return nwidth;
        break;
    case ChannelType_InputFeedback:
        break;
    case ChannelType_TcpBase:
        break;
    default:
        break;
    }

    //-----
    if (nPayloadSize > 0)
    {
        nwidth = nPayloadSize;
        proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PayloadData, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
    }
    //-----
    offset += dissect_xboxtcp_Common_PaddingData(tvb, pinfo, tree, data, offset, pHead);
    //-----
    nwidth = offset - noffset;
    //strcat(pszTitle, ".Open");
    return nwidth;
}
int dissect_xboxudp_Control_Streamer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset, struct tagXboxTcpHead* pHead, char* pszTitle)
{
    guint offset = noffset;
    guint nwidth;

    tagChannelNodePtr pcn = Channel_GetForID(pHead->connectid);
    if (pcn == NULL)
    {
        //strcat(pszTitle, "<Unknow.ConnectID>");
        nwidth = (guint)strlen(pszTitle);
        sprintf(pszTitle, "<Unknow.CID=%X>", pHead->connectid);
        return tvb_captured_length(tvb);
    }
    else {
        strcat(pszTitle, ".");
        strcat(pszTitle, Channel_GetDiscForType(pcn->nType));
    }
    //-----
    nwidth = 4;
    proto_tree_add_item(tree, hf_xboxtcp_data_Stream_Flags, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    nwidth = 4;
    proto_item* tiPayLoadType = proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PayloadType, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    guint32 nPayloadType = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += nwidth;
    //-----
    proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PayloadLen, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
    guint32 nPayloadSize = tvb_get_guint32(tvb, offset, ENC_LITTLE_ENDIAN);
    offset += nwidth;

    switch (pcn->nType)
    {
    case ChannelType_Video:
        switch (nPayloadType)
        {
        case PayloadTypeVideoAudio_SeverHandShake:
            proto_item_append_text(tiPayLoadType, ":SeverHandShake");
            break;
        case PayloadTypeVideoAudio_ClientHandShake:
            proto_item_append_text(tiPayLoadType, ":ClientHandShake");
            break;
        case PayloadTypeVideoAudio_Control:
            proto_item_append_text(tiPayLoadType, ":Control");
            break;
        case PayloadTypeVideoAudio_Data:
            proto_item_append_text(tiPayLoadType, ":Data");
            break;
        default:
            proto_item_append_text(tiPayLoadType, ":Unknow");
            break;
        }

        nwidth = offset - noffset;
        m_pDebugOutputA("      |--Video.begin");
        nwidth += dissect_xboxtcp_Control_Streamer_Video(tvb, pinfo, tree, data, offset, pHead, pszTitle, nPayloadType, nPayloadSize);
        m_pDebugOutputA("      |--Video.end");
        return nwidth;
        break;
    case ChannelType_Audio:
        switch (nPayloadType)
        {
        case PayloadTypeVideoAudio_SeverHandShake:
            proto_item_append_text(tiPayLoadType, ":SeverHandShake");
            break;
        case PayloadTypeVideoAudio_ClientHandShake:
            proto_item_append_text(tiPayLoadType, ":ClientHandShake");
            break;
        case PayloadTypeVideoAudio_Control:
            proto_item_append_text(tiPayLoadType, ":Control");
            break;
        case PayloadTypeVideoAudio_Data:
            proto_item_append_text(tiPayLoadType, ":Data");
            break;
        default:
            proto_item_append_text(tiPayLoadType, ":Unknow");
            break;
        }

        nwidth = offset - noffset;
        m_pDebugOutputA("      |--Audio.begin");
        nwidth += dissect_xboxtcp_Control_Streamer_Audio(tvb, pinfo, tree, data, offset, pHead, pszTitle, nPayloadType, nPayloadSize);
        m_pDebugOutputA("      |--Audio.end");
        return nwidth;
        break;
    case ChannelType_ChatAudio:
        break;
    case ChannelType_Control:
        nwidth = offset - noffset;
        m_pDebugOutputA("      |--Control.begin");
        nwidth += dissect_xboxtcp_Control_Streamer_Control(tvb, pinfo, tree, data, offset, pHead, pszTitle, nPayloadType, nPayloadSize);
        m_pDebugOutputA("      |--Control.end");
        return nwidth;

        break;
    case ChannelType_Input:
        switch (nPayloadType)
        {
        case PayloadTypeInput_SeverHandShake:
            proto_item_append_text(tiPayLoadType, ":SeverHandShake");
            break;
        case PayloadTypeInput_ClientHandShake:
            proto_item_append_text(tiPayLoadType, ":ClientHandShake");
            break;
        case PayloadTypeInput_FrameAck:
            proto_item_append_text(tiPayLoadType, ":FrameAck");
            break;
        case PayloadTypeInput_Frame:
            proto_item_append_text(tiPayLoadType, ":Frame");
            break;
        default:
            proto_item_append_text(tiPayLoadType, ":Unknow");
            break;
        }
        nwidth = offset - noffset;
        m_pDebugOutputA("      |--Input.begin");
        nwidth += dissect_xboxtcp_Control_Streamer_Input(tvb, pinfo, tree, data, offset, pHead, pszTitle, nPayloadType, nPayloadSize);
        m_pDebugOutputA("      |--Input.end");
        return nwidth;
        break;
    case ChannelType_InputFeedback:
        break;
    case ChannelType_TcpBase:
        break;
    default:
        break;
    }

    //-----
    if (nPayloadSize > 0)
    {
        nwidth = nPayloadSize;
        proto_tree_add_item(tree, hf_xboxtcp_data_Stream_PayloadData, tvb, offset, nwidth, ENC_LITTLE_ENDIAN);
        offset += nwidth;
    }
    //-----
    offset += dissect_xboxtcp_Common_PaddingData(tvb, pinfo, tree, data, offset, pHead);
    //-----
    nwidth = offset - noffset;
    //strcat(pszTitle, ".Open");
    return nwidth;
}

static int dissect_xboxtcp_OnePacket(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_, int noffset,char *pszTitle)
{
    //------------------------------------
    proto_item* item_top = proto_tree_add_item(tree, proto_xboxtcp, tvb, noffset, -1, ENC_NA);

    int offset = noffset;
    int nwidth;

    proto_item* ti2;
    proto_item* ti1;
    proto_tree* te2;
    proto_tree* foo_tree_headitems;

    struct tagXboxTcpHead Head;
    memset(&Head, 0,sizeof(struct tagXboxTcpHead));

    //proto_item_append_text(ti, ", Type %s",val_to_str(packet_type, pkt_type_names, "Unknown (0x%02x)"));
    proto_tree* foo_tree_head = proto_item_add_subtree(item_top, ett_xbox_head);
    //-----
    ti2 = proto_tree_add_item(foo_tree_head, hf_xboxtcp_head, tvb, offset, 16, ENC_BIG_ENDIAN);
    proto_item_set_text(ti2, "Head");

    foo_tree_headitems = proto_item_add_subtree(ti2, ett_xbox_head);

    //-----
    nwidth = 4;
    proto_tree_add_item(foo_tree_headitems, hf_xboxtcp_head_channelid, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    Head.channelid= tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;
    //-----
    nwidth = 1;
    ti1=proto_tree_add_item(foo_tree_headitems, hf_xboxtcp_head_flags1, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    te2 = proto_item_add_subtree(ti1, ett_xbox_head);
    proto_tree_add_item(te2, hf_xboxtcp_head_flags_version, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    proto_tree_add_item(te2, hf_xboxtcp_head_flags_padding, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    Head.flags_padding= tvb_get_guint8(tvb, offset) & BIT_xboxtcp_head_flags_padding;
    proto_tree_add_item(te2, hf_xboxtcp_head_flags_extension, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    Head.flags_extension = tvb_get_guint8(tvb, offset) & BIT_xboxtcp_head_flags_extension;
    proto_tree_add_item(te2, hf_xboxtcp_head_flags_csrccount, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    Head.flags_csrccount = tvb_get_guint8(tvb, offset) & BIT_xboxtcp_head_flags_csrccount;
    offset += nwidth;
    //-----
    nwidth = 1;
    ti1 = proto_tree_add_item(foo_tree_headitems, hf_xboxtcp_head_flags2, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    te2 = proto_item_add_subtree(ti1, ett_xbox_head);
    proto_tree_add_item(te2, hf_xboxtcp_head_flags_marker, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    proto_tree_add_item(te2, hf_xboxtcp_head_flags_payloadtype, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    Head.flags_payloadtype = tvb_get_guint8(tvb, offset) & BIT_xboxtcp_head_flags_payloadtype;
    col_add_fstr(pinfo->cinfo, COL_INFO, "Type %s", val_to_str(Head.flags_payloadtype, szPayloadTypestcp, "(0x%02x)"));
    offset += nwidth;
    //-----
    nwidth = 2;
    proto_tree_add_item(foo_tree_headitems, hf_xboxtcp_head_seq, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    Head.seq = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;
    //-----
    nwidth = 4;
    proto_tree_add_item(foo_tree_headitems, hf_xboxtcp_head_time, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    offset += nwidth;
    //-----
    nwidth = 4;
    proto_tree_add_item(foo_tree_headitems, hf_xboxtcp_head_connectid, tvb, offset, nwidth, ENC_BIG_ENDIAN);
    Head.connectid = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    offset += nwidth;
    //-----------------------------------------
    proto_tree* foo_tree_data = proto_item_add_subtree(item_top, ett_xbox_head);
    ti2 = proto_tree_add_item(foo_tree_data, hf_xboxtcp_head, tvb, offset, -1, ENC_BIG_ENDIAN);
    proto_item_set_text(ti2, "Data");
    proto_tree* foo_tree_dataitems = proto_item_add_subtree(ti2, ett_xbox_head);
    switch ((guint32)Head.flags_payloadtype)
    {
    case 0x23:  //Streamer
        strcpy(pszTitle, szPayloadTypestcp[0].strptr);
        nwidth = dissect_xboxtcp_Control_Streamer(tvb, pinfo, foo_tree_dataitems, data, offset, &Head, pszTitle);
        proto_item_set_len(ti2, nwidth);
        nwidth += (offset - noffset);
        proto_item_set_len(item_top, nwidth);
        proto_item_set_text(item_top, pszTitle);
        return nwidth;
        break;
    case 0x60:  //Control
        strcpy(pszTitle, szPayloadTypestcp[1].strptr);
        nwidth = dissect_xboxtcp_Control_Handshake(tvb, pinfo, foo_tree_dataitems, data, offset, &Head, pszTitle);
        proto_item_set_len(ti2,  nwidth);
        nwidth += (offset - noffset);
        proto_item_set_len(item_top,  nwidth);
        proto_item_set_text(item_top, pszTitle);
        return nwidth;
        break;
    case 0x61:  //Channel Control
        strcpy(pszTitle, szPayloadTypestcp[2].strptr);
        nwidth = dissect_xboxtcp_Channel_Control(tvb, pinfo, foo_tree_dataitems, data, offset, &Head, pszTitle);
        proto_item_set_len(ti2,  nwidth);
        nwidth += (offset - noffset);
        proto_item_set_len(item_top,  nwidth);
        proto_item_set_text(item_top, pszTitle);
        return nwidth;
        break;
    case 0x64:  //UDP Handshake
        strcpy(pszTitle, szPayloadTypestcp[3].strptr);
        proto_item_set_text(item_top, pszTitle);
        break;
    default:
        sprintf(pszTitle, "<Unknow:%x>", Head.flags_payloadtype);
        proto_item_set_text(item_top, pszTitle);
        break;
    }

    //------------------------------------
    return tvb_captured_length(tvb);
}


static int dissect_xboxtcp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree _U_, void* data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "XBOXTCP");
    /* Clear out stuff in the info column */
    col_clear(pinfo->cinfo, COL_INFO);
    //------------------------------------
    proto_item* ti = proto_tree_add_item(tree, proto_xboxtcp, tvb, 0, -1, ENC_NA);
    guint nsize = tvb_captured_length(tvb);

    guint offset = 0;
    guint ncursize;
    char szname[0x100];
    proto_tree* foo_tree_head;

    int ntemp=0;
    szname[0] = 0;

    //proto_item_append_text(ti, ", Type %s",val_to_str(packet_type, pkt_type_names, "Unknown (0x%02x)"));
    foo_tree_head = proto_item_add_subtree(ti, ett_xbox_head);
    char szmsg[0x100];

    sprintf(szmsg, "|--xbox.tcp data Top size:%d",  nsize);
    m_pDebugOutputA(szmsg);

    while (1)
    {
        sprintf(szmsg, "  |--xbox.tcp data pos:%d-%d",offset,nsize);
        m_pDebugOutputA(szmsg);
        if (offset >= nsize)
            break;
        ntemp = (int)strlen(szname);
        ncursize = dissect_xboxtcp_OnePacket(tvb, pinfo, foo_tree_head, data, offset, &szname[ntemp]);
        if (ncursize == 0)
            break;
        offset += ncursize;
        sprintf(szmsg, "      |--End.width:%d", ncursize);
        m_pDebugOutputA(szmsg);

        if (offset >= nsize)
            break;
        strcat(szname, "/");
    }
    col_add_fstr(pinfo->cinfo, COL_INFO, szname);

    return nsize;
}
