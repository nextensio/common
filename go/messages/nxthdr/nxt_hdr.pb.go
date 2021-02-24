// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        (unknown)
// source: nxt_hdr.proto

package nxthdr

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type NxtFlow_FLOW_TYPE int32

const (
	NxtFlow_L4 NxtFlow_FLOW_TYPE = 0
	NxtFlow_L3 NxtFlow_FLOW_TYPE = 1
)

// Enum value maps for NxtFlow_FLOW_TYPE.
var (
	NxtFlow_FLOW_TYPE_name = map[int32]string{
		0: "L4",
		1: "L3",
	}
	NxtFlow_FLOW_TYPE_value = map[string]int32{
		"L4": 0,
		"L3": 1,
	}
)

func (x NxtFlow_FLOW_TYPE) Enum() *NxtFlow_FLOW_TYPE {
	p := new(NxtFlow_FLOW_TYPE)
	*p = x
	return p
}

func (x NxtFlow_FLOW_TYPE) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (NxtFlow_FLOW_TYPE) Descriptor() protoreflect.EnumDescriptor {
	return file_nxt_hdr_proto_enumTypes[0].Descriptor()
}

func (NxtFlow_FLOW_TYPE) Type() protoreflect.EnumType {
	return &file_nxt_hdr_proto_enumTypes[0]
}

func (x NxtFlow_FLOW_TYPE) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use NxtFlow_FLOW_TYPE.Descriptor instead.
func (NxtFlow_FLOW_TYPE) EnumDescriptor() ([]byte, []int) {
	return file_nxt_hdr_proto_rawDescGZIP(), []int{1, 0}
}

type NxtHdr_STREAM_OP int32

const (
	NxtHdr_NOOP         NxtHdr_STREAM_OP = 0
	NxtHdr_CLOSE        NxtHdr_STREAM_OP = 1
	NxtHdr_FLOW_CONTROL NxtHdr_STREAM_OP = 2
)

// Enum value maps for NxtHdr_STREAM_OP.
var (
	NxtHdr_STREAM_OP_name = map[int32]string{
		0: "NOOP",
		1: "CLOSE",
		2: "FLOW_CONTROL",
	}
	NxtHdr_STREAM_OP_value = map[string]int32{
		"NOOP":         0,
		"CLOSE":        1,
		"FLOW_CONTROL": 2,
	}
)

func (x NxtHdr_STREAM_OP) Enum() *NxtHdr_STREAM_OP {
	p := new(NxtHdr_STREAM_OP)
	*p = x
	return p
}

func (x NxtHdr_STREAM_OP) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (NxtHdr_STREAM_OP) Descriptor() protoreflect.EnumDescriptor {
	return file_nxt_hdr_proto_enumTypes[1].Descriptor()
}

func (NxtHdr_STREAM_OP) Type() protoreflect.EnumType {
	return &file_nxt_hdr_proto_enumTypes[1]
}

func (x NxtHdr_STREAM_OP) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use NxtHdr_STREAM_OP.Descriptor instead.
func (NxtHdr_STREAM_OP) EnumDescriptor() ([]byte, []int) {
	return file_nxt_hdr_proto_rawDescGZIP(), []int{2, 0}
}

// agent: true if its an agent, false for connector.
// userid: username of the agent/connector
// uuid: a unique identifier for the agent, if the same userid has multiple devices
//       usually just a uuid.UUID suffices to be unique
// services: the service names advertised by this agent/connector
type NxtOnboard struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Agent       bool     `protobuf:"varint,1,opt,name=agent,proto3" json:"agent,omitempty"`
	Userid      string   `protobuf:"bytes,2,opt,name=userid,proto3" json:"userid,omitempty"`
	Uuid        string   `protobuf:"bytes,3,opt,name=uuid,proto3" json:"uuid,omitempty"`
	AccessToken string   `protobuf:"bytes,4,opt,name=accessToken,proto3" json:"accessToken,omitempty"`
	Services    []string `protobuf:"bytes,5,rep,name=services,proto3" json:"services,omitempty"`
}

func (x *NxtOnboard) Reset() {
	*x = NxtOnboard{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nxt_hdr_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NxtOnboard) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NxtOnboard) ProtoMessage() {}

func (x *NxtOnboard) ProtoReflect() protoreflect.Message {
	mi := &file_nxt_hdr_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NxtOnboard.ProtoReflect.Descriptor instead.
func (*NxtOnboard) Descriptor() ([]byte, []int) {
	return file_nxt_hdr_proto_rawDescGZIP(), []int{0}
}

func (x *NxtOnboard) GetAgent() bool {
	if x != nil {
		return x.Agent
	}
	return false
}

func (x *NxtOnboard) GetUserid() string {
	if x != nil {
		return x.Userid
	}
	return ""
}

func (x *NxtOnboard) GetUuid() string {
	if x != nil {
		return x.Uuid
	}
	return ""
}

func (x *NxtOnboard) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

func (x *NxtOnboard) GetServices() []string {
	if x != nil {
		return x.Services
	}
	return nil
}

// source, dest, sport, dport, proto: standard five tuple associated with any flow. Any/all of these
// can be empty based on whether that value is needed for that kind of flow etc..
//
// sourceAgent: the service name of the source agent/connector that can be used in the return direction
// to get back to the same agent/connector
//
// destAgent: the service name of the dest agent/connector. This field may (or may not) be the same as
// the "dest" field. For example if the dest field is a private service like kismis.org, the destAgent
// will be the same as kismis.org. But if the dest field is say google.com, then the destAgent can be
// set to say default-internet. In other words, destAgent gives the sender (agent/connector) flexibility
// to either say "route to whoever provides flow.dest" by setting flow.destAgent same as flow.dest OR to
// say "route exactly to this particular service" by setting a specific value for flow.destAgent different
// from flow.dest. The cluster always routes based on flow.destAgent field
//
// originAgent: This stores the information about which agent originated the flow. The source and dest of
// the flow can keep changing, but the originAgent will never change. The agents/connectors are expected
// to preserve this information and carry it across in every header.
//
// type: two types of nextensio flows - raw l3 packets, tcp/udp terminated l4
//
// key, value: set of extra attributes for the flow - typically filled in the cluster after OPA lookup
type NxtFlow struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Source      string            `protobuf:"bytes,1,opt,name=source,proto3" json:"source,omitempty"`
	Dest        string            `protobuf:"bytes,2,opt,name=dest,proto3" json:"dest,omitempty"`
	Sport       uint32            `protobuf:"varint,3,opt,name=sport,proto3" json:"sport,omitempty"`
	Dport       uint32            `protobuf:"varint,4,opt,name=dport,proto3" json:"dport,omitempty"`
	Proto       uint32            `protobuf:"varint,5,opt,name=proto,proto3" json:"proto,omitempty"`
	SourceAgent string            `protobuf:"bytes,6,opt,name=sourceAgent,proto3" json:"sourceAgent,omitempty"`
	DestAgent   string            `protobuf:"bytes,7,opt,name=destAgent,proto3" json:"destAgent,omitempty"`
	OriginAgent string            `protobuf:"bytes,8,opt,name=originAgent,proto3" json:"originAgent,omitempty"`
	Type        NxtFlow_FLOW_TYPE `protobuf:"varint,9,opt,name=type,proto3,enum=nxthdr.NxtFlow_FLOW_TYPE" json:"type,omitempty"`
	Usrattr     string            `protobuf:"bytes,10,opt,name=usrattr,proto3" json:"usrattr,omitempty"`
}

func (x *NxtFlow) Reset() {
	*x = NxtFlow{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nxt_hdr_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NxtFlow) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NxtFlow) ProtoMessage() {}

func (x *NxtFlow) ProtoReflect() protoreflect.Message {
	mi := &file_nxt_hdr_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NxtFlow.ProtoReflect.Descriptor instead.
func (*NxtFlow) Descriptor() ([]byte, []int) {
	return file_nxt_hdr_proto_rawDescGZIP(), []int{1}
}

func (x *NxtFlow) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

func (x *NxtFlow) GetDest() string {
	if x != nil {
		return x.Dest
	}
	return ""
}

func (x *NxtFlow) GetSport() uint32 {
	if x != nil {
		return x.Sport
	}
	return 0
}

func (x *NxtFlow) GetDport() uint32 {
	if x != nil {
		return x.Dport
	}
	return 0
}

func (x *NxtFlow) GetProto() uint32 {
	if x != nil {
		return x.Proto
	}
	return 0
}

func (x *NxtFlow) GetSourceAgent() string {
	if x != nil {
		return x.SourceAgent
	}
	return ""
}

func (x *NxtFlow) GetDestAgent() string {
	if x != nil {
		return x.DestAgent
	}
	return ""
}

func (x *NxtFlow) GetOriginAgent() string {
	if x != nil {
		return x.OriginAgent
	}
	return ""
}

func (x *NxtFlow) GetType() NxtFlow_FLOW_TYPE {
	if x != nil {
		return x.Type
	}
	return NxtFlow_L4
}

func (x *NxtFlow) GetUsrattr() string {
	if x != nil {
		return x.Usrattr
	}
	return ""
}

// The streamid and streamop is used only in cases where nextensio itself
// is providing stream operations on top of a bare transport like tcp/websocket.
// But if the transport is like an http2/rsocket/quic etc.., then these fields
// are just zero and hence wont occupy space on the wire (zero values are not
// sent on wire by protobuf)
// An Nxt message can be either an onboarding message or data for a user flow
type NxtHdr struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Streamid uint64           `protobuf:"varint,1,opt,name=streamid,proto3" json:"streamid,omitempty"`
	Streamop NxtHdr_STREAM_OP `protobuf:"varint,2,opt,name=streamop,proto3,enum=nxthdr.NxtHdr_STREAM_OP" json:"streamop,omitempty"`
	// Types that are assignable to Hdr:
	//	*NxtHdr_Onboard
	//	*NxtHdr_Flow
	Hdr isNxtHdr_Hdr `protobuf_oneof:"hdr"`
}

func (x *NxtHdr) Reset() {
	*x = NxtHdr{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nxt_hdr_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NxtHdr) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NxtHdr) ProtoMessage() {}

func (x *NxtHdr) ProtoReflect() protoreflect.Message {
	mi := &file_nxt_hdr_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NxtHdr.ProtoReflect.Descriptor instead.
func (*NxtHdr) Descriptor() ([]byte, []int) {
	return file_nxt_hdr_proto_rawDescGZIP(), []int{2}
}

func (x *NxtHdr) GetStreamid() uint64 {
	if x != nil {
		return x.Streamid
	}
	return 0
}

func (x *NxtHdr) GetStreamop() NxtHdr_STREAM_OP {
	if x != nil {
		return x.Streamop
	}
	return NxtHdr_NOOP
}

func (m *NxtHdr) GetHdr() isNxtHdr_Hdr {
	if m != nil {
		return m.Hdr
	}
	return nil
}

func (x *NxtHdr) GetOnboard() *NxtOnboard {
	if x, ok := x.GetHdr().(*NxtHdr_Onboard); ok {
		return x.Onboard
	}
	return nil
}

func (x *NxtHdr) GetFlow() *NxtFlow {
	if x, ok := x.GetHdr().(*NxtHdr_Flow); ok {
		return x.Flow
	}
	return nil
}

type isNxtHdr_Hdr interface {
	isNxtHdr_Hdr()
}

type NxtHdr_Onboard struct {
	Onboard *NxtOnboard `protobuf:"bytes,3,opt,name=onboard,proto3,oneof"`
}

type NxtHdr_Flow struct {
	Flow *NxtFlow `protobuf:"bytes,4,opt,name=flow,proto3,oneof"`
}

func (*NxtHdr_Onboard) isNxtHdr_Hdr() {}

func (*NxtHdr_Flow) isNxtHdr_Hdr() {}

var File_nxt_hdr_proto protoreflect.FileDescriptor

var file_nxt_hdr_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6e, 0x78, 0x74, 0x5f, 0x68, 0x64, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x06, 0x6e, 0x78, 0x74, 0x68, 0x64, 0x72, 0x22, 0x8c, 0x01, 0x0a, 0x0a, 0x4e, 0x78, 0x74, 0x4f,
	0x6e, 0x62, 0x6f, 0x61, 0x72, 0x64, 0x12, 0x14, 0x0a, 0x05, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x12, 0x16, 0x0a, 0x06,
	0x75, 0x73, 0x65, 0x72, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x75, 0x73,
	0x65, 0x72, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x75, 0x75, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x75, 0x75, 0x69, 0x64, 0x12, 0x20, 0x0a, 0x0b, 0x61, 0x63, 0x63, 0x65,
	0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x61,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x18, 0x05, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x22, 0xbf, 0x02, 0x0a, 0x07, 0x4e, 0x78, 0x74, 0x46, 0x6c,
	0x6f, 0x77, 0x12, 0x16, 0x0a, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x65,
	0x73, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x64, 0x65, 0x73, 0x74, 0x12, 0x14,
	0x0a, 0x05, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x73,
	0x70, 0x6f, 0x72, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0d, 0x52, 0x05, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x20, 0x0a, 0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x41, 0x67, 0x65,
	0x6e, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x64, 0x65, 0x73, 0x74, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x18,
	0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x64, 0x65, 0x73, 0x74, 0x41, 0x67, 0x65, 0x6e, 0x74,
	0x12, 0x20, 0x0a, 0x0b, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x18,
	0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x6f, 0x72, 0x69, 0x67, 0x69, 0x6e, 0x41, 0x67, 0x65,
	0x6e, 0x74, 0x12, 0x2d, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0e,
	0x32, 0x19, 0x2e, 0x6e, 0x78, 0x74, 0x68, 0x64, 0x72, 0x2e, 0x4e, 0x78, 0x74, 0x46, 0x6c, 0x6f,
	0x77, 0x2e, 0x46, 0x4c, 0x4f, 0x57, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x52, 0x04, 0x74, 0x79, 0x70,
	0x65, 0x12, 0x18, 0x0a, 0x07, 0x75, 0x73, 0x72, 0x61, 0x74, 0x74, 0x72, 0x18, 0x0a, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x07, 0x75, 0x73, 0x72, 0x61, 0x74, 0x74, 0x72, 0x22, 0x1b, 0x0a, 0x09, 0x46,
	0x4c, 0x4f, 0x57, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x12, 0x06, 0x0a, 0x02, 0x4c, 0x34, 0x10, 0x00,
	0x12, 0x06, 0x0a, 0x02, 0x4c, 0x33, 0x10, 0x01, 0x22, 0xec, 0x01, 0x0a, 0x06, 0x4e, 0x78, 0x74,
	0x48, 0x64, 0x72, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x69, 0x64, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x69, 0x64, 0x12,
	0x34, 0x0a, 0x08, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x6f, 0x70, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x0e, 0x32, 0x18, 0x2e, 0x6e, 0x78, 0x74, 0x68, 0x64, 0x72, 0x2e, 0x4e, 0x78, 0x74, 0x48, 0x64,
	0x72, 0x2e, 0x53, 0x54, 0x52, 0x45, 0x41, 0x4d, 0x5f, 0x4f, 0x50, 0x52, 0x08, 0x73, 0x74, 0x72,
	0x65, 0x61, 0x6d, 0x6f, 0x70, 0x12, 0x2e, 0x0a, 0x07, 0x6f, 0x6e, 0x62, 0x6f, 0x61, 0x72, 0x64,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x6e, 0x78, 0x74, 0x68, 0x64, 0x72, 0x2e,
	0x4e, 0x78, 0x74, 0x4f, 0x6e, 0x62, 0x6f, 0x61, 0x72, 0x64, 0x48, 0x00, 0x52, 0x07, 0x6f, 0x6e,
	0x62, 0x6f, 0x61, 0x72, 0x64, 0x12, 0x25, 0x0a, 0x04, 0x66, 0x6c, 0x6f, 0x77, 0x18, 0x04, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6e, 0x78, 0x74, 0x68, 0x64, 0x72, 0x2e, 0x4e, 0x78, 0x74,
	0x46, 0x6c, 0x6f, 0x77, 0x48, 0x00, 0x52, 0x04, 0x66, 0x6c, 0x6f, 0x77, 0x22, 0x32, 0x0a, 0x09,
	0x53, 0x54, 0x52, 0x45, 0x41, 0x4d, 0x5f, 0x4f, 0x50, 0x12, 0x08, 0x0a, 0x04, 0x4e, 0x4f, 0x4f,
	0x50, 0x10, 0x00, 0x12, 0x09, 0x0a, 0x05, 0x43, 0x4c, 0x4f, 0x53, 0x45, 0x10, 0x01, 0x12, 0x10,
	0x0a, 0x0c, 0x46, 0x4c, 0x4f, 0x57, 0x5f, 0x43, 0x4f, 0x4e, 0x54, 0x52, 0x4f, 0x4c, 0x10, 0x02,
	0x42, 0x05, 0x0a, 0x03, 0x68, 0x64, 0x72, 0x42, 0x2d, 0x5a, 0x2b, 0x67, 0x69, 0x74, 0x6c, 0x61,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x6e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x2f,
	0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x2f,
	0x6e, 0x78, 0x74, 0x68, 0x64, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_nxt_hdr_proto_rawDescOnce sync.Once
	file_nxt_hdr_proto_rawDescData = file_nxt_hdr_proto_rawDesc
)

func file_nxt_hdr_proto_rawDescGZIP() []byte {
	file_nxt_hdr_proto_rawDescOnce.Do(func() {
		file_nxt_hdr_proto_rawDescData = protoimpl.X.CompressGZIP(file_nxt_hdr_proto_rawDescData)
	})
	return file_nxt_hdr_proto_rawDescData
}

var file_nxt_hdr_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_nxt_hdr_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_nxt_hdr_proto_goTypes = []interface{}{
	(NxtFlow_FLOW_TYPE)(0), // 0: nxthdr.NxtFlow.FLOW_TYPE
	(NxtHdr_STREAM_OP)(0),  // 1: nxthdr.NxtHdr.STREAM_OP
	(*NxtOnboard)(nil),     // 2: nxthdr.NxtOnboard
	(*NxtFlow)(nil),        // 3: nxthdr.NxtFlow
	(*NxtHdr)(nil),         // 4: nxthdr.NxtHdr
}
var file_nxt_hdr_proto_depIdxs = []int32{
	0, // 0: nxthdr.NxtFlow.type:type_name -> nxthdr.NxtFlow.FLOW_TYPE
	1, // 1: nxthdr.NxtHdr.streamop:type_name -> nxthdr.NxtHdr.STREAM_OP
	2, // 2: nxthdr.NxtHdr.onboard:type_name -> nxthdr.NxtOnboard
	3, // 3: nxthdr.NxtHdr.flow:type_name -> nxthdr.NxtFlow
	4, // [4:4] is the sub-list for method output_type
	4, // [4:4] is the sub-list for method input_type
	4, // [4:4] is the sub-list for extension type_name
	4, // [4:4] is the sub-list for extension extendee
	0, // [0:4] is the sub-list for field type_name
}

func init() { file_nxt_hdr_proto_init() }
func file_nxt_hdr_proto_init() {
	if File_nxt_hdr_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_nxt_hdr_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NxtOnboard); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_nxt_hdr_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NxtFlow); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_nxt_hdr_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NxtHdr); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_nxt_hdr_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*NxtHdr_Onboard)(nil),
		(*NxtHdr_Flow)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_nxt_hdr_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_nxt_hdr_proto_goTypes,
		DependencyIndexes: file_nxt_hdr_proto_depIdxs,
		EnumInfos:         file_nxt_hdr_proto_enumTypes,
		MessageInfos:      file_nxt_hdr_proto_msgTypes,
	}.Build()
	File_nxt_hdr_proto = out.File
	file_nxt_hdr_proto_rawDesc = nil
	file_nxt_hdr_proto_goTypes = nil
	file_nxt_hdr_proto_depIdxs = nil
}