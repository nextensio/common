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
	return file_nxt_hdr_proto_rawDescGZIP(), []int{3, 0}
}

// The cluster sends a clock sync message to the agents with its time
// (serverTime), agent responds to the mssage with the serverTime
type NxtClockSync struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ServerTime uint64 `protobuf:"varint,1,opt,name=serverTime,proto3" json:"serverTime,omitempty"`
}

func (x *NxtClockSync) Reset() {
	*x = NxtClockSync{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nxt_hdr_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NxtClockSync) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NxtClockSync) ProtoMessage() {}

func (x *NxtClockSync) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use NxtClockSync.ProtoReflect.Descriptor instead.
func (*NxtClockSync) Descriptor() ([]byte, []int) {
	return file_nxt_hdr_proto_rawDescGZIP(), []int{0}
}

func (x *NxtClockSync) GetServerTime() uint64 {
	if x != nil {
		return x.ServerTime
	}
	return 0
}

// traceCtx is the Jaeger traceid (context) from the Uber-Trace-Id HTTP header.
//
// processingDuration is the time that the agent spent processing the flow from
// the first time it received it from the OS till it was sent to the cluster (in
// nsecs)
type NxtTrace struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TraceCtx           string `protobuf:"bytes,1,opt,name=traceCtx,proto3" json:"traceCtx,omitempty"`
	ProcessingDuration uint64 `protobuf:"varint,2,opt,name=processingDuration,proto3" json:"processingDuration,omitempty"`
	Source             string `protobuf:"bytes,3,opt,name=source,proto3" json:"source,omitempty"`
	Dest               string `protobuf:"bytes,4,opt,name=dest,proto3" json:"dest,omitempty"`
	Sport              uint32 `protobuf:"varint,5,opt,name=sport,proto3" json:"sport,omitempty"`
	Dport              uint32 `protobuf:"varint,6,opt,name=dport,proto3" json:"dport,omitempty"`
	Proto              uint32 `protobuf:"varint,7,opt,name=proto,proto3" json:"proto,omitempty"`
}

func (x *NxtTrace) Reset() {
	*x = NxtTrace{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nxt_hdr_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NxtTrace) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NxtTrace) ProtoMessage() {}

func (x *NxtTrace) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use NxtTrace.ProtoReflect.Descriptor instead.
func (*NxtTrace) Descriptor() ([]byte, []int) {
	return file_nxt_hdr_proto_rawDescGZIP(), []int{1}
}

func (x *NxtTrace) GetTraceCtx() string {
	if x != nil {
		return x.TraceCtx
	}
	return ""
}

func (x *NxtTrace) GetProcessingDuration() uint64 {
	if x != nil {
		return x.ProcessingDuration
	}
	return 0
}

func (x *NxtTrace) GetSource() string {
	if x != nil {
		return x.Source
	}
	return ""
}

func (x *NxtTrace) GetDest() string {
	if x != nil {
		return x.Dest
	}
	return ""
}

func (x *NxtTrace) GetSport() uint32 {
	if x != nil {
		return x.Sport
	}
	return 0
}

func (x *NxtTrace) GetDport() uint32 {
	if x != nil {
		return x.Dport
	}
	return 0
}

func (x *NxtTrace) GetProto() uint32 {
	if x != nil {
		return x.Proto
	}
	return 0
}

// agent: true if its an agent, false for connector.
//
// userid: username of the agent/connector
//
// uuid: a unique identifier for the agent, if the same userid has multiple
// devices, usually just a uuid.UUID suffices to be unique
//
// accessToken: The token of this user, got after logging into IDP. If its a
// bundle, the token will be a sharedKey generated by the controller
//
// services: the service names advertised by this agent/connector
//
// cluster: If the agent/connector is supposed to connect to a SPECIFIC cluster,
// the cluster field indicates that cluster name
//
// podname: The name of the pod on the cluster that this agent/connector should
// connect to
//
// connectId: Usually the agent/connectors username converted to a value that is
// palatable to various kubernetes entities like istio http header matching
// rules. This value is constructed by the controller
//
// attributes: json string of device attributes such as hostname, model,
// os_xyz: device/operating system details
type NxtOnboard struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Agent       bool     `protobuf:"varint,1,opt,name=agent,proto3" json:"agent,omitempty"`
	Userid      string   `protobuf:"bytes,2,opt,name=userid,proto3" json:"userid,omitempty"`
	Uuid        string   `protobuf:"bytes,3,opt,name=uuid,proto3" json:"uuid,omitempty"`
	AccessToken string   `protobuf:"bytes,4,opt,name=accessToken,proto3" json:"accessToken,omitempty"`
	Services    []string `protobuf:"bytes,5,rep,name=services,proto3" json:"services,omitempty"`
	Cluster     string   `protobuf:"bytes,6,opt,name=cluster,proto3" json:"cluster,omitempty"`
	Podname     string   `protobuf:"bytes,7,opt,name=podname,proto3" json:"podname,omitempty"`
	ConnectId   string   `protobuf:"bytes,8,opt,name=connectId,proto3" json:"connectId,omitempty"`
	Attributes  string   `protobuf:"bytes,9,opt,name=attributes,proto3" json:"attributes,omitempty"`
}

func (x *NxtOnboard) Reset() {
	*x = NxtOnboard{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nxt_hdr_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NxtOnboard) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NxtOnboard) ProtoMessage() {}

func (x *NxtOnboard) ProtoReflect() protoreflect.Message {
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

// Deprecated: Use NxtOnboard.ProtoReflect.Descriptor instead.
func (*NxtOnboard) Descriptor() ([]byte, []int) {
	return file_nxt_hdr_proto_rawDescGZIP(), []int{2}
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

func (x *NxtOnboard) GetCluster() string {
	if x != nil {
		return x.Cluster
	}
	return ""
}

func (x *NxtOnboard) GetPodname() string {
	if x != nil {
		return x.Podname
	}
	return ""
}

func (x *NxtOnboard) GetConnectId() string {
	if x != nil {
		return x.ConnectId
	}
	return ""
}

func (x *NxtOnboard) GetAttributes() string {
	if x != nil {
		return x.Attributes
	}
	return ""
}

type NxtFlow struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Source             string            `protobuf:"bytes,1,opt,name=source,proto3" json:"source,omitempty"`
	Dest               string            `protobuf:"bytes,2,opt,name=dest,proto3" json:"dest,omitempty"`
	DestSvc            string            `protobuf:"bytes,3,opt,name=destSvc,proto3" json:"destSvc,omitempty"`
	Sport              uint32            `protobuf:"varint,4,opt,name=sport,proto3" json:"sport,omitempty"`
	Dport              uint32            `protobuf:"varint,5,opt,name=dport,proto3" json:"dport,omitempty"`
	Proto              uint32            `protobuf:"varint,6,opt,name=proto,proto3" json:"proto,omitempty"`
	SourceAgent        string            `protobuf:"bytes,7,opt,name=sourceAgent,proto3" json:"sourceAgent,omitempty"`
	DestAgent          string            `protobuf:"bytes,8,opt,name=destAgent,proto3" json:"destAgent,omitempty"`
	AgentUuid          string            `protobuf:"bytes,9,opt,name=agentUuid,proto3" json:"agentUuid,omitempty"`
	Type               NxtFlow_FLOW_TYPE `protobuf:"varint,10,opt,name=type,proto3,enum=nxthdr.NxtFlow_FLOW_TYPE" json:"type,omitempty"`
	Usrattr            string            `protobuf:"bytes,11,opt,name=usrattr,proto3" json:"usrattr,omitempty"`
	ResponseData       bool              `protobuf:"varint,12,opt,name=responseData,proto3" json:"responseData,omitempty"`
	UserCluster        string            `protobuf:"bytes,13,opt,name=userCluster,proto3" json:"userCluster,omitempty"`
	UserPod            string            `protobuf:"bytes,14,opt,name=userPod,proto3" json:"userPod,omitempty"`
	Userid             string            `protobuf:"bytes,15,opt,name=userid,proto3" json:"userid,omitempty"`
	TraceCtx           string            `protobuf:"bytes,16,opt,name=traceCtx,proto3" json:"traceCtx,omitempty"`
	TraceRequestId     string            `protobuf:"bytes,17,opt,name=traceRequestId,proto3" json:"traceRequestId,omitempty"`
	ProcessingDuration uint64            `protobuf:"varint,18,opt,name=processingDuration,proto3" json:"processingDuration,omitempty"`
}

func (x *NxtFlow) Reset() {
	*x = NxtFlow{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nxt_hdr_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NxtFlow) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NxtFlow) ProtoMessage() {}

func (x *NxtFlow) ProtoReflect() protoreflect.Message {
	mi := &file_nxt_hdr_proto_msgTypes[3]
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
	return file_nxt_hdr_proto_rawDescGZIP(), []int{3}
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

func (x *NxtFlow) GetDestSvc() string {
	if x != nil {
		return x.DestSvc
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

func (x *NxtFlow) GetAgentUuid() string {
	if x != nil {
		return x.AgentUuid
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

func (x *NxtFlow) GetResponseData() bool {
	if x != nil {
		return x.ResponseData
	}
	return false
}

func (x *NxtFlow) GetUserCluster() string {
	if x != nil {
		return x.UserCluster
	}
	return ""
}

func (x *NxtFlow) GetUserPod() string {
	if x != nil {
		return x.UserPod
	}
	return ""
}

func (x *NxtFlow) GetUserid() string {
	if x != nil {
		return x.Userid
	}
	return ""
}

func (x *NxtFlow) GetTraceCtx() string {
	if x != nil {
		return x.TraceCtx
	}
	return ""
}

func (x *NxtFlow) GetTraceRequestId() string {
	if x != nil {
		return x.TraceRequestId
	}
	return ""
}

func (x *NxtFlow) GetProcessingDuration() uint64 {
	if x != nil {
		return x.ProcessingDuration
	}
	return 0
}

type NxtKeepalive struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *NxtKeepalive) Reset() {
	*x = NxtKeepalive{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nxt_hdr_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NxtKeepalive) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NxtKeepalive) ProtoMessage() {}

func (x *NxtKeepalive) ProtoReflect() protoreflect.Message {
	mi := &file_nxt_hdr_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NxtKeepalive.ProtoReflect.Descriptor instead.
func (*NxtKeepalive) Descriptor() ([]byte, []int) {
	return file_nxt_hdr_proto_rawDescGZIP(), []int{4}
}

type NxtClose struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *NxtClose) Reset() {
	*x = NxtClose{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nxt_hdr_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NxtClose) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NxtClose) ProtoMessage() {}

func (x *NxtClose) ProtoReflect() protoreflect.Message {
	mi := &file_nxt_hdr_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use NxtClose.ProtoReflect.Descriptor instead.
func (*NxtClose) Descriptor() ([]byte, []int) {
	return file_nxt_hdr_proto_rawDescGZIP(), []int{5}
}

// datalen: if there is raw data that follows this header, the size of raw data
// in bytes
//
// streamid: an identifier that helps multiplex multiple streams in one session
//
// oneof hdr: The header can be ONE of many different types based on what info
// it carries
type NxtHdr struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Datalen  uint32 `protobuf:"varint,1,opt,name=datalen,proto3" json:"datalen,omitempty"`
	Streamid uint64 `protobuf:"varint,2,opt,name=streamid,proto3" json:"streamid,omitempty"`
	// Types that are assignable to Hdr:
	//	*NxtHdr_Close
	//	*NxtHdr_Onboard
	//	*NxtHdr_Flow
	//	*NxtHdr_Keepalive
	//	*NxtHdr_Trace
	//	*NxtHdr_Sync
	Hdr isNxtHdr_Hdr `protobuf_oneof:"hdr"`
}

func (x *NxtHdr) Reset() {
	*x = NxtHdr{}
	if protoimpl.UnsafeEnabled {
		mi := &file_nxt_hdr_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *NxtHdr) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*NxtHdr) ProtoMessage() {}

func (x *NxtHdr) ProtoReflect() protoreflect.Message {
	mi := &file_nxt_hdr_proto_msgTypes[6]
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
	return file_nxt_hdr_proto_rawDescGZIP(), []int{6}
}

func (x *NxtHdr) GetDatalen() uint32 {
	if x != nil {
		return x.Datalen
	}
	return 0
}

func (x *NxtHdr) GetStreamid() uint64 {
	if x != nil {
		return x.Streamid
	}
	return 0
}

func (m *NxtHdr) GetHdr() isNxtHdr_Hdr {
	if m != nil {
		return m.Hdr
	}
	return nil
}

func (x *NxtHdr) GetClose() *NxtClose {
	if x, ok := x.GetHdr().(*NxtHdr_Close); ok {
		return x.Close
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

func (x *NxtHdr) GetKeepalive() *NxtKeepalive {
	if x, ok := x.GetHdr().(*NxtHdr_Keepalive); ok {
		return x.Keepalive
	}
	return nil
}

func (x *NxtHdr) GetTrace() *NxtTrace {
	if x, ok := x.GetHdr().(*NxtHdr_Trace); ok {
		return x.Trace
	}
	return nil
}

func (x *NxtHdr) GetSync() *NxtClockSync {
	if x, ok := x.GetHdr().(*NxtHdr_Sync); ok {
		return x.Sync
	}
	return nil
}

type isNxtHdr_Hdr interface {
	isNxtHdr_Hdr()
}

type NxtHdr_Close struct {
	Close *NxtClose `protobuf:"bytes,3,opt,name=close,proto3,oneof"`
}

type NxtHdr_Onboard struct {
	Onboard *NxtOnboard `protobuf:"bytes,4,opt,name=onboard,proto3,oneof"`
}

type NxtHdr_Flow struct {
	Flow *NxtFlow `protobuf:"bytes,5,opt,name=flow,proto3,oneof"`
}

type NxtHdr_Keepalive struct {
	Keepalive *NxtKeepalive `protobuf:"bytes,6,opt,name=keepalive,proto3,oneof"`
}

type NxtHdr_Trace struct {
	Trace *NxtTrace `protobuf:"bytes,7,opt,name=trace,proto3,oneof"`
}

type NxtHdr_Sync struct {
	Sync *NxtClockSync `protobuf:"bytes,8,opt,name=sync,proto3,oneof"`
}

func (*NxtHdr_Close) isNxtHdr_Hdr() {}

func (*NxtHdr_Onboard) isNxtHdr_Hdr() {}

func (*NxtHdr_Flow) isNxtHdr_Hdr() {}

func (*NxtHdr_Keepalive) isNxtHdr_Hdr() {}

func (*NxtHdr_Trace) isNxtHdr_Hdr() {}

func (*NxtHdr_Sync) isNxtHdr_Hdr() {}

var File_nxt_hdr_proto protoreflect.FileDescriptor

var file_nxt_hdr_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x6e, 0x78, 0x74, 0x5f, 0x68, 0x64, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x06, 0x6e, 0x78, 0x74, 0x68, 0x64, 0x72, 0x22, 0x2e, 0x0a, 0x0c, 0x4e, 0x78, 0x74, 0x43, 0x6c,
	0x6f, 0x63, 0x6b, 0x53, 0x79, 0x6e, 0x63, 0x12, 0x1e, 0x0a, 0x0a, 0x73, 0x65, 0x72, 0x76, 0x65,
	0x72, 0x54, 0x69, 0x6d, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0a, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x72, 0x54, 0x69, 0x6d, 0x65, 0x22, 0xc4, 0x01, 0x0a, 0x08, 0x4e, 0x78, 0x74, 0x54,
	0x72, 0x61, 0x63, 0x65, 0x12, 0x1a, 0x0a, 0x08, 0x74, 0x72, 0x61, 0x63, 0x65, 0x43, 0x74, 0x78,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x74, 0x72, 0x61, 0x63, 0x65, 0x43, 0x74, 0x78,
	0x12, 0x2e, 0x0a, 0x12, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x69, 0x6e, 0x67, 0x44, 0x75,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x12, 0x70, 0x72,
	0x6f, 0x63, 0x65, 0x73, 0x73, 0x69, 0x6e, 0x67, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x12, 0x16, 0x0a, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x65, 0x73, 0x74,
	0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x64, 0x65, 0x73, 0x74, 0x12, 0x14, 0x0a, 0x05,
	0x73, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x73, 0x70, 0x6f,
	0x72, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x06, 0x20, 0x01, 0x28,
	0x0d, 0x52, 0x05, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xfe,
	0x01, 0x0a, 0x0a, 0x4e, 0x78, 0x74, 0x4f, 0x6e, 0x62, 0x6f, 0x61, 0x72, 0x64, 0x12, 0x14, 0x0a,
	0x05, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x05, 0x61, 0x67,
	0x65, 0x6e, 0x74, 0x12, 0x16, 0x0a, 0x06, 0x75, 0x73, 0x65, 0x72, 0x69, 0x64, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x75,
	0x75, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x75, 0x75, 0x69, 0x64, 0x12,
	0x20, 0x0a, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x04,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65,
	0x6e, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x18, 0x05, 0x20,
	0x03, 0x28, 0x09, 0x52, 0x08, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x12, 0x18, 0x0a,
	0x07, 0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x18, 0x06, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07,
	0x63, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x12, 0x18, 0x0a, 0x07, 0x70, 0x6f, 0x64, 0x6e, 0x61,
	0x6d, 0x65, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x70, 0x6f, 0x64, 0x6e, 0x61, 0x6d,
	0x65, 0x12, 0x1c, 0x0a, 0x09, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x49, 0x64, 0x18, 0x08,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x49, 0x64, 0x12,
	0x1e, 0x0a, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x18, 0x09, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0a, 0x61, 0x74, 0x74, 0x72, 0x69, 0x62, 0x75, 0x74, 0x65, 0x73, 0x22,
	0xc1, 0x04, 0x0a, 0x07, 0x4e, 0x78, 0x74, 0x46, 0x6c, 0x6f, 0x77, 0x12, 0x16, 0x0a, 0x06, 0x73,
	0x6f, 0x75, 0x72, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x73, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x12, 0x12, 0x0a, 0x04, 0x64, 0x65, 0x73, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x04, 0x64, 0x65, 0x73, 0x74, 0x12, 0x18, 0x0a, 0x07, 0x64, 0x65, 0x73, 0x74, 0x53,
	0x76, 0x63, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x64, 0x65, 0x73, 0x74, 0x53, 0x76,
	0x63, 0x12, 0x14, 0x0a, 0x05, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x05, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x64, 0x70, 0x6f, 0x72, 0x74,
	0x18, 0x05, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x64, 0x70, 0x6f, 0x72, 0x74, 0x12, 0x14, 0x0a,
	0x05, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x20, 0x0a, 0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65, 0x41, 0x67, 0x65,
	0x6e, 0x74, 0x18, 0x07, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x41, 0x67, 0x65, 0x6e, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x64, 0x65, 0x73, 0x74, 0x41, 0x67, 0x65,
	0x6e, 0x74, 0x18, 0x08, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x64, 0x65, 0x73, 0x74, 0x41, 0x67,
	0x65, 0x6e, 0x74, 0x12, 0x1c, 0x0a, 0x09, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x55, 0x75, 0x69, 0x64,
	0x18, 0x09, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09, 0x61, 0x67, 0x65, 0x6e, 0x74, 0x55, 0x75, 0x69,
	0x64, 0x12, 0x2d, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x0e, 0x32,
	0x19, 0x2e, 0x6e, 0x78, 0x74, 0x68, 0x64, 0x72, 0x2e, 0x4e, 0x78, 0x74, 0x46, 0x6c, 0x6f, 0x77,
	0x2e, 0x46, 0x4c, 0x4f, 0x57, 0x5f, 0x54, 0x59, 0x50, 0x45, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65,
	0x12, 0x18, 0x0a, 0x07, 0x75, 0x73, 0x72, 0x61, 0x74, 0x74, 0x72, 0x18, 0x0b, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x75, 0x73, 0x72, 0x61, 0x74, 0x74, 0x72, 0x12, 0x22, 0x0a, 0x0c, 0x72, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x44, 0x61, 0x74, 0x61, 0x18, 0x0c, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x0c, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x44, 0x61, 0x74, 0x61, 0x12, 0x20,
	0x0a, 0x0b, 0x75, 0x73, 0x65, 0x72, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72, 0x18, 0x0d, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0b, 0x75, 0x73, 0x65, 0x72, 0x43, 0x6c, 0x75, 0x73, 0x74, 0x65, 0x72,
	0x12, 0x18, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x50, 0x6f, 0x64, 0x18, 0x0e, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x07, 0x75, 0x73, 0x65, 0x72, 0x50, 0x6f, 0x64, 0x12, 0x16, 0x0a, 0x06, 0x75, 0x73,
	0x65, 0x72, 0x69, 0x64, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x09, 0x52, 0x06, 0x75, 0x73, 0x65, 0x72,
	0x69, 0x64, 0x12, 0x1a, 0x0a, 0x08, 0x74, 0x72, 0x61, 0x63, 0x65, 0x43, 0x74, 0x78, 0x18, 0x10,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x74, 0x72, 0x61, 0x63, 0x65, 0x43, 0x74, 0x78, 0x12, 0x26,
	0x0a, 0x0e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x49, 0x64,
	0x18, 0x11, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0e, 0x74, 0x72, 0x61, 0x63, 0x65, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x49, 0x64, 0x12, 0x2e, 0x0a, 0x12, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73,
	0x73, 0x69, 0x6e, 0x67, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x12, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x12, 0x70, 0x72, 0x6f, 0x63, 0x65, 0x73, 0x73, 0x69, 0x6e, 0x67, 0x44, 0x75,
	0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22, 0x1b, 0x0a, 0x09, 0x46, 0x4c, 0x4f, 0x57, 0x5f, 0x54,
	0x59, 0x50, 0x45, 0x12, 0x06, 0x0a, 0x02, 0x4c, 0x34, 0x10, 0x00, 0x12, 0x06, 0x0a, 0x02, 0x4c,
	0x33, 0x10, 0x01, 0x22, 0x0e, 0x0a, 0x0c, 0x4e, 0x78, 0x74, 0x4b, 0x65, 0x65, 0x70, 0x61, 0x6c,
	0x69, 0x76, 0x65, 0x22, 0x0a, 0x0a, 0x08, 0x4e, 0x78, 0x74, 0x43, 0x6c, 0x6f, 0x73, 0x65, 0x22,
	0xd2, 0x02, 0x0a, 0x06, 0x4e, 0x78, 0x74, 0x48, 0x64, 0x72, 0x12, 0x18, 0x0a, 0x07, 0x64, 0x61,
	0x74, 0x61, 0x6c, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x64, 0x61, 0x74,
	0x61, 0x6c, 0x65, 0x6e, 0x12, 0x1a, 0x0a, 0x08, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x69, 0x64,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x08, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x69, 0x64,
	0x12, 0x28, 0x0a, 0x05, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x10, 0x2e, 0x6e, 0x78, 0x74, 0x68, 0x64, 0x72, 0x2e, 0x4e, 0x78, 0x74, 0x43, 0x6c, 0x6f, 0x73,
	0x65, 0x48, 0x00, 0x52, 0x05, 0x63, 0x6c, 0x6f, 0x73, 0x65, 0x12, 0x2e, 0x0a, 0x07, 0x6f, 0x6e,
	0x62, 0x6f, 0x61, 0x72, 0x64, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x12, 0x2e, 0x6e, 0x78,
	0x74, 0x68, 0x64, 0x72, 0x2e, 0x4e, 0x78, 0x74, 0x4f, 0x6e, 0x62, 0x6f, 0x61, 0x72, 0x64, 0x48,
	0x00, 0x52, 0x07, 0x6f, 0x6e, 0x62, 0x6f, 0x61, 0x72, 0x64, 0x12, 0x25, 0x0a, 0x04, 0x66, 0x6c,
	0x6f, 0x77, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x0f, 0x2e, 0x6e, 0x78, 0x74, 0x68, 0x64,
	0x72, 0x2e, 0x4e, 0x78, 0x74, 0x46, 0x6c, 0x6f, 0x77, 0x48, 0x00, 0x52, 0x04, 0x66, 0x6c, 0x6f,
	0x77, 0x12, 0x34, 0x0a, 0x09, 0x6b, 0x65, 0x65, 0x70, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x18, 0x06,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x14, 0x2e, 0x6e, 0x78, 0x74, 0x68, 0x64, 0x72, 0x2e, 0x4e, 0x78,
	0x74, 0x4b, 0x65, 0x65, 0x70, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x48, 0x00, 0x52, 0x09, 0x6b, 0x65,
	0x65, 0x70, 0x61, 0x6c, 0x69, 0x76, 0x65, 0x12, 0x28, 0x0a, 0x05, 0x74, 0x72, 0x61, 0x63, 0x65,
	0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e, 0x6e, 0x78, 0x74, 0x68, 0x64, 0x72, 0x2e,
	0x4e, 0x78, 0x74, 0x54, 0x72, 0x61, 0x63, 0x65, 0x48, 0x00, 0x52, 0x05, 0x74, 0x72, 0x61, 0x63,
	0x65, 0x12, 0x2a, 0x0a, 0x04, 0x73, 0x79, 0x6e, 0x63, 0x18, 0x08, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x14, 0x2e, 0x6e, 0x78, 0x74, 0x68, 0x64, 0x72, 0x2e, 0x4e, 0x78, 0x74, 0x43, 0x6c, 0x6f, 0x63,
	0x6b, 0x53, 0x79, 0x6e, 0x63, 0x48, 0x00, 0x52, 0x04, 0x73, 0x79, 0x6e, 0x63, 0x42, 0x05, 0x0a,
	0x03, 0x68, 0x64, 0x72, 0x42, 0x2d, 0x5a, 0x2b, 0x67, 0x69, 0x74, 0x6c, 0x61, 0x62, 0x2e, 0x63,
	0x6f, 0x6d, 0x2f, 0x6e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x2f, 0x63, 0x6f, 0x6d,
	0x6d, 0x6f, 0x6e, 0x2f, 0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x73, 0x2f, 0x6e, 0x78, 0x74,
	0x68, 0x64, 0x72, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
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

var file_nxt_hdr_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_nxt_hdr_proto_msgTypes = make([]protoimpl.MessageInfo, 7)
var file_nxt_hdr_proto_goTypes = []interface{}{
	(NxtFlow_FLOW_TYPE)(0), // 0: nxthdr.NxtFlow.FLOW_TYPE
	(*NxtClockSync)(nil),   // 1: nxthdr.NxtClockSync
	(*NxtTrace)(nil),       // 2: nxthdr.NxtTrace
	(*NxtOnboard)(nil),     // 3: nxthdr.NxtOnboard
	(*NxtFlow)(nil),        // 4: nxthdr.NxtFlow
	(*NxtKeepalive)(nil),   // 5: nxthdr.NxtKeepalive
	(*NxtClose)(nil),       // 6: nxthdr.NxtClose
	(*NxtHdr)(nil),         // 7: nxthdr.NxtHdr
}
var file_nxt_hdr_proto_depIdxs = []int32{
	0, // 0: nxthdr.NxtFlow.type:type_name -> nxthdr.NxtFlow.FLOW_TYPE
	6, // 1: nxthdr.NxtHdr.close:type_name -> nxthdr.NxtClose
	3, // 2: nxthdr.NxtHdr.onboard:type_name -> nxthdr.NxtOnboard
	4, // 3: nxthdr.NxtHdr.flow:type_name -> nxthdr.NxtFlow
	5, // 4: nxthdr.NxtHdr.keepalive:type_name -> nxthdr.NxtKeepalive
	2, // 5: nxthdr.NxtHdr.trace:type_name -> nxthdr.NxtTrace
	1, // 6: nxthdr.NxtHdr.sync:type_name -> nxthdr.NxtClockSync
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_nxt_hdr_proto_init() }
func file_nxt_hdr_proto_init() {
	if File_nxt_hdr_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_nxt_hdr_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NxtClockSync); i {
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
			switch v := v.(*NxtTrace); i {
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
		file_nxt_hdr_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
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
		file_nxt_hdr_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NxtKeepalive); i {
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
		file_nxt_hdr_proto_msgTypes[5].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*NxtClose); i {
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
		file_nxt_hdr_proto_msgTypes[6].Exporter = func(v interface{}, i int) interface{} {
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
	file_nxt_hdr_proto_msgTypes[6].OneofWrappers = []interface{}{
		(*NxtHdr_Close)(nil),
		(*NxtHdr_Onboard)(nil),
		(*NxtHdr_Flow)(nil),
		(*NxtHdr_Keepalive)(nil),
		(*NxtHdr_Trace)(nil),
		(*NxtHdr_Sync)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_nxt_hdr_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   7,
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
