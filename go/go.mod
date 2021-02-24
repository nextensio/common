module gitlab.com/nextensio/common/go

go 1.15

// This ideally should need to be done only in this repo because thats where we use gvisor
// But when someone else does "require common", this replace statement does not seem to be
// honored/inherited and hence those modules also have to cut+paste this same replace statement.
// The gvisor lib has a couple of fixes required for android and hence we have forked it into our
// own repo and added the couple of fixes on top
replace gvisor.dev/gvisor v0.0.0-20201204040109-0ba39926c86f => github.com/gopakumarce/gvisor v0.0.0-20210204213648-2e0adbf0d94a

require (
	github.com/golang/protobuf v1.4.3
	github.com/google/gopacket v1.1.19
	github.com/google/uuid v1.1.2
	github.com/gopakumarce/tlsx v0.0.0-20170624122154-28fd0e59bac4
	github.com/gorilla/websocket v1.4.2
	github.com/lucas-clemente/quic-go v0.19.3
	github.com/pion/dtls/v2 v2.0.4
	golang.org/x/net v0.0.0-20201031054903-ff519b6c9102
	golang.org/x/sys v0.0.0-20200930185726-fdedc70b468f
	google.golang.org/genproto v0.0.0-20200526211855-cb27e3aa2013 // indirect
	google.golang.org/protobuf v1.25.1-0.20201020201750-d3470999428b
	gvisor.dev/gvisor v0.0.0-20201204040109-0ba39926c86f
)
