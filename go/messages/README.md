# Generating code

The protobufs are shared between agent/connectors and the minions. Here is how to generate
the protobuf code for the Go agent (it has to be generated manually).
The protobuf code for the Rust agent is auto-generated when the Rust agent is built. 

## Generating go code

1. Get the protoc compiler (google and download)

2. Install the go extension for protoc
   go get -u github.com/golang/protobuf/protoc-gen-go
  
   The above will put protoc-gen-go in your $GOPATH:/bin, so $GOPATH:/bin has to be in your PATH

3. To generate go code, run the below command in the common/proto directory:
   protoc --go_out=. ./nxt_hdr.proto -I ./

   It will generate the protobuf go code in
       common/proto/gitlab.com/nextensio/common/messages/nxthdr/nxt_hdr.pb.go
   Copy that go file to
       common/go/messages/nxthdr/nxt_hdr.pb.go
   After that, the common/proto/gitlab.com/ subdirectory can be removed.
