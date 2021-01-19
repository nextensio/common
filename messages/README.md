# Generating code

The protobufs are shared between agent/connectors and the minions. Here is how to generate
the protobuf code. Also agents might be in different languages, so we need instructions on
how to generate it for each language

## Generating go code

1. Get the protoc compiler (google and download)

2. Install the go extension for protoc
   go get -u github.com/golang/protobuf/protoc-gen-go
  
   The above will put protoc-gen-go in your $GOPATH:/bin, so $GOPATH:/bin has to be in your PATH

3. To generate go code, run the below
   protoc --go_out=. ./nxt_hdr.proto -I ./

   It will generate the code in subdirectory gitlab.com/nextensio/message/nxthdr/ .. copy that go file
   from that directory to nxthdr/ and just remove the gitlab.com/... subdirectory

## Generating javascript code

Run this "protoc --js_out=import_style=commonjs,binary:. ./nxt_hdr.proto -I ./"

This will produce the javascript file, copy the javasript file to your javascript agent source code
