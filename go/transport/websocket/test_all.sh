#!/usr/bin/env bash

go test -run Test1Pkts
go test -run Test2ClientStreams
go test -run Test3ClientStreamServerClose
go test -run Test4ServerStreams
go test -run Test5ServerStreamsClientClose

