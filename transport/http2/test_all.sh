#!/usr/bin/env bash

go test -run Test1PktsPlainText
go test -run Test2Pkts
go test -run Test3ClientStreams
go test -run Test4ClientStreamsServerClose
