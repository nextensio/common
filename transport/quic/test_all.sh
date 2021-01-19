#!/usr/bin/env bash

go test -run Test1ServerStreams
go test -run Test2Pkts
go test -run Test3ClientStreams

