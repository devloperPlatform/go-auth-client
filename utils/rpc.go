package utils

import (
	"bytes"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"io"
)

const (
	blockSize = 1024*1024*2 - 1024*2
)

type GrpcStrSender interface {
	Send(value *wrapperspb.StringValue) error
}

type GrpcStrRecv interface {
	Recv() (*wrapperspb.StringValue, error)
}

func GrpcSendBytesToStrServer(server GrpcStrSender, data []byte) error {
	reader := bytes.NewReader(data)
	buf := make([]byte, blockSize, blockSize)
	for {
		readSize, err := reader.Read(buf)
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		if err = server.Send(wrapperspb.String(string(buf[:readSize]))); err != nil {
			return err
		}
	}
}

func GrpcRecvStreamStrToStr(server GrpcStrRecv) (string, error) {
	buf := &bytes.Buffer{}
	for {
		recv, err := server.Recv()
		if err == io.EOF {
			return buf.String(), nil
		}
		if err != nil {
			return "", err
		}
		buf.WriteString(recv.Value)
	}
}
