package pbinter

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

type TermCharatInfo struct {
	Version                []byte //30
	EventType              int32
	DocVersion             []byte //32
	Mac                    []byte //17
	TerminalBrand          []byte //32
	CacheSsid              []byte //256
	CaptureTime            []byte //20
	Rssi                   int64
	IdType                 int32
	IdCode                 []byte //64
	Ssid                   []byte //256
	ApMac                  []byte //17
	AccessApChannel        []byte //2
	AccessApEncryptionType []byte //2
	X                      []byte //8
	Y                      []byte //8
	LocationCode           []byte //14
	ApId                   []byte //21
	Longitude              []byte //11
	Latitude               []byte //11
	Source                 int16
	TerminalBrandType      []byte //32
	TerminalSystem         []byte //16
	SessionId              []byte //64
	DeviceId               []byte //64
	Imsi                   []byte //64
	LocationType           []byte //2
	Floor                  []byte //16
	PlasterSign            int8
	Associated             []byte //32
}

func TestPbinter(t *testing.T) {
	ti := TermCharatInfo{
		Version:                []byte("4.3.1"),
		EventType:              42,
		DocVersion:             []byte("4.3.1"),
		Mac:                    []byte("11:11:11:11:11:11"),
		TerminalBrand:          []byte("01"),
		CaptureTime:            []byte("2016-3-20 14:38:22"),
		Rssi:                   -20,
		IdType:                 19,
		IdCode:                 []byte("13552635245"),
		Ssid:                   []byte("hao123"),
		ApMac:                  []byte("22-22-22-22-22-22"),
		AccessApChannel:        []byte("6"),
		AccessApEncryptionType: []byte("09"),
		X:                 []byte("7"),
		Y:                 []byte("5"),
		LocationCode:      []byte("8"),
		ApId:              []byte("1020004"),
		Longitude:         []byte("123.23000"),
		Latitude:          []byte("133.000000"),
		TerminalBrandType: []byte("Iphone6"),
		TerminalSystem:    []byte("02"),
	}
	EventType := make([]byte, 4)
	IdType := make([]byte, 4)
	Rssi := make([]byte, 8)
	Source := make([]byte, 2)
	PlasterSign := make([]byte, 0)
	PlasterSign = append(PlasterSign, byte(ti.PlasterSign))
	binary.LittleEndian.PutUint32(EventType, uint32(ti.EventType))
	binary.LittleEndian.PutUint16(Source, uint16(ti.Source))
	binary.LittleEndian.PutUint32(IdType, uint32(ti.IdType))
	binary.LittleEndian.PutUint64(Rssi, uint64(ti.Rssi))
	as := [][]byte{ti.Version, EventType, ti.DocVersion, ti.Mac, ti.TerminalBrand, ti.CacheSsid,
		ti.CaptureTime, Rssi, IdType, ti.IdCode, ti.Ssid, ti.ApMac, ti.AccessApChannel, ti.AccessApEncryptionType,
		ti.X, ti.Y, ti.LocationCode, ti.ApId, ti.Longitude, ti.Latitude, Source, ti.TerminalBrandType, ti.TerminalSystem,
		ti.SessionId, ti.DeviceId, ti.DeviceId, ti.LocationType, ti.Floor, PlasterSign, ti.Associated}
	intervar := []byte{1}
	stream := make([]byte, 0)
	stream = bytes.Join(as, intervar)
	offset := len(stream) - (len(ti.Associated) + len(intervar) + 1)
	fmt.Println("offset =", offset)

	inter := Pbinter{
		Host:        "121.43.231.237:7777",
		Timeout:     10 * time.Second,
		OffsetRsend: int32(offset),
		Des: Pbdes{
			//Iv:  []byte("thvn#&@@"),
			Iv:  []byte("11111111"),
			Key: []byte("11111111"),
			//Key: []byte("pk$@gtjt"),
		},
	}
	if err := PbSend(stream, &inter); err != nil {
		fmt.Println("Send failed!")
	}
}
