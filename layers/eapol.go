// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"encoding/binary"
	"github.com/mistsys/gopacket"
)

// EAPOL defines an EAP over LAN (802.1x) layer.
type EAPOL struct {
	BaseLayer
	Version uint8
	Type    EAPOLType
	Length  uint16
}

// LayerType returns LayerTypeEAPOL.
func (e *EAPOL) LayerType() gopacket.LayerType { return LayerTypeEAPOL }

// DecodeFromBytes decodes the given bytes into this layer.
func (e *EAPOL) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	e.Version = data[0]
	e.Type = EAPOLType(data[1])
	e.Length = binary.BigEndian.Uint16(data[2:4])
	e.BaseLayer = BaseLayer{data[:4], data[4:]}
	return nil
}

// CanDecode returns the set of layer types that this DecodingLayer can decode.
func (e *EAPOL) CanDecode() gopacket.LayerClass {
	return LayerTypeEAPOL
}

// NextLayerType returns the layer type contained by this DecodingLayer.
func (e *EAPOL) NextLayerType() gopacket.LayerType {
	return e.Type.LayerType()
}

func decodeEAPOL(data []byte, p gopacket.PacketBuilder) error {
	e := &EAPOL{}
	return decodingLayerDecoder(e, data, p)
}

type KeyInfo uint16

const (
	KeyInfo_DescriptorVersion KeyInfo = 1 << 0
	KeyInfo_Type
	KeyInfo_Install
	KeyInfo_ACK
	KeyInfo_MIC
	KeyInfo_Secure
	KeyInfo_Error
	KeyInfo_Request
	KeyInfo_EncryptedKeyData
	KeyInfo_SMKMessage
)

type EAPOLKey struct {
	BaseLayer

	DescriptorType uint8
	KeyInfo        uint16

	KeyInfo_DescriptorVersion int
	KeyInfo_Type              int
	KeyInfo_Install           int
	KeyInfo_ACK               int
	KeyInfo_MIC               int
	KeyInfo_Secure            int
	KeyInfo_Error             int
	KeyInfo_Request           int
	KeyInfo_EncryptedKeyData  int
	KeyInfo_SMKMessage        int

	KeyLength uint16

	KeyReplayCounter []byte // 8 bytes
	KeyNonce         []byte // 32 bytes
	KeyIV            []byte // 16 bytes
	KeyRSC           []byte // 8 bytes
	//KeyMIC           []byte // variable length
	//KeyDataLength    uint16
	//KeyData          []byte
}

func (e *EAPOLKey) LayerType() gopacket.LayerType {
	return LayerTypeEAPOLKey
}

func (e *EAPOLKey) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {

	e.DescriptorType = uint8(data[0])
	e.KeyInfo = binary.LittleEndian.Uint16(data[1:3])

	e.KeyInfo_DescriptorVersion = int(e.KeyInfo & 7)
	e.KeyInfo_Type = int((e.KeyInfo >> 3) & 1)
	e.KeyInfo_Install = int((e.KeyInfo >> 6) & 1)
	e.KeyInfo_ACK = int((e.KeyInfo >> 7) & 1)
	e.KeyInfo_MIC = int((e.KeyInfo >> 8) & 1)
	e.KeyInfo_Secure = int((e.KeyInfo >> 9) & 1)
	e.KeyInfo_Error = int((e.KeyInfo >> 10) & 1)
	e.KeyInfo_Request = int((e.KeyInfo >> 11) & 1)
	e.KeyInfo_EncryptedKeyData = int((e.KeyInfo >> 12) & 1)
	e.KeyInfo_SMKMessage = int((e.KeyInfo >> 13) & 1)

	e.KeyLength = binary.LittleEndian.Uint16(data[3:5])

	e.KeyReplayCounter = data[5 : 5+8]
	e.KeyNonce = data[13 : 13+32]
	e.KeyIV = data[45 : 45+16]
	e.KeyRSC = data[61 : 61+8]

	e.BaseLayer = BaseLayer{Contents: data}
	e.Payload = nil
	return nil
}

func (e *EAPOLKey) CanDecode() gopacket.LayerClass {
	return LayerTypeEAPOLKey
}

func (e *EAPOLKey) NextLayerType() gopacket.LayerType {
	return gopacket.LayerTypePayload
}

func decodeEAPOLKey(data []byte, p gopacket.PacketBuilder) error {
	e := &EAPOLKey{}
	return decodingLayerDecoder(e, data, p)
}
