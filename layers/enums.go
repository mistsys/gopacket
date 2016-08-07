// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package layers

import (
	"errors"
	"fmt"

	"github.com/mistsys/gopacket"
)

// EnumMetadata keeps track of a set of metadata for each enumeration value
// for protocol enumerations.
type EnumMetadata struct {
	// DecodeWith is the decoder to use to decode this protocol's data.
	DecodeWith gopacket.Decoder
	// Name is the name of the enumeration value.
	Name string
	// LayerType is the layer type implied by the given enum.
	LayerType gopacket.LayerType
}

// errorFunc returns a decoder that spits out a specific error message.
func errorFunc(msg string) gopacket.Decoder {
	var e = errors.New(msg)
	return gopacket.DecodeFunc(func([]byte, gopacket.PacketBuilder) error {
		return e
	})
}

// EthernetType is an enumeration of ethernet type values, and acts as a decoder
// for any type it supports.
type EthernetType uint16

const (
	// EthernetTypeLLC is not an actual ethernet type.  It is instead a
	// placeholder we use in Ethernet frames that use the 802.3 standard of
	// srcmac|dstmac|length|LLC instead of srcmac|dstmac|ethertype.
	EthernetTypeLLC                         EthernetType = 0
	EthernetTypeIPv4                        EthernetType = 0x0800
	EthernetTypeARP                         EthernetType = 0x0806
	EthernetTypeIPv6                        EthernetType = 0x86DD
	EthernetTypeCiscoDiscovery              EthernetType = 0x2000
	EthernetTypeNortelDiscovery             EthernetType = 0x01a2
	EthernetTypeTransparentEthernetBridging EthernetType = 0x6558
	EthernetTypeDot1Q                       EthernetType = 0x8100
	EthernetTypePPPoEDiscovery              EthernetType = 0x8863
	EthernetTypePPPoESession                EthernetType = 0x8864
	EthernetTypeMPLSUnicast                 EthernetType = 0x8847
	EthernetTypeMPLSMulticast               EthernetType = 0x8848
	EthernetTypeEAPOL                       EthernetType = 0x888e
	EthernetTypeQinQ                        EthernetType = 0x88a8
	EthernetTypeLinkLayerDiscovery          EthernetType = 0x88cc
	EthernetTypeEthernetCTP                 EthernetType = 0x9000
)

// IPProtocol is an enumeration of IP protocol values, and acts as a decoder
// for any type it supports.
type IPProtocol uint8

const (
	IPProtocolIPv6HopByHop    IPProtocol = 0
	IPProtocolICMPv4          IPProtocol = 1
	IPProtocolIGMP            IPProtocol = 2
	IPProtocolIPv4            IPProtocol = 4
	IPProtocolTCP             IPProtocol = 6
	IPProtocolUDP             IPProtocol = 17
	IPProtocolRUDP            IPProtocol = 27
	IPProtocolIPv6            IPProtocol = 41
	IPProtocolIPv6Routing     IPProtocol = 43
	IPProtocolIPv6Fragment    IPProtocol = 44
	IPProtocolGRE             IPProtocol = 47
	IPProtocolESP             IPProtocol = 50
	IPProtocolAH              IPProtocol = 51
	IPProtocolICMPv6          IPProtocol = 58
	IPProtocolNoNextHeader    IPProtocol = 59
	IPProtocolIPv6Destination IPProtocol = 60
	IPProtocolIPIP            IPProtocol = 94
	IPProtocolEtherIP         IPProtocol = 97
	IPProtocolVRRP            IPProtocol = 112
	IPProtocolSCTP            IPProtocol = 132
	IPProtocolUDPLite         IPProtocol = 136
	IPProtocolMPLSInIP        IPProtocol = 137
)

// LinkType is an enumeration of link types, and acts as a decoder for any
// link type it supports.
type LinkType uint8

const (
	// According to pcap-linktype(7) and http://www.tcpdump.org/linktypes.html
	LinkTypeNull           LinkType = 0
	LinkTypeEthernet       LinkType = 1
	LinkTypeTokenRing      LinkType = 6
	LinkTypeArcNet         LinkType = 7
	LinkTypeSLIP           LinkType = 8
	LinkTypePPP            LinkType = 9
	LinkTypeFDDI           LinkType = 10
	LinkTypeATM_RFC1483    LinkType = 100
	LinkTypeRaw            LinkType = 101
	LinkTypePPP_HDLC       LinkType = 50
	LinkTypePPPEthernet    LinkType = 51
	LinkTypeC_HDLC         LinkType = 104
	LinkTypeIEEE802_11     LinkType = 105
	LinkTypeFRelay         LinkType = 107
	LinkTypeLoop           LinkType = 108
	LinkTypeLinuxSLL       LinkType = 113
	LinkTypeLTalk          LinkType = 104
	LinkTypePFLog          LinkType = 117
	LinkTypePrismHeader    LinkType = 119
	LinkTypeIPOverFC       LinkType = 122
	LinkTypeSunATM         LinkType = 123
	LinkTypeIEEE80211Radio LinkType = 127
	LinkTypeARCNetLinux    LinkType = 129
	LinkTypeLinuxIRDA      LinkType = 144
	LinkTypeLinuxLAPD      LinkType = 177
	LinkTypeLinuxUSB       LinkType = 220
	LinkTypeIPv4           LinkType = 228
	LinkTypeIPv6           LinkType = 229
)

// PPPoECode is the PPPoE code enum, taken from http://tools.ietf.org/html/rfc2516
type PPPoECode uint8

const (
	PPPoECodePADI    PPPoECode = 0x09
	PPPoECodePADO    PPPoECode = 0x07
	PPPoECodePADR    PPPoECode = 0x19
	PPPoECodePADS    PPPoECode = 0x65
	PPPoECodePADT    PPPoECode = 0xA7
	PPPoECodeSession PPPoECode = 0x00
)

// PPPType is an enumeration of PPP type values, and acts as a decoder for any
// type it supports.
type PPPType uint16

const (
	PPPTypeIPv4          PPPType = 0x0021
	PPPTypeIPv6          PPPType = 0x0057
	PPPTypeMPLSUnicast   PPPType = 0x0281
	PPPTypeMPLSMulticast PPPType = 0x0283
)

// SCTPChunkType is an enumeration of chunk types inside SCTP packets.
type SCTPChunkType uint8

const (
	SCTPChunkTypeData             SCTPChunkType = 0
	SCTPChunkTypeInit             SCTPChunkType = 1
	SCTPChunkTypeInitAck          SCTPChunkType = 2
	SCTPChunkTypeSack             SCTPChunkType = 3
	SCTPChunkTypeHeartbeat        SCTPChunkType = 4
	SCTPChunkTypeHeartbeatAck     SCTPChunkType = 5
	SCTPChunkTypeAbort            SCTPChunkType = 6
	SCTPChunkTypeShutdown         SCTPChunkType = 7
	SCTPChunkTypeShutdownAck      SCTPChunkType = 8
	SCTPChunkTypeError            SCTPChunkType = 9
	SCTPChunkTypeCookieEcho       SCTPChunkType = 10
	SCTPChunkTypeCookieAck        SCTPChunkType = 11
	SCTPChunkTypeShutdownComplete SCTPChunkType = 14
)

// FDDIFrameControl is an enumeration of FDDI frame control bytes.
type FDDIFrameControl uint8

const (
	FDDIFrameControlLLC FDDIFrameControl = 0x50
)

// EAPOLType is an enumeration of EAPOL packet types.
type EAPOLType uint8

const (
	EAPOLTypeEAP      EAPOLType = 0
	EAPOLTypeStart    EAPOLType = 1
	EAPOLTypeLogOff   EAPOLType = 2
	EAPOLTypeKey      EAPOLType = 3
	EAPOLTypeASFAlert EAPOLType = 4
)

// ProtocolFamily is the set of values defined as PF_* in sys/socket.h
type ProtocolFamily uint8

const (
	ProtocolFamilyIPv4 ProtocolFamily = 2
	// BSDs use different values for INET6... glory be.  These values taken from
	// tcpdump 4.3.0.
	ProtocolFamilyIPv6BSD     ProtocolFamily = 24
	ProtocolFamilyIPv6FreeBSD ProtocolFamily = 28
	ProtocolFamilyIPv6Darwin  ProtocolFamily = 30
	ProtocolFamilyIPv6Linux   ProtocolFamily = 10
)

// Dot11Type is a combination of IEEE 802.11 frame's Type and Subtype fields.
// By combining these two fields together into a single type, we're able to
// provide a String function that correctly displays the subtype given the
// top-level type.
//
// If you just care about the top-level type, use the MainType function.
type Dot11Type uint8

// MainType strips the subtype information from the given type,
// returning just the overarching type (Mgmt, Ctrl, Data, Reserved).
func (d Dot11Type) MainType() Dot11Type {
	return d & dot11TypeMask
}

const (
	Dot11TypeMgmt     Dot11Type = 0x00
	Dot11TypeCtrl     Dot11Type = 0x01
	Dot11TypeData     Dot11Type = 0x02
	Dot11TypeReserved Dot11Type = 0x03
	dot11TypeMask               = 0x03

	// The following are type/subtype conglomerations.

	// Management
	Dot11TypeMgmtAssociationReq    Dot11Type = 0x00
	Dot11TypeMgmtAssociationResp   Dot11Type = 0x04
	Dot11TypeMgmtReassociationReq  Dot11Type = 0x08
	Dot11TypeMgmtReassociationResp Dot11Type = 0x0c
	Dot11TypeMgmtProbeReq          Dot11Type = 0x10
	Dot11TypeMgmtProbeResp         Dot11Type = 0x14
	Dot11TypeMgmtMeasurementPilot  Dot11Type = 0x18
	Dot11TypeMgmtBeacon            Dot11Type = 0x20
	Dot11TypeMgmtATIM              Dot11Type = 0x24
	Dot11TypeMgmtDisassociation    Dot11Type = 0x28
	Dot11TypeMgmtAuthentication    Dot11Type = 0x2c
	Dot11TypeMgmtDeauthentication  Dot11Type = 0x30
	Dot11TypeMgmtAction            Dot11Type = 0x34
	Dot11TypeMgmtActionNoAck       Dot11Type = 0x38

	// Control
	Dot11TypeCtrlWrapper       Dot11Type = 0x1d
	Dot11TypeCtrlBlockAckReq   Dot11Type = 0x21
	Dot11TypeCtrlBlockAck      Dot11Type = 0x25
	Dot11TypeCtrlPowersavePoll Dot11Type = 0x29
	Dot11TypeCtrlRTS           Dot11Type = 0x2d
	Dot11TypeCtrlCTS           Dot11Type = 0x31
	Dot11TypeCtrlAck           Dot11Type = 0x35
	Dot11TypeCtrlCFEnd         Dot11Type = 0x39
	Dot11TypeCtrlCFEndAck      Dot11Type = 0x3d

	// Data
	Dot11TypeDataCFAck              Dot11Type = 0x06
	Dot11TypeDataCFPoll             Dot11Type = 0x0a
	Dot11TypeDataCFAckPoll          Dot11Type = 0x0e
	Dot11TypeDataNull               Dot11Type = 0x12
	Dot11TypeDataCFAckNoData        Dot11Type = 0x16
	Dot11TypeDataCFPollNoData       Dot11Type = 0x1a
	Dot11TypeDataCFAckPollNoData    Dot11Type = 0x1e
	Dot11TypeDataQOSData            Dot11Type = 0x22
	Dot11TypeDataQOSDataCFAck       Dot11Type = 0x26
	Dot11TypeDataQOSDataCFPoll      Dot11Type = 0x2a
	Dot11TypeDataQOSDataCFAckPoll   Dot11Type = 0x2e
	Dot11TypeDataQOSNull            Dot11Type = 0x32
	Dot11TypeDataQOSCFPollNoData    Dot11Type = 0x3a
	Dot11TypeDataQOSCFAckPollNoData Dot11Type = 0x3e
)

var (
	// Each of the following arrays contains mappings of how to handle enum
	// values for various enum types in gopacket/layers.
	//
	// So, EthernetTypeMetadata[2] contains information on how to handle EthernetType
	// 2, including which name to give it and which decoder to use to decode
	// packet data of that type.  These arrays are filled by default with all of the
	// protocols gopacket/layers knows how to handle, but users of the library can
	// add new decoders or override existing ones.  For example, if you write a better
	// TCP decoder, you can override IPProtocolMetadata[IPProtocolTCP].DecodeWith
	// with your new decoder, and all gopacket/layers decoding will use your new
	// decoder whenever they encounter that IPProtocol.
	EthernetTypeMetadata     [65536]EnumMetadata
	IPProtocolMetadata       [265]EnumMetadata
	SCTPChunkTypeMetadata    [265]EnumMetadata
	PPPTypeMetadata          [65536]EnumMetadata
	PPPoECodeMetadata        [256]EnumMetadata
	LinkTypeMetadata         [256]EnumMetadata
	FDDIFrameControlMetadata [256]EnumMetadata
	EAPOLTypeMetadata        [256]EnumMetadata
	ProtocolFamilyMetadata   [256]EnumMetadata
	Dot11TypeMetadata        [256]EnumMetadata
	USBTypeMetadata          [256]EnumMetadata
)

func (a EthernetType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if EthernetTypeMetadata[a].DecodeWith != nil {
		return EthernetTypeMetadata[a].DecodeWith.Decode(data, p)
	}
	return fmt.Errorf("Unable to decode ethernet type %d", a)
}
func (a EthernetType) String() string {
	if EthernetTypeMetadata[a].Name != "" {
		return EthernetTypeMetadata[a].Name
	}
	return fmt.Sprintf("UnknownEthernetType(%d)", a)
}
func (a EthernetType) LayerType() gopacket.LayerType {
	return EthernetTypeMetadata[a].LayerType
}
func (a IPProtocol) Decode(data []byte, p gopacket.PacketBuilder) error {
	if IPProtocolMetadata[a].DecodeWith != nil {
		return IPProtocolMetadata[a].DecodeWith.Decode(data, p)
	}
	return fmt.Errorf("Unable to decode IP protocol %d", a)
}
func (a IPProtocol) String() string {
	if IPProtocolMetadata[a].Name != "" {
		return IPProtocolMetadata[a].Name
	}
	return fmt.Sprintf("UnknownIPProtocol(%d)", a)
}
func (a IPProtocol) LayerType() gopacket.LayerType {
	return IPProtocolMetadata[a].LayerType
}
func (a SCTPChunkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if SCTPChunkTypeMetadata[a].DecodeWith != nil {
		return SCTPChunkTypeMetadata[a].DecodeWith.Decode(data, p)
	}
	return fmt.Errorf("Unable to decode SCTP chunk type %d", a)
}
func (a SCTPChunkType) String() string {
	if SCTPChunkTypeMetadata[a].Name != "" {
		return SCTPChunkTypeMetadata[a].Name
	}
	return fmt.Sprintf("UnknownSCTPChunkType(%d)", a)
}
func (a PPPType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if PPPTypeMetadata[a].DecodeWith != nil {
		return PPPTypeMetadata[a].DecodeWith.Decode(data, p)
	}
	return fmt.Errorf("Unable to decode PPP type %d", a)
}
func (a PPPType) String() string {
	if PPPTypeMetadata[a].Name != "" {
		return PPPTypeMetadata[a].Name
	}
	return fmt.Sprintf("UnknownPPPType(%d)", a)
}
func (a LinkType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if LinkTypeMetadata[a].DecodeWith != nil {
		return LinkTypeMetadata[a].DecodeWith.Decode(data, p)
	}
	return fmt.Errorf("Unable to decode link type %d", a)
}
func (a LinkType) String() string {
	if LinkTypeMetadata[a].Name != "" {
		return LinkTypeMetadata[a].Name
	}
	return fmt.Sprintf("UnknownLinkType(%d)", a)
}
func (a PPPoECode) Decode(data []byte, p gopacket.PacketBuilder) error {
	if PPPoECodeMetadata[a].DecodeWith != nil {
		return PPPoECodeMetadata[a].DecodeWith.Decode(data, p)
	}
	return fmt.Errorf("Unable to decode PPPoE code %d", a)
}
func (a PPPoECode) String() string {
	if PPPoECodeMetadata[a].Name != "" {
		return PPPoECodeMetadata[a].Name
	}
	return fmt.Sprintf("UnknownPPPoECode(%d)", a)
}
func (a FDDIFrameControl) Decode(data []byte, p gopacket.PacketBuilder) error {
	if FDDIFrameControlMetadata[a].DecodeWith != nil {
		return FDDIFrameControlMetadata[a].DecodeWith.Decode(data, p)
	}
	return fmt.Errorf("Unable to decode FDDI frame control %d", a)
}
func (a FDDIFrameControl) String() string {
	if FDDIFrameControlMetadata[a].Name != "" {
		return FDDIFrameControlMetadata[a].Name
	}
	return fmt.Sprintf("UnknownFDDIFrameControl(%d)", a)
}
func (a EAPOLType) Decode(data []byte, p gopacket.PacketBuilder) error {
	if EAPOLTypeMetadata[a].DecodeWith != nil {
		return EAPOLTypeMetadata[a].DecodeWith.Decode(data, p)
	}
	return fmt.Errorf("Unable to decode EAPOL type %d", a)
}
func (a EAPOLType) String() string {
	if EAPOLTypeMetadata[a].Name != "" {
		return EAPOLTypeMetadata[a].Name
	}
	return fmt.Sprintf("UnknownEAPOLType(%d)", a)

}
func (a EAPOLType) LayerType() gopacket.LayerType {
	return EAPOLTypeMetadata[a].LayerType
}
func (a ProtocolFamily) Decode(data []byte, p gopacket.PacketBuilder) error {
	if ProtocolFamilyMetadata[a].DecodeWith != nil {
		return ProtocolFamilyMetadata[a].DecodeWith.Decode(data, p)
	}
	return fmt.Errorf("Unable to decode protocol family %d", a)
}
func (a ProtocolFamily) String() string {
	if ProtocolFamilyMetadata[a].Name != "" {
		return ProtocolFamilyMetadata[a].Name
	}
	return fmt.Sprintf("UnknownProtocolFamily(%d)", a)
}
func (a ProtocolFamily) LayerType() gopacket.LayerType {
	return ProtocolFamilyMetadata[a].LayerType
}
func (a Dot11Type) Decode(data []byte, p gopacket.PacketBuilder) error {
	if Dot11TypeMetadata[a].DecodeWith != nil {
		return Dot11TypeMetadata[a].DecodeWith.Decode(data, p)
	}
	return fmt.Errorf("Unable to decode Dot11 type %d", a)
}
func (a Dot11Type) String() string {
	if Dot11TypeMetadata[a].Name != "" {
		return Dot11TypeMetadata[a].Name
	}
	return fmt.Sprintf("UnknownDot11Type(%d)", a)
}
func (a Dot11Type) LayerType() gopacket.LayerType {
	return Dot11TypeMetadata[a].LayerType
}

// Decode a raw v4 or v6 IP packet.
func decodeIPv4or6(data []byte, p gopacket.PacketBuilder) error {
	version := data[0] >> 4
	switch version {
	case 4:
		return decodeIPv4(data, p)
	case 6:
		return decodeIPv6(data, p)
	}
	return fmt.Errorf("Invalid IP packet version %v", version)
}

func init() {
	// Here we link up all enumerations with their respective names and decoders.

	EthernetTypeMetadata[EthernetTypeLLC] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLLC), Name: "LLC", LayerType: LayerTypeLLC}
	EthernetTypeMetadata[EthernetTypeIPv4] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4), Name: "IPv4", LayerType: LayerTypeIPv4}
	EthernetTypeMetadata[EthernetTypeIPv6] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6", LayerType: LayerTypeIPv6}
	EthernetTypeMetadata[EthernetTypeARP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeARP), Name: "ARP", LayerType: LayerTypeARP}
	EthernetTypeMetadata[EthernetTypeDot1Q] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot1Q), Name: "Dot1Q", LayerType: LayerTypeDot1Q}
	EthernetTypeMetadata[EthernetTypePPPoEDiscovery] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPPoE), Name: "PPPoEDiscovery", LayerType: LayerTypePPPoE}
	EthernetTypeMetadata[EthernetTypePPPoESession] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPPoE), Name: "PPPoESession", LayerType: LayerTypePPPoE}
	EthernetTypeMetadata[EthernetTypeEthernetCTP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEthernetCTP), Name: "EthernetCTP", LayerType: LayerTypeEthernetCTP}
	EthernetTypeMetadata[EthernetTypeCiscoDiscovery] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeCiscoDiscovery), Name: "CiscoDiscovery", LayerType: LayerTypeCiscoDiscovery}
	EthernetTypeMetadata[EthernetTypeNortelDiscovery] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeNortelDiscovery), Name: "NortelDiscovery", LayerType: LayerTypeNortelDiscovery}
	EthernetTypeMetadata[EthernetTypeLinkLayerDiscovery] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLinkLayerDiscovery), Name: "LinkLayerDiscovery", LayerType: LayerTypeLinkLayerDiscovery}
	EthernetTypeMetadata[EthernetTypeMPLSUnicast] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeMPLS), Name: "MPLSUnicast", LayerType: LayerTypeMPLS}
	EthernetTypeMetadata[EthernetTypeMPLSMulticast] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeMPLS), Name: "MPLSMulticast", LayerType: LayerTypeMPLS}
	EthernetTypeMetadata[EthernetTypeEAPOL] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEAPOL), Name: "EAPOL", LayerType: LayerTypeEAPOL}
	EthernetTypeMetadata[EthernetTypeQinQ] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot1Q), Name: "Dot1Q", LayerType: LayerTypeDot1Q}
	EthernetTypeMetadata[EthernetTypeTransparentEthernetBridging] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEthernet), Name: "TransparentEthernetBridging", LayerType: LayerTypeEthernet}

	IPProtocolMetadata[IPProtocolIPv4] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4), Name: "IPv4", LayerType: LayerTypeIPv4}
	IPProtocolMetadata[IPProtocolTCP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeTCP), Name: "TCP", LayerType: LayerTypeTCP}
	IPProtocolMetadata[IPProtocolUDP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeUDP), Name: "UDP", LayerType: LayerTypeUDP}
	IPProtocolMetadata[IPProtocolICMPv4] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeICMPv4), Name: "ICMPv4", LayerType: LayerTypeICMPv4}
	IPProtocolMetadata[IPProtocolICMPv6] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeICMPv6), Name: "ICMPv6", LayerType: LayerTypeICMPv6}
	IPProtocolMetadata[IPProtocolSCTP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTP), Name: "SCTP", LayerType: LayerTypeSCTP}
	IPProtocolMetadata[IPProtocolIPv6] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6", LayerType: LayerTypeIPv6}
	IPProtocolMetadata[IPProtocolIPIP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4), Name: "IPv4", LayerType: LayerTypeIPv4}
	IPProtocolMetadata[IPProtocolEtherIP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEtherIP), Name: "EtherIP", LayerType: LayerTypeEtherIP}
	IPProtocolMetadata[IPProtocolRUDP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeRUDP), Name: "RUDP", LayerType: LayerTypeRUDP}
	IPProtocolMetadata[IPProtocolGRE] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeGRE), Name: "GRE", LayerType: LayerTypeGRE}
	IPProtocolMetadata[IPProtocolIPv6HopByHop] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6HopByHop), Name: "IPv6HopByHop", LayerType: LayerTypeIPv6HopByHop}
	IPProtocolMetadata[IPProtocolIPv6Routing] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6Routing), Name: "IPv6Routing", LayerType: LayerTypeIPv6Routing}
	IPProtocolMetadata[IPProtocolIPv6Fragment] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6Fragment), Name: "IPv6Fragment", LayerType: LayerTypeIPv6Fragment}
	IPProtocolMetadata[IPProtocolIPv6Destination] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6Destination), Name: "IPv6Destination", LayerType: LayerTypeIPv6Destination}
	IPProtocolMetadata[IPProtocolAH] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPSecAH), Name: "IPSecAH", LayerType: LayerTypeIPSecAH}
	IPProtocolMetadata[IPProtocolESP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPSecESP), Name: "IPSecESP", LayerType: LayerTypeIPSecESP}
	IPProtocolMetadata[IPProtocolUDPLite] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeUDPLite), Name: "UDPLite", LayerType: LayerTypeUDPLite}
	IPProtocolMetadata[IPProtocolMPLSInIP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeMPLS), Name: "MPLS", LayerType: LayerTypeMPLS}
	IPProtocolMetadata[IPProtocolNoNextHeader] = EnumMetadata{DecodeWith: gopacket.DecodePayload, Name: "NoNextHeader", LayerType: gopacket.LayerTypePayload}
	IPProtocolMetadata[IPProtocolIGMP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIGMP), Name: "IGMP", LayerType: LayerTypeIGMP}
	IPProtocolMetadata[IPProtocolVRRP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeVRRP), Name: "VRRP", LayerType: LayerTypeVRRP}

	SCTPChunkTypeMetadata[SCTPChunkTypeData] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPData), Name: "Data"}
	SCTPChunkTypeMetadata[SCTPChunkTypeInit] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPInit), Name: "Init"}
	SCTPChunkTypeMetadata[SCTPChunkTypeInitAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPInit), Name: "InitAck"}
	SCTPChunkTypeMetadata[SCTPChunkTypeSack] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPSack), Name: "Sack"}
	SCTPChunkTypeMetadata[SCTPChunkTypeHeartbeat] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPHeartbeat), Name: "Heartbeat"}
	SCTPChunkTypeMetadata[SCTPChunkTypeHeartbeatAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPHeartbeat), Name: "HeartbeatAck"}
	SCTPChunkTypeMetadata[SCTPChunkTypeAbort] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPError), Name: "Abort"}
	SCTPChunkTypeMetadata[SCTPChunkTypeError] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPError), Name: "Error"}
	SCTPChunkTypeMetadata[SCTPChunkTypeShutdown] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPShutdown), Name: "Shutdown"}
	SCTPChunkTypeMetadata[SCTPChunkTypeShutdownAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPShutdownAck), Name: "ShutdownAck"}
	SCTPChunkTypeMetadata[SCTPChunkTypeCookieEcho] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPCookieEcho), Name: "CookieEcho"}
	SCTPChunkTypeMetadata[SCTPChunkTypeCookieAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPEmptyLayer), Name: "CookieAck"}
	SCTPChunkTypeMetadata[SCTPChunkTypeShutdownComplete] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeSCTPEmptyLayer), Name: "ShutdownComplete"}

	PPPTypeMetadata[PPPTypeIPv4] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4), Name: "IPv4"}
	PPPTypeMetadata[PPPTypeIPv6] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6"}
	PPPTypeMetadata[PPPTypeMPLSUnicast] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeMPLS), Name: "MPLSUnicast"}
	PPPTypeMetadata[PPPTypeMPLSMulticast] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeMPLS), Name: "MPLSMulticast"}

	PPPoECodeMetadata[PPPoECodeSession] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPP), Name: "PPP"}

	LinkTypeMetadata[LinkTypeEthernet] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEthernet), Name: "Ethernet"}
	LinkTypeMetadata[LinkTypePPP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePPP), Name: "PPP"}
	LinkTypeMetadata[LinkTypeFDDI] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeFDDI), Name: "FDDI"}
	LinkTypeMetadata[LinkTypeNull] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLoopback), Name: "Null"}
	LinkTypeMetadata[LinkTypeLoop] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLoopback), Name: "Loop"}
	LinkTypeMetadata[LinkTypeRaw] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4or6), Name: "Raw"}
	LinkTypeMetadata[LinkTypePFLog] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePFLog), Name: "PFLog"}
	LinkTypeMetadata[LinkTypeIEEE80211Radio] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeRadioTap), Name: "RadioTap"}
	LinkTypeMetadata[LinkTypeLinuxUSB] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeUSB), Name: "USB"}
	LinkTypeMetadata[LinkTypeLinuxSLL] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLinuxSLL), Name: "Linux SLL"}
	LinkTypeMetadata[LinkTypePrismHeader] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodePrismHeader), Name: "Prism"}

	FDDIFrameControlMetadata[FDDIFrameControlLLC] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeLLC), Name: "LLC"}

	EAPOLTypeMetadata[EAPOLTypeEAP] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeEAP), Name: "EAP", LayerType: LayerTypeEAP}

	ProtocolFamilyMetadata[ProtocolFamilyIPv4] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv4), Name: "IPv4", LayerType: LayerTypeIPv4}
	ProtocolFamilyMetadata[ProtocolFamilyIPv6BSD] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6", LayerType: LayerTypeIPv6}
	ProtocolFamilyMetadata[ProtocolFamilyIPv6FreeBSD] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6", LayerType: LayerTypeIPv6}
	ProtocolFamilyMetadata[ProtocolFamilyIPv6Darwin] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6", LayerType: LayerTypeIPv6}
	ProtocolFamilyMetadata[ProtocolFamilyIPv6Linux] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeIPv6), Name: "IPv6", LayerType: LayerTypeIPv6}

	Dot11TypeMetadata[Dot11TypeMgmtAssociationReq] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtAssociationReq), Name: "MgmtAssociationReq", LayerType: LayerTypeDot11MgmtAssociationReq}
	Dot11TypeMetadata[Dot11TypeMgmtAssociationResp] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtAssociationResp), Name: "MgmtAssociationResp", LayerType: LayerTypeDot11MgmtAssociationResp}
	Dot11TypeMetadata[Dot11TypeMgmtReassociationReq] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtReassociationReq), Name: "MgmtReassociationReq", LayerType: LayerTypeDot11MgmtReassociationReq}
	Dot11TypeMetadata[Dot11TypeMgmtReassociationResp] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtReassociationResp), Name: "MgmtReassociationResp", LayerType: LayerTypeDot11MgmtReassociationResp}
	Dot11TypeMetadata[Dot11TypeMgmtProbeReq] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtProbeReq), Name: "MgmtProbeReq", LayerType: LayerTypeDot11MgmtProbeReq}
	Dot11TypeMetadata[Dot11TypeMgmtProbeResp] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtProbeResp), Name: "MgmtProbeResp", LayerType: LayerTypeDot11MgmtProbeResp}
	Dot11TypeMetadata[Dot11TypeMgmtMeasurementPilot] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtMeasurementPilot), Name: "MgmtMeasurementPilot", LayerType: LayerTypeDot11MgmtMeasurementPilot}
	Dot11TypeMetadata[Dot11TypeMgmtBeacon] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtBeacon), Name: "MgmtBeacon", LayerType: LayerTypeDot11MgmtBeacon}
	Dot11TypeMetadata[Dot11TypeMgmtATIM] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtATIM), Name: "MgmtATIM", LayerType: LayerTypeDot11MgmtATIM}
	Dot11TypeMetadata[Dot11TypeMgmtDisassociation] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtDisassociation), Name: "MgmtDisassociation", LayerType: LayerTypeDot11MgmtDisassociation}
	Dot11TypeMetadata[Dot11TypeMgmtAuthentication] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtAuthentication), Name: "MgmtAuthentication", LayerType: LayerTypeDot11MgmtAuthentication}
	Dot11TypeMetadata[Dot11TypeMgmtDeauthentication] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtDeauthentication), Name: "MgmtDeauthentication", LayerType: LayerTypeDot11MgmtDeauthentication}
	Dot11TypeMetadata[Dot11TypeMgmtAction] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtAction), Name: "MgmtAction", LayerType: LayerTypeDot11MgmtAction}
	Dot11TypeMetadata[Dot11TypeMgmtActionNoAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11MgmtActionNoAck), Name: "MgmtActionNoAck", LayerType: LayerTypeDot11MgmtActionNoAck}
	Dot11TypeMetadata[Dot11TypeCtrlWrapper] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11Ctrl), Name: "CtrlWrapper", LayerType: LayerTypeDot11Ctrl}
	Dot11TypeMetadata[Dot11TypeCtrlBlockAckReq] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11CtrlBlockAckReq), Name: "CtrlBlockAckReq", LayerType: LayerTypeDot11CtrlBlockAckReq}
	Dot11TypeMetadata[Dot11TypeCtrlBlockAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11CtrlBlockAck), Name: "CtrlBlockAck", LayerType: LayerTypeDot11CtrlBlockAck}
	Dot11TypeMetadata[Dot11TypeCtrlPowersavePoll] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11CtrlPowersavePoll), Name: "CtrlPowersavePoll", LayerType: LayerTypeDot11CtrlPowersavePoll}
	Dot11TypeMetadata[Dot11TypeCtrlRTS] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11CtrlRTS), Name: "CtrlRTS", LayerType: LayerTypeDot11CtrlRTS}
	Dot11TypeMetadata[Dot11TypeCtrlCTS] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11CtrlCTS), Name: "CtrlCTS", LayerType: LayerTypeDot11CtrlCTS}
	Dot11TypeMetadata[Dot11TypeCtrlAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11CtrlAck), Name: "CtrlAck", LayerType: LayerTypeDot11CtrlAck}
	Dot11TypeMetadata[Dot11TypeCtrlCFEnd] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11CtrlCFEnd), Name: "CtrlCFEnd", LayerType: LayerTypeDot11CtrlCFEnd}
	Dot11TypeMetadata[Dot11TypeCtrlCFEndAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11CtrlCFEndAck), Name: "CtrlCFEndAck", LayerType: LayerTypeDot11CtrlCFEndAck}
	Dot11TypeMetadata[Dot11TypeData] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11Data), Name: "Data", LayerType: LayerTypeDot11Data}
	Dot11TypeMetadata[Dot11TypeDataCFAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataCFAck), Name: "DataCFAck", LayerType: LayerTypeDot11DataCFAck}
	Dot11TypeMetadata[Dot11TypeDataCFPoll] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataCFPoll), Name: "DataCFPoll", LayerType: LayerTypeDot11DataCFPoll}
	Dot11TypeMetadata[Dot11TypeDataCFAckPoll] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataCFAckPoll), Name: "DataCFAckPoll", LayerType: LayerTypeDot11DataCFAckPoll}
	Dot11TypeMetadata[Dot11TypeDataNull] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataNull), Name: "DataNull", LayerType: LayerTypeDot11DataNull}
	Dot11TypeMetadata[Dot11TypeDataCFAckNoData] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataCFAckNoData), Name: "DataCFAckNoData", LayerType: LayerTypeDot11DataCFAckNoData}
	Dot11TypeMetadata[Dot11TypeDataCFPollNoData] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataCFPollNoData), Name: "DataCFPollNoData", LayerType: LayerTypeDot11DataCFPollNoData}
	Dot11TypeMetadata[Dot11TypeDataCFAckPollNoData] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataCFAckPollNoData), Name: "DataCFAckPollNoData", LayerType: LayerTypeDot11DataCFAckPollNoData}
	Dot11TypeMetadata[Dot11TypeDataQOSData] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataQOSData), Name: "DataQOSData", LayerType: LayerTypeDot11DataQOSData}
	Dot11TypeMetadata[Dot11TypeDataQOSDataCFAck] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataQOSDataCFAck), Name: "DataQOSDataCFAck", LayerType: LayerTypeDot11DataQOSDataCFAck}
	Dot11TypeMetadata[Dot11TypeDataQOSDataCFPoll] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataQOSDataCFPoll), Name: "DataQOSDataCFPoll", LayerType: LayerTypeDot11DataQOSDataCFPoll}
	Dot11TypeMetadata[Dot11TypeDataQOSDataCFAckPoll] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataQOSDataCFAckPoll), Name: "DataQOSDataCFAckPoll", LayerType: LayerTypeDot11DataQOSDataCFAckPoll}
	Dot11TypeMetadata[Dot11TypeDataQOSNull] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataQOSNull), Name: "DataQOSNull", LayerType: LayerTypeDot11DataQOSNull}
	Dot11TypeMetadata[Dot11TypeDataQOSCFPollNoData] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataQOSCFPollNoData), Name: "DataQOSCFPollNoData", LayerType: LayerTypeDot11DataQOSCFPollNoData}
	Dot11TypeMetadata[Dot11TypeDataQOSCFAckPollNoData] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeDot11DataQOSCFAckPollNoData), Name: "DataQOSCFAckPollNoData", LayerType: LayerTypeDot11DataQOSCFAckPollNoData}

	USBTypeMetadata[USBTransportTypeInterrupt] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeUSBInterrupt), Name: "Interrupt", LayerType: LayerTypeUSBInterrupt}
	USBTypeMetadata[USBTransportTypeControl] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeUSBControl), Name: "Control", LayerType: LayerTypeUSBControl}
	USBTypeMetadata[USBTransportTypeBulk] = EnumMetadata{DecodeWith: gopacket.DecodeFunc(decodeUSBBulk), Name: "Bulk", LayerType: LayerTypeUSBBulk}
}
