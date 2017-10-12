//-----------------------------------------------------------------------------
/*

Cisco AP Packet Header

Cisco inserts the following structure after the Linux SLL header and before
the OmniPeek header.

struct APPacketHdr {
  unsigned int ap_msg_type;
  unsigned int ap_msg_subtype;
  unsigned int ap_msg_length;
};

Presumably the next layer is a function of message type/subtype - but I don't
know what the enumerations are- so I'm just going with the observed evidence at
this point.

*/
//-----------------------------------------------------------------------------

package layers

import (
	"encoding/binary"

	"github.com/mistsys/gopacket"
)

//-----------------------------------------------------------------------------

type CiscoAP struct {
	BaseLayer

	Type    uint32 // message type (typically 1)
	Subtype uint32 // message subtype (typically 4)
	Length  uint32 // number of payload bytes after this header
}

func (m *CiscoAP) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return nil
}

func (m *CiscoAP) LayerType() gopacket.LayerType { return LayerTypeCiscoAP }

func (m *CiscoAP) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	m.Type = binary.BigEndian.Uint32(data[0 : 0+4])
	m.Subtype = binary.BigEndian.Uint32(data[4 : 4+4])
	m.Length = binary.BigEndian.Uint32(data[8 : 8+4])
	m.BaseLayer = BaseLayer{Contents: data[:12], Payload: data[12:]}
	return nil
}

func (m *CiscoAP) CanDecode() gopacket.LayerClass { return LayerTypeCiscoAP }

// TODO fix this when we know what the message type/subtype means.
func (m *CiscoAP) NextLayerType() gopacket.LayerType { return LayerTypeOmniPeek }

//-----------------------------------------------------------------------------

func decodeCiscoAP(data []byte, p gopacket.PacketBuilder) error {
	m := &CiscoAP{}
	return decodingLayerDecoder(m, data, p)
}

//-----------------------------------------------------------------------------
