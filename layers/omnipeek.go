//-----------------------------------------------------------------------------
/*

OmniPeek Header Decoder

Cisco uses omnipeek headers on their 802.11 management frames to record RF meta data.

Here are the C structures provided to us by Cisco:

typedef struct aptrace_timeval_s {
    uint32_t tv_sec;
    uint32_t tv_usec;
} __attribute__ ((packed)) aptrace_timeval_t;

Old Style Omnipeek/Wireshark header for legacy 802.11a/b/g packets

typedef struct peek_hdr_s {
  uint8_t signal_dBm;       // signal dBm
  uint8_t noise_dBm;        // noise dBm
  uint16_t packet_length;    // contains correct info
  uint16_t slice_length;     // contains correct info
  uint8_t flags;            // only PEEK_CONTROL is filled based on IEEE80211 control frame or not
  uint8_t status;            // PEEK_ENCRYPTED and PEEK_SHORT_PREAMBLE are the only valid bits
  aptrace_timeval_t ts;       // replaced the original 64-bit field with what gettimeofday uses

  // equivalent to the wireless_80211_private_hdr
  uint8_t data_rate;          // data rate in 500Kbps
  uint8_t channel;            // channel numbers 1-14 for 2.4GHz, 36-161 for 5GHz

  uint8_t signal_strength;    // signal strength is a number between 0-100
  uint8_t noise_strength;     // noise strength

} __attribute__ ((packed)) peek_hdr_t;

New Style Omnipeek/Wireshark header for 802.11n packets

typedef struct peek_hdr_11n_s {
#define PEEK_HDR_MAGIC_VAL 0x00ffabcd
  uint32_t magic_value;         // Always set to 0x00ffabcd
  uint8_t version;             // version 2 of the Omnipeak/Wireshark header

  // MediaSpecificPrivateHeader
  uint32_t size;                // size of this structure
  uint32_t type;                // Omnipeak expects this field to always be 6

  // Wireless80211PrivateHeaderCisco
  uint16_t data_rate;           // PHY data rate (or MCS index for 802.11n/ac)

  int16_t channel;             // channel numbers 1-14 for 2.4GHz, 36-161 for 5GHz
  uint32_t frequency;           // frequency in Mhz (2346 for 2346 Mhz)
  uint32_t band;                // see below for definitions

  uint32_t dot11_ht_vht_flags;  // for 802.11n/ac only, see below for definitions

  uint8_t signal_strength;     // signal strength is a % between 0-100
  uint8_t noise_strength;      // noise strength is a % between 0-100
  int8_t signal_dbm;          // signal power (dBm)
  int8_t noise_dbm;           // noise power (dBm)
  int8_t signal1_dbm;         // not used
  int8_t signal2_dbm;         // not used
  int8_t signal3_dbm;         // not used
  int8_t signal4_dbm;         // not used
  int8_t noise1_dbm;          // not used
  int8_t noise2_dbm;          // not used
  int8_t noise3_dbm;          // not used
  int8_t noise4_dbm;          // not used

  uint16_t packet_length;    // contains correct info
  uint16_t slice_length;     // contains correct info
  uint8_t flags;            // only PEEK_CONTROL is filled based on IEEE80211 control frame or not
  uint8_t status;           // PEEK_ENCRYPTED and PEEK_SHORT_PREAMBLE are the only valid bits
  aptrace_timeval_t ts;      // replaced the original 64-bit field with what gettimeofday uses

} __attribute__ ((packed)) peek_hdr_11n_t;

*/
//-----------------------------------------------------------------------------

package layers

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/mistsys/gopacket"
)

//-----------------------------------------------------------------------------

const (
	HDR_VERSION_0 = iota // old style 802.11a/bg header
	HDR_VERSION_1        // new style 802.11n/ac header
)

// constants for old header style
const PEEK_HDR0_SIZE = 20

// constants for the new header style
const PEEK_HDR1_MAGIC_VAL = 0x00ffabcd
const PEEK_HDR1_VERSION = 2
const PEEK_HDR1_SIZE = 55
const PEEK_HDR1_TYPE = 6

//-----------------------------------------------------------------------------

// Note: There are two omnipeek header types. This structure is a union of the
// data within these headers.

type OmniPeek struct {
	BaseLayer

	HeaderVersion uint8

	TimeStamp      time.Time // packet timestamp
	Flags          uint8     // only PEEK_CONTROL is filled based on IEEE80211 control frame or not
	Status         uint8     // PEEK_ENCRYPTED and PEEK_SHORT_PREAMBLE are the only valid bits
	PacketLength   uint16
	SliceLength    uint16
	NoiseStrength  uint8  // signal strength is a % between 0-100
	SignalStrength uint8  // signal strength is a % between 0-100
	Noise_dBm      int8   // noise power (dBm)
	Signal_dBm     int8   // signal power (dbm)
	Channel        int16  // channel numbers 1-14 for 2.4GHz, 36-161 for 5GHz
	DataRate       uint16 // PHY data rate (or MCS index for 802.11n/ac)

	// HDR_VERSION_1 only
	Frequency          uint32 // frequency in Mhz (2346 for 2346 Mhz)
	Band               uint32 // see below for definitions
	Dot11_HT_VHT_Flags uint32 // for 802.11n/ac only, see below for definitions
}

func (m *OmniPeek) SerializeTo(b gopacket.SerializeBuffer, opts gopacket.SerializeOptions) error {
	return nil
}

func (m *OmniPeek) LayerType() gopacket.LayerType { return LayerTypeOmniPeek }

func (m *OmniPeek) DecodeFromBytes(data []byte, df gopacket.DecodeFeedback) error {
	var length int

	hdr_magic := binary.BigEndian.Uint32(data[0:4])

	if hdr_magic == PEEK_HDR1_MAGIC_VAL {
		// new style 802.11n header

		hdr_version := data[4]
		if hdr_version != PEEK_HDR1_VERSION {
			return fmt.Errorf("bad header version %d", hdr_version)
		}

		hdr_size := binary.BigEndian.Uint32(data[5 : 5+4])
		if hdr_size != PEEK_HDR1_SIZE {
			return fmt.Errorf("bad header size %d", hdr_size)
		}

		hdr_type := binary.BigEndian.Uint32(data[9 : 9+4])
		if hdr_type != PEEK_HDR1_TYPE {
			return fmt.Errorf("bad header type %d", hdr_type)
		}

		m.HeaderVersion = HDR_VERSION_1
		m.DataRate = binary.BigEndian.Uint16(data[13 : 13+2])
		m.Channel = int16(binary.BigEndian.Uint16(data[15 : 15+2]))
		m.Frequency = binary.BigEndian.Uint32(data[17 : 17+4])
		m.Band = binary.BigEndian.Uint32(data[21 : 21+4])
		m.Dot11_HT_VHT_Flags = binary.BigEndian.Uint32(data[25 : 25+4])
		m.SignalStrength = data[29]
		m.Signal_dBm = int8(data[31])
		m.NoiseStrength = data[30]
		m.Noise_dBm = int8(data[32])
		m.PacketLength = binary.BigEndian.Uint16(data[41 : 41+2])
		m.SliceLength = binary.BigEndian.Uint16(data[43 : 43+2])
		m.Flags = data[45]
		m.Status = data[46]
		secs := binary.BigEndian.Uint32(data[47 : 47+4])
		usecs := binary.BigEndian.Uint32(data[51 : 51+4])
		m.TimeStamp = time.Unix(int64(secs), int64(usecs)*1000)
		length = PEEK_HDR1_SIZE
	} else {
		// legacy 802.11 a/bg header
		m.HeaderVersion = HDR_VERSION_0
		m.Signal_dBm = int8(data[0])
		m.Noise_dBm = int8(data[1])
		m.PacketLength = binary.BigEndian.Uint16(data[2 : 2+2])
		m.SliceLength = binary.BigEndian.Uint16(data[4 : 4+2])
		m.Flags = data[6]
		m.Status = data[7]
		secs := binary.BigEndian.Uint32(data[8 : 8+4])
		usecs := binary.BigEndian.Uint32(data[12 : 12+4])
		m.TimeStamp = time.Unix(int64(secs), int64(usecs)*1000)
		m.DataRate = uint16(data[16])
		m.Channel = int16(data[17])
		m.SignalStrength = data[18]
		m.NoiseStrength = data[19]
		length = PEEK_HDR0_SIZE
	}

	m.BaseLayer = BaseLayer{Contents: data[:length], Payload: data[length:]}
	return nil
}

func (m *OmniPeek) CanDecode() gopacket.LayerClass { return LayerTypeOmniPeek }

func (m *OmniPeek) NextLayerType() gopacket.LayerType { return LayerTypeDot11 }

//-----------------------------------------------------------------------------

func decodeOmniPeek(data []byte, p gopacket.PacketBuilder) error {
	m := &OmniPeek{}
	return decodingLayerDecoder(m, data, p)
}

//-----------------------------------------------------------------------------
