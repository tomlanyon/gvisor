// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package header

import (
	"encoding/binary"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
)

const (
	// NDPTargetLinkLayerAddressOptionType is the type of the Target
	// Link-Layer Address option, as per RFC 4861 section 4.6.1.
	NDPTargetLinkLayerAddressOptionType = 2

	// ndpTargetEthernetLinkLayerAddressSize is the size of a Target
	// Link Layer Option for an Ethernet address.
	ndpTargetEthernetLinkLayerAddressSize = 8

	// ndpPrefixInformationType is the type of the Prefix Information
	// option, as per RFC 4861 section 4.6.2.
	ndpPrefixInformationType = 3

	// ndpPrefixInformationLength is the expected value in the Length field
	// of an NDP Prefix Information option, as per RFC 4861 section 4.6.2.
	ndpPrefixInformationLength = 4

	// ndpPrefixInformationPrefixLengthOffset is the offset of the Prefix
	// Length field within an NDPPrefixInformation.
	ndpPrefixInformationPrefixLengthOffset = 0

	// ndpPrefixInformationFlagsOffset is the offset of the flags within an
	// NDPPrefixInformation.
	ndpPrefixInformationFlagsOffset = 1

	// ndpPrefixInformationOnLinkFlagMask is the mask of the On-Link Flag
	// field in the flags byte within an NDPPrefixInformation.
	ndpPrefixInformationOnLinkFlagMask = (1 << 7)

	// ndpPrefixInformationAutoAddrConfFlagMAsk is the mask of the
	// Autonomous Address-Configuration flag field in the flags byte within
	// an NDPPrefixInformation.
	ndpPrefixInformationAutoAddrConfFlagMask = (1 << 6)

	// ndpPrefixInformationReserved1FlagsMask is the mask of the Reserved1
	// field in the flags byte within an NDPPrefixInformation.
	ndpPrefixInformationReserved1FlagsMask = 0b111111

	// ndpPrefixInformationValidLifetimeOffset is the start of the Valid
	// Lifetime field within an NDPPrefixInformation.
	ndpPrefixInformationValidLifetimeOffset = 2

	// NDPPrefixInformationInfiniteLifetime is a value that represents
	// infinity for the Valid and Preferred Lifetime fields in a NDP Prefix
	// Information option. Its value is (2^32 - 1)s = 4294967295s
	NDPPrefixInformationInfiniteLifetime = time.Second * 4294967295

	// ndpPrefixInformationPreferredLifetimeOffset is the start of the
	// Preferred Lifetime field within an NDPPrefixInformation.
	ndpPrefixInformationPreferredLifetimeOffset = 6

	// ndpPrefixInformationReserved2Offset is the start of the Reserved2
	// field within an NDPPrefixInformation.
	ndpPrefixInformationReserved2Offset = 10

	// ndpPrefixInformationReserved2Length is the length of the Reserved2
	// field.
	//
	// It is 4-bytes.
	ndpPrefixInformationReserved2Length = 4

	// ndpPrefixInformationPrefixOffset is the start of the Prefix field
	// within an NDPPrefixInformation.
	ndpPrefixInformationPrefixOffset = 14

	// lengthByteUnits is the multiplier factor for the Length field of an
	// NDP option. That is, the length field for NDP options is in units of
	// 8 octets, as per RFC 4861 section 4.6.
	lengthByteUnits = 8
)

// NDPOptions is a buffer of NDP options as defined by RFC 4861 section 4.6.
type NDPOptions []byte

// Serialize serializes the provided list of NDP options into o.
func (b NDPOptions) Serialize(s NDPOptionsSerializer) {
	if s.Length() == 0 {
		return
	}

	done := 0
	for _, o := range s {
		l := o.Length()

		if l == 0 {
			continue
		}

		bytes := int(l) * lengthByteUnits

		buf := b[done:][:bytes]
		buf[0] = o.Type()
		buf[1] = l
		o.Serialize(buf[2:])

		done += bytes
	}
}

// NDPOption is the set of functions to be implemented by all NDP option types.
type NDPOption interface {
	// Type returns the type of this NDPOption.
	Type() uint8

	// Length returns the length of this NDPOption, including the bytes for
	// the Type and Length fields, in units of lengthByteUnits bytes..
	Length() uint8

	// Serialize serializes this NDPOption into the provided byte buffer.
	Serialize([]byte)
}

// NDPOptionsSerializer is a serializer for NDP options.
type NDPOptionsSerializer []NDPOption

// Length returns the total number of bytes required to serialize.
func (b NDPOptionsSerializer) Length() uint16 {
	l := uint8(0)

	for _, o := range b {
		l += o.Length()
	}

	// o.Length() returns bytes in lengthByteUnits units so we multiply by
	// lengthByteUnits to get the total number of bytes.
	return uint16(l) * lengthByteUnits
}

// NDPTargetLinkLayerAddressOption is the NDP Target Link Layer Option
// as defined by RFC 4861 section 4.6.1.
//
// It is the first X bytes following the NDP option's Type and Length field
// where X is the value in Length multiplied by lengthByteUnits.
type NDPTargetLinkLayerAddressOption tcpip.LinkAddress

// Type implements NdpOption.Type.
func (o NDPTargetLinkLayerAddressOption) Type() uint8 {
	return NDPTargetLinkLayerAddressOptionType
}

// Length implements NdpOption.Length.
func (o NDPTargetLinkLayerAddressOption) Length() uint8 {
	if len(o) == 0 {
		return 0
	}

	// Length includes the 2 Type and Length bytes.
	l := len(o) + 2

	// Add extra bytes if needed to make sure the option is
	// lengthByteUnits-byte aligned. We do this by adding lengthByteUnits-1
	// to l and then stripping off the last few LSBits from l. This will
	// make sure that l is rounded up to the nearest unit of
	// lengthByteUnits. This works since lengthByteUnits is a power of 2
	// (= 8).
	mask := lengthByteUnits - 1
	l += mask
	l &^= mask

	if l > 255 {
		// Should never happen, so just return 0 so this option does not
		// get serialized.
		//
		// Returning 0 here will make sure that this option does not get
		// serialized when NDPOptions.Serialize is called with the
		// NDPOptionsSerializer that holds this option, effectively
		// skipping this option during serialization. Also note that
		// a value of zero for the Length field in an NDP option is
		// invalid so this is another sign to the caller that this NDP
		// option is malformed, as per RFC 4861 section 4.6.
		return 0
	}

	// Return length in units of lengthByteUnits bytes.
	return uint8(l / lengthByteUnits)
}

// Serialize implements NdpOption.Serialize.
func (o NDPTargetLinkLayerAddressOption) Serialize(b []byte) {
	copy(b[:len(o)], o)

	// Zero out remaining (padding) bytes, if any exists.
	for i := len(o); i < len(b); i++ {
		b[i] = 0
	}
}

// NDPPrefixInformation is the NDP Prefix Information option as defined by
// RFC 4861 section 4.6.2.
//
// It is the first X bytes following the NDP option's Type and Length field
// where X is the value in Length multiplied by lengthByteUnits.
//
// The length of a valid NDP Prefix Information option (including the Type and
// Length fields) MUST be ndpPrefixInformationLength * lengthByteUnits bytes.
// Given this, a valid NDPPrefixInformation MUST contain exactly
// ndpPrefixInformationLength * lengthByteUnits - 2 bytes.
type NDPPrefixInformation []byte

// Type implements NdpOption.Type.
func (o NDPPrefixInformation) Type() uint8 {
	return ndpPrefixInformationType
}

// Length implements NdpOption.Length.
func (o NDPPrefixInformation) Length() uint8 {
	return ndpPrefixInformationLength
}

// Serialize implements NdpOption.Serialize.
func (o NDPPrefixInformation) Serialize(b []byte) {
	copy(b[:len(o)], o)

	// Zero out the Reserved1 field.
	b[ndpPrefixInformationFlagsOffset] &^= ndpPrefixInformationReserved1FlagsMask

	// Zero out the Reserved2 field.
	for i := ndpPrefixInformationReserved2Offset; i < ndpPrefixInformationReserved2Offset+ndpPrefixInformationReserved2Length; i++ {
		b[i] = 0
	}
}

// PrefixLength returns the value in the number of leading bits in the Prefix
// that are valid.
//
// Valid values are in the range [0, 128].
func (o NDPPrefixInformation) PrefixLength() uint8 {
	return o[ndpPrefixInformationPrefixLengthOffset]
}

// OnLinkFlag returns true of the prefix is considered on-link. On-link means
// that a forwarding node is not needed to send packets to other nodes on the
// same prefix.
//
// Note, when this function returns false, no statement is made about the
// on-link property of a prefix. That is, if OnLinkFlag returns false, the
// caller MUST NOT conclude that the prefix is off-link and MUST NOT update any
// previously stored state for this prefix about its on-link status.
func (o NDPPrefixInformation) OnLinkFlag() bool {
	return o[ndpPrefixInformationFlagsOffset]&ndpPrefixInformationOnLinkFlagMask != 0
}

// AutonomousAddressConfigurationFlag returns true if the prefix can be used for
// Stateless Address Auto-Configuration (as specified in RFC 4862).
func (o NDPPrefixInformation) AutonomousAddressConfigurationFlag() bool {
	return o[ndpPrefixInformationFlagsOffset]&ndpPrefixInformationAutoAddrConfFlagMask != 0
}

// ValidLifetime returns the length of time that the prefix is valid for the
// purpose of on-link determination. This value is relative to send time of the
// packet that the Prefix Information option was present in.
//
// Note, a value of 0 implies the prefix should not be used for on-link
// determination, and a value of infinity is represented by
// NDPPrefixInformationInfiniteLifetime.
func (o NDPPrefixInformation) ValidLifetime() time.Duration {
	// The field is the time in seconds, as per RFC 4861 section 4.6.2.
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpPrefixInformationValidLifetimeOffset:]))
}

// PreferredLifetime returns the length of time that an address generated from
// the prefix via Stateless Address Auto-Configuration remains preferred. This
// value is relative to send time of the packet that the Prefix Information
// option was present in.
//
// Note, a value of 0 implies that addresses generated from the prefix should
// no longer remain preffered, and a value of infinity is represented by
// NDPPrefixInformationInfiniteLifetime.
//
// Also note that the value of this field MUST NOT exceed the Valid Lifetime
// field to avoid preferring addresses that are no longer valid.
func (o NDPPrefixInformation) PreferredLifetime() time.Duration {
	// The field is the time in seconds, as per RFC 4861 section 4.6.2.
	return time.Second * time.Duration(binary.BigEndian.Uint32(o[ndpPrefixInformationPreferredLifetimeOffset:]))
}

// Prefix returns an IPv6 address or a prefix of an IPv6 address. The Prefix
// Length field (see NDPPrefixInformation.PrefixLength) contains the number
// of valid leading bits in the prefix.
//
// Hosts SHOULD ignore an NDP Prefix Information option where the Prefix field
// holds the link-local prefix (fe80::/10).
func (o NDPPrefixInformation) Prefix() tcpip.Address {
	return tcpip.Address(o[ndpPrefixInformationPrefixOffset:][:IPv6AddressSize])
}
