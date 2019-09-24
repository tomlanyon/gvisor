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
	"fmt"
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

	// NDPPrefixInformationType is the type of the Prefix Information
	// option, as per RFC 4861 section 4.6.2.
	NDPPrefixInformationType = 3

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

// NDPOptionIterator is an iterator of NDPOption.
//
// Note, between when an NDPOptionIterator is obtained and last used, no changes
// to the NDPOptions may happen. Doing so may cause undefined and unexpected
// behaviour. It is fine to obtain an NDPOptionIterator, iterate over the first
// few NDPOption then modify the backing NDPOptions so long as the
// NDPOptionIterator obtained before modification is no longer used.
type NDPOptionIterator struct {
	// The NDPOptions this NDPOptionIterator is iterating over.
	opts NDPOptions

	// idx holds the offset to the next NDP option in b. That is, it will
	// point to the Type field of the next NDP option.
	idx int
}

// Next returns the next element in the backing NDPOptions, or true if we are
// done, or false if an error occured.
//
// The return can be read as (option, done, ok) := i.Next().
func (i *NDPOptionIterator) Next() (NDPOption, bool, bool) {
	for {
		// Do we still have elements to look at?
		if i.idx >= len(i.opts) {
			// nil NDP option, done, success.
			return nil, true, true
		}

		// Get the Type field.
		t := i.opts[i.idx]

		// Get the Length field.
		l := i.opts[i.idx+1]

		// This would indicate an erroneous NDP option as the Length
		// field should never be 0.
		if l == 0 {
			// nil NDP option, done, error.
			return nil, true, false
		}

		// How many bytes is in the options body?
		bytes := int(l)*lengthByteUnits - 2

		// This would indicate an erroenous NDP options buffer as we ran
		// out of the buffer in the middle of an NDP option buffer.
		if left := len(i.opts) - 2; left < bytes {
			// nil NDP option, done, error.
			return nil, true, false
		}

		// Get the options body.
		buf := i.opts[i.idx+2:][:bytes]

		// Update idx to point to the beginning of the next NDP option.
		i.idx += 2 + bytes

		switch t {
		case NDPTargetLinkLayerAddressOptionType:
			// Target Link Layer NDP Option, not done, success.
			return NDPTargetLinkLayerAddressOption(buf), false, true

		case NDPPrefixInformationType:
			// Make sure the Length of a Prefix Information option
			// is ndpPrefixInformationLength, as per RFC 4861
			// section 4.6.2.
			if l != ndpPrefixInformationLength {
				// nil NDP option, done, error.
				return nil, true, false
			}

			// Prefix Information NDP Option, not done, success.
			return NDPPrefixInformation(buf), false, true
		default:
			// We do not yet recognize the option, just skip for
			// now. This is okay because RFC 4861 allows us to
			// skip/ignore any unrecognized options. However,
			// we MUST recognized all the options in RFC 4861.
			//
			// TODO(b/141487990): Handle all NDP options as defined
			//                    by RFC 4861.
		}
	}
}

// NDPOptions is a buffer of NDP options as defined by RFC 4861 section 4.6.
type NDPOptions []byte

// Iter returns an iterator of NDPOption.
//
// If check is true, Iter will iterator over the iterator and return true along
// with the iterator if no error occured while iterating, false otherwise. If
// check is false, true will be returned along with the iterator without first
// checking b.
//
// See NDPOptionIterator for more information.
func (b NDPOptions) Iter(check bool) (NDPOptionIterator, bool) {
	it := NDPOptionIterator{opts: b, idx: 0}

	if check {
		for it2 := it; true; {
			_, done, ok := it2.Next()

			if !ok {
				return it, false
			} else if done {
				return it, true
			}
		}
	}

	return it, true
}

// Serialize serializes the provided list of NDP options into o.
//
// Note, b must be of sufficient size to hold all the options in s. See
// NDPOptionsSerializer.Length for details on the getting the total size
// of a serialized NDPOptionsSerializer.
//
// Serialize may panic if b is not of sufficient size to hold all the options
// in s.
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
		serializeNDPOption(o, buf[2:])

		done += bytes
	}
}

// NDPOption is the set of functions to be implemented by all NDP option types.
type NDPOption interface {
	// Type returns the type of this NDPOption.
	Type() uint8

	// Length returns the length of this NDPOption, including the bytes for
	// the Type and Length fields, in units of lengthByteUnits bytes.
	Length() uint8

	// Body returns the body of this NDPOption (the buffer of this NDP
	// option excluding the Type and Length fields (first two bytes). The
	// body MUST be a buffer of Length * lengthByteUnits - 2 bytes.
	Body() []byte

	// serializeInto serializes this NDPOption into the provided byte
	// buffer.
	//
	// Note, the caller MUST provide a byte buffer with size of at least
	// Length * lengthByteUnits - 2 bytes. Implementers of this function
	// may assume that the byte buffer is of sufficient size. serializeInto
	// MAY panic if the provided byte buffer is not of sufficient size.
	//
	// Callers that want to serialize an NDP option's body SHOULD use
	// serializeNDPOption. See serializeNDPOption for more information.
	//
	// serializeInto will return the number of bytes that was used to
	// serialize this NDPOption. Implementers must only use the number of
	// bytes required to serialize this NDPOption. Callers MAY provide a
	// larger buffer than required to serialize into.
	serializeInto([]byte) int
}

// serializeNDPOption serializes the NDP option (o)'s body into b after checking
// the size of b.
//
// serializeNDPOption may panic if b is not of sufficient size.
//
// When b is of sufficient size to serialize o, this function is equivalent
// to calling o.serializeInto(b).
func serializeNDPOption(o NDPOption, b []byte) {
	need, have := int(o.Length())*lengthByteUnits-2, len(b)
	if need > have {
		// Should never happen as callers should have queried the
		// required length to determine the right size for the buffer
		// before attempting to serialize.
		panic(fmt.Sprintf("cannot serialize NDP option body into the provided buffer as we only have %d bytes but need %d bytes", have, need))
	}

	// We know it's safe to call o.serializeInto because we just made sure
	// that b is of sufficient size to serialize o, meeting the requirements
	// of NDPOption.serializeInto. See NDPOption.serializeInto for more
	// information.
	if used := o.serializeInto(b); used != need {
		panic(fmt.Sprintf("should have used %d bytes to serialize, but actually used %d bytes", need, used))
	}
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

// Type implements NDPOption.Type.
func (o NDPTargetLinkLayerAddressOption) Type() uint8 {
	return NDPTargetLinkLayerAddressOptionType
}

// Length implements NDPOption.Length.
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

// Body implements NDPOption.Body.
func (o NDPTargetLinkLayerAddressOption) Body() []byte {
	return []byte(o)
}

// serializeInto implements NDPOption.serializeInto.
func (o NDPTargetLinkLayerAddressOption) serializeInto(b []byte) int {
	// copy will copy only the portion of the option that is not padding.
	used := copy(b, o)

	// Zero out remaining (padding) bytes, if any exists.
	need := int(o.Length())*lengthByteUnits - 2
	for i := used; i < need; i++ {
		// This will panic if b is not of sufficient size as documented
		// by NDPOption.serializeInto.
		b[i] = 0

		used++
	}

	return used
}

// EthernetAddress will return an ethernet (MAC) address if the
// NDPTargetLinkLayerAddressOption's body has at minimum EthernetAddressSize
// bytes. If the body has more than EthernetAddressSize bytes, only the first
// EthernetAddressSize bytes are returned as that is all that is needed for an
// Ethernet address.
func (o NDPTargetLinkLayerAddressOption) EthernetAddress() tcpip.LinkAddress {
	if len(o) >= EthernetAddressSize {
		return tcpip.LinkAddress(o[:EthernetAddressSize])
	}

	return tcpip.LinkAddress([]byte(nil))
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

// Type implements NDPOption.Type.
func (o NDPPrefixInformation) Type() uint8 {
	return NDPPrefixInformationType
}

// Length implements NDPOption.Length.
func (o NDPPrefixInformation) Length() uint8 {
	return ndpPrefixInformationLength
}

// Body implements NDPOption.Body.
func (o NDPPrefixInformation) Body() []byte {
	return o
}

// serializeInto implements NDPOption.serializeInto.
func (o NDPPrefixInformation) serializeInto(b []byte) int {
	used := copy(b, o)

	// Zero out the Reserved1 field.
	b[ndpPrefixInformationFlagsOffset] &^= ndpPrefixInformationReserved1FlagsMask

	// Zero out the Reserved2 field.
	reserved2 := b[ndpPrefixInformationReserved2Offset:][:ndpPrefixInformationReserved2Length]
	for i := range reserved2 {
		reserved2[i] = 0
	}

	return used
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
