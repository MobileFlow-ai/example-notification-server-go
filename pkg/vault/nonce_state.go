package vault

import "encoding/binary"

const nonceStateBytes = 12

type nonceState struct {
	Prefix       uint32
	NextSequence uint64
}

func encodeNonceState(state nonceState) []byte {
	encoded := make([]byte, nonceStateBytes)
	binary.BigEndian.PutUint32(encoded[:4], state.Prefix)
	binary.BigEndian.PutUint64(encoded[4:], state.NextSequence)
	return encoded
}

func decodeNonceState(encoded []byte) (nonceState, error) {
	if len(encoded) != nonceStateBytes {
		return nonceState{}, ErrStoreUnavailable
	}
	return nonceState{
		Prefix:       binary.BigEndian.Uint32(encoded[:4]),
		NextSequence: binary.BigEndian.Uint64(encoded[4:]),
	}, nil
}
