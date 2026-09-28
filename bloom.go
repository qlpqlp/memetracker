package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
)

// BIP-37 / BIP-111 constants (same inventory ids Dogecoin/bitcoinj SPV wallets use).
const (
	MSG_FILTERED_BLOCK = 3
	NODE_BLOOM         = uint64(1 << 2)

	BLOOM_UPDATE_NONE          = 0
	BLOOM_UPDATE_ALL           = 1
	BLOOM_UPDATE_P2PUBKEY_ONLY = 2

	maxBloomFilterSize = 36000
	maxBloomHashFuncs  = 50
)

// BloomFilter is a BIP-37 bloom filter used for filterload / MSG_FILTERED_BLOCK.
type BloomFilter struct {
	data      []byte
	nHash     uint32
	nTweak    uint32
	nFlags    byte
	nElements uint32
}

// NewBloomFilter sizes a filter for roughly nElements inserts at the given false-positive rate.
func NewBloomFilter(nElements uint32, fpRate float64, nTweak uint32, flags byte) *BloomFilter {
	if nElements == 0 {
		nElements = 1
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.0001
	}
	// nFilterBytes = -n*ln(p) / (ln2)^2
	nBytes := int(math.Ceil(-float64(nElements)*math.Log(fpRate) / (math.Ln2 * math.Ln2) / 8))
	if nBytes < 1 {
		nBytes = 1
	}
	if nBytes > maxBloomFilterSize {
		nBytes = maxBloomFilterSize
	}
	// nHashFuncs = (nFilterBytes*8 / n) * ln2
	nHash := uint32(math.Ceil((float64(nBytes) * 8 / float64(nElements)) * math.Ln2))
	if nHash < 1 {
		nHash = 1
	}
	if nHash > maxBloomHashFuncs {
		nHash = maxBloomHashFuncs
	}
	return &BloomFilter{
		data:      make([]byte, nBytes),
		nHash:     nHash,
		nTweak:    nTweak,
		nFlags:    flags,
		nElements: nElements,
	}
}

func (f *BloomFilter) Add(data []byte) {
	if f == nil || len(f.data) == 0 || len(data) == 0 {
		return
	}
	nBits := uint32(len(f.data) * 8)
	for i := uint32(0); i < f.nHash; i++ {
		idx := murmur3(data, i*0xfba4c795+f.nTweak) % nBits
		f.data[idx>>3] |= 1 << (7 & idx)
	}
}

func (f *BloomFilter) FilterloadPayload() []byte {
	if f == nil {
		return nil
	}
	out := encodeVarInt(uint64(len(f.data)))
	out = append(out, f.data...)
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, f.nHash)
	out = append(out, tmp...)
	binary.LittleEndian.PutUint32(tmp, f.nTweak)
	out = append(out, tmp...)
	out = append(out, f.nFlags)
	return out
}

func encodeVarInt(n uint64) []byte {
	if n < 0xfd {
		return []byte{byte(n)}
	}
	if n <= 0xffff {
		out := []byte{0xfd, 0, 0}
		binary.LittleEndian.PutUint16(out[1:], uint16(n))
		return out
	}
	if n <= 0xffffffff {
		out := []byte{0xfe, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(out[1:], uint32(n))
		return out
	}
	out := make([]byte, 9)
	out[0] = 0xff
	binary.LittleEndian.PutUint64(out[1:], n)
	return out
}

// murmur3 is Bitcoin Core's MurmurHash3 (x86_32) used by BIP-37.
func murmur3(data []byte, seed uint32) uint32 {
	const (
		c1 = 0xcc9e2d51
		c2 = 0x1b873593
	)
	h1 := seed
	nblocks := len(data) / 4
	for i := 0; i < nblocks; i++ {
		k1 := binary.LittleEndian.Uint32(data[i*4:])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2

		h1 ^= k1
		h1 = (h1 << 13) | (h1 >> 19)
		h1 = h1*5 + 0xe6546b64
	}
	tail := data[nblocks*4:]
	var k1 uint32
	switch len(tail) {
	case 3:
		k1 ^= uint32(tail[2]) << 16
		fallthrough
	case 2:
		k1 ^= uint32(tail[1]) << 8
		fallthrough
	case 1:
		k1 ^= uint32(tail[0])
		k1 *= c1
		k1 = (k1 << 15) | (k1 >> 17)
		k1 *= c2
		h1 ^= k1
	}
	h1 ^= uint32(len(data))
	h1 ^= h1 >> 16
	h1 *= 0x85ebca6b
	h1 ^= h1 >> 13
	h1 *= 0xc2b2ae35
	h1 ^= h1 >> 16
	return h1
}

// merkleBlockResult is the parsed BIP-37 merkleblock used for SPV-style confirms.
type merkleBlockResult struct {
	Header80    []byte
	TotalTxs    uint32
	MatchedTxid []string // display-order hex (same as txidHex)
}

// parseMerkleBlock decodes a merkleblock payload and extracts matched txids.
func parseMerkleBlock(payload []byte) (*merkleBlockResult, error) {
	if len(payload) < 84 {
		return nil, errors.New("merkleblock too short")
	}
	h80 := make([]byte, 80)
	copy(h80, payload[:80])
	off := 80
	if off+4 > len(payload) {
		return nil, errors.New("merkleblock truncated total_txns")
	}
	totalTxs := binary.LittleEndian.Uint32(payload[off:])
	off += 4

	nHashes, err := readVarInt(payload, &off)
	if err != nil {
		return nil, err
	}
	if nHashes > 100000 {
		return nil, errors.New("merkleblock hash count too large")
	}
	hashes := make([][]byte, 0, int(nHashes))
	for i := 0; i < int(nHashes); i++ {
		if off+32 > len(payload) {
			return nil, errors.New("merkleblock hashes truncated")
		}
		h := make([]byte, 32)
		copy(h, payload[off:off+32])
		off += 32
		hashes = append(hashes, h)
	}

	nFlags, err := readVarInt(payload, &off)
	if err != nil {
		return nil, err
	}
	if !offsetFits(off, nFlags, len(payload)) {
		return nil, errors.New("merkleblock flags truncated")
	}
	flags := make([]byte, int(nFlags))
	copy(flags, payload[off:off+int(nFlags)])

	matched, err := extractMatchedTxids(totalTxs, hashes, flags)
	if err != nil {
		return nil, err
	}
	return &merkleBlockResult{
		Header80:    h80,
		TotalTxs:    totalTxs,
		MatchedTxid: matched,
	}, nil
}

func extractMatchedTxids(totalTxs uint32, hashes [][]byte, flags []byte) ([]string, error) {
	if totalTxs == 0 {
		return nil, errors.New("merkleblock zero txs")
	}
	bitsUsed := 0
	hashIdx := 0
	var matched []string

	var walk func(height, pos uint32) ([]byte, error)
	walk = func(height, pos uint32) ([]byte, error) {
		if bitsUsed >= len(flags)*8 {
			return nil, errors.New("merkle bits exhausted")
		}
		parentOfMatch := (flags[bitsUsed/8] & (uint8(1) << (bitsUsed % 8))) != 0
		bitsUsed++
		if height == 0 || !parentOfMatch {
			if hashIdx >= len(hashes) {
				return nil, errors.New("merkle hashes exhausted")
			}
			h := hashes[hashIdx]
			hashIdx++
			if height == 0 && parentOfMatch {
				matched = append(matched, reverseBytesToHex(h))
			}
			return h, nil
		}
		left, err := walk(height-1, pos*2)
		if err != nil {
			return nil, err
		}
		var right []byte
		if pos*2+1 < calcTreeWidth(totalTxs, height-1) {
			right, err = walk(height-1, pos*2+1)
			if err != nil {
				return nil, err
			}
		} else {
			right = left
		}
		return merkleParent(left, right), nil
	}

	height := calcTreeHeight(totalTxs)
	root, err := walk(height, 0)
	if err != nil {
		return nil, err
	}
	_ = root
	if hashIdx != len(hashes) {
		return nil, errors.New("merkle hashes unused")
	}
	return matched, nil
}

func calcTreeWidth(nTx, height uint32) uint32 {
	return (nTx + (1 << height) - 1) >> height
}

func calcTreeHeight(nTx uint32) uint32 {
	var h uint32
	for calcTreeWidth(nTx, h) > 1 {
		h++
	}
	return h
}

func merkleParent(left, right []byte) []byte {
	buf := make([]byte, 0, 64)
	buf = append(buf, left...)
	buf = append(buf, right...)
	sum := sha256d(buf)
	out := make([]byte, 32)
	copy(out, sum[:])
	return out
}

// bloomFromWatched builds a BIP-37 filter covering watched P2PKH hash160 pushes.
func bloomFromWatched(hash160Hexes []string, tweak uint32) *BloomFilter {
	n := uint32(len(hash160Hexes))
	if n == 0 {
		n = 1
	}
	// Extra headroom for false positives / multi-output scripts.
	f := NewBloomFilter(n*2+8, 0.0001, tweak, BLOOM_UPDATE_ALL)
	for _, hx := range hash160Hexes {
		b, err := hex.DecodeString(hx)
		if err != nil || len(b) != 20 {
			continue
		}
		f.Add(b)
	}
	return f
}
