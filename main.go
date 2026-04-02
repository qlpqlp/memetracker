// MemeTracker — Dogecoin mempool watcher (open source, MIT License; see LICENSE).
//
// Copyright (c) Paulo Vidal · https://x.com/inevitable360 · Dogecoin Foundation Dev
//
// MemeTracker connects to Dogecoin peers only to observe the relay mempool: after
// handshake it sends the mempool message, then handles inv (requesting getdata only
// for MSG_TX / witness-tx inventory types), tx, and ping. It does not sync blocks,
// headers, or chain state—unlike monolithic SPV samples that also parse blocks.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MAGIC               = 0xC0C0C0C0
	COMMAND_LEN         = 12
	MSG_WITNESS_FLAG    = 1 << 30
	MSG_TX              = 1 // inventory type for transactions (and MSG_TX|MSG_WITNESS_FLAG for segwit); never MSG_BLOCK
	NODE_NETWORK        = 1 << 0
	NODE_WITNESS        = 1 << 3
	GETDATA_BATCH       = 48
	MAX_TX_FETCH_INV    = 200
	MEMPOOL_RESYNC_SEC  = 90
	MEMPOOL_WATCHER_SEC = 3
	P2P_READ_IDLE_SEC   = 20
	SESSION_SEC         = 300
)

//go:embed static/*
var staticFiles embed.FS

var mainnetP2PKHVersion = byte(0x1E)
var testnetP2PKHVersion = byte(0x71)

// Same seed hostnames as memetracker/mainnet Dogecoin DNS.
var mainnetDNSSeeds = []string{
	"seed.dogecoin.org",
	"seed.dogecoin.net",
	"seed.multidoge.org",
	"seed2.multidoge.org",
	// seed.dogecoin.com omitted: often NXDOMAIN; remaining seeds match chainparams.
}

// ------- Utilities -------

func sha256d(data []byte) [32]byte {
	h1 := sha256.Sum256(data)
	h2 := sha256.Sum256(h1[:])
	return h2
}

func mustEnvDefault(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func envString(key, def string) string {
	return mustEnvDefault(key, def)
}

// ------- Base58Check (P2PKH -> hash160) -------

var b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

func b58Index(b byte) (int64, error) {
	idx := strings.IndexByte(b58Alphabet, b)
	if idx < 0 {
		return 0, fmt.Errorf("invalid base58 char: %q", b)
	}
	return int64(idx), nil
}

func b58Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errors.New("empty base58")
	}
	n := new(big.Int)
	for i := 0; i < len(s); i++ {
		c := s[i]
		v, err := b58Index(c)
		if err != nil {
			return nil, err
		}
		n.Mul(n, big.NewInt(58))
		n.Add(n, big.NewInt(v))
	}

	// Leading '1's are leading 0x00 bytes.
	pad := 0
	for pad < len(s) && s[pad] == '1' {
		pad++
	}

	raw := n.Bytes() // big-endian, no leading zeros
	out := make([]byte, 0, pad+len(raw))
	out = append(out, make([]byte, pad)...)
	out = append(out, raw...)
	return out, nil
}

func b58checkDecode(addr string) ([]byte, error) {
	raw, err := b58Decode(addr)
	if err != nil {
		return nil, err
	}
	if len(raw) < 5 {
		return nil, errors.New("invalid address length")
	}
	payload, chk := raw[:len(raw)-4], raw[len(raw)-4:]
	sum := sha256d(payload)
	if !strings.EqualFold(hex.EncodeToString(sum[:4]), hex.EncodeToString(chk)) {
		return nil, errors.New("bad checksum")
	}
	return payload, nil
}

func decodePayoutToHash160(address string, network string) ([]byte, error) {
	wantVer := mainnetP2PKHVersion
	if strings.ToLower(network) != "mainnet" {
		wantVer = testnetP2PKHVersion
	}
	p, err := b58checkDecode(address)
	if err != nil {
		return nil, err
	}
	if len(p) != 21 || p[0] != wantVer {
		return nil, fmt.Errorf("need P2PKH base58 address for %s", network)
	}
	return p[1:21], nil
}

// ------- Tx parsing -------

// maxVarIntSlice is the largest count we allow when advancing an offset into a buffer
// (avoids uint64→int overflow that can make the offset negative and panic in readVarInt).
const maxVarIntSlice = uint64(32 * 1024 * 1024)

func readVarInt(data []byte, off *int) (uint64, error) {
	if *off < 0 || *off >= len(data) {
		return 0, errors.New("eof")
	}
	b0 := data[*off]
	*off++
	if b0 < 0xFD {
		return uint64(b0), nil
	}
	if b0 == 0xFD {
		if *off+2 > len(data) {
			return 0, errors.New("eof")
		}
		v := binary.LittleEndian.Uint16(data[*off:])
		*off += 2
		return uint64(v), nil
	}
	if b0 == 0xFE {
		if *off+4 > len(data) {
			return 0, errors.New("eof")
		}
		v := binary.LittleEndian.Uint32(data[*off:])
		*off += 4
		return uint64(v), nil
	}
	// 0xFF
	if *off+8 > len(data) {
		return 0, errors.New("eof")
	}
	v := binary.LittleEndian.Uint64(data[*off:])
	*off += 8
	return v, nil
}

func offsetFits(off int, n uint64, bufLen int) bool {
	if off < 0 || off > bufLen {
		return false
	}
	if n > maxVarIntSlice || n > uint64(bufLen-off) {
		return false
	}
	if n > uint64(^uint(0)>>1) {
		return false
	}
	return true
}

func offsetAdd(off *int, n uint64, bufLen int) bool {
	if !offsetFits(*off, n, bufLen) {
		return false
	}
	*off += int(n)
	return true
}

func scriptPubKeyHash160(script []byte) ([]byte, bool) {
	// P2PKH: OP_DUP OP_HASH160 0x14 <20> OP_EQUALVERIFY OP_CHECKSIG
	if len(script) == 25 &&
		script[0] == 0x76 &&
		script[1] == 0xA9 &&
		script[2] == 0x14 &&
		script[23] == 0x88 &&
		script[24] == 0xAC {
		out := make([]byte, 20)
		copy(out, script[3:23])
		return out, true
	}

	// P2SH: OP_HASH160 0x14 <20> OP_EQUAL
	if len(script) == 23 &&
		script[0] == 0xA9 &&
		script[1] == 0x14 &&
		script[22] == 0x87 {
		out := make([]byte, 20)
		copy(out, script[2:22])
		return out, true
	}

	// v0 P2WPKH (OP_0 0x14 <20>)
	if len(script) == 22 && script[0] == 0x00 && script[1] == 0x14 {
		out := make([]byte, 20)
		copy(out, script[2:22])
		return out, true
	}

	return nil, false
}

type txOutput struct {
	valueSats int64
	script    []byte
}

func parseTxOutputs(raw []byte) ([]txOutput, bool, error) {
	if len(raw) < 8 {
		return nil, false, nil
	}

	off := 0

	// version (4 bytes)
	if off+4 > len(raw) {
		return nil, false, errors.New("truncated_version")
	}
	off += 4

	isSegwit := false
	if off+2 <= len(raw) && raw[off] == 0 && raw[off+1] == 1 {
		isSegwit = true
		off += 2
	}

	// vin count
	nin, err := readVarInt(raw, &off)
	if err != nil {
		return nil, isSegwit, err
	}

	// skip vin scripts and sequences
	for i := 0; i < int(nin); i++ {
		// outpoint: 32 hash + 4 vout
		if off+36 > len(raw) {
			return nil, isSegwit, errors.New("truncated_txin")
		}
		off += 32 + 4
		// scriptSig
		slen, err := readVarInt(raw, &off)
		if err != nil {
			return nil, isSegwit, err
		}
		if !offsetFits(off, slen, len(raw)) {
			return nil, isSegwit, errors.New("truncated_scriptSig")
		}
		off += int(slen)
		// sequence (4 bytes)
		if off+4 > len(raw) {
			return nil, isSegwit, errors.New("truncated_sequence")
		}
		off += 4
	}

	// vin done, now vout count
	nout, err := readVarInt(raw, &off)
	if err != nil {
		return nil, isSegwit, err
	}

	outs := make([]txOutput, 0, int(nout))
	for i := 0; i < int(nout); i++ {
		if off+8 > len(raw) {
			return nil, isSegwit, errors.New("truncated_value")
		}
		value := int64(binary.LittleEndian.Uint64(raw[off:]))
		off += 8

		slen, err := readVarInt(raw, &off)
		if err != nil {
			return nil, isSegwit, err
		}
		if !offsetFits(off, slen, len(raw)) {
			return nil, isSegwit, errors.New("truncated_pk_script")
		}
		ns := int(slen)
		script := raw[off : off+ns]
		off += ns

		cp := make([]byte, len(script))
		copy(cp, script)
		outs = append(outs, txOutput{valueSats: value, script: cp})
	}

	// Skip witness data after outputs.
	if isSegwit {
		for i := 0; i < int(nin); i++ {
			nstk, err := readVarInt(raw, &off)
			if err != nil {
				return nil, isSegwit, err
			}
			for j := 0; j < int(nstk); j++ {
				elen, err := readVarInt(raw, &off)
				if err != nil {
					return nil, isSegwit, err
				}
				if !offsetFits(off, elen, len(raw)) {
					return nil, isSegwit, errors.New("truncated_witness")
				}
				off += int(elen)
			}
		}
	}

	return outs, isSegwit, nil
}

func txidHex(raw []byte) string {
	if len(raw) < 8 {
		sum := sha256d(raw)
		rev := make([]byte, 32)
		for i := 0; i < 32; i++ {
			rev[i] = sum[31-i]
		}
		return hex.EncodeToString(rev)
	}

	off := 4
	isSegwit := len(raw) >= off+2 && raw[off] == 0 && raw[off+1] == 1
	if isSegwit {
		off += 2
	}
	bodyStart := off
	nin64, err := readVarInt(raw, &off)
	if err != nil {
		sum := sha256d(raw)
		rev := make([]byte, 32)
		for i := 0; i < 32; i++ {
			rev[i] = sum[31-i]
		}
		return hex.EncodeToString(rev)
	}
	nin := nin64
	if nin > uint64(len(raw)) {
		sum := sha256d(raw)
		rev := make([]byte, 32)
		for i := 0; i < 32; i++ {
			rev[i] = sum[31-i]
		}
		return hex.EncodeToString(rev)
	}

	// inputs: [prevout(32)+vout(4)+scriptLen+script+sequence(4)] repeated
	for i := 0; i < int(nin); i++ {
		if off+36 > len(raw) {
			sum := sha256d(raw)
			rev := make([]byte, 32)
			for i := 0; i < 32; i++ {
				rev[i] = sum[31-i]
			}
			return hex.EncodeToString(rev)
		}
		off += 36 // prevout hash + vout index
		slen64, err := readVarInt(raw, &off)
		if err != nil {
			sum := sha256d(raw)
			rev := make([]byte, 32)
			for i := 0; i < 32; i++ {
				rev[i] = sum[31-i]
			}
			return hex.EncodeToString(rev)
		}
		if !offsetFits(off, slen64, len(raw)) {
			sum := sha256d(raw)
			rev := make([]byte, 32)
			for i := 0; i < 32; i++ {
				rev[i] = sum[31-i]
			}
			return hex.EncodeToString(rev)
		}
		off += int(slen64)
		// sequence
		if off+4 > len(raw) {
			sum := sha256d(raw)
			rev := make([]byte, 32)
			for i := 0; i < 32; i++ {
				rev[i] = sum[31-i]
			}
			return hex.EncodeToString(rev)
		}
		off += 4
	}

	nout64, err := readVarInt(raw, &off)
	if err != nil {
		sum := sha256d(raw)
		rev := make([]byte, 32)
		for i := 0; i < 32; i++ {
			rev[i] = sum[31-i]
		}
		return hex.EncodeToString(rev)
	}
	if nout64 > uint64(len(raw)) {
		sum := sha256d(raw)
		rev := make([]byte, 32)
		for i := 0; i < 32; i++ {
			rev[i] = sum[31-i]
		}
		return hex.EncodeToString(rev)
	}
	for i := 0; i < int(nout64); i++ {
		if off+8 > len(raw) {
			sum := sha256d(raw)
			rev := make([]byte, 32)
			for i := 0; i < 32; i++ {
				rev[i] = sum[31-i]
			}
			return hex.EncodeToString(rev)
		}
		off += 8
		slen64, err := readVarInt(raw, &off)
		if err != nil {
			sum := sha256d(raw)
			rev := make([]byte, 32)
			for i := 0; i < 32; i++ {
				rev[i] = sum[31-i]
			}
			return hex.EncodeToString(rev)
		}
		if !offsetFits(off, slen64, len(raw)) {
			sum := sha256d(raw)
			rev := make([]byte, 32)
			for i := 0; i < 32; i++ {
				rev[i] = sum[31-i]
			}
			return hex.EncodeToString(rev)
		}
		off += int(slen64)
	}
	endOutputs := off

	rest := endOutputs
	if isSegwit {
		nwi64, err := readVarInt(raw, &rest)
		if err != nil {
			sum := sha256d(raw)
			rev := make([]byte, 32)
			for i := 0; i < 32; i++ {
				rev[i] = sum[31-i]
			}
			return hex.EncodeToString(rev)
		}
		for i := 0; i < int(nwi64); i++ {
			ns64, err := readVarInt(raw, &rest)
			if err != nil {
				sum := sha256d(raw)
				rev := make([]byte, 32)
				for i := 0; i < 32; i++ {
					rev[i] = sum[31-i]
				}
				return hex.EncodeToString(rev)
			}
			for j := 0; j < int(ns64); j++ {
				el64, err := readVarInt(raw, &rest)
				if err != nil {
					sum := sha256d(raw)
					rev := make([]byte, 32)
					for i := 0; i < 32; i++ {
						rev[i] = sum[31-i]
					}
					return hex.EncodeToString(rev)
				}
				if !offsetFits(rest, el64, len(raw)) {
					sum := sha256d(raw)
					rev := make([]byte, 32)
					for i := 0; i < 32; i++ {
						rev[i] = sum[31-i]
					}
					return hex.EncodeToString(rev)
				}
				rest += int(el64)
			}
		}
	}
	var locktime []byte
	if rest+4 <= len(raw) {
		locktime = raw[rest : rest+4]
	} else {
		locktime = []byte{0, 0, 0, 0}
	}

	var preimage []byte
	if isSegwit {
		if bodyStart > endOutputs || endOutputs > len(raw) {
			sum := sha256d(raw)
			rev := make([]byte, 32)
			for i := 0; i < 32; i++ {
				rev[i] = sum[31-i]
			}
			return hex.EncodeToString(rev)
		}
		// preimage = version(4) + body(non-witness, from body_start to end_outputs) + locktime
		preimage = append(append([]byte{}, raw[0:4]...), raw[bodyStart:endOutputs]...)
		preimage = append(preimage, locktime...)
	} else {
		if endOutputs > len(raw) {
			sum := sha256d(raw)
			rev := make([]byte, 32)
			for i := 0; i < 32; i++ {
				rev[i] = sum[31-i]
			}
			return hex.EncodeToString(rev)
		}
		preimage = append(append([]byte{}, raw[0:endOutputs]...), locktime...)
	}

	sum := sha256d(preimage)
	rev := make([]byte, 32)
	for i := 0; i < 32; i++ {
		rev[i] = sum[31-i]
	}
	return hex.EncodeToString(rev)
}

func wtxidHex(raw []byte) string {
	sum := sha256d(raw)
	rev := make([]byte, 32)
	for i := 0; i < 32; i++ {
		rev[i] = sum[31-i]
	}
	return hex.EncodeToString(rev)
}

// ------- P2P protocol -------

func writeVarInt(n int) []byte {
	if n < 0xFD {
		return []byte{byte(n)}
	}
	if n <= 0xFFFF {
		out := make([]byte, 3)
		out[0] = 0xFD
		binary.LittleEndian.PutUint16(out[1:], uint16(n))
		return out
	}
	if n <= 0xFFFFFFFF {
		out := make([]byte, 5)
		out[0] = 0xFE
		binary.LittleEndian.PutUint32(out[1:], uint32(n))
		return out
	}
	out := make([]byte, 9)
	out[0] = 0xFF
	binary.LittleEndian.PutUint64(out[1:], uint64(n))
	return out
}

func buildMessage(command string, payload []byte) []byte {
	cmd := []byte(command)
	if len(cmd) > COMMAND_LEN {
		cmd = cmd[:COMMAND_LEN]
	}
	padded := make([]byte, COMMAND_LEN)
	copy(padded, cmd)
	checksum := sha256d(payload)

	out := make([]byte, 0, 24+len(payload))
	hdr := make([]byte, 0, 24)

	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, uint32(MAGIC))
	hdr = append(hdr, tmp...)

	hdr = append(hdr, padded...)
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(payload)))
	hdr = append(hdr, size...)
	hdr = append(hdr, checksum[:4]...)

	out = append(out, hdr...)
	out = append(out, payload...)
	return out
}

func readExact(conn net.Conn, size int) ([]byte, error) {
	out := make([]byte, 0, size)
	for len(out) < size {
		part := make([]byte, size-len(out))
		n, err := conn.Read(part)
		if err != nil {
			return nil, err
		}
		if n == 0 {
			return nil, io.EOF
		}
		out = append(out, part[:n]...)
	}
	return out, nil
}

// Dogecoin mainnet P2P message magic is 0xc0c0c0c0 as a uint32; on the wire it is 4 bytes little-endian.
func dogeMagicWireHexLE() string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], uint32(MAGIC))
	return hex.EncodeToString(b[:])
}

func hexSnippet(b []byte, max int) string {
	if len(b) <= max {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:max]) + fmt.Sprintf("…(%d more bytes)", len(b)-max)
}

// Summarize our outgoing version payload (same layout as buildVersionPayload).
func summarizeOutgoingVersionPayload(p []byte, destPort int) string {
	if len(p) < 81 {
		return fmt.Sprintf("short_payload_len=%d", len(p))
	}
	ver := int32(binary.LittleEndian.Uint32(p[0:4]))
	services := binary.LittleEndian.Uint64(p[4:12])
	ts := int64(binary.LittleEndian.Uint64(p[12:20]))
	off := 20 + 26 + 26 // after addr_recv, addr_from
	if len(p) < off+8 {
		return fmt.Sprintf("truncated_at=%d", len(p))
	}
	nonce := binary.LittleEndian.Uint64(p[off : off+8])
	off += 8
	if off >= len(p) {
		return fmt.Sprintf("bad_ua_off len=%d", len(p))
	}
	uaLen := int(p[off])
	off++
	if off+uaLen+4+1 > len(p) {
		return fmt.Sprintf("bad_ua len=%d uaLen=%d", len(p), uaLen)
	}
	ua := string(p[off : off+uaLen])
	off += uaLen
	startH := int32(binary.LittleEndian.Uint32(p[off : off+4]))
	relay := p[off+4]
	return fmt.Sprintf("proto=%d services=0x%x(NODE_NETWORK=%d NODE_WITNESS=%d) timestamp_unix=%d nonce=0x%x user_agent=%q start_height=%d relay=%t addr_port_big_endian=%d",
		ver, services, (services&NODE_NETWORK)>>0, (services&NODE_WITNESS)>>3, ts, nonce, ua, startH, relay != 0, destPort)
}

// First fields of peer's version message (variable user_agent; we only decode fixed prefix + try UA).
func summarizePeerVersionPayload(p []byte) string {
	if len(p) < 20 {
		return fmt.Sprintf("len=%d (too short for version prefix)", len(p))
	}
	ver := int32(binary.LittleEndian.Uint32(p[0:4]))
	services := binary.LittleEndian.Uint64(p[4:12])
	ts := int64(binary.LittleEndian.Uint64(p[12:20]))
	off := 20 + 26 + 26
	if len(p) < off+8 {
		return fmt.Sprintf("proto=%d services=0x%x ts_unix=%d (truncated before nonce, len=%d)", ver, services, ts, len(p))
	}
	nonce := binary.LittleEndian.Uint64(p[off : off+8])
	off += 8
	ua := ""
	if off >= len(p) {
		ua = "(no user_agent)"
	} else {
		off2 := off
		uaLen64, err := readVarInt(p, &off2)
		if err != nil || uaLen64 > 4096 || off2+int(uaLen64) > len(p) {
			ua = fmt.Sprintf("(user_agent_compact err=%v n=%d)", err, uaLen64)
		} else {
			ua = string(p[off2 : off2+int(uaLen64)])
			off2 += int(uaLen64)
			off = off2
		}
	}
	var startH int32
	var relay byte
	if off+5 <= len(p) {
		startH = int32(binary.LittleEndian.Uint32(p[off : off+4]))
		relay = p[off+4]
	}
	return fmt.Sprintf("peer_proto=%d services=0x%x ts_unix=%d nonce=0x%x user_agent=%q start_height=%d relay=%t",
		ver, services, ts, nonce, ua, startH, relay != 0)
}

func parseInvPayload(payload []byte) ([]invItem, error) {
	off := 0
	n64, err := readVarInt(payload, &off)
	if err != nil {
		return nil, err
	}
	n := int(n64)
	if n > 100000 {
		n = 100000
	}
	out := make([]invItem, 0, n)
	for i := 0; i < n; i++ {
		if off+36 > len(payload) {
			break
		}
		invType := binary.LittleEndian.Uint32(payload[off:])
		h := payload[off+4 : off+36]
		cp := make([]byte, 32)
		copy(cp, h)
		off += 36
		out = append(out, invItem{invType: int(invType), hash: cp})
	}
	return out, nil
}

type invItem struct {
	invType int
	hash    []byte // 32 bytes in wire order
}

func invTypeIsTx(t int) bool {
	return (t & ^MSG_WITNESS_FLAG) == MSG_TX
}

func buildGetdataPayload(items []invItem) []byte {
	parts := make([]byte, 0, 1+len(items)*36)
	parts = append(parts, writeVarInt(len(items))...)
	for _, it := range items {
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, uint32(it.invType))
		parts = append(parts, tmp...)
		parts = append(parts, it.hash...)
	}
	return parts
}

func buildVersionPayload(p2pPort int) []byte {
	version := int32(70015)
	services := uint64(NODE_NETWORK | NODE_WITNESS)
	timestamp := uint64(time.Now().Unix())

	// addr_recv: (services=0, addr=16 zero, port big-end)
	addrRecv := make([]byte, 8+16+2)
	binary.LittleEndian.PutUint64(addrRecv[:8], 0)
	// 16 zero already
	binary.BigEndian.PutUint16(addrRecv[8+16:], uint16(p2pPort))

	addrFrom := make([]byte, 8+16+2)
	binary.LittleEndian.PutUint64(addrFrom[:8], 0)
	binary.BigEndian.PutUint16(addrFrom[8+16:], uint16(p2pPort))

	nonceBytes := make([]byte, 8)
	_, _ = rand.Read(nonceBytes)
	nonce := binary.LittleEndian.Uint64(nonceBytes)

	userAgent := "/MemeTracker:1.0.0/"
	uaLen := len(userAgent)
	ua := make([]byte, 1+uaLen)
	ua[0] = byte(uaLen)
	copy(ua[1:], []byte(userAgent))

	startHeight := int32(0)
	relay := byte(1)

	out := make([]byte, 0, 110)
	tmp1 := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp1, uint32(version))
	out = append(out, tmp1...)
	tmp2 := make([]byte, 8)
	binary.LittleEndian.PutUint64(tmp2, services)
	out = append(out, tmp2...)

	tmp3 := make([]byte, 8)
	binary.LittleEndian.PutUint64(tmp3, timestamp)
	out = append(out, tmp3...)
	out = append(out, addrRecv...)
	out = append(out, addrFrom...)

	tmp4 := make([]byte, 8)
	binary.LittleEndian.PutUint64(tmp4, nonce)
	out = append(out, tmp4...)

	out = append(out, ua...)

	tmp5 := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp5, uint32(startHeight))
	out = append(out, tmp5...)
	out = append(out, relay)

	return out
}

// ------- Store (file-backed DB) -------

type TxRecord struct {
	Txid       string  `json:"txid"`
	Datetime   string  `json:"datetime"`
	AmountDoge float64 `json:"amount_doge"`
}

type AddressData struct {
	Address       string     `json:"address"`
	Hash160Hex    string     `json:"hash160_hex"`
	CallbackURL   string     `json:"callback_url,omitempty"`
	TrackedSince  time.Time  `json:"tracked_since"`
	LastRequested time.Time  `json:"last_requested"`
	Txs           []TxRecord `json:"txs"`
}

type Store struct {
	mu            sync.RWMutex
	storageDir    string
	addressesDir  string
	listLimit     int
	retentionDays int

	watchByHash map[string]*AddressData // hash160hex -> data

	mempoolKick atomic.Bool // set after /track/ so P2P loop sends "mempool" again
}

func (s *Store) kickMempoolResync() {
	s.mempoolKick.Store(true)
}

func (s *Store) takeMempoolKick() bool {
	return s.mempoolKick.Swap(false)
}

func (s *Store) watcherCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.watchByHash)
}

func NewStore(storageDir string, listLimit int, retentionDays int) (*Store, error) {
	addressesDir := filepath.Join(storageDir, "addresses")
	if err := os.MkdirAll(addressesDir, 0o755); err != nil {
		return nil, err
	}
	s := &Store{
		storageDir:    storageDir,
		addressesDir:  addressesDir,
		listLimit:     listLimit,
		retentionDays: retentionDays,
		watchByHash:   make(map[string]*AddressData),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	s.purgeExpiredLocked(time.Now())
	return s, nil
}

func (s *Store) fileForHash(hashHex string) string {
	return filepath.Join(s.addressesDir, hashHex+".json")
}

func (s *Store) load() error {
	entries, err := os.ReadDir(s.addressesDir)
	if err != nil {
		return err
	}
	now := time.Now()
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(s.addressesDir, name))
		if err != nil {
			continue
		}
		var ad AddressData
		if err := json.Unmarshal(b, &ad); err != nil {
			continue
		}
		if ad.Hash160Hex == "" {
			// best-effort: infer from filename
			ad.Hash160Hex = strings.TrimSuffix(name, ".json")
		}
		if ad.Address == "" {
			continue
		}
		// Ensure newest-first and truncated.
		if len(ad.Txs) > s.listLimit {
			ad.Txs = ad.Txs[:s.listLimit]
		}
		// Purge old
		if now.Sub(ad.LastRequested) > time.Duration(s.retentionDays)*24*time.Hour {
			continue
		}
		if ad.TrackedSince.IsZero() {
			ad.TrackedSince = ad.LastRequested
		}
		s.watchByHash[ad.Hash160Hex] = &ad
	}
	return nil
}

func (s *Store) purgeExpiredLocked(now time.Time) {
	for hashHex, ad := range s.watchByHash {
		if now.Sub(ad.LastRequested) > time.Duration(s.retentionDays)*24*time.Hour {
			delete(s.watchByHash, hashHex)
			_ = os.Remove(s.fileForHash(hashHex))
		}
	}
}

func (s *Store) persistAddressLocked(ad *AddressData) error {
	tmp := struct {
		Address       string     `json:"address"`
		Hash160Hex    string     `json:"hash160_hex"`
		CallbackURL   string     `json:"callback_url,omitempty"`
		TrackedSince  time.Time  `json:"tracked_since"`
		LastRequested time.Time  `json:"last_requested"`
		Txs           []TxRecord `json:"txs"`
	}{
		Address:       ad.Address,
		Hash160Hex:    ad.Hash160Hex,
		CallbackURL:   ad.CallbackURL,
		TrackedSince:  ad.TrackedSince,
		LastRequested: ad.LastRequested,
		Txs:           ad.Txs,
	}
	b, err := json.Marshal(tmp)
	if err != nil {
		return err
	}
	fn := s.fileForHash(ad.Hash160Hex)
	tmpfn := fn + ".tmp"
	if err := os.WriteFile(tmpfn, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmpfn, fn)
}

func (s *Store) UpsertTracking(address string, hash160 []byte, callbackURL string) (alreadyMonitoring bool, recent []TxRecord, appliedCallback string, err error) {
	hashHex := hex.EncodeToString(hash160)
	now := time.Now().UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	if ad, ok := s.watchByHash[hashHex]; ok {
		alreadyMonitoring = true
		ad.LastRequested = now
		if ad.TrackedSince.IsZero() {
			ad.TrackedSince = now
		}
		if strings.TrimSpace(callbackURL) != "" {
			ad.CallbackURL = strings.TrimSpace(callbackURL)
		}
		if err := s.persistAddressLocked(ad); err != nil {
			return alreadyMonitoring, nil, "", err
		}
		s.kickMempoolResync()
		return alreadyMonitoring, ad.Txs, ad.CallbackURL, nil
	}

	ad := &AddressData{
		Address:       address,
		Hash160Hex:    hashHex,
		CallbackURL:   strings.TrimSpace(callbackURL),
		TrackedSince:  now,
		LastRequested: now,
		Txs:           []TxRecord{},
	}
	s.watchByHash[hashHex] = ad
	if err := s.persistAddressLocked(ad); err != nil {
		return false, nil, "", err
	}
	s.kickMempoolResync()
	return false, ad.Txs, ad.CallbackURL, nil
}

func (s *Store) AddTx(hashHex string, txid string, dt time.Time, amountDoge float64) (inserted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ad, ok := s.watchByHash[hashHex]
	if !ok {
		return false
	}

	// Dedupe by txid within the stored limited window.
	for _, r := range ad.Txs {
		if r.Txid == txid {
			return false
		}
	}

	rec := TxRecord{
		Txid:       txid,
		Datetime:   dt.UTC().Format(time.RFC3339),
		AmountDoge: amountDoge,
	}

	// Store newest first.
	ad.Txs = append([]TxRecord{rec}, ad.Txs...)
	if len(ad.Txs) > s.listLimit {
		ad.Txs = ad.Txs[:s.listLimit]
	}
	_ = s.persistAddressLocked(ad)
	return true
}

func (s *Store) CallbackTarget(hashHex string) (address string, callbackURL string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ad, found := s.watchByHash[hashHex]
	if !found {
		return "", "", false
	}
	return ad.Address, strings.TrimSpace(ad.CallbackURL), true
}

func (s *Store) GetRecent(address string, hash160 []byte) ([]TxRecord, bool) {
	hashHex := hex.EncodeToString(hash160)
	s.mu.RLock()
	defer s.mu.RUnlock()
	ad, ok := s.watchByHash[hashHex]
	if !ok {
		return nil, false
	}
	return ad.Txs, true
}

func (s *Store) SetLimits(listLimit, retentionDays int) {
	if listLimit < 1 {
		listLimit = 1
	}
	if retentionDays < 1 {
		retentionDays = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listLimit = listLimit
	s.retentionDays = retentionDays
	for _, ad := range s.watchByHash {
		if len(ad.Txs) > s.listLimit {
			ad.Txs = ad.Txs[:s.listLimit]
			_ = s.persistAddressLocked(ad)
		}
	}
}

func (s *Store) RemoveAddress(hashHex string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.watchByHash[hashHex]; !ok {
		return false
	}
	delete(s.watchByHash, hashHex)
	_ = os.Remove(s.fileForHash(hashHex))
	s.kickMempoolResync()
	return true
}

func (s *Store) RemoveTx(hashHex, txid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ad, ok := s.watchByHash[hashHex]
	if !ok {
		return false
	}
	out := ad.Txs[:0]
	for _, r := range ad.Txs {
		if r.Txid != txid {
			out = append(out, r)
		}
	}
	if len(out) == len(ad.Txs) {
		return false
	}
	ad.Txs = out
	_ = s.persistAddressLocked(ad)
	return true
}

func (s *Store) ListAddressSnapshots() []map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]map[string]any, 0, len(s.watchByHash))
	for _, ad := range s.watchByHash {
		ts := ad.TrackedSince
		if ts.IsZero() {
			ts = ad.LastRequested
		}
		out = append(out, map[string]any{
			"address":        ad.Address,
			"hash160_hex":    ad.Hash160Hex,
			"tracked_since":  ts.UTC().Format(time.RFC3339),
			"last_requested": ad.LastRequested.UTC().Format(time.RFC3339),
			"tx_count":       len(ad.Txs),
		})
	}
	return out
}

func (s *Store) FlattenTransactions() []map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var rows []map[string]any
	for _, ad := range s.watchByHash {
		for _, tx := range ad.Txs {
			rows = append(rows, map[string]any{
				"address":       ad.Address,
				"hash160_hex":   ad.Hash160Hex,
				"txid":          tx.Txid,
				"datetime":      tx.Datetime,
				"amount_doge":   tx.AmountDoge,
			})
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		ti, ei := time.Parse(time.RFC3339, rows[i]["datetime"].(string))
		tj, ej := time.Parse(time.RFC3339, rows[j]["datetime"].(string))
		if ei != nil || ej != nil {
			return i > j
		}
		return ti.After(tj)
	})
	return rows
}

func (s *Store) StoredTransactionRows() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := 0
	for _, ad := range s.watchByHash {
		n += len(ad.Txs)
	}
	return n
}

func (s *Store) Limits() (listLimit, retentionDays int) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listLimit, s.retentionDays
}

func (s *Store) metricsSnapshot() (watched int, totalTx int, latestPayment string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	watched = len(s.watchByHash)
	var latest time.Time
	for _, ad := range s.watchByHash {
		totalTx += len(ad.Txs)
		for _, tx := range ad.Txs {
			if tx.Txid == "" {
				continue
			}
			t, err := time.Parse(time.RFC3339, tx.Datetime)
			if err != nil {
				continue
			}
			if t.After(latest) {
				latest = t
				short := tx.Txid
				if len(short) > 14 {
					short = short[:8] + "…" + short[len(short)-4:]
				}
				latestPayment = fmt.Sprintf("%s  %.8f DOGE  %s", short, tx.AmountDoge, tx.Datetime)
			}
		}
	}
	if latestPayment == "" {
		latestPayment = "—"
	}
	return
}

// ------- Dogebox metrics (same contract as CORE monitor) -------

type peerSession struct {
	WorkerID  int       `json:"worker_id"`
	Address   string    `json:"address"`
	Connected bool      `json:"connected"`
	Updated   time.Time `json:"updated"`
}

type MetricsCollector struct {
	mu            sync.RWMutex
	byWorker      map[int]peerSession // one logical session per P2P worker
	mempoolTxIDs  map[string]struct{}
	maxMempoolIDs int
}

func NewMetricsCollector(maxMempool int) *MetricsCollector {
	if maxMempool <= 0 {
		maxMempool = 50000
	}
	return &MetricsCollector{
		byWorker:      make(map[int]peerSession),
		mempoolTxIDs:  make(map[string]struct{}),
		maxMempoolIDs: maxMempool,
	}
}

func (m *MetricsCollector) SetPeerSession(workerID int, addr string, connected bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.byWorker[workerID] = peerSession{
		WorkerID:  workerID,
		Address:   addr,
		Connected: connected,
		Updated:   time.Now().UTC(),
	}
}

func (m *MetricsCollector) snapshotPeers() (rows []peerSession, connectedN int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, s := range m.byWorker {
		rows = append(rows, s)
		if s.Connected {
			connectedN++
		}
	}
	return rows, connectedN
}

func (m *MetricsCollector) observeMempoolTxid(txid string) {
	if txid == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.mempoolTxIDs[txid]; ok {
		return
	}
	for len(m.mempoolTxIDs) >= m.maxMempoolIDs {
		for k := range m.mempoolTxIDs {
			delete(m.mempoolTxIDs, k)
			break
		}
	}
	m.mempoolTxIDs[txid] = struct{}{}
}

func (m *MetricsCollector) snapshot() (mempoolN int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.mempoolTxIDs)
}

func submitDogeboxMetrics(store *Store, col *MetricsCollector) {
	host := strings.TrimSpace(os.Getenv("DBX_HOST"))
	port := strings.TrimSpace(os.Getenv("DBX_PORT"))
	if host == "" || port == "" {
		return
	}

	watched, totalTx, latestPay := store.metricsSnapshot()
	mempoolN := col.snapshot()
	peerRows, nConn := col.snapshotPeers()

	p2pConnected := "no"
	if nConn > 0 {
		p2pConnected = "yes"
	}
	peerDetail := fmt.Sprintf("connected_workers=%d", nConn)
	if len(peerRows) > 0 {
		var b strings.Builder
		for _, pr := range peerRows {
			st := "idle"
			if pr.Connected {
				st = "live"
			}
			if b.Len() > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "w%d:%s:%s", pr.WorkerID, st, pr.Address)
		}
		peerDetail = b.String()
	}

	payload := map[string]interface{}{
		"tracked_transactions":   map[string]interface{}{"value": totalTx},
		"watched_addresses":      map[string]interface{}{"value": watched},
		"mempool_tx_count":       map[string]interface{}{"value": mempoolN},
		"p2p_connected":          map[string]interface{}{"value": p2pConnected},
		"p2p_peer_detail":        map[string]interface{}{"value": peerDetail},
		"latest_tracked_payment": map[string]interface{}{"value": latestPay},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[MTR-METRICS] marshal: %v", err)
		return
	}

	url := fmt.Sprintf("http://%s:%s/dbx/metrics", host, port)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[MTR-METRICS] request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[MTR-METRICS] post: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		log.Printf("[MTR-METRICS] status=%d body=%s", resp.StatusCode, string(b))
	}
}

// ------- P2P watcher -------

type ProcessedSet struct {
	mu sync.Mutex
	m  map[string]struct{}
}

type PaymentCallbackPayload struct {
	Address    string  `json:"address"`
	Txid       string  `json:"txid"`
	AmountDoge float64 `json:"payment_amount"`
	Datetime   string  `json:"datetime"`
}

func notifyCallback(callbackURL string, payload PaymentCallbackPayload) {
	u := strings.TrimSpace(callbackURL)
	if u == "" {
		return
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		log.Printf("[MTR-CB] invalid callback url=%q err=%v", u, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "MemeTracker/1.0")
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[MTR-CB] notify failed url=%q txid=%s err=%v", u, payload.Txid, err)
		return
	}
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		log.Printf("[MTR-CB] notify non-2xx url=%q txid=%s status=%d", u, payload.Txid, resp.StatusCode)
	}
}

func NewProcessedSet() *ProcessedSet {
	return &ProcessedSet{m: make(map[string]struct{})}
}

func (ps *ProcessedSet) Has(k string) bool {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	_, ok := ps.m[k]
	return ok
}

func (ps *ProcessedSet) Add(k string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	ps.m[k] = struct{}{}
}

func (ps *ProcessedSet) Remove(k string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	delete(ps.m, k)
}

func chooseSeeds(network string) ([]string, int) {
	if strings.ToLower(network) == "mainnet" {
		return mainnetDNSSeeds, 22556
	}
	// Simplified testnet support.
	return []string{"seed.testnet.dogecoin.org"}, 44556
}

func shufflePeerIPs(workerID int, ips []string) []string {
	if len(ips) <= 1 {
		return ips
	}
	out := make([]string, len(ips))
	copy(out, ips)
	rnd := mrand.New(mrand.NewSource(time.Now().UnixNano() + int64(workerID)*1_000_003))
	rnd.Shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// mempoolSniffer runs several parallel P2P sessions (like the arcade pup rotating seeds/peers)
// so inv/getdata gossip reaches MemeTracker faster and more reliably than a single connection.
// Closing stop unblocks workers between peers (active sessions may finish naturally up to SESSION_SEC).
func mempoolSniffer(store *Store, network string, p2pHost string, p2pPort int, p2pLog int, mcol *MetricsCollector, processed *ProcessedSet, parallel int, stop <-chan struct{}) {
	if parallel < 1 {
		parallel = 1
	}
	if parallel > 8 {
		parallel = 8
	}
	for w := 0; w < parallel; w++ {
		go mempoolP2PWorker(w, parallel, store, network, p2pHost, p2pPort, p2pLog, mcol, processed, stop)
	}
}

func sleepOrStop(d time.Duration, stop <-chan struct{}) bool {
	select {
	case <-stop:
		return true
	case <-time.After(d):
		return false
	}
}

func mempoolP2PWorker(workerID, parallel int, store *Store, network, p2pHost string, p2pPort, p2pLog int, mcol *MetricsCollector, processed *ProcessedSet, stop <-chan struct{}) {
	seeds, defaultPort := chooseSeeds(network)
	if p2pPort == 0 {
		p2pPort = defaultPort
	}
	if p2pHost != "" {
		seeds = []string{p2pHost}
	}
	logf := func(format string, args ...any) {
		if p2pLog <= 0 {
			return
		}
		log.Printf("[MTR-P2P] [w%d] "+format, append([]any{workerID}, args...)...)
	}
	logv := func(format string, args ...any) {
		if p2pLog < 2 {
			return
		}
		log.Printf("[MTR-P2P] [w%d:v] "+format, append([]any{workerID}, args...)...)
	}

	for round := 0; ; round++ {
		select {
		case <-stop:
			return
		default:
		}
		seedHost := seeds[(round*parallel+workerID)%len(seeds)]
		ips, err := net.LookupHost(seedHost)
		if err != nil || len(ips) == 0 {
			log.Printf("[MTR-P2P] [w%d] DNS resolve failed seed=%s:%d err=%v", workerID, seedHost, p2pPort, err)
			if sleepOrStop(3*time.Second, stop) {
				return
			}
			continue
		}
		if len(ips) > 12 {
			ips = ips[:12]
		}

		// Stride peers by worker so parallel goroutines do not all dial the same IP at once
		// (peers often drop duplicate inbound links from the same host).
		shuffled := shufflePeerIPs(workerID, ips)
		for idx := workerID; idx < len(shuffled); idx += parallel {
			select {
			case <-stop:
				return
			default:
			}
			peer := shuffled[idx]
			if peer == "" {
				continue
			}
			logf("connecting TCP %s:%d …", peer, p2pPort)

			conn, err := net.DialTimeout("tcp", net.JoinHostPort(peer, strconv.Itoa(p2pPort)), 8*time.Second)
			if err != nil {
				logf("connect failed: %v", err)
				mcol.SetPeerSession(workerID, "", false)
				continue
			}
			// Do not SetDeadline on the whole conn: sessions run up to SESSION_SEC; a short
			// absolute deadline caused peers to be abandoned and payments missed.
			_ = conn.SetDeadline(time.Time{})

			stateLastPeer := net.JoinHostPort(peer, strconv.Itoa(p2pPort))
			mcol.SetPeerSession(workerID, stateLastPeer, true)
			memetrackerP2PSession(conn, stateLastPeer, store, processed, mcol, p2pPort, logf, logv)
			mcol.SetPeerSession(workerID, stateLastPeer, false)
			_ = conn.Close()
		}

		if sleepOrStop(5*time.Second, stop) {
			return
		}
	}
}

func memetrackerP2PSession(conn net.Conn, stateLastPeer string, store *Store, processed *ProcessedSet, mcol *MetricsCollector, p2pPort int, logf, logv func(string, ...any)) {
	gotVerack := false
	mempoolSent := false
	lastMempoolResync := time.Time{}
	start := time.Now()
	var sessionExit error // set on non-timeout read/write failure or bad checksum

	logf("connected peer=%s handshake start (Dogecoin P2P magic_u32le=0x%x wire_magic_4b_le_hex=%s)", stateLastPeer, MAGIC, dogeMagicWireHexLE())
	verOut := buildVersionPayload(p2pPort)
	verMsg := buildMessage("version", verOut)
	logf("sending VERSION cmd payload_len=%d total_msg_bytes=%d — %s", len(verOut), len(verMsg), summarizeOutgoingVersionPayload(verOut, p2pPort))
	logv("outgoing version raw payload hex (first 128b)=%s", hexSnippet(verOut, 128))
	logv("message framing: all header fields little-endian except command is 12-byte ASCII null-padded; payload length u32le; checksum=first4bytes(sha256(sha256(payload)))")

	_ = conn.SetDeadline(time.Time{})
	_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
	_, werr := conn.Write(verMsg)
	_ = conn.SetWriteDeadline(time.Time{})
	if werr != nil {
		logf("write version failed: %v", werr)
		return
	}
	logv("wrote version message ok")

readLoop:
	// Compare to time.Duration seconds — bare SESSION_SEC (300) is converted to 300ns, not 300s.
	for time.Since(start) < time.Duration(SESSION_SEC)*time.Second {
		_ = conn.SetReadDeadline(time.Now().Add(P2P_READ_IDLE_SEC * time.Second))
		header, err := readExact(conn, 24)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				_ = conn.SetReadDeadline(time.Time{})
				logv("read deadline (%ds idle) no header yet — gotVerack=%v mempoolSent=%v", P2P_READ_IDLE_SEC, gotVerack, mempoolSent)
				if gotVerack && mempoolSent {
					if store.takeMempoolKick() {
						_, _ = conn.Write(buildMessage("mempool", nil))
						lastMempoolResync = time.Now()
						logf("mempool (after /track/ or resync request)")
					}
					nw := store.watcherCount()
					interval := MEMPOOL_RESYNC_SEC
					if nw > 0 {
						interval = MEMPOOL_WATCHER_SEC
					}
					if time.Since(lastMempoolResync) >= time.Duration(interval)*time.Second {
						_, _ = conn.Write(buildMessage("mempool", nil))
						lastMempoolResync = time.Now()
						logf("mempool periodic watchers=%d interval=%ds", nw, interval)
					}
				}
				continue
			}
			sessionExit = err
			logf("read message header failed peer=%s err=%v (gotVerack=%v mempoolSent=%v)", stateLastPeer, err, gotVerack, mempoolSent)
			logv("header read fatal: %#v", err)
			break readLoop
		}
		_ = conn.SetReadDeadline(time.Time{})

		magic := binary.LittleEndian.Uint32(header[0:4])
		cmdRaw := header[4:16]
		cmd := strings.TrimRight(string(cmdRaw), "\x00")
		size := binary.LittleEndian.Uint32(header[16:20])
		chkWire := header[20:24]

		logv("recv header24: magic_u32le=0x%x cmd12=%q payload_len_u32le=%d checksum4=%x cmd_raw_bytes=%q",
			magic, cmd, size, chkWire, hex.EncodeToString(cmdRaw))

		if magic != uint32(MAGIC) {
			logf("wrong magic peer=%s got_u32le=0x%x want_u32le=0x%x (LE bytes got_hex=%s want_hex=%s) — skipping 24b, stream may be misaligned (TLS/wrong chain?)",
				stateLastPeer, magic, MAGIC, hex.EncodeToString(header[0:4]), dogeMagicWireHexLE())
			logv("full_header24_hex=%s", hex.EncodeToString(header))
			continue
		}

		if size > 32*1024*1024 {
			logf("reject absurd payload_len peer=%s cmd=%s size=%d", stateLastPeer, cmd, size)
			sessionExit = fmt.Errorf("absurd payload size %d", size)
			break readLoop
		}

		payload := []byte{}
		if size > 0 {
			logv("reading payload %d bytes for cmd=%s", size, cmd)
			payload, err = readExact(conn, int(size))
			if err != nil {
				sessionExit = err
				logf("read payload failed peer=%s cmd=%s want=%d err=%v", stateLastPeer, cmd, size, err)
				logv("payload partial hex=%s", hexSnippet(payload, 64))
				break readLoop
			}
		}

		hash2 := sha256d(payload)
		wantSum := hash2[:4]
		if !bytes.Equal(chkWire, wantSum) {
			sessionExit = fmt.Errorf("checksum mismatch")
			logf("P2P checksum mismatch peer=%s cmd=%s payload_len=%d wire_checksum4=%x computed_double_sha256_4=%x — closing",
				stateLastPeer, cmd, len(payload), chkWire, wantSum)
			logv("payload_head_hex=%s", hexSnippet(payload, 256))
			break readLoop
		}
		logv("checksum ok cmd=%s payload_len=%d", cmd, len(payload))

		switch cmd {
		case "version":
			logf("recv VERSION from peer=%s — %s", stateLastPeer, summarizePeerVersionPayload(payload))
			logv("peer version payload head hex=%s", hexSnippet(payload, 256))
			ack := buildMessage("verack", nil)
			_, werr := conn.Write(ack)
			if werr != nil {
				sessionExit = werr
				logf("write verack failed: %v", werr)
				break readLoop
			}
			logf("sent VERACK (%d bytes) awaiting peer VERACK", len(ack))
			logv("verack message hex=%s", hex.EncodeToString(ack))
		case "verack":
			gotVerack = true
			logf("recv VERACK from peer=%s — handshake version negotiation complete (little-endian fields were already validated on VERSION)", stateLastPeer)
			if !mempoolSent {
				mem := buildMessage("mempool", nil)
				_, werr := conn.Write(mem)
				if werr != nil {
					sessionExit = werr
					logf("write mempool failed: %v", werr)
					break readLoop
				}
				mempoolSent = true
				lastMempoolResync = time.Now()
				logf("sent MEMPOOL request to peer=%s (%d bytes) — expecting inv/tx for relayed txs", stateLastPeer, len(mem))
				logv("mempool msg hex=%s", hex.EncodeToString(mem))
			}
		case "ping":
			logv("recv PING payload_len=%d", len(payload))
			pong := buildMessage("pong", payload)
			_, werr := conn.Write(pong)
			if werr != nil {
				sessionExit = werr
				logf("write pong failed: %v", werr)
				break readLoop
			}
			logv("sent PONG %d bytes", len(pong))
		case "tx":
			txidEarly := txidHex(payload)
			mcol.observeMempoolTxid(txidEarly)
			logv("recv TX raw len=%d txid_le=%s", len(payload), txidEarly)

			store.mu.RLock()
			hasWatchers := len(store.watchByHash) > 0
			store.mu.RUnlock()
			if !hasWatchers {
				logv("tx %s ignored (no watched addresses)", txidEarly)
				continue
			}

			outs, _, err := parseTxOutputs(payload)
			if err != nil {
				log.Printf("[MTR-P2P] parse tx %s: %v", txidEarly, err)
				continue
			}
			txid := txidHex(payload)
			wtxid := wtxidHex(payload)

			if processed.Has(txid) || processed.Has(wtxid) {
				continue
			}

			amtByHash := make(map[string]int64)
			store.mu.RLock()
			for _, o := range outs {
				h160, ok := scriptPubKeyHash160(o.script)
				if !ok {
					continue
				}
				hashHex := hex.EncodeToString(h160)
				if _, watching := store.watchByHash[hashHex]; watching {
					amtByHash[hashHex] += o.valueSats
				}
			}
			store.mu.RUnlock()

			if len(amtByHash) == 0 {
				continue
			}

			dt := time.Now().UTC()
			matchedAny := false
			for hashHex, sats := range amtByHash {
				if sats <= 0 {
					continue
				}
				amountDoge := float64(sats) / 1e8
				if store.AddTx(hashHex, txid, dt, amountDoge) {
					matchedAny = true
					addr, cbURL, ok := store.CallbackTarget(hashHex)
					if ok && cbURL != "" {
						go notifyCallback(cbURL, PaymentCallbackPayload{
							Address:    addr,
							Txid:       txid,
							AmountDoge: amountDoge,
							Datetime:   dt.Format(time.RFC3339),
						})
					}
				}
			}
			if matchedAny {
				processed.Add(txid)
				processed.Add(wtxid)
				logf("tx matched watched address(es) peer=%s txid=%s", stateLastPeer, txid)
			} else {
				logv("tx %s had watched outputs but nothing new stored (e.g. duplicate)", txid)
			}

		case "inv":
			if !gotVerack || !mempoolSent {
				logv("INV dropped (handshake incomplete) gotVerack=%v mempoolSent=%v", gotVerack, mempoolSent)
				continue
			}
			if len(payload) == 0 {
				logv("INV empty payload")
				continue
			}
			invs, err := parseInvPayload(payload)
			if err != nil {
				logf("INV parse error peer=%s: %v", stateLastPeer, err)
				logv("inv payload head hex=%s", hexSnippet(payload, 128))
				continue
			}
			txLike := 0
			for _, it := range invs {
				if invTypeIsTx(it.invType) {
					txLike++
				}
			}
			logf("recv INV peer=%s entries=%d tx_like=%d (inv vector: type u32le + hash 32 bytes wire order per entry; hash is internal byte order)",
				stateLastPeer, len(invs), txLike)
			logv("inv payload_len=%d parse_ok entries=%d", len(payload), len(invs))

			for _, it := range invs {
				if invTypeIsTx(it.invType) {
					mcol.observeMempoolTxid(reverseBytesToHex(it.hash))
				}
			}

			store.mu.RLock()
			hasWatchers := len(store.watchByHash) > 0
			store.mu.RUnlock()
			if !hasWatchers {
				continue
			}

			// Same strategy as arcade/server.py: getdata all new tx invs (dedupe by inv type+hash), not only when already seen as txid.
			fetch := make([]invItem, 0, MAX_TX_FETCH_INV)
			invSeen := make(map[string]struct{})
			for _, it := range invs {
				if !invTypeIsTx(it.invType) {
					continue
				}
				invKey := fmt.Sprintf("%x:%x", it.invType, it.hash)
				if _, ok := invSeen[invKey]; ok {
					continue
				}
				invSeen[invKey] = struct{}{}
				txHashHex := reverseBytesToHex(it.hash)
				if processed.Has(txHashHex) {
					continue
				}
				fetch = append(fetch, it)
				if len(fetch) >= MAX_TX_FETCH_INV {
					break
				}
			}

			getdataFail := false
			for i := 0; i < len(fetch); i += GETDATA_BATCH {
				j := i + GETDATA_BATCH
				if j > len(fetch) {
					j = len(fetch)
				}
				pl := buildGetdataPayload(fetch[i:j])
				gd := buildMessage("getdata", pl)
				if _, werr := conn.Write(gd); werr != nil {
					sessionExit = werr
					logf("write getdata failed peer=%s: %v", stateLastPeer, werr)
					getdataFail = true
					break
				}
				logv("sent GETDATA batch [%d:%d) n=%d msg_bytes=%d (tx hashes in getdata use same wire order as inv)", i, j, j-i, len(gd))
			}
			if getdataFail {
				break readLoop
			}
			if len(fetch) > 0 {
				logf("getdata dispatched total_tx_inv=%d peer=%s", len(fetch), stateLastPeer)
			}

		default:
			logf("recv cmd=%q peer=%s payload_len=%d (magic+checksum validated; not handled in switch)", cmd, stateLastPeer, len(payload))
			logv("unhandled payload head hex=%s", hexSnippet(payload, 128))
		}

		if gotVerack && mempoolSent {
			nw := store.watcherCount()
			interval := MEMPOOL_RESYNC_SEC
			if nw > 0 {
				interval = MEMPOOL_WATCHER_SEC
			}
			if time.Since(lastMempoolResync) >= time.Duration(interval)*time.Second {
				_, werr := conn.Write(buildMessage("mempool", nil))
				if werr != nil {
					sessionExit = werr
					logf("periodic mempool write failed: %v", werr)
					break readLoop
				}
				lastMempoolResync = time.Now()
				logv("periodic MEMPOOL resent interval=%ds watchers=%d", interval, nw)
			}
		}
	}

	_ = conn.SetReadDeadline(time.Time{})
	if sessionExit != nil {
		logf("session end peer=%s gotVerack=%v mempoolSent=%v duration=%s err=%v",
			stateLastPeer, gotVerack, mempoolSent, time.Since(start).Truncate(time.Millisecond), sessionExit)
	} else {
		logf("session end peer=%s gotVerack=%v mempoolSent=%v duration=%s (session cap %ds, no wire error)",
			stateLastPeer, gotVerack, mempoolSent, time.Since(start).Truncate(time.Millisecond), SESSION_SEC)
	}
}

func reverseBytesToHex(b []byte) string {
	// Used to convert inventory hashes to the same endianness as txidHex() returns.
	r := make([]byte, len(b))
	for i := 0; i < len(b); i++ {
		r[i] = b[len(b)-1-i]
	}
	return hex.EncodeToString(r)
}

// ------- HTTP API -------

func deriveCallbackURL(r *http.Request, address string) string {
	// Preferred explicit callback from caller.
	qCB := strings.TrimSpace(r.URL.Query().Get("callback"))
	if qCB != "" {
		if u, err := url.ParseRequestURI(qCB); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
			return qCB
		}
	}
	hCB := strings.TrimSpace(r.Header.Get("X-Callback-Url"))
	if hCB != "" {
		if u, err := url.ParseRequestURI(hCB); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
			return hCB
		}
	}

	// Fallback: infer from requester IP and configurable callback port.
	host := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
	if host != "" {
		if idx := strings.Index(host, ","); idx >= 0 {
			host = strings.TrimSpace(host[:idx])
		}
	}
	if host == "" {
		h, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
		if err == nil {
			host = strings.TrimSpace(h)
		}
	}
	if host == "" {
		return ""
	}
	scheme := strings.TrimSpace(envString("MTR_CALLBACK_SCHEME", "http"))
	if scheme != "https" {
		scheme = "http"
	}
	port := envInt("MTR_CALLBACK_PORT", 10001)
	return fmt.Sprintf("%s://%s/%s/", scheme, net.JoinHostPort(host, strconv.Itoa(port)), url.PathEscape(address))
}

func defaultStorageDir() string {
	if runtime.GOOS == "windows" {
		d, err := os.UserConfigDir()
		if err == nil && d != "" {
			return filepath.Join(d, "MemeTracker", "data")
		}
		return filepath.Join(".", "memetracker-data")
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return filepath.Join(h, ".memetracker", "data")
	}
	return filepath.Join(".", "memetracker-data")
}

type diskSettings struct {
	ListLimit     int `json:"list_limit"`
	RetentionDays int `json:"retention_days"`
}

func readDiskSettings(path string) (diskSettings, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return diskSettings{}, false
	}
	var s diskSettings
	if json.Unmarshal(b, &s) != nil {
		return diskSettings{}, false
	}
	return s, true
}

func writeDiskSettings(path string, s diskSettings) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// MemeTrackerConfig is the full on-disk configuration (memetracker_config.json).
// P2P and retention jobs start only after this file validates as complete (on boot)
// or after POST /api/start.
type MemeTrackerConfig struct {
	HTTPPort       int      `json:"http_port"`
	HTTPBind       string   `json:"http_bind"`
	Network        string   `json:"network"`
	StorageDir     string   `json:"storage_dir"`
	ListLimit      int      `json:"list_limit"`
	RetentionDays  int      `json:"retention_days"`
	P2PHost        string   `json:"p2p_host"`
	P2PPort        int      `json:"p2p_port"`
	P2PParallel    int      `json:"p2p_parallel"`
	P2PLog         int      `json:"p2p_log"`
	APIAllowedIPs  []string `json:"api_allowed_ips,omitempty"` // empty or omitted = allow all IPs on /api/* and /track/*
}

func (c *MemeTrackerConfig) ApplyDefaults() {
	if c.HTTPPort == 0 {
		c.HTTPPort = 33555
	}
	c.HTTPBind = strings.TrimSpace(c.HTTPBind)
	if c.HTTPBind == "" {
		c.HTTPBind = "0.0.0.0"
	}
	c.Network = strings.TrimSpace(c.Network)
	if c.Network == "" {
		c.Network = "mainnet"
	}
	if c.ListLimit == 0 {
		c.ListLimit = 10
	}
	if c.RetentionDays == 0 {
		c.RetentionDays = 7
	}
	if c.P2PPort == 0 {
		c.P2PPort = 22556
	}
	if c.P2PParallel == 0 {
		c.P2PParallel = 3
	}
	if c.P2PLog < 0 {
		c.P2PLog = 0
	}
	if c.P2PLog > 2 {
		c.P2PLog = 2
	}
}

func (c *MemeTrackerConfig) IsComplete() bool {
	c.ApplyDefaults()
	if c.HTTPPort < 1 || c.HTTPPort > 65535 {
		return false
	}
	if strings.TrimSpace(c.HTTPBind) == "" {
		return false
	}
	n := strings.ToLower(strings.TrimSpace(c.Network))
	if n != "mainnet" && n != "testnet" {
		return false
	}
	if c.ListLimit < 1 || c.RetentionDays < 1 {
		return false
	}
	if c.P2PPort < 1 || c.P2PPort > 65535 {
		return false
	}
	if c.P2PParallel < 1 || c.P2PParallel > 8 {
		return false
	}
	return true
}

func normalizeAPIAllowedIPs(in []string) []string {
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// clientIPForAPI returns the client address for access control.
// Set MTR_TRUST_XFF=1 to use the first hop in X-Forwarded-For (only behind a trusted reverse proxy).
func clientIPForAPI(r *http.Request) string {
	if strings.TrimSpace(os.Getenv("MTR_TRUST_XFF")) == "1" {
		xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For"))
		if xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err != nil {
		return strings.TrimSpace(r.RemoteAddr)
	}
	return host
}

func ipAllowedForAPI(host string, rules []string) bool {
	rules = normalizeAPIAllowedIPs(rules)
	if len(rules) == 0 {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, rule := range rules {
		rule = strings.TrimSpace(rule)
		if rule == "" {
			continue
		}
		if strings.Contains(rule, "/") {
			_, cidr, err := net.ParseCIDR(rule)
			if err != nil {
				continue
			}
			if cidr.Contains(ip) {
				return true
			}
			continue
		}
		if rIP := net.ParseIP(rule); rIP != nil && rIP.Equal(ip) {
			return true
		}
	}
	return false
}

func apiPathNeedsIPCheck(path string) bool {
	if strings.HasPrefix(path, "/api/") {
		return true
	}
	if strings.HasPrefix(path, "/track/") {
		return true
	}
	return false
}

func apiAccessMiddleware(app *appState, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !apiPathNeedsIPCheck(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		cfg := app.snapshotCfg()
		cl := clientIPForAPI(r)
		if cl == "" {
			cl = "unknown"
		}
		if !ipAllowedForAPI(cl, cfg.APIAllowedIPs) {
			writeJSONError(w, http.StatusForbidden, fmt.Sprintf("API access denied for IP %s; add this address or your subnet (CIDR) to api_allowed_ips in memetracker_config.json or the API access screen, or clear the list to allow all", cl))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeMemeTrackerConfigFile(path string, c *MemeTrackerConfig) error {
	cp := *c
	cp.ApplyDefaults()
	b, err := json.MarshalIndent(&cp, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

type appState struct {
	mu           sync.RWMutex
	cfg          MemeTrackerConfig
	configPath   string
	dataDir      string
	store        *Store
	mcol         *MetricsCollector
	processed    *ProcessedSet
	settingsPath string
	httpPort     int
	httpBind     string
	p2pMu        sync.Mutex
	p2pStarted   bool
	p2pStopCh    chan struct{} // closed to signal P2P workers + metrics loop to exit
}

func runMetricsLoop(store *Store, col *MetricsCollector, stop <-chan struct{}) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			submitDogeboxMetrics(store, col)
		}
	}
}

func (a *appState) snapshotCfg() MemeTrackerConfig {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cfg
}

func (a *appState) setCfg(c MemeTrackerConfig) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfg = c
}

func (a *appState) isP2PRunning() bool {
	a.p2pMu.Lock()
	defer a.p2pMu.Unlock()
	return a.p2pStarted
}

func (a *appState) startP2P() {
	a.p2pMu.Lock()
	if a.p2pStarted {
		a.p2pMu.Unlock()
		return
	}
	stopCh := make(chan struct{})
	a.p2pStopCh = stopCh
	a.p2pStarted = true
	a.p2pMu.Unlock()

	cfg := a.snapshotCfg()
	network := strings.ToLower(strings.TrimSpace(cfg.Network))
	host := strings.TrimSpace(cfg.P2PHost)
	go mempoolSniffer(a.store, network, host, cfg.P2PPort, cfg.P2PLog, a.mcol, a.processed, cfg.P2PParallel, stopCh)
	go runMetricsLoop(a.store, a.mcol, stopCh)
	log.Printf("[MTR] P2P mempool watcher started (network=%s, p2p_parallel=%d)", network, cfg.P2PParallel)
}

func (a *appState) stopP2P() {
	a.p2pMu.Lock()
	if !a.p2pStarted || a.p2pStopCh == nil {
		a.p2pMu.Unlock()
		return
	}
	ch := a.p2pStopCh
	a.p2pStopCh = nil
	a.p2pStarted = false
	a.p2pMu.Unlock()
	close(ch)
	log.Printf("[MTR] P2P mempool watcher stop requested (workers exit between peer sessions)")
}

func openBrowser(urlStr string) {
	if strings.TrimSpace(os.Getenv("MTR_NO_BROWSER")) != "" {
		return
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", urlStr)
	case "darwin":
		cmd = exec.Command("open", urlStr)
	default:
		cmd = exec.Command("xdg-open", urlStr)
	}
	cmd.Stdout = nil
	cmd.Stderr = nil
	_ = cmd.Start()
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b, err := staticFiles.ReadFile("static/index.html")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(b)
}

func serveLogo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b, err := staticFiles.ReadFile("static/logo.png")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func apiStatus(w http.ResponseWriter, r *http.Request, app *appState) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cfg := app.snapshotCfg()
	ll, rd := app.store.Limits()
	peers, nConn := app.mcol.snapshotPeers()
	peerOut := make([]map[string]any, 0, len(peers))
	for _, p := range peers {
		peerOut = append(peerOut, map[string]any{
			"worker_id": p.WorkerID,
			"address":   p.Address,
			"connected": p.Connected,
			"updated":   p.Updated.UTC().Format(time.RFC3339),
		})
	}
	allowCopy := cfg.APIAllowedIPs
	if allowCopy == nil {
		allowCopy = []string{}
	}
	fc := map[string]any{
		"http_port":        cfg.HTTPPort,
		"http_bind":        cfg.HTTPBind,
		"network":          cfg.Network,
		"storage_dir":      app.dataDir,
		"list_limit":       cfg.ListLimit,
		"retention_days":   cfg.RetentionDays,
		"p2p_host":         cfg.P2PHost,
		"p2p_port":         cfg.P2PPort,
		"p2p_parallel":     cfg.P2PParallel,
		"p2p_log":          cfg.P2PLog,
		"api_allowed_ips":  allowCopy,
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"p2p_running":               app.isP2PRunning(),
		"memetracker_config_path":   app.configPath,
		"watched_addresses":         app.store.watcherCount(),
		"stored_transaction_rows":   app.store.StoredTransactionRows(),
		"mempool_tx_count":          app.mcol.snapshot(),
		"peers_connected_count":     nConn,
		"peers":                     peerOut,
		"addresses":                 app.store.ListAddressSnapshots(),
		"transactions":              app.store.FlattenTransactions(),
		"full_config":               fc,
		"config": map[string]any{
			"network":             strings.ToLower(cfg.Network),
			"mtr_http_bind":       app.httpBind,
			"mtr_http_port":       app.httpPort,
			"mtr_storage_dir":     app.dataDir,
			"p2p_host":            cfg.P2PHost,
			"p2p_port":            cfg.P2PPort,
			"p2p_parallel":        cfg.P2PParallel,
			"p2p_log":             cfg.P2PLog,
			"list_limit":          ll,
			"retention_days":      rd,
			"settings_file_note":  "list_limit and retention_days sync to settings.json from the Configuration tab when saved",
		},
	})
}

func apiGetConfig(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ll, rd := store.Limits()
	writeJSON(w, http.StatusOK, map[string]any{"list_limit": ll, "retention_days": rd})
}

func apiPostConfig(w http.ResponseWriter, r *http.Request, app *appState) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		ListLimit     int `json:"list_limit"`
		RetentionDays int `json:"retention_days"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	if body.ListLimit < 1 || body.RetentionDays < 1 {
		writeJSONError(w, http.StatusBadRequest, "list_limit and retention_days must be >= 1")
		return
	}
	app.store.SetLimits(body.ListLimit, body.RetentionDays)
	app.mu.Lock()
	app.cfg.ListLimit = body.ListLimit
	app.cfg.RetentionDays = body.RetentionDays
	app.mu.Unlock()
	if err := writeDiskSettings(app.settingsPath, diskSettings{ListLimit: body.ListLimit, RetentionDays: body.RetentionDays}); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func apiDeleteAddress(w http.ResponseWriter, r *http.Request, store *Store) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/addresses/")
	id = strings.TrimSpace(strings.Trim(id, "/"))
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing id")
		return
	}
	if !store.RemoveAddress(strings.ToLower(id)) {
		writeJSONError(w, http.StatusNotFound, "address not tracked")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func apiDeleteTransaction(w http.ResponseWriter, r *http.Request, store *Store, processed *ProcessedSet) {
	if r.Method != http.MethodDelete {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	txid := strings.TrimSpace(r.URL.Query().Get("txid"))
	hashHex := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("hash160_hex")))
	if txid == "" || hashHex == "" {
		writeJSONError(w, http.StatusBadRequest, "txid and hash160_hex required")
		return
	}
	if !store.RemoveTx(hashHex, txid) {
		writeJSONError(w, http.StatusNotFound, "transaction not found")
		return
	}
	processed.Remove(txid)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func apiPostStart(w http.ResponseWriter, r *http.Request, app *appState) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body MemeTrackerConfig
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	body.APIAllowedIPs = normalizeAPIAllowedIPs(body.APIAllowedIPs)
	body.ApplyDefaults()
	if !body.IsComplete() {
		writeJSONError(w, http.StatusBadRequest, "incomplete configuration: need valid network (mainnet/testnet), ports, list_limit, retention_days, p2p_parallel 1–8")
		return
	}
	newDataDir := filepath.Clean(strings.TrimSpace(body.StorageDir))
	if newDataDir == "" {
		newDataDir = app.dataDir
	}
	body.StorageDir = newDataDir
	if newDataDir != app.dataDir {
		if err := writeMemeTrackerConfigFile(app.configPath, &body); err != nil {
			writeJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":                true,
			"restart_required":  true,
			"message":           "storage_dir does not match the running data directory; restart MemeTracker to apply. Config file was saved.",
			"p2p_running":       false,
		})
		return
	}
	if err := writeMemeTrackerConfigFile(app.configPath, &body); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	app.setCfg(body)
	app.store.SetLimits(body.ListLimit, body.RetentionDays)
	if err := writeDiskSettings(app.settingsPath, diskSettings{ListLimit: body.ListLimit, RetentionDays: body.RetentionDays}); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	app.startP2P()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "p2p_running": true})
}

func apiPostStop(w http.ResponseWriter, r *http.Request, app *appState) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	app.stopP2P()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "p2p_running": false})
}

func apiPostAllowlist(w http.ResponseWriter, r *http.Request, app *appState) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var body struct {
		APIAllowedIPs []string `json:"api_allowed_ips"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	normalized := normalizeAPIAllowedIPs(body.APIAllowedIPs)
	app.mu.Lock()
	app.cfg.APIAllowedIPs = normalized
	cfgCopy := app.cfg
	app.mu.Unlock()
	if err := writeMemeTrackerConfigFile(app.configPath, &cfgCopy); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "api_allowed_ips": normalized})
}

func main() {
	log.SetOutput(os.Stderr)

	envStorage := strings.TrimSpace(envString("MTR_STORAGE_DIR", ""))
	if envStorage == "" {
		envStorage = defaultStorageDir()
	}
	configPath := strings.TrimSpace(envString("MTR_CONFIG_PATH", ""))
	if configPath == "" {
		configPath = filepath.Join(envStorage, "memetracker_config.json")
	}

	var fileCfg MemeTrackerConfig
	configFileRead := false
	if b, err := os.ReadFile(configPath); err == nil {
		if json.Unmarshal(b, &fileCfg) == nil {
			configFileRead = true
		}
	}
	fileCfg.ApplyDefaults()

	publicPort := envInt("MTR_HTTP_PORT", envInt("PUBLIC_PORT", 33555))
	bindIP := envString("MTR_HTTP_BIND", envString("DBX_PUP_IP", "0.0.0.0"))
	if configFileRead {
		if fileCfg.HTTPPort > 0 {
			publicPort = fileCfg.HTTPPort
		}
		if strings.TrimSpace(fileCfg.HTTPBind) != "" {
			bindIP = fileCfg.HTTPBind
		}
	}

	storageDir := envStorage
	if configFileRead && strings.TrimSpace(fileCfg.StorageDir) != "" {
		storageDir = filepath.Clean(fileCfg.StorageDir)
	}

	listLimit := envInt("MTR_LIST_LIMIT", envInt("LIST_LIMIT", 10))
	retentionDays := envInt("MTR_RETENTION_DAYS", envInt("RETENTION_DAYS", 7))
	network := strings.ToLower(envString("MTR_NETWORK", envString("NETWORK", "mainnet")))
	p2pHost := strings.TrimSpace(envString("MTR_P2P_HOST", envString("P2P_HOST", "")))
	p2pPort := envInt("MTR_P2P_PORT", envInt("P2P_PORT", 22556))
	p2pLog := envInt("MTR_P2P_LOG", envInt("P2P_LOG", 1))
	p2pParallel := envInt("MTR_P2P_PARALLEL", envInt("P2P_PARALLEL", 3))

	if configFileRead {
		if fileCfg.ListLimit > 0 {
			listLimit = fileCfg.ListLimit
		}
		if fileCfg.RetentionDays > 0 {
			retentionDays = fileCfg.RetentionDays
		}
		if strings.TrimSpace(fileCfg.Network) != "" {
			network = strings.ToLower(fileCfg.Network)
		}
		if fileCfg.P2PPort > 0 {
			p2pPort = fileCfg.P2PPort
		}
		p2pParallel = fileCfg.P2PParallel
		p2pLog = fileCfg.P2PLog
		if strings.TrimSpace(fileCfg.P2PHost) != "" {
			p2pHost = strings.TrimSpace(fileCfg.P2PHost)
		}
		fileCfg.ApplyDefaults()
	}

	settingsPath := filepath.Join(storageDir, "settings.json")
	if ds, ok := readDiskSettings(settingsPath); ok {
		if ds.ListLimit >= 1 {
			listLimit = ds.ListLimit
		}
		if ds.RetentionDays >= 1 {
			retentionDays = ds.RetentionDays
		}
	}

	store, err := NewStore(storageDir, listLimit, retentionDays)
	if err != nil {
		log.Fatalf("failed init store: %v", err)
	}

	go func() {
		t := time.NewTicker(1 * time.Minute)
		defer t.Stop()
		for now := range t.C {
			store.mu.Lock()
			store.purgeExpiredLocked(now.UTC())
			store.mu.Unlock()
		}
	}()

	mcol := NewMetricsCollector(50000)
	processed := NewProcessedSet()

	effectiveCfg := MemeTrackerConfig{
		HTTPPort:      publicPort,
		HTTPBind:      bindIP,
		Network:       network,
		StorageDir:    storageDir,
		ListLimit:     listLimit,
		RetentionDays: retentionDays,
		P2PHost:       p2pHost,
		P2PPort:       p2pPort,
		P2PParallel:   p2pParallel,
		P2PLog:        p2pLog,
	}
	effectiveCfg.ApplyDefaults()
	if configFileRead {
		effectiveCfg.APIAllowedIPs = normalizeAPIAllowedIPs(fileCfg.APIAllowedIPs)
	}

	diskComplete := false
	if configFileRead {
		var verify MemeTrackerConfig
		if b, err := os.ReadFile(configPath); err == nil {
			_ = json.Unmarshal(b, &verify)
			verify.ApplyDefaults()
			diskComplete = verify.IsComplete()
		}
	}
	autoStart := diskComplete && strings.TrimSpace(os.Getenv("MTR_NO_AUTOSTART")) == ""

	app := &appState{
		cfg:          effectiveCfg,
		configPath:   configPath,
		dataDir:      storageDir,
		store:        store,
		mcol:         mcol,
		processed:    processed,
		settingsPath: settingsPath,
		httpPort:     publicPort,
		httpBind:     bindIP,
	}
	if autoStart {
		app.startP2P()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/api/allowlist", func(w http.ResponseWriter, r *http.Request) {
		apiPostAllowlist(w, r, app)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		ll, rd := app.store.Limits()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":              true,
			"server_time_utc": time.Now().UTC().Format(time.RFC3339),
			"list_limit":      ll,
			"retention_days":  rd,
			"storage_dir":     app.dataDir,
			"p2p_running":     app.isP2PRunning(),
		})
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		apiStatus(w, r, app)
	})
	mux.HandleFunc("/api/start", func(w http.ResponseWriter, r *http.Request) {
		apiPostStart(w, r, app)
	})
	mux.HandleFunc("/api/stop", func(w http.ResponseWriter, r *http.Request) {
		apiPostStop(w, r, app)
	})
	mux.HandleFunc("/api/config", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			apiGetConfig(w, r, app.store)
		case http.MethodPost:
			apiPostConfig(w, r, app)
		default:
			writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	})
	mux.HandleFunc("/api/addresses/", func(w http.ResponseWriter, r *http.Request) {
		apiDeleteAddress(w, r, app.store)
	})
	mux.HandleFunc("/api/transactions", func(w http.ResponseWriter, r *http.Request) {
		apiDeleteTransaction(w, r, app.store, app.processed)
	})

	mux.HandleFunc("/track/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !app.isP2PRunning() {
			writeJSONError(w, http.StatusServiceUnavailable, "P2P watcher is not running: open the web UI, confirm settings, and click Start (or add a complete memetracker_config.json and restart)")
			return
		}
		addr := strings.TrimPrefix(r.URL.Path, "/track/")
		addr = strings.TrimSpace(addr)
		addr = strings.Trim(addr, "/")
		if addr == "" {
			http.Error(w, "missing address", http.StatusBadRequest)
			return
		}

		netw := strings.ToLower(app.snapshotCfg().Network)
		hash160, err := decodePayoutToHash160(addr, netw)
		if err != nil {
			http.Error(w, "invalid address: "+err.Error(), http.StatusBadRequest)
			return
		}

		callbackURL := deriveCallbackURL(r, addr)
		already, recents, appliedCallback, err := app.store.UpsertTracking(addr, hash160, callbackURL)
		if err != nil {
			http.Error(w, "storage error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		ll, rd := app.store.Limits()
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"address":             addr,
			"monitored":           true,
			"already_monitoring":  already,
			"callback_url":        appliedCallback,
			"retention_days":      rd,
			"stored_tx_limit":     ll,
			"transactions":        recents,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/logo.png", serveLogo)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		serveIndex(w, r)
	})

	handler := apiAccessMiddleware(app, mux)
	srv := &http.Server{
		Handler:      handler,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	addr := net.JoinHostPort(bindIP, strconv.Itoa(publicPort))
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	go func() {
		time.Sleep(300 * time.Millisecond)
		_, portStr, _ := net.SplitHostPort(ln.Addr().String())
		openBrowser("http://127.0.0.1:" + portStr + "/")
	}()

	ll, rd := store.Limits()
	log.Printf("[MTR] listening on %s (storage=%s, p2p_running=%v config=%s)", ln.Addr(), storageDir, app.isP2PRunning(), configPath)
	log.Printf("[MTR] effective listLimit=%d retentionDays=%d (network=%s)", ll, rd, network)
	log.Fatal(srv.Serve(ln))
}
