// MemeTracker - Dogecoin mempool watcher (open source, MIT License; see LICENSE).
//
// Copyright (c) Paulo Vidal Â· https://x.com/inevitable360 Â· Dogecoin Foundation Dev
//
// Priority 1: mempool watching (mempool / inv / getdata / tx / ping) must not fail.
// Priority 2: header tip tracking + rare tip-block scans as backup when a watched
// payment skips mempool relay and is mined immediately.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
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

	"golang.org/x/crypto/ripemd160"
)

const (
	ConfirmModeMsgBlock  = "msg_block"
	ConfirmModeNodeBloom = "node_bloom"
)

func normalizeConfirmMode(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case ConfirmModeNodeBloom, "bloom", "spv", "bip37":
		return ConfirmModeNodeBloom
	default:
		return ConfirmModeMsgBlock
	}
}

func confirmModeIsBloom(s string) bool {
	return normalizeConfirmMode(s) == ConfirmModeNodeBloom
}

// bloomPeerCache remembers peers that advertised NODE_BLOOM so workers can dial them first
// (same idea as bitcoinj PeerGroup.setRequiredServices(NODE_BLOOM) in dogecoin-wallet).
type bloomPeerCache struct {
	mu    sync.Mutex
	addrs []string
	max   int
}

func newBloomPeerCache() *bloomPeerCache {
	return &bloomPeerCache{max: 64}
}

func (c *bloomPeerCache) Note(addr string) {
	if c == nil {
		return
	}
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, a := range c.addrs {
		if a == addr {
			return
		}
	}
	c.addrs = append([]string{addr}, c.addrs...)
	if len(c.addrs) > c.max {
		c.addrs = c.addrs[:c.max]
	}
}

func (c *bloomPeerCache) Prefer(candidates []string) []string {
	if c == nil || len(candidates) == 0 {
		return candidates
	}
	c.mu.Lock()
	known := append([]string(nil), c.addrs...)
	c.mu.Unlock()
	if len(known) == 0 {
		return candidates
	}
	out := make([]string, 0, len(candidates))
	seen := make(map[string]struct{}, len(candidates))
	for _, a := range known {
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			host = a
		}
		for _, cand := range candidates {
			if cand == host || cand == a {
				if _, ok := seen[cand]; ok {
					continue
				}
				seen[cand] = struct{}{}
				out = append(out, cand)
			}
		}
	}
	for _, cand := range candidates {
		if _, ok := seen[cand]; ok {
			continue
		}
		out = append(out, cand)
	}
	return out
}

func (c *bloomPeerCache) Count() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.addrs)
}

const (
	magicMainnet       = uint32(0xC0C0C0C0) // pchMessageStart c0 c0 c0 c0
	magicLegacyTestnet = uint32(0xDCB7C1FC) // legacy testnet3: fc c1 b7 dc
	magicRebootTestnet = uint32(0xE1DCD4FD) // DogeGo/Core reboot testnet: fd d4 dc e1
	COMMAND_LEN        = 12
	MSG_WITNESS_FLAG   = 1 << 30
	MSG_TX             = 1 // inventory type for transactions (and MSG_TX|MSG_WITNESS_FLAG for segwit)
	NODE_NETWORK       = 1 << 0
	NODE_WITNESS       = 1 << 3
	// NODE_BLOOM is defined in bloom.go (BIP-111); used for SPV filtered-block confirms.
	GETDATA_BATCH          = 100
	MAX_TX_FETCH_INV       = 500 // per inv; mark requested so large mempool dumps progress past this window
	MAX_BROADCAST_TX_BYTES = 400000 // max raw signed tx accepted for /api/broadcast
	MEMPOOL_RESYNC_SEC     = 90
	MEMPOOL_WATCHER_SEC    = 3
	P2P_READ_IDLE_SEC      = 20
	SESSION_SEC            = 300
	MAX_CONFIRMATIONS      = 5 // UI/API display cap for confirmation depth
	MEMPOOL_UI_RECENT      = 20
	MEMPOOL_PAGE_DEFAULT   = 50
	MEMPOOL_PAGE_MAX       = 100
)

// activeP2PMagic is the wire magic for the configured network (set when P2P starts).
var activeP2PMagic atomic.Uint32

func currentMagic() uint32 {
	m := activeP2PMagic.Load()
	if m == 0 {
		return magicMainnet
	}
	return m
}

func setActiveP2PMagic(network string) {
	activeP2PMagic.Store(networkMagic(network))
}

func normalizeNetwork(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "main", "mainnet":
		return "mainnet"
	case "testnet", "test", "testnet3", "legacytestnet":
		return "testnet"
	case "reboot", "reboottestnet", "reboot-testnet", "reboot_testnet":
		return "reboottestnet"
	default:
		return strings.ToLower(strings.TrimSpace(s))
	}
}

func isValidNetwork(s string) bool {
	switch normalizeNetwork(s) {
	case "mainnet", "testnet", "reboottestnet":
		return true
	default:
		return false
	}
}

func networkMagic(network string) uint32 {
	switch normalizeNetwork(network) {
	case "reboottestnet":
		return magicRebootTestnet
	case "testnet":
		return magicLegacyTestnet
	default:
		return magicMainnet
	}
}

func networkDefaultPort(network string) int {
	switch normalizeNetwork(network) {
	case "reboottestnet", "testnet":
		return 44556
	default:
		return 22556
	}
}

//go:embed static/*
var staticFiles embed.FS

var mainnetP2PKHVersion = byte(0x1E)
var testnetP2PKHVersion = byte(0x71)      // legacy Dogecoin testnet3
var rebootTestnetP2PKHVersion = byte(0x41) // DogeGo/Core reboot testnet ("n"/"m"-style T-prefix in Core docs = 0x41)

// Same seed hostnames as memetracker/mainnet Dogecoin DNS.
var mainnetDNSSeeds = []string{
	"seed.dogecoin.org",
	"seed.dogecoin.net",
	"seed.multidoge.org",
	"seed2.multidoge.org",
	// seed.dogecoin.com omitted: often NXDOMAIN; remaining seeds match chainparams.
}

// Reboot testnet discovery (DogeGo): seed.dogego.org first, then Core fixed seeds via DNS when available.
var rebootTestnetDNSSeeds = []string{
	"seed.dogego.org",
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

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
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

func b58Encode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	zeros := 0
	for zeros < len(b) && b[zeros] == 0 {
		zeros++
	}
	x := new(big.Int).SetBytes(b)
	base := big.NewInt(58)
	mod := new(big.Int)
	var out []byte
	for x.Sign() > 0 {
		x.DivMod(x, base, mod)
		out = append(out, b58Alphabet[mod.Int64()])
	}
	for i := 0; i < zeros; i++ {
		out = append(out, '1')
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func b58checkEncode(ver byte, payload []byte) string {
	raw := make([]byte, 1+len(payload))
	raw[0] = ver
	copy(raw[1:], payload)
	sum := sha256d(raw)
	return b58Encode(append(raw, sum[:4]...))
}

func hash160(data []byte) []byte {
	h := sha256.Sum256(data)
	r := ripemd160.New()
	_, _ = r.Write(h[:])
	return r.Sum(nil)
}

func p2pkhVersionForNetwork(network string) byte {
	switch normalizeNetwork(network) {
	case "reboottestnet":
		return rebootTestnetP2PKHVersion
	case "testnet":
		return testnetP2PKHVersion
	default:
		return mainnetP2PKHVersion
	}
}

func encodeP2PKHAddress(h160 []byte, network string) string {
	if len(h160) != 20 {
		return ""
	}
	return b58checkEncode(p2pkhVersionForNetwork(network), h160)
}

func decodePayoutToHash160(address string, network string) ([]byte, error) {
	wantVer := p2pkhVersionForNetwork(network)
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
// (avoids uint64â†’int overflow that can make the offset negative and panic in readVarInt).
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

type txInputOutpoint struct {
	prevTxid string
	vout     uint32
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

func parseTxInputOutpoints(raw []byte) ([]txInputOutpoint, error) {
	if len(raw) < 8 {
		return nil, nil
	}
	off := 0
	if off+4 > len(raw) {
		return nil, errors.New("truncated_version")
	}
	off += 4
	if off+2 <= len(raw) && raw[off] == 0 && raw[off+1] == 1 {
		off += 2
	}
	nin, err := readVarInt(raw, &off)
	if err != nil {
		return nil, err
	}
	out := make([]txInputOutpoint, 0, int(nin))
	for i := 0; i < int(nin); i++ {
		if off+36 > len(raw) {
			return out, errors.New("truncated_txin")
		}
		prevLE := raw[off : off+32]
		rev := make([]byte, 32)
		for j := 0; j < 32; j++ {
			rev[j] = prevLE[31-j]
		}
		prevTxid := hex.EncodeToString(rev)
		vout := binary.LittleEndian.Uint32(raw[off+32 : off+36])
		out = append(out, txInputOutpoint{prevTxid: prevTxid, vout: vout})
		off += 36
		slen, err := readVarInt(raw, &off)
		if err != nil {
			return out, err
		}
		if !offsetAdd(&off, slen, len(raw)) {
			return out, errors.New("truncated_scriptSig")
		}
		if off+4 > len(raw) {
			return out, errors.New("truncated_sequence")
		}
		off += 4
	}
	return out, nil
}

func isLikelyPubkey(b []byte) bool {
	if len(b) == 33 && (b[0] == 0x02 || b[0] == 0x03) {
		return true
	}
	if len(b) == 65 && b[0] == 0x04 {
		return true
	}
	return false
}

// extractScriptPushes returns data pushes from a Bitcoin/Dogecoin script.
func extractScriptPushes(script []byte) [][]byte {
	var pushes [][]byte
	i := 0
	for i < len(script) {
		op := script[i]
		i++
		switch {
		case op == 0x00:
			continue
		case op >= 0x01 && op <= 0x4b:
			n := int(op)
			if i+n > len(script) {
				return pushes
			}
			pushes = append(pushes, script[i:i+n])
			i += n
		case op == 0x4c: // OP_PUSHDATA1
			if i >= len(script) {
				return pushes
			}
			n := int(script[i])
			i++
			if i+n > len(script) {
				return pushes
			}
			pushes = append(pushes, script[i:i+n])
			i += n
		case op == 0x4d: // OP_PUSHDATA2
			if i+2 > len(script) {
				return pushes
			}
			n := int(binary.LittleEndian.Uint16(script[i : i+2]))
			i += 2
			if i+n > len(script) {
				return pushes
			}
			pushes = append(pushes, script[i:i+n])
			i += n
		case op == 0x4e: // OP_PUSHDATA4
			if i+4 > len(script) {
				return pushes
			}
			n := int(binary.LittleEndian.Uint32(script[i : i+4]))
			i += 4
			if n < 0 || i+n > len(script) {
				return pushes
			}
			pushes = append(pushes, script[i:i+n])
			i += n
		default:
			// Non-push opcode; continue scanning (rare in scriptSig).
		}
	}
	return pushes
}

func isNullHash32(b []byte) bool {
	if len(b) != 32 {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// extractSenderAddresses derives P2PKH Dogecoin addresses from input scriptSig /
// witness pubkeys (HASH160). Works for classic P2PKH and P2WPKH spends when the
// pubkey is present in the witnessed transaction. Coinbase and exotic scripts
// may yield an empty result.
func extractSenderAddresses(raw []byte, network string) (primary string, all []string) {
	if len(raw) < 8 {
		return "", nil
	}
	off := 0
	if off+4 > len(raw) {
		return "", nil
	}
	off += 4
	isSegwit := false
	if off+2 <= len(raw) && raw[off] == 0 && raw[off+1] == 1 {
		isSegwit = true
		off += 2
	}
	nin, err := readVarInt(raw, &off)
	if err != nil || nin == 0 {
		return "", nil
	}
	type vinData struct {
		coinbase bool
		script   []byte
	}
	vins := make([]vinData, 0, int(nin))
	for i := 0; i < int(nin); i++ {
		if off+36 > len(raw) {
			return "", nil
		}
		prev := raw[off : off+32]
		off += 36
		slen, err := readVarInt(raw, &off)
		if err != nil {
			return "", nil
		}
		if !offsetFits(off, slen, len(raw)) {
			return "", nil
		}
		script := make([]byte, int(slen))
		copy(script, raw[off:off+int(slen)])
		off += int(slen)
		if off+4 > len(raw) {
			return "", nil
		}
		off += 4
		vins = append(vins, vinData{coinbase: isNullHash32(prev), script: script})
	}
	// Skip outputs.
	nout, err := readVarInt(raw, &off)
	if err != nil {
		return "", nil
	}
	for i := 0; i < int(nout); i++ {
		if off+8 > len(raw) {
			return "", nil
		}
		off += 8
		slen, err := readVarInt(raw, &off)
		if err != nil {
			return "", nil
		}
		if !offsetAdd(&off, slen, len(raw)) {
			return "", nil
		}
	}
	witnesses := make([][][]byte, int(nin))
	if isSegwit {
		for i := 0; i < int(nin); i++ {
			nstk, err := readVarInt(raw, &off)
			if err != nil {
				return "", nil
			}
			stack := make([][]byte, 0, int(nstk))
			for j := 0; j < int(nstk); j++ {
				elen, err := readVarInt(raw, &off)
				if err != nil {
					return "", nil
				}
				if !offsetFits(off, elen, len(raw)) {
					return "", nil
				}
				item := make([]byte, int(elen))
				copy(item, raw[off:off+int(elen)])
				off += int(elen)
				stack = append(stack, item)
			}
			witnesses[i] = stack
		}
	}

	seen := make(map[string]struct{})
	addPubkey := func(pk []byte) {
		if !isLikelyPubkey(pk) {
			return
		}
		addr := encodeP2PKHAddress(hash160(pk), network)
		if addr == "" {
			return
		}
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		all = append(all, addr)
	}

	for i, vin := range vins {
		if vin.coinbase {
			continue
		}
		for _, push := range extractScriptPushes(vin.script) {
			addPubkey(push)
		}
		for _, item := range witnesses[i] {
			addPubkey(item)
		}
	}
	if len(all) > 0 {
		primary = all[0]
	}
	return primary, all
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
	binary.LittleEndian.PutUint32(tmp, currentMagic())
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
	binary.LittleEndian.PutUint32(b[:], currentMagic())
	return hex.EncodeToString(b[:])
}

func hexSnippet(b []byte, max int) string {
	if len(b) <= max {
		return hex.EncodeToString(b)
	}
	return hex.EncodeToString(b[:max]) + fmt.Sprintf("â€¦(%d more bytes)", len(b)-max)
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
func parsePeerStartHeight(p []byte) int32 {
	if len(p) < 20 {
		return 0
	}
	off := 20 + 26 + 26
	if len(p) < off+8 {
		return 0
	}
	off += 8
	if off >= len(p) {
		return 0
	}
	off2 := off
	uaLen64, err := readVarInt(p, &off2)
	if err != nil || uaLen64 > 4096 || off2+int(uaLen64) > len(p) {
		return 0
	}
	off2 += int(uaLen64)
	if off2+4 > len(p) {
		return 0
	}
	return int32(binary.LittleEndian.Uint32(p[off2 : off2+4]))
}

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
	Txid           string   `json:"txid"`
	Vout           uint32   `json:"vout"`
	Utxo           string   `json:"utxo"` // txid:vout — spendable outpoint when the watcher holds the key
	Datetime       string   `json:"datetime"`
	AmountDoge     float64  `json:"amount_doge"`
	DoubleSpent    bool     `json:"double_spent"`
	Confirmed      bool     `json:"confirmed"`
	Confirmations  int      `json:"confirmations"` // 0..MAX_CONFIRMATIONS (headers/blocks since inclusion)
	BlockHeight    int64    `json:"block_height,omitempty"`
	FromAddress    string   `json:"from_address,omitempty"`    // payer P2PKH derived from input pubkey(s)
	FromAddresses  []string `json:"from_addresses,omitempty"` // all unique payer addresses when multi-input
}

func formatUtxo(txid string, vout uint32) string {
	if txid == "" {
		return ""
	}
	return txid + ":" + strconv.FormatUint(uint64(vout), 10)
}

func clampConfirmations(n int) int {
	if n < 0 {
		return 0
	}
	if n > MAX_CONFIRMATIONS {
		return MAX_CONFIRMATIONS
	}
	return n
}

func confirmationsFromHeights(blockHeight, tipHeight int64) int {
	if blockHeight < 0 {
		return 1 // seen in a block but height unknown
	}
	if tipHeight < 0 || tipHeight < blockHeight {
		return 1
	}
	return clampConfirmations(int(tipHeight - blockHeight + 1))
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
	network       string // mainnet | testnet — used to encode payer P2PKH addresses

	watchByHash map[string]*AddressData // hash160hex -> data

	// txIndex maps txid -> watched hash160 hexes that store that payment.
	// Makes confirmation O(relevant addresses) instead of scanning every watcher.
	txIndex map[string][]string

	// unconfirmedCount is the number of stored payment rows with Confirmed=false.
	unconfirmedCount int

	mempoolKick atomic.Bool // set after /track/ so P2P loop sends "mempool" again
	bloomKick   atomic.Bool // set when watched set changes so peers reload BIP-37 filter
}

func (s *Store) SetNetwork(network string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.network = strings.ToLower(strings.TrimSpace(network))
}

func (s *Store) Network() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.network == "" {
		return "mainnet"
	}
	return s.network
}

func (s *Store) kickMempoolResync() {
	s.mempoolKick.Store(true)
	s.bloomKick.Store(true)
}

func (s *Store) takeMempoolKick() bool {
	return s.mempoolKick.Swap(false)
}

func (s *Store) takeBloomKick() bool {
	return s.bloomKick.Swap(false)
}

func (s *Store) watcherCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.watchByHash)
}

// WatchedHash160Hexes returns all tracked hash160 hex strings (for BIP-37 bloom).
func (s *Store) WatchedHash160Hexes() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.watchByHash))
	for hx := range s.watchByHash {
		out = append(out, hx)
	}
	sort.Strings(out)
	return out
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
		txIndex:       make(map[string][]string),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	s.rebuildIndexesLocked()
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
			s.dropAddressIndexLocked(hashHex, ad)
			delete(s.watchByHash, hashHex)
			_ = os.Remove(s.fileForHash(hashHex))
		}
	}
}

func (s *Store) rebuildIndexesLocked() {
	s.txIndex = make(map[string][]string)
	s.unconfirmedCount = 0
	for hashHex, ad := range s.watchByHash {
		changed := false
		for i := range ad.Txs {
			tx := &ad.Txs[i]
			if tx.Txid == "" {
				continue
			}
			if tx.Utxo == "" {
				tx.Utxo = formatUtxo(tx.Txid, tx.Vout)
				changed = true
			}
			s.indexAddLocked(tx.Txid, hashHex)
			if !tx.Confirmed {
				s.unconfirmedCount++
			}
		}
		if changed {
			_ = s.persistAddressLocked(ad)
		}
	}
}

func (s *Store) indexAddLocked(txid, hashHex string) {
	if txid == "" || hashHex == "" {
		return
	}
	refs := s.txIndex[txid]
	for _, h := range refs {
		if h == hashHex {
			return
		}
	}
	s.txIndex[txid] = append(refs, hashHex)
}

func (s *Store) indexRemoveLocked(txid, hashHex string) {
	refs := s.txIndex[txid]
	if len(refs) == 0 {
		return
	}
	out := refs[:0]
	for _, h := range refs {
		if h != hashHex {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		delete(s.txIndex, txid)
		return
	}
	s.txIndex[txid] = out
}

func (s *Store) dropAddressIndexLocked(hashHex string, ad *AddressData) {
	if ad == nil {
		return
	}
	for _, tx := range ad.Txs {
		s.indexRemoveLocked(tx.Txid, hashHex)
		if !tx.Confirmed {
			s.unconfirmedCount--
		}
	}
	if s.unconfirmedCount < 0 {
		s.unconfirmedCount = 0
	}
}

func (s *Store) dropTxLocked(hashHex string, tx TxRecord) {
	s.indexRemoveLocked(tx.Txid, hashHex)
	if !tx.Confirmed {
		s.unconfirmedCount--
		if s.unconfirmedCount < 0 {
			s.unconfirmedCount = 0
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

func (s *Store) AddTx(hashHex string, txid string, vout uint32, dt time.Time, amountDoge float64, doubleSpent bool, fromAddress string, fromAddresses []string) (inserted bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ad, ok := s.watchByHash[hashHex]
	if !ok {
		return false
	}

	fromAddress = strings.TrimSpace(fromAddress)
	if fromAddresses != nil {
		fromAddresses = append([]string(nil), fromAddresses...)
	}

	// Dedupe by outpoint (txid:vout); one tx may create multiple UTXOs to the same address.
	for i := range ad.Txs {
		if ad.Txs[i].Txid == txid && ad.Txs[i].Vout == vout {
			changed := false
			if doubleSpent && !ad.Txs[i].DoubleSpent {
				ad.Txs[i].DoubleSpent = true
				changed = true
			}
			// Backfill payer when we re-see the raw tx (e.g. mempool then block).
			if fromAddress != "" && ad.Txs[i].FromAddress == "" {
				ad.Txs[i].FromAddress = fromAddress
				changed = true
			}
			if len(fromAddresses) > 0 && len(ad.Txs[i].FromAddresses) == 0 {
				ad.Txs[i].FromAddresses = fromAddresses
				changed = true
			}
			if changed {
				_ = s.persistAddressLocked(ad)
			}
			return false
		}
	}

	rec := TxRecord{
		Txid:          txid,
		Vout:          vout,
		Utxo:          formatUtxo(txid, vout),
		Datetime:      dt.UTC().Format(time.RFC3339),
		AmountDoge:    amountDoge,
		DoubleSpent:   doubleSpent,
		Confirmed:     false,
		Confirmations: 0,
		FromAddress:   fromAddress,
		FromAddresses: fromAddresses,
	}

	// Store newest first.
	ad.Txs = append([]TxRecord{rec}, ad.Txs...)
	s.indexAddLocked(txid, hashHex)
	s.unconfirmedCount++
	if len(ad.Txs) > s.listLimit {
		for _, dropped := range ad.Txs[s.listLimit:] {
			s.dropTxLocked(hashHex, dropped)
		}
		ad.Txs = ad.Txs[:s.listLimit]
	}
	_ = s.persistAddressLocked(ad)
	return true
}

// NoteTxConfirmed marks a stored payment as included in a block and sets
// confirmations from block height vs tip (capped at MAX_CONFIRMATIONS).
// Returns true when a row newly became confirmed (was unconfirmed before).
func (s *Store) NoteTxConfirmed(txid string, blockHeight, tipHeight int64) bool {
	if strings.TrimSpace(txid) == "" {
		return false
	}
	confs := confirmationsFromHeights(blockHeight, tipHeight)
	s.mu.Lock()
	defer s.mu.Unlock()
	refs := s.txIndex[txid]
	if len(refs) == 0 {
		return false
	}
	newlyConfirmed := false
	for _, hashHex := range refs {
		ad := s.watchByHash[hashHex]
		if ad == nil {
			continue
		}
		adChanged := false
		for i := range ad.Txs {
			if ad.Txs[i].Txid != txid {
				continue
			}
			tx := &ad.Txs[i]
			if !tx.Confirmed {
				tx.Confirmed = true
				newlyConfirmed = true
				adChanged = true
				s.unconfirmedCount--
				if s.unconfirmedCount < 0 {
					s.unconfirmedCount = 0
				}
			}
			if blockHeight >= 0 && (tx.BlockHeight <= 0 || tx.BlockHeight > blockHeight) {
				tx.BlockHeight = blockHeight
				adChanged = true
			}
			want := confs
			if tx.BlockHeight > 0 {
				want = confirmationsFromHeights(tx.BlockHeight, tipHeight)
			}
			if tx.Confirmations != want {
				tx.Confirmations = want
				adChanged = true
			}
		}
		if adChanged {
			_ = s.persistAddressLocked(ad)
		}
	}
	return newlyConfirmed
}

// MarkTxConfirmedManual marks a stored payment confirmed from the UI/API when the
// inclusion block is older than the catch-up window (e.g. stale mempool row).
func (s *Store) MarkTxConfirmedManual(hashHex, txid string, tipHeight int64) bool {
	hashHex = strings.ToLower(strings.TrimSpace(hashHex))
	txid = strings.TrimSpace(txid)
	if hashHex == "" || txid == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ad := s.watchByHash[hashHex]
	if ad == nil {
		return false
	}
	changed := false
	for i := range ad.Txs {
		if ad.Txs[i].Txid != txid {
			continue
		}
		tx := &ad.Txs[i]
		if !tx.Confirmed {
			tx.Confirmed = true
			s.unconfirmedCount--
			if s.unconfirmedCount < 0 {
				s.unconfirmedCount = 0
			}
			changed = true
		}
		want := MAX_CONFIRMATIONS
		if tx.BlockHeight > 0 && tipHeight >= 0 {
			want = confirmationsFromHeights(tx.BlockHeight, tipHeight)
		}
		if tx.Confirmations != want {
			tx.Confirmations = want
			changed = true
		}
	}
	if !changed {
		return false
	}
	_ = s.persistAddressLocked(ad)
	return true
}

func (s *Store) KnowsTxid(txid string) bool {
	if strings.TrimSpace(txid) == "" {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.txIndex[txid]
	return ok
}

// HasUnconfirmedTxs is true when any stored payment was never seen in a scanned block body.
func (s *Store) HasUnconfirmedTxs() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unconfirmedCount > 0
}

// RefreshConfirmations updates confirmation counts for already-confirmed txs as tip advances.
func (s *Store) RefreshConfirmations(tipHeight int64) {
	if tipHeight < 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ad := range s.watchByHash {
		adChanged := false
		for i := range ad.Txs {
			tx := &ad.Txs[i]
			if !tx.Confirmed || tx.BlockHeight <= 0 {
				continue
			}
			want := confirmationsFromHeights(tx.BlockHeight, tipHeight)
			if tx.Confirmations != want {
				tx.Confirmations = want
				adChanged = true
			}
		}
		if adChanged {
			_ = s.persistAddressLocked(ad)
		}
	}
}

func (s *Store) MarkTxDoubleSpent(txid string) bool {
	if strings.TrimSpace(txid) == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	refs := s.txIndex[txid]
	if len(refs) == 0 {
		return false
	}
	changed := false
	for _, hashHex := range refs {
		ad := s.watchByHash[hashHex]
		if ad == nil {
			continue
		}
		adChanged := false
		for i := range ad.Txs {
			if ad.Txs[i].Txid == txid && !ad.Txs[i].DoubleSpent {
				ad.Txs[i].DoubleSpent = true
				adChanged = true
				changed = true
			}
		}
		if adChanged {
			_ = s.persistAddressLocked(ad)
		}
	}
	return changed
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
	for hashHex, ad := range s.watchByHash {
		if len(ad.Txs) > s.listLimit {
			for _, dropped := range ad.Txs[s.listLimit:] {
				s.dropTxLocked(hashHex, dropped)
			}
			ad.Txs = ad.Txs[:s.listLimit]
			_ = s.persistAddressLocked(ad)
		}
	}
}

func (s *Store) RemoveAddress(hashHex string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	ad, ok := s.watchByHash[hashHex]
	if !ok {
		return false
	}
	s.dropAddressIndexLocked(hashHex, ad)
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
	removed := false
	for _, r := range ad.Txs {
		if r.Txid == txid {
			s.dropTxLocked(hashHex, r)
			removed = true
			continue
		}
		out = append(out, r)
	}
	if !removed {
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
			row := map[string]any{
				"address":       ad.Address,
				"hash160_hex":   ad.Hash160Hex,
				"txid":          tx.Txid,
				"vout":          tx.Vout,
				"utxo":          tx.Utxo,
				"datetime":      tx.Datetime,
				"amount_doge":   tx.AmountDoge,
				"double_spent":  tx.DoubleSpent,
				"confirmed":     tx.Confirmed,
				"confirmations": clampConfirmations(tx.Confirmations),
				"block_height":  tx.BlockHeight,
			}
			if tx.FromAddress != "" {
				row["from_address"] = tx.FromAddress
			}
			if len(tx.FromAddresses) > 0 {
				row["from_addresses"] = tx.FromAddresses
			}
			rows = append(rows, row)
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
					short = short[:8] + "â€¦" + short[len(short)-4:]
				}
				latestPayment = fmt.Sprintf("%s  %.8f DOGE  %s", short, tx.AmountDoge, tx.Datetime)
			}
		}
	}
	if latestPayment == "" {
		latestPayment = "n/a"
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
	mu             sync.RWMutex
	byWorker       map[int]peerSession // one logical session per P2P worker
	mempoolTxIDs   map[string]struct{}
	mempoolOrder   []string // newest first; used for recent + paginated listing
	maxMempoolIDs  int
	outpointToTxs  map[string]map[string]struct{}
	txToOutpoints  map[string][]string
	doubleSpentTx  map[string]bool
	recentTxBodies []string // newest last; raw TX messages received (not full mempool dump)
	maxRecentTx    int
}

func NewMetricsCollector(maxMempool int) *MetricsCollector {
	if maxMempool <= 0 {
		maxMempool = 50000
	}
	return &MetricsCollector{
		byWorker:       make(map[int]peerSession),
		mempoolTxIDs:   make(map[string]struct{}),
		mempoolOrder:   make([]string, 0, 1024),
		maxMempoolIDs:  maxMempool,
		outpointToTxs:  make(map[string]map[string]struct{}),
		txToOutpoints:  make(map[string][]string),
		doubleSpentTx:  make(map[string]bool),
		recentTxBodies: make([]string, 0, 40),
		maxRecentTx:    40,
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

// lockedConn serializes writes so P2P session traffic and /api/broadcast cannot interleave.
type lockedConn struct {
	net.Conn
	wmu sync.Mutex
}

func (c *lockedConn) Write(b []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return c.Conn.Write(b)
}

func (c *lockedConn) WriteDeadline(b []byte, d time.Duration) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_ = c.Conn.SetWriteDeadline(time.Now().Add(d))
	n, err := c.Conn.Write(b)
	_ = c.Conn.SetWriteDeadline(time.Time{})
	return n, err
}

// PeerHub tracks live P2P worker connections for outbound tx broadcast.
type PeerHub struct {
	mu    sync.RWMutex
	peers map[int]*lockedConn
	addrs map[int]string
}

func NewPeerHub() *PeerHub {
	return &PeerHub{
		peers: make(map[int]*lockedConn),
		addrs: make(map[int]string),
	}
}

func (h *PeerHub) Register(workerID int, addr string, lc *lockedConn) {
	if h == nil || lc == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.peers[workerID] = lc
	h.addrs[workerID] = addr
}

func (h *PeerHub) Unregister(workerID int, lc *lockedConn) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if cur, ok := h.peers[workerID]; ok && cur == lc {
		delete(h.peers, workerID)
		delete(h.addrs, workerID)
	}
}

func (h *PeerHub) ConnectedCount() int {
	if h == nil {
		return 0
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.peers)
}

type peerBroadcastResult struct {
	WorkerID     int    `json:"worker_id"`
	Peer         string `json:"peer"`
	OK           bool   `json:"ok"`
	BytesWritten int    `json:"bytes_written,omitempty"`
	Error        string `json:"error,omitempty"`
}

type BroadcastResult struct {
	OK          bool                  `json:"ok"`
	Transmitted bool                  `json:"transmitted"`
	Txid        string                `json:"txid"`
	SizeBytes   int                   `json:"size_bytes"`
	PeersTotal  int                   `json:"peers_total"`
	PeersSent   int                   `json:"peers_sent"`
	PeersFailed int                   `json:"peers_failed"`
	Results     []peerBroadcastResult `json:"results"`
}

func decodeRawTxHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	s = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\n', '\r', '\t':
			return -1
		default:
			return r
		}
	}, s)
	if s == "" {
		return nil, errors.New("empty hex")
	}
	if len(s)%2 != 0 {
		return nil, errors.New("hex length must be even")
	}
	raw, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("invalid hex")
	}
	if len(raw) < 10 {
		return nil, errors.New("transaction too short")
	}
	if len(raw) > MAX_BROADCAST_TX_BYTES {
		return nil, fmt.Errorf("transaction too large (max %d bytes)", MAX_BROADCAST_TX_BYTES)
	}
	if _, _, err := parseTxOutputs(raw); err != nil {
		return nil, fmt.Errorf("invalid transaction: %v", err)
	}
	return raw, nil
}

func wireHashFromTxidHex(txid string) ([]byte, error) {
	b, err := hex.DecodeString(txid)
	if err != nil || len(b) != 32 {
		return nil, errors.New("bad txid")
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		out[i] = b[31-i]
	}
	return out, nil
}

// BroadcastRawTx pushes a signed raw tx to every connected peer and returns per-peer write confirmation.
func (h *PeerHub) BroadcastRawTx(raw []byte) BroadcastResult {
	txid := txidHex(raw)
	out := BroadcastResult{
		Txid:      txid,
		SizeBytes: len(raw),
		Results:   []peerBroadcastResult{},
	}
	if h == nil {
		return out
	}

	txMsg := buildMessage("tx", raw)
	var invMsg []byte
	if wh, err := wireHashFromTxidHex(txid); err == nil {
		invMsg = buildMessage("inv", buildGetdataPayload([]invItem{{invType: MSG_TX, hash: wh}}))
	}

	type entry struct {
		id   int
		addr string
		lc   *lockedConn
	}
	h.mu.RLock()
	list := make([]entry, 0, len(h.peers))
	for id, lc := range h.peers {
		list = append(list, entry{id: id, addr: h.addrs[id], lc: lc})
	}
	h.mu.RUnlock()

	out.PeersTotal = len(list)
	for _, e := range list {
		row := peerBroadcastResult{WorkerID: e.id, Peer: e.addr}
		n, err := e.lc.WriteDeadline(txMsg, 20*time.Second)
		if err != nil {
			row.Error = err.Error()
			out.PeersFailed++
			out.Results = append(out.Results, row)
			continue
		}
		if n != len(txMsg) {
			row.Error = fmt.Sprintf("short write %d/%d", n, len(txMsg))
			row.BytesWritten = n
			out.PeersFailed++
			out.Results = append(out.Results, row)
			continue
		}
		row.OK = true
		row.BytesWritten = n
		out.PeersSent++
		out.Results = append(out.Results, row)
		// Best-effort inv so peers can gossip further; transmission confirmation is the tx write above.
		if len(invMsg) > 0 {
			_, _ = e.lc.WriteDeadline(invMsg, 10*time.Second)
		}
	}
	out.Transmitted = out.PeersSent > 0
	out.OK = out.Transmitted
	return out
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
	for len(m.mempoolOrder) >= m.maxMempoolIDs {
		old := m.mempoolOrder[len(m.mempoolOrder)-1]
		m.mempoolOrder = m.mempoolOrder[:len(m.mempoolOrder)-1]
		delete(m.mempoolTxIDs, old)
		m.dropTxLocked(old)
	}
	m.mempoolTxIDs[txid] = struct{}{}
	m.mempoolOrder = append([]string{txid}, m.mempoolOrder...)
}

func (m *MetricsCollector) noteTxBody(txid string) {
	if txid == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.recentTxBodies = append(m.recentTxBodies, txid)
	if m.maxRecentTx > 0 && len(m.recentTxBodies) > m.maxRecentTx {
		m.recentTxBodies = append([]string(nil), m.recentTxBodies[len(m.recentTxBodies)-m.maxRecentTx:]...)
	}
}

func (m *MetricsCollector) recentTxBodySnapshot() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]string, len(m.recentTxBodies))
	copy(out, m.recentTxBodies)
	return out
}

func (m *MetricsCollector) snapshot() (mempoolN int) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.mempoolOrder)
}

// mempoolRecent returns up to limit newest-first txids for the dashboard strip.
func (m *MetricsCollector) mempoolRecent(limit int) []string {
	if limit <= 0 {
		limit = MEMPOOL_UI_RECENT
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if limit > len(m.mempoolOrder) {
		limit = len(m.mempoolOrder)
	}
	out := make([]string, limit)
	copy(out, m.mempoolOrder[:limit])
	return out
}

// mempoolPage returns a newest-first page for progressive UI loading.
func (m *MetricsCollector) mempoolPage(offset, limit int) (ids []string, total, nextOffset int, hasMore bool) {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = MEMPOOL_PAGE_DEFAULT
	}
	if limit > MEMPOOL_PAGE_MAX {
		limit = MEMPOOL_PAGE_MAX
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	total = len(m.mempoolOrder)
	if offset >= total {
		return []string{}, total, offset, false
	}
	end := offset + limit
	if end > total {
		end = total
	}
	ids = make([]string, end-offset)
	copy(ids, m.mempoolOrder[offset:end])
	nextOffset = end
	hasMore = end < total
	return ids, total, nextOffset, hasMore
}

func (m *MetricsCollector) registerTrackedTxInputs(txid string, inputs []txInputOutpoint) []string {
	if strings.TrimSpace(txid) == "" || len(inputs) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	conflicts := make(map[string]struct{})
	var keys []string
	for _, in := range inputs {
		if strings.TrimSpace(in.prevTxid) == "" {
			continue
		}
		key := in.prevTxid + ":" + strconv.FormatUint(uint64(in.vout), 10)
		keys = append(keys, key)
		set := m.outpointToTxs[key]
		if set == nil {
			set = make(map[string]struct{})
			m.outpointToTxs[key] = set
		}
		for other := range set {
			if other == txid {
				continue
			}
			conflicts[other] = struct{}{}
			conflicts[txid] = struct{}{}
		}
		set[txid] = struct{}{}
	}
	if len(keys) > 0 {
		m.txToOutpoints[txid] = keys
	}
	if len(conflicts) == 0 {
		return nil
	}
	out := make([]string, 0, len(conflicts))
	for c := range conflicts {
		m.doubleSpentTx[c] = true
		out = append(out, c)
	}
	return out
}

func (m *MetricsCollector) isDoubleSpent(txid string) bool {
	if strings.TrimSpace(txid) == "" {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.doubleSpentTx[txid]
}

func (m *MetricsCollector) dropTxLocked(txid string) {
	keys := m.txToOutpoints[txid]
	if len(keys) == 0 {
		delete(m.doubleSpentTx, txid)
		return
	}
	delete(m.txToOutpoints, txid)
	for _, key := range keys {
		set := m.outpointToTxs[key]
		if set == nil {
			continue
		}
		delete(set, txid)
		if len(set) == 0 {
			delete(m.outpointToTxs, key)
		}
	}
	delete(m.doubleSpentTx, txid)
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

// ProcessedSet tracks txids already requested via getdata and/or inspected from a
// tx body. Without marking non-matches, large mempool inv dumps keep refetching
// the same first MAX_TX_FETCH_INV entries and never reach later payments.
type ProcessedSet struct {
	mu  sync.Mutex
	m   map[string]struct{}
	max int
}

type PaymentCallbackPayload struct {
	Address       string   `json:"address"`
	Txid          string   `json:"txid"`
	Vout          uint32   `json:"vout"`
	Utxo          string   `json:"utxo"`
	AmountDoge    float64  `json:"payment_amount"`
	Datetime      string   `json:"datetime"`
	FromAddress   string   `json:"from_address,omitempty"`
	FromAddresses []string `json:"from_addresses,omitempty"`
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
	return &ProcessedSet{m: make(map[string]struct{}), max: 100000}
}

func (ps *ProcessedSet) Has(k string) bool {
	if k == "" {
		return false
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	_, ok := ps.m[k]
	return ok
}

func (ps *ProcessedSet) Add(k string) {
	if k == "" {
		return
	}
	ps.mu.Lock()
	defer ps.mu.Unlock()
	if _, ok := ps.m[k]; ok {
		return
	}
	for ps.max > 0 && len(ps.m) >= ps.max {
		for old := range ps.m {
			delete(ps.m, old)
			break
		}
	}
	ps.m[k] = struct{}{}
}

func (ps *ProcessedSet) Remove(k string) {
	ps.mu.Lock()
	defer ps.mu.Unlock()
	delete(ps.m, k)
}

func chooseSeeds(network string) ([]string, int) {
	switch normalizeNetwork(network) {
	case "mainnet":
		return mainnetDNSSeeds, networkDefaultPort(network)
	case "reboottestnet":
		// https://github.com/qlpqlp/dogego — reboot testnet DNS seed first.
		return rebootTestnetDNSSeeds, networkDefaultPort(network)
	default:
		// Legacy Dogecoin testnet3.
		return []string{"seed.testnet.dogecoin.org"}, networkDefaultPort(network)
	}
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

// BlockWorkQueue scans full block bodies off the P2P read loop so mempool
// inv/tx handling is not stalled by confirmation walks.
type BlockWorkQueue struct {
	ch   chan []byte
	stop <-chan struct{}
}

func NewBlockWorkQueue(buf int) *BlockWorkQueue {
	if buf < 4 {
		buf = 4
	}
	return &BlockWorkQueue{ch: make(chan []byte, buf)}
}

func (q *BlockWorkQueue) Submit(payload []byte) {
	if q == nil || len(payload) == 0 {
		return
	}
	cp := append([]byte(nil), payload...)
	select {
	case q.ch <- cp:
		return
	default:
	}
	// Bounded wait so a slow scanner does not permanently drop, but the P2P
	// reader never blocks for long.
	select {
	case q.ch <- cp:
	case <-time.After(100 * time.Millisecond):
		log.Printf("[MTR-P2P] block scan queue full; dropping one block body (%d bytes)", len(cp))
	}
}

func (q *BlockWorkQueue) Run(workers int, store *Store, processed *ProcessedSet, mcol *MetricsCollector, htrack *HeaderTracker, stop <-chan struct{}) {
	if q == nil {
		return
	}
	q.stop = stop
	if workers < 1 {
		workers = 1
	}
	if workers > 4 {
		workers = 4
	}
	logf := func(format string, args ...any) {
		log.Printf("[MTR-BLOCK] "+format, args...)
	}
	logv := func(format string, args ...any) {
		log.Printf("[MTR-BLOCK:v] "+format, args...)
	}
	for i := 0; i < workers; i++ {
		go func() {
			for {
				select {
				case <-stop:
					return
				case payload, ok := <-q.ch:
					if !ok {
						return
					}
					_ = handleBlockPayload(store, processed, mcol, htrack, payload, logf, logv)
				}
			}
		}()
	}
}

// mempoolSniffer runs several parallel P2P sessions (like the arcade pup rotating seeds/peers)
// so inv/getdata gossip reaches MemeTracker faster and more reliably than a single connection.
// Closing stop unblocks workers between peers (active sessions may finish naturally up to SESSION_SEC).
func mempoolSniffer(store *Store, network string, p2pHost string, p2pPort int, p2pLog int, mcol *MetricsCollector, htrack *HeaderTracker, processed *ProcessedSet, peers *PeerHub, blocks *BlockWorkQueue, parallel int, confirmMode string, bloomPeers *bloomPeerCache, stop <-chan struct{}) {
	if parallel < 1 {
		parallel = 1
	}
	if parallel > 8 {
		parallel = 8
	}
	confirmMode = normalizeConfirmMode(confirmMode)
	if htrack == nil {
		htrack = NewHeaderTracker("")
	}
	if bloomPeers == nil {
		bloomPeers = newBloomPeerCache()
	}
	setActiveP2PMagic(network)
	log.Printf("[MTR-P2P] confirm_mode=%s network=%s magic=0x%x (msg_block=full bodies; node_bloom=BIP-37 SPV, require NODE_BLOOM peers)", confirmMode, normalizeNetwork(network), currentMagic())
	for w := 0; w < parallel; w++ {
		go mempoolP2PWorker(w, parallel, store, network, p2pHost, p2pPort, p2pLog, mcol, htrack, processed, peers, blocks, confirmMode, bloomPeers, stop)
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

func mempoolP2PWorker(workerID, parallel int, store *Store, network, p2pHost string, p2pPort, p2pLog int, mcol *MetricsCollector, htrack *HeaderTracker, processed *ProcessedSet, peers *PeerHub, blocks *BlockWorkQueue, confirmMode string, bloomPeers *bloomPeerCache, stop <-chan struct{}) {
	seeds, defaultPort := chooseSeeds(network)
	if p2pPort == 0 {
		p2pPort = defaultPort
	}
	if p2pHost != "" {
		seeds = []string{p2pHost}
	}
	requireBloom := confirmModeIsBloom(confirmMode)
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

		// Prefer known NODE_BLOOM peers first when in SPV mode (dogecoin-wallet style).
		if requireBloom {
			ips = bloomPeers.Prefer(ips)
		}
		// Stride peers by worker so parallel goroutines do not all dial the same IP at once
		// (peers often drop duplicate inbound links from the same host).
		shuffled := shufflePeerIPs(workerID, ips)
		if requireBloom {
			// Prefer again after shuffle so known bloom IPs stay early for this worker stride.
			shuffled = bloomPeers.Prefer(shuffled)
		}
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
			_ = conn.SetDeadline(time.Time{})

			stateLastPeer := net.JoinHostPort(peer, strconv.Itoa(p2pPort))
			lc := &lockedConn{Conn: conn}
			mcol.SetPeerSession(workerID, stateLastPeer, true)
			if peers != nil {
				peers.Register(workerID, stateLastPeer, lc)
			}
			memetrackerP2PSession(lc, stateLastPeer, store, processed, mcol, htrack, blocks, p2pPort, confirmMode, bloomPeers, logf, logv)
			if peers != nil {
				peers.Unregister(workerID, lc)
			}
			mcol.SetPeerSession(workerID, stateLastPeer, false)
			_ = conn.Close()
		}

		if sleepOrStop(5*time.Second, stop) {
			return
		}
	}
}

// considerWatchedPayment matches outputs against watched addresses and stores hits.
// When fromMempool is true, double-spend tracking runs on inputs.
// When fromMempool is false, blockHeight/tipHeight update confirmed + confirmations (0..5).
// Returns how many new address rows were inserted (one row per matching UTXO / vout).
func considerWatchedPayment(store *Store, processed *ProcessedSet, mcol *MetricsCollector, raw []byte, fromMempool bool, blockHeight, tipHeight int64, logf, logv func(string, ...any)) int {
	if len(raw) == 0 {
		return 0
	}
	store.mu.RLock()
	hasWatchers := len(store.watchByHash) > 0
	store.mu.RUnlock()
	if !hasWatchers {
		return 0
	}

	outs, _, err := parseTxOutputs(raw)
	if err != nil {
		logv("parse tx failed: %v", err)
		return 0
	}
	txid := txidHex(raw)
	wtxid := wtxidHex(raw)
	// Always mark inspected so getdata can progress through large mempool dumps.
	// Matching still runs even if the id was already marked when getdata was sent.
	defer func() {
		processed.Add(txid)
		processed.Add(wtxid)
	}()

	type matchedOut struct {
		hashHex string
		vout    uint32
		sats    int64
	}
	var matched []matchedOut
	store.mu.RLock()
	for i, o := range outs {
		h160, ok := scriptPubKeyHash160(o.script)
		if !ok {
			continue
		}
		hashHex := hex.EncodeToString(h160)
		if _, watching := store.watchByHash[hashHex]; watching {
			matched = append(matched, matchedOut{hashHex: hashHex, vout: uint32(i), sats: o.valueSats})
		}
	}
	store.mu.RUnlock()
	if len(matched) == 0 {
		return 0
	}

	isDoubleSpent := false
	if fromMempool {
		inputs, inErr := parseTxInputOutpoints(raw)
		if inErr != nil {
			logv("tx %s input parse failed for double-spend detection: %v", txid, inErr)
		}
		conflictedTxids := mcol.registerTrackedTxInputs(txid, inputs)
		isDoubleSpent = len(conflictedTxids) > 0 || mcol.isDoubleSpent(txid)
		if len(conflictedTxids) > 0 {
			for _, cTxid := range conflictedTxids {
				_ = store.MarkTxDoubleSpent(cTxid)
			}
		}
	}

	dt := time.Now().UTC()
	fromAddr, fromAddrs := extractSenderAddresses(raw, store.Network())
	inserted := 0
	for _, m := range matched {
		if m.sats <= 0 {
			continue
		}
		amountDoge := float64(m.sats) / 1e8
		if store.AddTx(m.hashHex, txid, m.vout, dt, amountDoge, isDoubleSpent, fromAddr, fromAddrs) {
			inserted++
			addr, cbURL, ok := store.CallbackTarget(m.hashHex)
			if ok && cbURL != "" {
				go notifyCallback(cbURL, PaymentCallbackPayload{
					Address:       addr,
					Txid:          txid,
					Vout:          m.vout,
					Utxo:          formatUtxo(txid, m.vout),
					AmountDoge:    amountDoge,
					Datetime:      dt.Format(time.RFC3339),
					FromAddress:   fromAddr,
					FromAddresses: fromAddrs,
				})
			}
		}
	}
	if !fromMempool {
		if store.NoteTxConfirmed(txid, blockHeight, tipHeight) {
			logv("tx confirmed in block txid=%s height=%d tip=%d", txid, blockHeight, tipHeight)
		}
	}
	if inserted > 0 {
		logf("tx matched watched address(es) txid=%s inserted=%d mempool=%v", txid, inserted, fromMempool)
	}
	return inserted
}

func sendGetHeaders(conn net.Conn, htrack *HeaderTracker, logf, logv func(string, ...any)) error {
	loc := htrack.LocatorHashes(101)
	pl := buildGetHeadersPayload(loc)
	msg := buildMessage("getheaders", pl)
	_, err := conn.Write(msg)
	if err != nil {
		return err
	}
	logv("sent GETHEADERS locator_n=%d", len(loc))
	return nil
}

func queueBlockFetches(conn net.Conn, htrack *HeaderTracker, hashHexes []string, logf, logv func(string, ...any)) error {
	_, err := queueBlockFetchesOpt(conn, htrack, hashHexes, true, false, logf, logv)
	return err
}

func queueBlockFetchesOpt(conn net.Conn, htrack *HeaderTracker, hashHexes []string, requireWant bool, filtered bool, logf, logv func(string, ...any)) ([]string, error) {
	pending := make([]string, 0, MAX_BLOCK_FETCH_INV)
	for _, hx := range hashHexes {
		if requireWant && !htrack.WantBlockBody(hx) {
			continue
		}
		if !htrack.NeedBlock(hx) {
			continue
		}
		if !htrack.MarkPending(hx) {
			continue
		}
		pending = append(pending, hx)
		if len(pending) >= MAX_BLOCK_FETCH_INV {
			break
		}
	}
	if len(pending) == 0 {
		return nil, nil
	}
	pl := buildBlockGetdata(pending, filtered)
	if len(pl) == 0 {
		for _, hx := range pending {
			htrack.ClearPending(hx)
		}
		return nil, nil
	}
	if _, err := conn.Write(buildMessage("getdata", pl)); err != nil {
		for _, hx := range pending {
			htrack.ClearPending(hx)
		}
		return nil, err
	}
	if filtered {
		logf("getdata filtered blocks (SPV merkleblock) n=%d sequential=%v", len(pending), !requireWant)
	} else {
		logf("getdata blocks n=%d sequential=%v", len(pending), !requireWant)
	}
	return pending, nil
}

// queueBlockScanFetch chooses tip-only SPV when idle, or sequential no-skip catch-up
// when unconfirmed payments still need inclusion proof.
func queueBlockScanFetch(conn net.Conn, store *Store, htrack *HeaderTracker, filtered bool, logf, logv func(string, ...any)) ([]string, error) {
	if store == nil || htrack == nil {
		return nil, nil
	}
	if n := htrack.ExpireStalePending(); n > 0 {
		logf("expired stale block getdata n=%d (no body/merkleblock in %s)", n, PENDING_BLOCK_TIMEOUT)
		if filtered {
			// Tell caller via log; session sets forceFullCatchup when expire happens during bloom.
			logf("bloom filtered getdata timed out — will fall back to MSG_BLOCK")
		}
	}
	watching := store.watcherCount() > 0
	needConfirm := store.HasUnconfirmedTxs()
	if !watching && !needConfirm {
		htrack.AdvanceBodyCursorToTip()
		return nil, nil
	}

	// Unconfirmed payments: sequential catch-up from cursor toward tip. Never skip
	// intermediate headers we still have; if the ring has a gap, snap past it.
	if needConfirm {
		limit := MAX_BLOCK_FETCH_INV
		if filtered {
			limit = 1 // one merkleblock at a time — fast SPV, no pending pile
		} else {
			limit = 1 // one full body at a time when falling back
		}
		hashes := htrack.NextSequentialBodyHashesNoSkip(limit)
		if len(hashes) == 0 {
			if ok, fromH, toH := htrack.SnapPastHeaderGap(); ok {
				logf("confirm cursor snapped past missing header gap from=%d to=%d (use Mark confirmed for older txs)", fromH, toH)
				hashes = htrack.NextSequentialBodyHashesNoSkip(limit)
			}
		}
		if len(hashes) == 0 {
			logv("sequential confirm catch-up idle (cursor caught up or waiting headers)")
			return nil, nil
		}
		logf("sequential confirm catch-up n=%d filtered=%v first=%s last=%s", len(hashes), filtered, hashes[0], hashes[len(hashes)-1])
		return queueBlockFetchesOpt(conn, htrack, hashes, false, filtered, logf, logv)
	}

	// Idle watch (no unconfirmed): keep cursor on tip.
	// In NODE_BLOOM mode, still request tip merkleblock so mined-without-mempool payments are seen.
	tip := htrack.TipHash()
	if tip == "" {
		return nil, nil
	}
	if htrack.AlreadyScanned(tip) {
		htrack.AdvanceBodyCursorToTip()
		return nil, nil
	}
	if filtered {
		logv("tip SPV merkleblock fetch hash=%s (idle watch, NODE_BLOOM)", tip)
		return queueBlockFetchesOpt(conn, htrack, []string{tip}, false, true, logf, logv)
	}
	htrack.AdvanceBodyCursorToTip()
	return nil, nil
}

// queueTipBlockFetch / queueSequentialBlockBodies keep older names working.
func queueTipBlockFetch(conn net.Conn, store *Store, htrack *HeaderTracker, filtered bool, logf, logv func(string, ...any)) ([]string, error) {
	return queueBlockScanFetch(conn, store, htrack, filtered, logf, logv)
}

func queueSequentialBlockBodies(conn net.Conn, store *Store, htrack *HeaderTracker, filtered bool, logf, logv func(string, ...any)) ([]string, error) {
	return queueBlockScanFetch(conn, store, htrack, filtered, logf, logv)
}

func handleBlockPayload(store *Store, processed *ProcessedSet, mcol *MetricsCollector, htrack *HeaderTracker, payload []byte, logf, logv func(string, ...any)) []string {
	if len(payload) < 80 {
		return nil
	}
	h80 := payload[:80]
	hashHex, _ := htrack.RememberHeader80(h80)
	if hashHex == "" {
		return nil
	}
	tipH := htrack.TipHeight()
	store.RefreshConfirmations(tipH)
	if htrack.AlreadyScanned(hashHex) {
		htrack.ClearPending(hashHex)
		return nil
	}
	blockH := htrack.HeaderHeight(hashHex)
	if blockH < 0 && tipH >= 0 && hashHex == htrack.TipHash() {
		blockH = tipH
	}
	htrack.SetScanning(hashHex, blockH)
	defer htrack.ClearScanning(hashHex)
	hits := 0
	confirmedNew := 0
	err := forEachBlockTxRaw(payload, func(idx int, txRaw []byte) error {
		if idx == 0 {
			return nil // skip coinbase
		}
		txid := txidHex(txRaw)
		// Fast path: confirm known mempool payments via txid index (O(1) lookup).
		if store.KnowsTxid(txid) {
			if store.NoteTxConfirmed(txid, blockH, tipH) {
				confirmedNew++
			}
			return nil
		}
		// Slow path only for txs never seen in mempool: output â†’ watchByHash lookup.
		n := considerWatchedPayment(store, processed, mcol, txRaw, false, blockH, tipH, logf, logv)
		hits += n
		return nil
	})
	if err != nil {
		logf("block scan failed hash=%s err=%v", hashHex, err)
		htrack.ClearPending(hashHex)
		return nil
	}
	htrack.MarkScanned(hashHex)
	if hits > 0 || confirmedNew > 0 {
		htrack.AddConfirmedHits(hits + confirmedNew)
		logf("block safeguard hash=%s new_payments=%d newly_confirmed=%d", hashHex, hits, confirmedNew)
	} else {
		logv("block scanned hash=%s no watched payment matches", hashHex)
	}
	// Do not chain-walk parent bodies here; mempool stays first, tip block is enough backup.
	return nil
}

// handleMerkleBlockPayload processes a BIP-37 merkleblock (SPV path): confirm known
// mempool payments from the partial merkle tree using header height, without a full body.
// Returns how many matched txs the peer should still deliver as follow-up "tx" messages.
func handleMerkleBlockPayload(store *Store, htrack *HeaderTracker, payload []byte, logf, logv func(string, ...any)) (hashHex string, height int64, matchedLeft int) {
	mb, err := parseMerkleBlock(payload)
	if err != nil {
		logf("merkleblock parse failed: %v", err)
		return "", -1, 0
	}
	hashHex, _ = htrack.RememberHeader80(mb.Header80)
	if hashHex == "" {
		return "", -1, 0
	}
	tipH := htrack.TipHeight()
	store.RefreshConfirmations(tipH)
	// Always drop pending for this hash — merkleblock IS the getdata response.
	htrack.ClearPending(hashHex)
	if htrack.AlreadyScanned(hashHex) {
		return hashHex, -1, 0
	}
	blockH := htrack.HeaderHeight(hashHex)
	if blockH < 0 && tipH >= 0 && hashHex == htrack.TipHash() {
		blockH = tipH
	}
	htrack.SetScanning(hashHex, blockH)
	confirmedNew := 0
	for _, txid := range mb.MatchedTxid {
		if store.KnowsTxid(txid) {
			if store.NoteTxConfirmed(txid, blockH, tipH) {
				confirmedNew++
			}
		}
	}
	matchedLeft = len(mb.MatchedTxid)
	// Advance cursor immediately (SPV). Follow-up tx messages can still discover new payments.
	htrack.MarkScanned(hashHex)
	htrack.ClearScanning(hashHex)
	if hashHex == htrack.TipHash() {
		htrack.AdvanceBodyCursorToTip()
	}
	if confirmedNew > 0 {
		htrack.AddConfirmedHits(confirmedNew)
		logf("merkleblock SPV confirm hash=%s newly_confirmed=%d matched=%d height=%d", hashHex, confirmedNew, matchedLeft, blockH)
	} else {
		logf("merkleblock SPV scanned hash=%s matched=%d height=%d (no watched confirms)", hashHex, matchedLeft, blockH)
	}
	return hashHex, blockH, matchedLeft
}

func parsePeerServices(p []byte) uint64 {
	if len(p) < 12 {
		return 0
	}
	return binary.LittleEndian.Uint64(p[4:12])
}

func sendBloomFilter(conn net.Conn, store *Store, logf func(string, ...any)) error {
	watched := store.WatchedHash160Hexes()
	if len(watched) == 0 {
		_, err := conn.Write(buildMessage("filterclear", nil))
		if err == nil {
			logf("sent FILTERCLEAR (no watched addresses)")
		}
		return err
	}
	tweak := uint32(time.Now().UnixNano() & 0xffffffff)
	f := bloomFromWatched(watched, tweak)
	msg := buildMessage("filterload", f.FilterloadPayload())
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	logf("sent FILTERLOAD watched=%d filter_bytes=%d hash_funcs=%d (BIP-37 SPV)", len(watched), len(f.data), f.nHash)
	return nil
}

// clearPendingFromNotfound clears block getdata pending entries reported in a notfound message.
func clearPendingFromNotfound(htrack *HeaderTracker, payload []byte, logf func(string, ...any)) int {
	items, err := parseInvPayload(payload)
	if err != nil || len(items) == 0 {
		return 0
	}
	n := 0
	for _, it := range items {
		if !invTypeIsBlock(it.invType) && (it.invType&^MSG_WITNESS_FLAG) != MSG_FILTERED_BLOCK {
			continue
		}
		hx := reverseBytesToHex(it.hash)
		htrack.ClearPending(hx)
		n++
	}
	if n > 0 {
		logf("notfound cleared pending block getdata n=%d", n)
	}
	return n
}

func memetrackerP2PSession(conn net.Conn, stateLastPeer string, store *Store, processed *ProcessedSet, mcol *MetricsCollector, htrack *HeaderTracker, blocks *BlockWorkQueue, p2pPort int, confirmMode string, bloomPeers *bloomPeerCache, logf, logv func(string, ...any)) {
	if htrack == nil {
		htrack = NewHeaderTracker("")
	}
	confirmMode = normalizeConfirmMode(confirmMode)
	bloomMode := confirmModeIsBloom(confirmMode)
	gotVerack := false
	mempoolSent := false
	headersEnabled := false
	peerServices := uint64(0)
	peerBloom := false
	filterLoaded := false
	// After merkleblock, peer sends matched txs; count them as block inclusions.
	merkleFollowLeft := 0
	merkleFollowHash := ""
	merkleFollowHeight := int64(-1)
	lastMempoolResync := time.Time{}
	lastGetHeaders := time.Time{}
	lastTxActivity := time.Time{}
	start := time.Now()
	var sessionExit error
	var sessionBlockPending []string

	noteBlockPending := func(queued []string, err error) error {
		if len(queued) > 0 {
			sessionBlockPending = append(sessionBlockPending, queued...)
		}
		return err
	}

	defer func() {
		htrack.ClearPendingMany(sessionBlockPending)
	}()

	clearBloom := func() {
		if !filterLoaded {
			return
		}
		_, _ = conn.Write(buildMessage("filterclear", nil))
		filterLoaded = false
		logv("sent FILTERCLEAR (restore full mempool relay)")
	}

	loadBloom := func() error {
		watched := store.WatchedHash160Hexes()
		if len(watched) == 0 {
			clearBloom()
			return nil
		}
		if err := sendBloomFilter(conn, store, logf); err != nil {
			filterLoaded = false
			return err
		}
		filterLoaded = true
		return nil
	}

	forceFullCatchup := false // after filtered getdata times out / notfound, fall back to MSG_BLOCK
	expireStreak := 0
	queueScan := func() error {
		if n := htrack.ExpireStalePending(); n > 0 {
			expireStreak++
			logf("expired stale block getdata n=%d streak=%d", n, expireStreak)
			if bloomMode {
				forceFullCatchup = true
				logf("NODE_BLOOM catch-up falling back to MSG_BLOCK after timed-out filtered getdata")
			}
			// Old unconfirmed rows outside reachable bodies: stop spamming pending.
			if expireStreak >= 2 && store.HasUnconfirmedTxs() {
				logf("confirm catch-up stalled — advancing cursor to tip; Mark confirmed for remaining unconfirmed rows")
				htrack.AdvanceBodyCursorToTip()
				expireStreak = 0
				return nil
			}
		} else {
			expireStreak = 0
		}

		useFilt := bloomMode && peerBloom && !forceFullCatchup && len(store.WatchedHash160Hexes()) > 0
		if useFilt {
			if err := loadBloom(); err != nil {
				logf("bloom filterload failed: %v — using MSG_BLOCK", err)
				useFilt = false
				forceFullCatchup = true
			}
		}
		if useFilt {
			logf("confirm catch-up MSG_FILTERED_BLOCK peer=%s (temporary bloom)", stateLastPeer)
		} else if bloomMode && store.HasUnconfirmedTxs() {
			logf("confirm catch-up MSG_BLOCK peer=%s forceFull=%v", stateLastPeer, forceFullCatchup)
		}
		queued, err := queueBlockScanFetch(conn, store, htrack, useFilt, logf, logv)
		// Always clear bloom after getdata so mempool inv/tx relay resumes (dashboard graph).
		// In-flight merkleblock/block responses still arrive for the getdata already sent.
		clearBloom()
		return noteBlockPending(queued, err)
	}

	finishMerkleFollow := func() {
		if merkleFollowHash == "" {
			return
		}
		if merkleFollowLeft <= 0 {
			// Cursor already advanced when merkleblock arrived; just clear follow state.
			merkleFollowHash = ""
			merkleFollowHeight = -1
			merkleFollowLeft = 0
		}
	}

	logf("connected peer=%s handshake start (Dogecoin P2P magic_u32le=0x%x wire_magic_4b_le_hex=%s)", stateLastPeer, currentMagic(), dogeMagicWireHexLE())
	verOut := buildVersionPayload(p2pPort)
	verMsg := buildMessage("version", verOut)
	logf("sending VERSION cmd payload_len=%d total_msg_bytes=%d - %s", len(verOut), len(verMsg), summarizeOutgoingVersionPayload(verOut, p2pPort))
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

	mempoolBusy := func() bool {
		if store.watcherCount() == 0 {
			return false
		}
		// Only pause header/catch-up briefly after real mempool traffic.
		// Never treat "no tx seen yet" as busy — that starved getheaders when bloom
		// had suppressed relay and left the scan cursor stuck.
		if lastTxActivity.IsZero() {
			return false
		}
		return time.Since(lastTxActivity) < 20*time.Second
	}

	maybeHeaderMaintenance := func(allowBackfill bool) error {
		if !gotVerack || !headersEnabled {
			return nil
		}
		if store.takeBloomKick() {
			// Never leave a filter loaded — MemeTracker needs full mempool for the UI.
			clearBloom()
		}
		if err := queueScan(); err != nil {
			return err
		}
		if mempoolBusy() && !htrack.NeedsHeaderSync() {
			return nil
		}
		topup := time.Duration(GETHEADERS_TOPUP_SEC) * time.Second
		if store.watcherCount() == 0 || htrack.NeedsHeaderSync() {
			topup = time.Duration(GETHEADERS_TOPUP_IDLE_SEC) * time.Second
		}
		if htrack.NeedsHeaderSync() {
			topup = 5 * time.Second // cold-start: keep pulling header batches toward tip
		}
		if time.Since(lastGetHeaders) >= topup {
			if err := sendGetHeaders(conn, htrack, logf, logv); err != nil {
				return err
			}
			lastGetHeaders = time.Now()
		}
		return nil
	}

readLoop:
	// Compare to time.Duration seconds - bare SESSION_SEC (300) is converted to 300ns, not 300s.
	for time.Since(start) < time.Duration(SESSION_SEC)*time.Second {
		_ = conn.SetReadDeadline(time.Now().Add(P2P_READ_IDLE_SEC * time.Second))
		header, err := readExact(conn, 24)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				_ = conn.SetReadDeadline(time.Time{})
				logv("read deadline (%ds idle) no header yet - gotVerack=%v mempoolSent=%v", P2P_READ_IDLE_SEC, gotVerack, mempoolSent)
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
				if err := maybeHeaderMaintenance(true); err != nil {
					sessionExit = err
					break readLoop
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

		if magic != currentMagic() {
			logf("wrong magic peer=%s got_u32le=0x%x want_u32le=0x%x (LE bytes got_hex=%s want_hex=%s) - skipping 24b, stream may be misaligned (TLS/wrong chain?)",
				stateLastPeer, magic, currentMagic(), hex.EncodeToString(header[0:4]), dogeMagicWireHexLE())
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
			logf("P2P checksum mismatch peer=%s cmd=%s payload_len=%d wire_checksum4=%x computed_double_sha256_4=%x - closing",
				stateLastPeer, cmd, len(payload), chkWire, wantSum)
			logv("payload_head_hex=%s", hexSnippet(payload, 256))
			break readLoop
		}
		logv("checksum ok cmd=%s payload_len=%d", cmd, len(payload))

		switch cmd {
		case "version":
			logf("recv VERSION from peer=%s - %s", stateLastPeer, summarizePeerVersionPayload(payload))
			logv("peer version payload head hex=%s", hexSnippet(payload, 256))
			peerServices = parsePeerServices(payload)
			peerBloom = peerServices&NODE_BLOOM != 0
			if bloomMode && !peerBloom {
				sessionExit = fmt.Errorf("peer lacks NODE_BLOOM (confirm_mode=node_bloom)")
				logf("skip peer=%s services=0x%x — no NODE_BLOOM (dogecoin-wallet requiredServices)", stateLastPeer, peerServices)
				break readLoop
			}
			if peerBloom && bloomPeers != nil {
				bloomPeers.Note(stateLastPeer)
			}
			htrack.NotePeerStartHeight(parsePeerStartHeight(payload))
			ack := buildMessage("verack", nil)
			_, werr := conn.Write(ack)
			if werr != nil {
				sessionExit = werr
				logf("write verack failed: %v", werr)
				break readLoop
			}
			logf("sent VERACK (%d bytes) awaiting peer VERACK (NODE_BLOOM=%v confirm_mode=%s)", len(ack), peerBloom, confirmMode)
			logv("verack message hex=%s", hex.EncodeToString(ack))
		case "verack":
			gotVerack = true
			logf("recv VERACK from peer=%s - handshake complete confirm_mode=%s bloom=%v (mempool unfiltered; bloom only around SPV getdata)", stateLastPeer, confirmMode, peerBloom)
			clearBloom()
			if !headersEnabled {
				if _, werr := conn.Write(buildMessage("sendheaders", nil)); werr != nil {
					sessionExit = werr
					logf("write sendheaders failed: %v", werr)
					break readLoop
				}
				headersEnabled = true
				logf("sent SENDHEADERS (realtime tip headers)")
				if err := sendGetHeaders(conn, htrack, logf, logv); err != nil {
					sessionExit = err
					break readLoop
				}
				lastGetHeaders = time.Now()
			}
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
				logf("sent MEMPOOL request to peer=%s (%d bytes) - expecting inv/tx for relayed txs", stateLastPeer, len(mem))
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
			mcol.noteTxBody(txidEarly)
			lastTxActivity = time.Now()
			logv("recv TX raw len=%d txid_le=%s", len(payload), txidEarly)
			fromMempool := true
			blockH, tipH := int64(-1), int64(-1)
			if merkleFollowLeft > 0 && merkleFollowHash != "" {
				fromMempool = false
				blockH = merkleFollowHeight
				tipH = htrack.TipHeight()
				merkleFollowLeft--
				n := considerWatchedPayment(store, processed, mcol, payload, false, blockH, tipH, logf, logv)
				if n > 0 {
					htrack.AddConfirmedHits(n)
				}
				finishMerkleFollow()
			} else {
				_ = considerWatchedPayment(store, processed, mcol, payload, fromMempool, blockH, tipH, logf, logv)
			}

		case "headers":
			hdrs, err := decodeHeadersPayload(payload)
			if err != nil {
				logf("headers parse error peer=%s: %v", stateLastPeer, err)
				continue
			}
			logf("recv HEADERS peer=%s count=%d", stateLastPeer, len(hdrs))
			for _, h80 := range hdrs {
				_, _ = htrack.RememberHeader80(h80)
			}
			store.RefreshConfirmations(htrack.TipHeight())
			// Sequential bodies after cursor (never tip-only when intermediates remain).
			if err := queueScan(); err != nil {
				sessionExit = err
				break readLoop
			}
			if len(hdrs) > 0 {
				lastGetHeaders = time.Now()
				// Keep chaining getheaders while the peer returns full batches, or until tip height is known.
				if (len(hdrs) >= 2000 || htrack.NeedsHeaderSync()) && (!mempoolBusy() || htrack.NeedsHeaderSync()) {
					if err := sendGetHeaders(conn, htrack, logf, logv); err != nil {
						sessionExit = err
						break readLoop
					}
					lastGetHeaders = time.Now()
				}
			}

		case "merkleblock":
			logf("recv MERKLEBLOCK payload_len=%d peer=%s (SPV)", len(payload), stateLastPeer)
			hx, height, left := handleMerkleBlockPayload(store, htrack, payload, logf, logv)
			forceFullCatchup = false // filtered path works on this peer
			if left > 0 {
				merkleFollowHash = hx
				merkleFollowHeight = height
				merkleFollowLeft = left
			}
			if err := queueScan(); err != nil {
				sessionExit = err
				break readLoop
			}

		case "notfound":
			n := clearPendingFromNotfound(htrack, payload, logf)
			if n > 0 && bloomMode {
				forceFullCatchup = true
				logf("peer notfound for filtered/block getdata — falling back to MSG_BLOCK")
				if err := queueScan(); err != nil {
					sessionExit = err
					break readLoop
				}
			}

		case "block":
			logv("recv BLOCK payload_len=%d (queued for async scan)", len(payload))
			// Never scan the full body on the P2P reader thread.
			if blocks != nil {
				blocks.Submit(payload)
			} else {
				_ = handleBlockPayload(store, processed, mcol, htrack, payload, logf, logv)
			}
			// Keep requesting the next sequential bodies while scanners work.
			if err := queueScan(); err != nil {
				sessionExit = err
				break readLoop
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
			blockLike := 0
			blockHashes := make([]string, 0)
			for _, it := range invs {
				if invTypeIsTx(it.invType) {
					txLike++
					mcol.observeMempoolTxid(reverseBytesToHex(it.hash))
				}
				if invTypeIsBlock(it.invType) {
					blockLike++
					blockHashes = append(blockHashes, reverseBytesToHex(it.hash))
				}
			}
			logf("recv INV peer=%s entries=%d tx_like=%d block_like=%d", stateLastPeer, len(invs), txLike, blockLike)
			logv("inv payload_len=%d parse_ok entries=%d", len(payload), len(invs))

			if txLike > 0 {
				lastTxActivity = time.Now()
			}

			store.mu.RLock()
			hasWatchers := len(store.watchByHash) > 0
			store.mu.RUnlock()

			// Priority 1: mempool tx getdata. Never let block backup delay this.
			if hasWatchers {
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
					// Mark before write so the next inv advances past this window
					// (even if the peer never returns the body).
					processed.Add(txHashHex)
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
			}

			// Priority 2: confirm catch-up / tip maintenance (after mempool getdata).
			if err := queueScan(); err != nil {
				sessionExit = err
				break readLoop
			}

		default:
			logv("recv cmd=%q peer=%s payload_len=%d (not handled)", cmd, stateLastPeer, len(payload))
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
					logf("write periodic mempool failed: %v", werr)
					break readLoop
				}
				lastMempoolResync = time.Now()
				logv("mempool periodic watchers=%d", nw)
			}
			if store.takeBloomKick() {
				clearBloom()
			}
		}
	}

	_ = conn.SetReadDeadline(time.Time{})
	if sessionExit != nil {
		logf("session end peer=%s gotVerack=%v mempoolSent=%v bloom=%v duration=%s err=%v",
			stateLastPeer, gotVerack, mempoolSent, peerBloom, time.Since(start).Truncate(time.Millisecond), sessionExit)
	} else {
		logf("session end peer=%s gotVerack=%v mempoolSent=%v bloom=%v duration=%s (session cap %ds, no wire error)",
			stateLastPeer, gotVerack, mempoolSent, peerBloom, time.Since(start).Truncate(time.Millisecond), SESSION_SEC)
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
	// ConfirmMode: "msg_block" (default) = full block bodies from any peer;
	// "node_bloom" = BIP-37 SPV like dogecoin-wallet (only peers advertising NODE_BLOOM).
	ConfirmMode string `json:"confirm_mode,omitempty"`
	// StartCheckpointHash is an optional block hash hex used as the cold-start
	// getheaders locator instead of the network genesis (faster tip sync).
	StartCheckpointHash string `json:"start_checkpoint_hash,omitempty"`
	// StartCheckpointHeight is the height of StartCheckpointHash when known.
	// Ignored when start_checkpoint_hash is empty. Use -1 if hash is set but height is unknown.
	StartCheckpointHeight int64 `json:"start_checkpoint_height"`
	APIAllowedIPs         []string `json:"api_allowed_ips,omitempty"` // shared IP allowlist (full access when matched)
	UserToken             string   `json:"user_token,omitempty"`       // user: /{token}/track/... , /{token}/healthz, /{token}/broadcast
	AdminToken            string   `json:"admin_token,omitempty"`      // admin: web UI + /api/* + everything
	// APIToken is a legacy alias for UserToken (read from older memetracker_config.json).
	APIToken string `json:"api_token,omitempty"`
}

func (c *MemeTrackerConfig) ApplyDefaults() {
	if c.HTTPPort == 0 {
		c.HTTPPort = 33555
	}
	c.HTTPBind = strings.TrimSpace(c.HTTPBind)
	if c.HTTPBind == "" {
		c.HTTPBind = "0.0.0.0"
	}
	c.Network = normalizeNetwork(c.Network)
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
		c.P2PPort = networkDefaultPort(c.Network)
	}
	c.StartCheckpointHash = strings.ToLower(strings.TrimSpace(c.StartCheckpointHash))
	c.StartCheckpointHash = strings.TrimPrefix(c.StartCheckpointHash, "0x")
	if c.P2PParallel == 0 {
		c.P2PParallel = 3
	}
	if c.P2PLog < 0 {
		c.P2PLog = 0
	}
	if c.P2PLog > 2 {
		c.P2PLog = 2
	}
	c.ConfirmMode = normalizeConfirmMode(c.ConfirmMode)
	// Migrate legacy api_token â†’ user_token.
	c.UserToken = normalizeAPIToken(c.UserToken)
	c.APIToken = normalizeAPIToken(c.APIToken)
	if c.UserToken == "" && c.APIToken != "" {
		c.UserToken = c.APIToken
	}
	c.APIToken = "" // always persist as user_token going forward
	c.AdminToken = normalizeAPIToken(c.AdminToken)
}

func (c *MemeTrackerConfig) IsComplete() bool {
	c.ApplyDefaults()
	if c.HTTPPort < 1 || c.HTTPPort > 65535 {
		return false
	}
	if strings.TrimSpace(c.HTTPBind) == "" {
		return false
	}
	n := normalizeNetwork(c.Network)
	if !isValidNetwork(n) {
		return false
	}
	c.Network = n
	if c.StartCheckpointHash != "" {
		if len(c.StartCheckpointHash) != 64 {
			return false
		}
		if _, err := hex.DecodeString(c.StartCheckpointHash); err != nil {
			return false
		}
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

func normalizeAPIToken(s string) string {
	return strings.TrimSpace(s)
}

func validateAPIToken(s string) error {
	s = normalizeAPIToken(s)
	if s == "" {
		return nil
	}
	if strings.ContainsAny(s, "/?#") {
		return errors.New("token must not contain /, ?, or #")
	}
	switch strings.ToLower(s) {
	case "api", "track", "healthz", "logo.png", "static", "admin", "broadcast":
		return errors.New("token cannot be a reserved path name (api, track, healthz, logo.png, admin, broadcast)")
	}
	return nil
}

// stripAPITokenPrefix returns the path after /{token} when the first path segment matches token.
func stripAPITokenPrefix(path, token string) (string, bool) {
	token = normalizeAPIToken(token)
	if token == "" {
		return path, false
	}
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	rest := strings.TrimPrefix(path, "/")
	seg, after, found := strings.Cut(rest, "/")
	if subtle.ConstantTimeCompare([]byte(seg), []byte(token)) != 1 {
		return path, false
	}
	if !found {
		return "/", true
	}
	return "/" + after, true
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

func requestWantsHTML(r *http.Request) bool {
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/html") {
		return false
	}
	if strings.Contains(accept, "text/html") {
		return true
	}
	path := r.URL.Path
	if path == "/" || path == "" {
		return true
	}
	if strings.HasPrefix(path, "/api/") || strings.HasPrefix(path, "/track/") || path == "/healthz" || path == "/broadcast" {
		return false
	}
	return true
}

func serveAccessDenied(w http.ResponseWriter, r *http.Request) {
	if requestWantsHTML(r) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Access denied</title>
<style>
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
font-family:"Comic Neue","Comic Sans MS",cursive,system-ui,sans-serif;background:#0c1018;color:#e8edf5;}
.card{max-width:24rem;padding:1.5rem 1.75rem;border:1px solid rgba(255,255,255,.08);border-radius:10px;background:#151d2c;text-align:center;}
h1{margin:0;color:#e85d5d;font-size:1.35rem;}
</style></head><body><div class="card"><h1>Access denied</h1></div></body></html>`)
		return
	}
	writeJSONError(w, http.StatusForbidden, "Access denied")
}

func pathIsUserAllowed(path string) bool {
	return strings.HasPrefix(path, "/track/") || path == "/healthz" || path == "/broadcast"
}

func apiAccessMiddleware(app *appState, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := app.snapshotCfg()
		userTok := normalizeAPIToken(cfg.UserToken)
		adminTok := normalizeAPIToken(cfg.AdminToken)
		rules := normalizeAPIAllowedIPs(cfg.APIAllowedIPs)
		hasIPRules := len(rules) > 0
		hasUserTok := userTok != ""
		hasAdminTok := adminTok != ""

		// No access controls configured: open.
		if !hasIPRules && !hasUserTok && !hasAdminTok {
			next.ServeHTTP(w, r)
			return
		}

		// Admin token: everything (web UI, /api/*, /track/*, /healthz).
		if hasAdminTok {
			if newPath, ok := stripAPITokenPrefix(r.URL.Path, adminTok); ok {
				r2 := r.Clone(r.Context())
				r2.URL.Path = newPath
				next.ServeHTTP(w, r2)
				return
			}
		}

		// User token: /track/*, /healthz, and /broadcast only.
		if hasUserTok {
			if newPath, ok := stripAPITokenPrefix(r.URL.Path, userTok); ok {
				if pathIsUserAllowed(newPath) {
					r2 := r.Clone(r.Context())
					r2.URL.Path = newPath
					next.ServeHTTP(w, r2)
					return
				}
				serveAccessDenied(w, r)
				return
			}
		}

		// Shared IP whitelist: full access (same as admin) without a token.
		cl := clientIPForAPI(r)
		if cl == "" {
			cl = "unknown"
		}
		if hasIPRules && ipAllowedForAPI(cl, rules) {
			next.ServeHTTP(w, r)
			return
		}

		serveAccessDenied(w, r)
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
	htrack       *HeaderTracker
	processed    *ProcessedSet
	peers        *PeerHub
	bloomPeers   *bloomPeerCache
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
	a.cfg = c
	a.mu.Unlock()
	if a.store != nil {
		a.store.SetNetwork(c.Network)
	}
	if a.htrack != nil {
		a.htrack.SetNetwork(c.Network)
		a.htrack.SetStartCheckpoint(c.StartCheckpointHash, c.StartCheckpointHeight)
		a.htrack.EnsureGenesisTipSeed()
	}
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
	a.store.SetNetwork(network)
	if a.htrack != nil {
		a.htrack.SetNetwork(network)
		a.htrack.SetStartCheckpoint(cfg.StartCheckpointHash, cfg.StartCheckpointHeight)
		a.htrack.EnsureGenesisTipSeed()
	}
	host := strings.TrimSpace(cfg.P2PHost)
	if a.bloomPeers == nil {
		a.bloomPeers = newBloomPeerCache()
	}
	blockQ := NewBlockWorkQueue(24)
	blockQ.Run(2, a.store, a.processed, a.mcol, a.htrack, stopCh)
	go mempoolSniffer(a.store, network, host, cfg.P2PPort, cfg.P2PLog, a.mcol, a.htrack, a.processed, a.peers, blockQ, cfg.P2PParallel, cfg.ConfirmMode, a.bloomPeers, stopCh)
	go runMetricsLoop(a.store, a.mcol, stopCh)
	log.Printf("[MTR] P2P mempool watcher started (network=%s, p2p_parallel=%d, confirm_mode=%s)", network, cfg.P2PParallel, normalizeConfirmMode(cfg.ConfirmMode))
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
		"http_port":       cfg.HTTPPort,
		"http_bind":       cfg.HTTPBind,
		"network":         cfg.Network,
		"storage_dir":     app.dataDir,
		"list_limit":      cfg.ListLimit,
		"retention_days":  cfg.RetentionDays,
		"p2p_host":        cfg.P2PHost,
		"p2p_port":        cfg.P2PPort,
		"p2p_parallel":    cfg.P2PParallel,
		"p2p_log":         cfg.P2PLog,
		"confirm_mode":    normalizeConfirmMode(cfg.ConfirmMode),
		"api_allowed_ips": allowCopy,
		"user_token":      cfg.UserToken,
		"admin_token":     cfg.AdminToken,
	}
	hs := map[string]any{}
	if app.htrack != nil {
		hs = app.htrack.Snapshot()
	}
	bloomKnown := 0
	if app.bloomPeers != nil {
		bloomKnown = app.bloomPeers.Count()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"p2p_running":               app.isP2PRunning(),
		"memetracker_config_path":   app.configPath,
		"watched_addresses":         app.store.watcherCount(),
		"stored_transaction_rows":   app.store.StoredTransactionRows(),
		"mempool_tx_count":          app.mcol.snapshot(),
		"mempool_txids_recent":      app.mcol.mempoolRecent(MEMPOOL_UI_RECENT),
		"recent_tx_bodies":          app.mcol.recentTxBodySnapshot(),
		"peers_connected_count":     nConn,
		"peers":                     peerOut,
		"header_safeguard":          hs,
		"confirm_mode":              normalizeConfirmMode(cfg.ConfirmMode),
		"bloom_peers_known":         bloomKnown,
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
			"confirm_mode":        normalizeConfirmMode(cfg.ConfirmMode),
			"list_limit":          ll,
			"retention_days":      rd,
			"settings_file_note":  "list_limit and retention_days sync to settings.json from the Configuration tab when saved",
		},
	})
}

func apiGetMempool(w http.ResponseWriter, r *http.Request, app *appState) {
	if r.Method != http.MethodGet {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	q := r.URL.Query()
	offset, _ := strconv.Atoi(strings.TrimSpace(q.Get("offset")))
	limit, _ := strconv.Atoi(strings.TrimSpace(q.Get("limit")))
	if limit <= 0 {
		limit = MEMPOOL_PAGE_DEFAULT
	}
	if limit > MEMPOOL_PAGE_MAX {
		limit = MEMPOOL_PAGE_MAX
	}
	if offset < 0 {
		offset = 0
	}
	ids, total, nextOffset, hasMore := app.mcol.mempoolPage(offset, limit)
	writeJSON(w, http.StatusOK, map[string]any{
		"txids":       ids,
		"total":       total,
		"offset":      offset,
		"limit":       limit,
		"next_offset": nextOffset,
		"has_more":    hasMore,
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

func apiConfirmTransaction(w http.ResponseWriter, r *http.Request, store *Store, htrack *HeaderTracker) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	txid := strings.TrimSpace(r.URL.Query().Get("txid"))
	hashHex := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("hash160_hex")))
	if r.Header.Get("Content-Type") != "" && strings.Contains(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Txid       string `json:"txid"`
			Hash160Hex string `json:"hash160_hex"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if strings.TrimSpace(body.Txid) != "" {
			txid = strings.TrimSpace(body.Txid)
		}
		if strings.TrimSpace(body.Hash160Hex) != "" {
			hashHex = strings.ToLower(strings.TrimSpace(body.Hash160Hex))
		}
	}
	if txid == "" || hashHex == "" {
		writeJSONError(w, http.StatusBadRequest, "txid and hash160_hex required")
		return
	}
	tipH := int64(-1)
	if htrack != nil {
		tipH = htrack.TipHeight()
	}
	if !store.MarkTxConfirmedManual(hashHex, txid, tipH) {
		writeJSONError(w, http.StatusNotFound, "transaction not found or already confirmed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":            true,
		"txid":          txid,
		"hash160_hex":   hashHex,
		"confirmed":     true,
		"confirmations": MAX_CONFIRMATIONS,
	})
}

func apiPostBroadcast(w http.ResponseWriter, r *http.Request, app *appState) {
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !app.isP2PRunning() {
		writeJSONError(w, http.StatusServiceUnavailable, "P2P watcher is not running")
		return
	}
	var body struct {
		RawTx string `json:"raw_tx"`
		Hex   string `json:"hex"`
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, MAX_BROADCAST_TX_BYTES*2+4096))
	if err := dec.Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	rawHex := body.RawTx
	if strings.TrimSpace(rawHex) == "" {
		rawHex = body.Hex
	}
	raw, err := decodeRawTxHex(rawHex)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	if app.peers == nil || app.peers.ConnectedCount() == 0 {
		writeJSONError(w, http.StatusServiceUnavailable, "no connected peers to transmit to")
		return
	}
	res := app.peers.BroadcastRawTx(raw)
	writeJSON(w, http.StatusOK, res)
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
	body.ApplyDefaults() // migrates legacy api_token â†’ user_token
	if err := validateAPIToken(body.UserToken); err != nil {
		writeJSONError(w, http.StatusBadRequest, "user_token: "+err.Error())
		return
	}
	if err := validateAPIToken(body.AdminToken); err != nil {
		writeJSONError(w, http.StatusBadRequest, "admin_token: "+err.Error())
		return
	}
	if body.UserToken != "" && body.AdminToken != "" && subtle.ConstantTimeCompare([]byte(body.UserToken), []byte(body.AdminToken)) == 1 {
		writeJSONError(w, http.StatusBadRequest, "user_token and admin_token must be different")
		return
	}
	if !body.IsComplete() {
		writeJSONError(w, http.StatusBadRequest, "incomplete configuration: need valid network (mainnet/testnet/reboottestnet), ports, list_limit, retention_days, p2p_parallel 1–8")
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
	if app.isP2PRunning() {
		msg := "Config saved."
		if strings.TrimSpace(body.StartCheckpointHash) != "" {
			msg = "Config saved; header tip jumped to start checkpoint (getheaders will continue from there)."
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":          true,
			"p2p_running": true,
			"message":     msg,
		})
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
		UserToken     *string  `json:"user_token"`  // user token; omit to leave unchanged, "" to clear
		APIToken      *string  `json:"api_token"`   // legacy alias for user_token
		AdminToken    *string  `json:"admin_token"` // admin token; omit to leave unchanged, "" to clear
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid json")
		return
	}
	normalized := normalizeAPIAllowedIPs(body.APIAllowedIPs)
	app.mu.Lock()
	app.cfg.APIAllowedIPs = normalized
	var userPtr *string
	if body.UserToken != nil {
		userPtr = body.UserToken
	} else if body.APIToken != nil {
		userPtr = body.APIToken
	}
	if userPtr != nil {
		tok := normalizeAPIToken(*userPtr)
		if err := validateAPIToken(tok); err != nil {
			app.mu.Unlock()
			writeJSONError(w, http.StatusBadRequest, "user_token: "+err.Error())
			return
		}
		app.cfg.UserToken = tok
	}
	if body.AdminToken != nil {
		tok := normalizeAPIToken(*body.AdminToken)
		if err := validateAPIToken(tok); err != nil {
			app.mu.Unlock()
			writeJSONError(w, http.StatusBadRequest, "admin_token: "+err.Error())
			return
		}
		app.cfg.AdminToken = tok
	}
	if app.cfg.UserToken != "" && app.cfg.AdminToken != "" &&
		subtle.ConstantTimeCompare([]byte(app.cfg.UserToken), []byte(app.cfg.AdminToken)) == 1 {
		app.mu.Unlock()
		writeJSONError(w, http.StatusBadRequest, "user_token and admin_token must be different")
		return
	}
	app.cfg.APIToken = ""
	cfgCopy := app.cfg
	app.mu.Unlock()
	if err := writeMemeTrackerConfigFile(app.configPath, &cfgCopy); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":              true,
		"api_allowed_ips": normalized,
		"user_token":      cfgCopy.UserToken,
		"admin_token":     cfgCopy.AdminToken,
	})
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
	store.SetNetwork(network)

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
	htrack := NewHeaderTracker(storageDir)
	htrack.SetNetwork(network)
	if tip := htrack.TipHash(); tip != "" {
		log.Printf("[MTR] header tip resumed from disk hash=%s path=%s", tip, filepath.Join(storageDir, headerTipFileName))
	}
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
		ConfirmMode:   ConfirmModeMsgBlock,
	}
	effectiveCfg.ApplyDefaults()
	if configFileRead {
		effectiveCfg.ConfirmMode = normalizeConfirmMode(fileCfg.ConfirmMode)
		effectiveCfg.StartCheckpointHash = fileCfg.StartCheckpointHash
		effectiveCfg.StartCheckpointHeight = fileCfg.StartCheckpointHeight
		effectiveCfg.APIAllowedIPs = normalizeAPIAllowedIPs(fileCfg.APIAllowedIPs)
		fileCfg.ApplyDefaults() // migrates legacy api_token → user_token
		effectiveCfg.StartCheckpointHash = fileCfg.StartCheckpointHash
		effectiveCfg.StartCheckpointHeight = fileCfg.StartCheckpointHeight
		effectiveCfg.UserToken = fileCfg.UserToken
		effectiveCfg.AdminToken = fileCfg.AdminToken
		if err := validateAPIToken(effectiveCfg.UserToken); err != nil {
			log.Printf("[MTR] warning: ignoring invalid user_token in config: %v", err)
			effectiveCfg.UserToken = ""
		}
		if err := validateAPIToken(effectiveCfg.AdminToken); err != nil {
			log.Printf("[MTR] warning: ignoring invalid admin_token in config: %v", err)
			effectiveCfg.AdminToken = ""
		}
		if effectiveCfg.UserToken != "" && effectiveCfg.AdminToken != "" &&
			subtle.ConstantTimeCompare([]byte(effectiveCfg.UserToken), []byte(effectiveCfg.AdminToken)) == 1 {
			log.Printf("[MTR] warning: user_token and admin_token were identical; clearing admin_token")
			effectiveCfg.AdminToken = ""
		}
	}
	htrack.SetStartCheckpoint(effectiveCfg.StartCheckpointHash, effectiveCfg.StartCheckpointHeight)
	htrack.EnsureGenesisTipSeed()
	if tip := htrack.TipHash(); tip != "" {
		log.Printf("[MTR] header tip ready hash=%s height=%d path=%s", tip, htrack.TipHeight(), filepath.Join(storageDir, headerTipFileName))
	}
	if envTok := normalizeAPIToken(firstNonEmpty(os.Getenv("MTR_USER_TOKEN"), os.Getenv("MTR_API_TOKEN"))); envTok != "" {
		if err := validateAPIToken(envTok); err != nil {
			log.Fatalf("invalid user token env: %v", err)
		}
		effectiveCfg.UserToken = envTok
	}
	if envAdmin := normalizeAPIToken(os.Getenv("MTR_ADMIN_TOKEN")); envAdmin != "" {
		if err := validateAPIToken(envAdmin); err != nil {
			log.Fatalf("invalid MTR_ADMIN_TOKEN: %v", err)
		}
		effectiveCfg.AdminToken = envAdmin
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
		htrack:       htrack,
		processed:    processed,
		peers:        NewPeerHub(),
		bloomPeers:   newBloomPeerCache(),
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
		cfg := app.snapshotCfg()
		_, nConn := app.mcol.snapshotPeers()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"p2p_running":           app.isP2PRunning(),
			"peers_connected_count": nConn,
			"network":               strings.ToLower(cfg.Network),
		})
	})

	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		apiStatus(w, r, app)
	})
	mux.HandleFunc("/api/mempool", func(w http.ResponseWriter, r *http.Request) {
		apiGetMempool(w, r, app)
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
	mux.HandleFunc("/api/transactions/confirm", func(w http.ResponseWriter, r *http.Request) {
		apiConfirmTransaction(w, r, app.store, app.htrack)
	})
	mux.HandleFunc("/api/broadcast", func(w http.ResponseWriter, r *http.Request) {
		apiPostBroadcast(w, r, app)
	})
	mux.HandleFunc("/broadcast", func(w http.ResponseWriter, r *http.Request) {
		apiPostBroadcast(w, r, app)
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
		_, recents, _, err := app.store.UpsertTracking(addr, hash160, callbackURL)
		if err != nil {
			http.Error(w, "storage error: "+err.Error(), http.StatusInternalServerError)
			return
		}
		ll, rd := app.store.Limits()
		// Public track payload: confirmations only (0 = mempool / not yet in a block).
		txs := make([]map[string]any, 0, len(recents))
		for _, tx := range recents {
			row := map[string]any{
				"txid":          tx.Txid,
				"vout":          tx.Vout,
				"utxo":          tx.Utxo,
				"datetime":      tx.Datetime,
				"amount_doge":   tx.AmountDoge,
				"double_spent":  tx.DoubleSpent,
				"confirmations": clampConfirmations(tx.Confirmations),
			}
			if tx.BlockHeight != 0 {
				row["block_height"] = tx.BlockHeight
			}
			if tx.FromAddress != "" {
				row["from_address"] = tx.FromAddress
			}
			if len(tx.FromAddresses) > 0 {
				row["from_addresses"] = tx.FromAddresses
			}
			txs = append(txs, row)
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"address":         addr,
			"monitored":       true,
			"retention_days":  rd,
			"stored_tx_limit": ll,
			"transactions":    txs,
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
