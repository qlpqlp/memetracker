package main

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	MSG_BLOCK                 = 2
	AUXPOW_VERSION_BIT        = uint32(1 << 8)
	HEADER_RETENTION          = 24 * time.Hour
	// Block bodies are backup-only (missed mempool -> mined). Keep this tiny so mempool wins.
	BLOCK_BODY_SCAN_MAX_AGE   = 30 * time.Minute
	BLOCK_BODY_SCAN_MAX_DEPTH = 3
	MAX_HEADER_RING           = 2000
	MAX_BLOCK_FETCH_INV       = 1
	MAX_PENDING_BLOCKS        = 2
	GETHEADERS_TOPUP_SEC      = 120 // slower while watching payments
	GETHEADERS_TOPUP_IDLE_SEC = 45  // faster tip tracking when no watchers
	PROTOCOL_VERSION_HEADERS  = int32(70015)
	headerTipFileName         = "header_tip.json"
)

type storedHeader struct {
	HashHex  string
	PrevHex  string
	Time     time.Time
	Height   int64 // -1 if unknown
	Header80 []byte
}

type headerTipDisk struct {
	TipHash        string `json:"tip_hash"`
	TipTimeUTC     string `json:"tip_time_utc"`
	TipHeight      int64  `json:"tip_height"`
	TipHeader80Hex string `json:"tip_header80_hex"`
	UpdatedUTC     string `json:"updated_utc"`
}

// HeaderTracker keeps a rolling ~24h window of headers for tip resume/locators.
// Full block downloads are a backup path only: catch watched payments that skipped
// mempool relay and landed in a block. Mempool watching must stay first priority.
type HeaderTracker struct {
	mu            sync.RWMutex
	byHash        map[string]*storedHeader
	order         []string // oldest -> newest hash hex
	scanned       map[string]struct{}
	pending       map[string]struct{}
	tipHash       string
	tipTime       time.Time
	tipHeight     int64 // -1 unknown
	tipHeader80   []byte
	persistPath   string
	headersSeen   int64
	blocksScanned int64
	confirmedHits int64
	walkBackDone  bool
	loadedFromDisk bool
}

func NewHeaderTracker(persistDir string) *HeaderTracker {
	h := &HeaderTracker{
		byHash:    make(map[string]*storedHeader),
		scanned:   make(map[string]struct{}),
		pending:   make(map[string]struct{}),
		tipHeight: -1,
	}
	if persistDir != "" {
		h.persistPath = filepath.Join(persistDir, headerTipFileName)
		h.mu.Lock()
		h.loadTipLocked()
		h.mu.Unlock()
	}
	return h
}

func headerHashHex(h80 []byte) string {
	if len(h80) != 80 {
		return ""
	}
	sum := sha256d(h80)
	return reverseBytesToHex(sum[:])
}

func headerPrevHashHex(h80 []byte) string {
	if len(h80) != 80 {
		return ""
	}
	return reverseBytesToHex(h80[4:36])
}

func headerTimestamp(h80 []byte) time.Time {
	if len(h80) != 80 {
		return time.Time{}
	}
	sec := binary.LittleEndian.Uint32(h80[68:72])
	return time.Unix(int64(sec), 0).UTC()
}

func wireHashFromDisplayHex(hashHex string) ([]byte, error) {
	b, err := hex.DecodeString(hashHex)
	if err != nil || len(b) != 32 {
		return nil, errors.New("bad hash hex")
	}
	out := make([]byte, 32)
	for i := 0; i < 32; i++ {
		out[i] = b[31-i]
	}
	return out, nil
}

func (h *HeaderTracker) loadTipLocked() {
	if h.persistPath == "" {
		return
	}
	b, err := os.ReadFile(h.persistPath)
	if err != nil || len(b) == 0 {
		return
	}
	var disk headerTipDisk
	if json.Unmarshal(b, &disk) != nil {
		return
	}
	disk.TipHash = strings.TrimSpace(strings.ToLower(disk.TipHash))
	if disk.TipHash == "" || len(disk.TipHash) != 64 {
		return
	}
	height := disk.TipHeight
	if height < -1 {
		height = -1
	}
	ts := time.Time{}
	if disk.TipTimeUTC != "" {
		if t, err := time.Parse(time.RFC3339, disk.TipTimeUTC); err == nil {
			ts = t.UTC()
		}
	}
	h80, err := hex.DecodeString(strings.TrimSpace(disk.TipHeader80Hex))
	if err == nil && len(h80) == 80 && headerHashHex(h80) == disk.TipHash {
		if ts.IsZero() {
			ts = headerTimestamp(h80)
		}
		cp := append([]byte(nil), h80...)
		h.byHash[disk.TipHash] = &storedHeader{
			HashHex:  disk.TipHash,
			PrevHex:  headerPrevHashHex(h80),
			Time:     ts,
			Height:   height,
			Header80: cp,
		}
		h.order = append(h.order, disk.TipHash)
		h.tipHeader80 = cp
		h.scanned[disk.TipHash] = struct{}{}
		h.headersSeen = 1
	} else {
		// Locator-only resume seed (hash known, header bytes missing).
		h.byHash[disk.TipHash] = &storedHeader{
			HashHex: disk.TipHash,
			Time:    ts,
			Height:  height,
		}
		h.order = append(h.order, disk.TipHash)
		h.headersSeen = 1
	}
	h.tipHash = disk.TipHash
	h.tipTime = ts
	h.tipHeight = height
	h.loadedFromDisk = true
}

func (h *HeaderTracker) saveTipLocked() {
	if h.persistPath == "" || h.tipHash == "" {
		return
	}
	disk := headerTipDisk{
		TipHash:    h.tipHash,
		TipHeight:  h.tipHeight,
		UpdatedUTC: time.Now().UTC().Format(time.RFC3339),
	}
	if !h.tipTime.IsZero() {
		disk.TipTimeUTC = h.tipTime.UTC().Format(time.RFC3339)
	}
	if len(h.tipHeader80) == 80 {
		disk.TipHeader80Hex = hex.EncodeToString(h.tipHeader80)
	} else if sh, ok := h.byHash[h.tipHash]; ok && len(sh.Header80) == 80 {
		disk.TipHeader80Hex = hex.EncodeToString(sh.Header80)
	}
	b, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return
	}
	_ = os.MkdirAll(filepath.Dir(h.persistPath), 0o755)
	tmp := h.persistPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return
	}
	_ = os.Rename(tmp, h.persistPath)
}

func (h *HeaderTracker) Snapshot() map[string]any {
	h.mu.RLock()
	defer h.mu.RUnlock()
	tipTime := ""
	if !h.tipTime.IsZero() {
		tipTime = h.tipTime.UTC().Format(time.RFC3339)
	}
	var tipHeight any
	if h.tipHeight >= 0 {
		tipHeight = h.tipHeight
	} else {
		tipHeight = nil
	}
	return map[string]any{
		"tip_hash":              h.tipHash,
		"tip_height":            tipHeight,
		"tip_time_utc":          tipTime,
		"headers_kept":          len(h.byHash),
		"headers_seen_total":    h.headersSeen,
		"blocks_scanned":        h.blocksScanned,
		"confirmed_hits":        h.confirmedHits,
		"pending_block_fetches": len(h.pending),
		"retention":             HEADER_RETENTION.String(),
		"persist_path":          h.persistPath,
		"resumed_from_disk":     h.loadedFromDisk,
	}
}

func (h *HeaderTracker) TipHash() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.tipHash
}

func (h *HeaderTracker) TipHeight() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.tipHeight
}

func (h *HeaderTracker) HeaderHeight(hashHex string) int64 {
	if hashHex == "" {
		return -1
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if sh, ok := h.byHash[hashHex]; ok {
		return sh.Height
	}
	return -1
}

func (h *HeaderTracker) HasHeader(hashHex string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.byHash[hashHex]
	return ok
}

func (h *HeaderTracker) AlreadyScanned(hashHex string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	_, ok := h.scanned[hashHex]
	return ok
}

func (h *HeaderTracker) MarkScanned(hashHex string) {
	if hashHex == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.scanned[hashHex]; !ok {
		h.scanned[hashHex] = struct{}{}
		h.blocksScanned++
	}
	delete(h.pending, hashHex)
}

func (h *HeaderTracker) AddConfirmedHits(n int) {
	if n <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.confirmedHits += int64(n)
}

func (h *HeaderTracker) MarkPending(hashHex string) bool {
	if hashHex == "" {
		return false
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.scanned[hashHex]; ok {
		return false
	}
	if _, ok := h.pending[hashHex]; ok {
		return false
	}
	if len(h.pending) >= MAX_PENDING_BLOCKS {
		return false
	}
	h.pending[hashHex] = struct{}{}
	return true
}

func (h *HeaderTracker) ClearPending(hashHex string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.pending, hashHex)
}

func (h *HeaderTracker) NeedBlock(hashHex string) bool {
	if hashHex == "" {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if _, ok := h.scanned[hashHex]; ok {
		return false
	}
	if _, ok := h.pending[hashHex]; ok {
		return false
	}
	return true
}

// WantBlockBody is true only for recent tip-area blocks. Older headers stay in the
// 24h ring for resume/locators but must not flood P2P with full-block downloads
// (that starves mempool inv/getdata).
func (h *HeaderTracker) WantBlockBody(hashHex string) bool {
	if hashHex == "" {
		return false
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if hashHex == h.tipHash {
		return true
	}
	sh, ok := h.byHash[hashHex]
	if !ok {
		// Unknown hash from inv: allow (likely a new tip announcement).
		return true
	}
	if !sh.Time.IsZero() && time.Since(sh.Time) <= BLOCK_BODY_SCAN_MAX_AGE {
		return true
	}
	if h.tipHeight >= 0 && sh.Height >= 0 && (h.tipHeight-sh.Height) >= 0 && (h.tipHeight-sh.Height) <= BLOCK_BODY_SCAN_MAX_DEPTH {
		return true
	}
	return false
}

func (h *HeaderTracker) markHeaderOnlyLocked(hashHex string) {
	if hashHex == "" || hashHex == h.tipHash {
		return
	}
	if _, ok := h.scanned[hashHex]; !ok {
		h.scanned[hashHex] = struct{}{}
	}
	delete(h.pending, hashHex)
}

// NotePeerStartHeight adopts peer tip height only when our tip looks current
// (so long catch-up from a resumed old tip does not stamp the wrong height).
func (h *HeaderTracker) NotePeerStartHeight(peerHeight int32) {
	if peerHeight <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tipHash == "" {
		return
	}
	if h.tipHeight >= 0 {
		return
	}
	if h.tipTime.IsZero() || time.Since(h.tipTime) > 30*time.Minute {
		return
	}
	h.tipHeight = int64(peerHeight)
	if sh, ok := h.byHash[h.tipHash]; ok {
		sh.Height = h.tipHeight
	}
	h.saveTipLocked()
}

func (h *HeaderTracker) RememberHeader80(h80 []byte) (hashHex string, isNew bool) {
	if len(h80) != 80 {
		return "", false
	}
	hashHex = headerHashHex(h80)
	prev := headerPrevHashHex(h80)
	ts := headerTimestamp(h80)
	cp := make([]byte, 80)
	copy(cp, h80)

	h.mu.Lock()
	defer h.mu.Unlock()
	if existing, exists := h.byHash[hashHex]; exists {
		if len(existing.Header80) != 80 {
			existing.Header80 = cp
			existing.PrevHex = prev
			existing.Time = ts
		}
		if h.tipHash == hashHex && len(h.tipHeader80) != 80 {
			h.tipHeader80 = cp
			h.tipTime = ts
			h.saveTipLocked()
		}
		h.pruneLocked(time.Now().UTC())
		return hashHex, false
	}

	height := int64(-1)
	if psh, ok := h.byHash[prev]; ok && psh.Height >= 0 {
		height = psh.Height + 1
	} else if h.tipHash != "" && prev == h.tipHash && h.tipHeight >= 0 {
		height = h.tipHeight + 1
	}

	h.byHash[hashHex] = &storedHeader{
		HashHex:  hashHex,
		PrevHex:  prev,
		Time:     ts,
		Height:   height,
		Header80: cp,
	}
	h.order = append(h.order, hashHex)
	h.headersSeen++

	extendsTip := h.tipHash == "" || prev == h.tipHash
	if extendsTip {
		if h.tipHeight >= 0 && prev == h.tipHash {
			height = h.tipHeight + 1
			h.byHash[hashHex].Height = height
		}
		h.tipHash = hashHex
		h.tipTime = ts
		h.tipHeader80 = cp
		if height >= 0 {
			h.tipHeight = height
		}
		h.saveTipLocked()
	} else if !h.tipTime.IsZero() && ts.After(h.tipTime) {
		h.tipHash = hashHex
		h.tipTime = ts
		h.tipHeader80 = cp
		if height >= 0 {
			h.tipHeight = height
		} else {
			h.tipHeight = -1
		}
		h.saveTipLocked()
	}

	// Keep old headers for the 24h ring/locator, but do not schedule full body downloads.
	if hashHex != h.tipHash {
		tooOld := !ts.IsZero() && time.Since(ts) > BLOCK_BODY_SCAN_MAX_AGE
		tooDeep := h.tipHeight >= 0 && height >= 0 && (h.tipHeight-height) > BLOCK_BODY_SCAN_MAX_DEPTH
		if tooOld || tooDeep {
			h.markHeaderOnlyLocked(hashHex)
		}
	}

	h.pruneLocked(time.Now().UTC())
	return hashHex, true
}

func (h *HeaderTracker) ParentToBackfill() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.tipHash == "" {
		return ""
	}
	cutoff := time.Now().UTC().Add(-HEADER_RETENTION)
	cur := h.tipHash
	for steps := 0; steps < MAX_HEADER_RING; steps++ {
		sh, ok := h.byHash[cur]
		if !ok || len(sh.Header80) != 80 {
			return ""
		}
		if sh.Time.Before(cutoff) {
			h.walkBackDone = true
			return ""
		}
		// Only walk parents that are still inside the recent body-scan window.
		if !sh.Time.IsZero() && time.Since(sh.Time) > BLOCK_BODY_SCAN_MAX_AGE {
			h.walkBackDone = true
			return ""
		}
		prev := sh.PrevHex
		if prev == "" || prev == "0000000000000000000000000000000000000000000000000000000000000000" {
			h.walkBackDone = true
			return ""
		}
		if psh, ok := h.byHash[prev]; ok {
			if !psh.Time.IsZero() && time.Since(psh.Time) > BLOCK_BODY_SCAN_MAX_AGE {
				h.walkBackDone = true
				return ""
			}
			if _, scanned := h.scanned[prev]; !scanned {
				if _, pending := h.pending[prev]; pending {
					return ""
				}
				return prev
			}
			cur = prev
			continue
		}
		if _, pending := h.pending[prev]; pending {
			return ""
		}
		return prev
	}
	return ""
}

func (h *HeaderTracker) LocatorHashes(max int) [][32]byte {
	if max <= 0 {
		max = 101
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	if h.tipHash == "" {
		return nil
	}
	out := make([][32]byte, 0, max)
	seen := make(map[string]struct{})
	cur := h.tipHash
	step := 1
	for len(out) < max && cur != "" {
		if _, ok := seen[cur]; ok {
			break
		}
		seen[cur] = struct{}{}
		wire, err := wireHashFromDisplayHex(cur)
		if err != nil {
			break
		}
		var arr [32]byte
		copy(arr[:], wire)
		out = append(out, arr)

		next := ""
		if sh, ok := h.byHash[cur]; ok {
			next = sh.PrevHex
			for i := 1; i < step && next != ""; i++ {
				nsh, ok2 := h.byHash[next]
				if !ok2 {
					next = ""
					break
				}
				next = nsh.PrevHex
			}
		}
		if step < 128 {
			step *= 2
		}
		cur = next
	}
	return out
}

func (h *HeaderTracker) pruneLocked(now time.Time) {
	cutoff := now.Add(-HEADER_RETENTION)
	for len(h.order) > 0 {
		oldest := h.order[0]
		if oldest == h.tipHash {
			if len(h.order) == 1 {
				break
			}
			h.order = append(h.order[1:], oldest)
			continue
		}
		sh, ok := h.byHash[oldest]
		if !ok {
			h.order = h.order[1:]
			continue
		}
		if len(h.order) > MAX_HEADER_RING || (!sh.Time.IsZero() && sh.Time.Before(cutoff)) {
			delete(h.byHash, oldest)
			delete(h.scanned, oldest)
			delete(h.pending, oldest)
			h.order = h.order[1:]
			continue
		}
		break
	}
}

func buildGetHeadersPayload(locator [][32]byte) []byte {
	if len(locator) > 101 {
		locator = locator[:101]
	}
	buf := make([]byte, 0, 4+9+len(locator)*32+32)
	tmp := make([]byte, 4)
	binary.LittleEndian.PutUint32(tmp, uint32(PROTOCOL_VERSION_HEADERS))
	buf = append(buf, tmp...)
	buf = append(buf, writeVarInt(len(locator))...)
	for _, h := range locator {
		buf = append(buf, h[:]...)
	}
	buf = append(buf, make([]byte, 32)...) // hash_stop = zero
	return buf
}

func skipTxRaw(data []byte, off *int) error {
	if *off+4 > len(data) {
		return errors.New("truncated_tx_version")
	}
	*off += 4
	isSegwit := false
	if *off+2 <= len(data) && data[*off] == 0 && data[*off+1] == 1 {
		isSegwit = true
		*off += 2
	}
	nin, err := readVarInt(data, off)
	if err != nil {
		return err
	}
	if nin > maxVarIntSlice {
		return errors.New("vin too large")
	}
	for i := uint64(0); i < nin; i++ {
		if *off+36 > len(data) {
			return errors.New("truncated_txin")
		}
		*off += 36
		slen, err := readVarInt(data, off)
		if err != nil {
			return err
		}
		if !offsetAdd(off, slen, len(data)) {
			return errors.New("truncated_scriptSig")
		}
		if *off+4 > len(data) {
			return errors.New("truncated_sequence")
		}
		*off += 4
	}
	nout, err := readVarInt(data, off)
	if err != nil {
		return err
	}
	if nout > maxVarIntSlice {
		return errors.New("vout too large")
	}
	for i := uint64(0); i < nout; i++ {
		if *off+8 > len(data) {
			return errors.New("truncated_value")
		}
		*off += 8
		slen, err := readVarInt(data, off)
		if err != nil {
			return err
		}
		if !offsetAdd(off, slen, len(data)) {
			return errors.New("truncated_pk_script")
		}
	}
	if isSegwit {
		for i := uint64(0); i < nin; i++ {
			nstk, err := readVarInt(data, off)
			if err != nil {
				return err
			}
			for j := uint64(0); j < nstk; j++ {
				elen, err := readVarInt(data, off)
				if err != nil {
					return err
				}
				if !offsetAdd(off, elen, len(data)) {
					return errors.New("truncated_witness")
				}
			}
		}
	}
	if *off+4 > len(data) {
		return errors.New("truncated_locktime")
	}
	*off += 4
	return nil
}

func skipAuxPow(data []byte, off *int) error {
	if err := skipTxRaw(data, off); err != nil {
		return fmt.Errorf("auxpow coinbase: %w", err)
	}
	if *off+32 > len(data) {
		return errors.New("auxpow hashblock truncated")
	}
	*off += 32
	nMB, err := readVarInt(data, off)
	if err != nil {
		return err
	}
	if nMB > 64 {
		return errors.New("auxpow merkle branch too long")
	}
	if !offsetAdd(off, nMB*32, len(data)) {
		return errors.New("auxpow merkle branch truncated")
	}
	if *off+4 > len(data) {
		return errors.New("auxpow merkle index truncated")
	}
	*off += 4
	nCB, err := readVarInt(data, off)
	if err != nil {
		return err
	}
	if nCB > 64 {
		return errors.New("auxpow chain branch too long")
	}
	if !offsetAdd(off, nCB*32, len(data)) {
		return errors.New("auxpow chain branch truncated")
	}
	if *off+4 > len(data) {
		return errors.New("auxpow chain index truncated")
	}
	*off += 4
	if *off+80 > len(data) {
		return errors.New("auxpow parent header truncated")
	}
	*off += 80
	return nil
}

// decodeHeadersPayload returns 80-byte header slices from a headers P2P message.
func decodeHeadersPayload(payload []byte) ([][]byte, error) {
	off := 0
	n, err := readVarInt(payload, &off)
	if err != nil {
		return nil, err
	}
	if n > 2000 {
		return nil, fmt.Errorf("too many headers %d", n)
	}
	out := make([][]byte, 0, int(n))
	for i := uint64(0); i < n; i++ {
		if off+80 > len(payload) {
			return nil, errors.New("truncated header")
		}
		h80 := make([]byte, 80)
		copy(h80, payload[off:off+80])
		off += 80
		ver := binary.LittleEndian.Uint32(h80[0:4])
		if ver&AUXPOW_VERSION_BIT != 0 {
			if err := skipAuxPow(payload, &off); err != nil {
				return nil, fmt.Errorf("header %d auxpow: %w", i, err)
			}
		}
		nTx, err := readVarInt(payload, &off)
		if err != nil {
			return nil, err
		}
		if nTx != 0 {
			return nil, fmt.Errorf("header %d: expected 0 tx count, got %d", i, nTx)
		}
		out = append(out, h80)
	}
	return out, nil
}

func forEachBlockTxRaw(block []byte, fn func(idx int, txRaw []byte) error) error {
	if len(block) < 81 {
		return errors.New("block too short")
	}
	off := 80
	ver := binary.LittleEndian.Uint32(block[0:4])
	if ver&AUXPOW_VERSION_BIT != 0 {
		if err := skipAuxPow(block, &off); err != nil {
			return fmt.Errorf("block auxpow: %w", err)
		}
	}
	nTx, err := readVarInt(block, &off)
	if err != nil {
		return err
	}
	if nTx == 0 {
		return errors.New("zero transactions")
	}
	if nTx > 200000 {
		return fmt.Errorf("excessive tx count %d", nTx)
	}
	for i := 0; i < int(nTx); i++ {
		start := off
		if err := skipTxRaw(block, &off); err != nil {
			return fmt.Errorf("tx %d: %w", i, err)
		}
		raw := make([]byte, off-start)
		copy(raw, block[start:off])
		if err := fn(i, raw); err != nil {
			return err
		}
	}
	return nil
}

func invTypeIsBlock(t int) bool {
	base := t & ^MSG_WITNESS_FLAG
	return base == MSG_BLOCK
}

func buildBlockGetdata(hashHexes []string) []byte {
	items := make([]invItem, 0, len(hashHexes))
	for _, hx := range hashHexes {
		wire, err := wireHashFromDisplayHex(hx)
		if err != nil {
			continue
		}
		items = append(items, invItem{invType: MSG_BLOCK, hash: wire})
	}
	if len(items) == 0 {
		return nil
	}
	return buildGetdataPayload(items)
}
