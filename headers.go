package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

const (
	MSG_BLOCK              = 2
	AUXPOW_VERSION_BIT     = uint32(1 << 8)
	HEADER_RETENTION       = 24 * time.Hour
	MAX_HEADER_RING        = 2000
	MAX_BLOCK_FETCH_INV    = 8
	MAX_PENDING_BLOCKS     = 64
	GETHEADERS_TOPUP_SEC   = 45
	PROTOCOL_VERSION_HEADERS = int32(70015)
)

type storedHeader struct {
	HashHex string
	PrevHex string
	Time    time.Time
	Header80 []byte
}

// HeaderTracker keeps a rolling ~24h window of headers and tracks which
// block bodies were scanned for watched payments (mempool miss safeguard).
type HeaderTracker struct {
	mu             sync.RWMutex
	byHash         map[string]*storedHeader
	order          []string // oldest -> newest hash hex
	scanned        map[string]struct{}
	pending        map[string]struct{}
	tipHash        string
	tipTime        time.Time
	headersSeen    int64
	blocksScanned  int64
	confirmedHits  int64
	walkBackDone   bool
}

func NewHeaderTracker() *HeaderTracker {
	return &HeaderTracker{
		byHash:  make(map[string]*storedHeader),
		scanned: make(map[string]struct{}),
		pending: make(map[string]struct{}),
	}
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

func (h *HeaderTracker) Snapshot() map[string]any {
	h.mu.RLock()
	defer h.mu.RUnlock()
	tipTime := ""
	if !h.tipTime.IsZero() {
		tipTime = h.tipTime.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"tip_hash":               h.tipHash,
		"tip_time_utc":           tipTime,
		"headers_kept":           len(h.byHash),
		"headers_seen_total":     h.headersSeen,
		"blocks_scanned":         h.blocksScanned,
		"confirmed_hits":         h.confirmedHits,
		"pending_block_fetches":  len(h.pending),
		"retention":              HEADER_RETENTION.String(),
	}
}

func (h *HeaderTracker) TipHash() string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.tipHash
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
	if _, exists := h.byHash[hashHex]; exists {
		h.pruneLocked(time.Now().UTC())
		return hashHex, false
	}
	h.byHash[hashHex] = &storedHeader{
		HashHex:  hashHex,
		PrevHex:  prev,
		Time:     ts,
		Header80: cp,
	}
	h.order = append(h.order, hashHex)
	h.headersSeen++
	if h.tipHash == "" || ts.After(h.tipTime) || (ts.Equal(h.tipTime) && hashHex > h.tipHash) {
		h.tipHash = hashHex
		h.tipTime = ts
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
	// Walk from tip backwards until missing parent within retention.
	cur := h.tipHash
	for steps := 0; steps < MAX_HEADER_RING; steps++ {
		sh, ok := h.byHash[cur]
		if !ok {
			return ""
		}
		if sh.Time.Before(cutoff) {
			h.walkBackDone = true
			return ""
		}
		prev := sh.PrevHex
		if prev == "" || prev == "0000000000000000000000000000000000000000000000000000000000000000" {
			h.walkBackDone = true
			return ""
		}
		if _, ok := h.byHash[prev]; !ok {
			if _, pending := h.pending[prev]; pending {
				return ""
			}
			if _, scanned := h.scanned[prev]; scanned {
				// Have body but not header entry; still try once via getdata.
			}
			return prev
		}
		cur = prev
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
		sh, ok := h.byHash[cur]
		if !ok {
			break
		}
		wire, err := wireHashFromDisplayHex(sh.HashHex)
		if err != nil {
			break
		}
		var arr [32]byte
		copy(arr[:], wire)
		out = append(out, arr)
		// Exponential-ish walk using stored prev links.
		next := sh.PrevHex
		for i := 1; i < step && next != ""; i++ {
			nsh, ok2 := h.byHash[next]
			if !ok2 {
				next = ""
				break
			}
			next = nsh.PrevHex
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
		sh, ok := h.byHash[oldest]
		if !ok {
			h.order = h.order[1:]
			continue
		}
		if len(h.order) > MAX_HEADER_RING || sh.Time.Before(cutoff) {
			delete(h.byHash, oldest)
			delete(h.scanned, oldest)
			delete(h.pending, oldest)
			h.order = h.order[1:]
			if h.tipHash == oldest {
				h.tipHash = ""
				h.tipTime = time.Time{}
				if len(h.order) > 0 {
					newest := h.order[len(h.order)-1]
					if nsh, ok2 := h.byHash[newest]; ok2 {
						h.tipHash = nsh.HashHex
						h.tipTime = nsh.Time
					}
				}
			}
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
