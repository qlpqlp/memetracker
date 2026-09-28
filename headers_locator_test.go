package main

import (
	"encoding/binary"
	"testing"
	"time"
)

func TestLocatorHashesColdStartUsesGenesis(t *testing.T) {
	h := NewHeaderTracker("")
	h.SetNetwork("mainnet")
	loc := h.LocatorHashes(101)
	if len(loc) != 1 {
		t.Fatalf("cold-start locator len=%d want 1 (genesis)", len(loc))
	}
	wire, err := wireHashFromDisplayHex(mainnetGenesisHashHex)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		if loc[0][i] != wire[i] {
			t.Fatalf("locator is not mainnet genesis")
		}
	}
}

func TestLocatorHashesRebootGenesis(t *testing.T) {
	h := NewHeaderTracker("")
	h.SetNetwork("reboottestnet")
	loc := h.LocatorHashes(101)
	if len(loc) != 1 {
		t.Fatalf("reboot cold-start locator len=%d want 1", len(loc))
	}
	wire, err := wireHashFromDisplayHex(rebootTestnetGenesisHashHex)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		if loc[0][i] != wire[i] {
			t.Fatalf("locator is not reboot testnet genesis from dogego")
		}
	}
}

func TestLocatorHashesUsesConfiguredCheckpoint(t *testing.T) {
	const cp = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	h := NewHeaderTracker("")
	h.SetNetwork("mainnet")
	h.SetStartCheckpoint(cp, 123456)
	loc := h.LocatorHashes(101)
	if len(loc) < 1 {
		t.Fatal("expected locator")
	}
	wire, err := wireHashFromDisplayHex(cp)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		if loc[0][i] != wire[i] {
			t.Fatalf("locator[0] is not configured checkpoint")
		}
	}
	if h.TipHash() != cp {
		t.Fatalf("tip seeded=%q want %q", h.TipHash(), cp)
	}
	if h.TipHeight() != 123456 {
		t.Fatalf("tip height=%d want 123456", h.TipHeight())
	}
}

func TestCheckpointJumpsOverGenesisWalk(t *testing.T) {
	const cp = "cc4ea83ae0882b21a54912dc5fc288d02662cf95dee0adf48ca249da61fc0a3d"
	h := NewHeaderTracker("")
	h.SetNetwork("mainnet")
	// Simulate a tip stuck mid-genesis walk (no height, old hash).
	h.mu.Lock()
	h.tipHash = "3150255d3cb2af7acab8883141a590322483e4532a82de0690952d2228075643"
	h.tipHeight = -1
	h.tipTime = time.Date(2015, 8, 13, 16, 48, 9, 0, time.UTC)
	h.mu.Unlock()

	h.SetStartCheckpoint(cp, 6393155)
	if h.TipHash() != cp {
		t.Fatalf("tip=%q want checkpoint", h.TipHash())
	}
	if h.TipHeight() != 6393155 {
		t.Fatalf("height=%d want 6393155", h.TipHeight())
	}
	if !h.NeedsHeaderSync() {
		t.Fatal("checkpoint seed without header80 should still need header sync")
	}
}

func TestGenesisTipSeedAdvancesHeight(t *testing.T) {
	h := NewHeaderTracker("")
	h.SetNetwork("mainnet")
	h.EnsureGenesisTipSeed()
	if h.TipHash() != mainnetGenesisHashHex {
		t.Fatalf("tip=%q want genesis", h.TipHash())
	}
	if h.TipHeight() != 0 {
		t.Fatalf("height=%d want 0", h.TipHeight())
	}
	// Simulate first header after genesis (prev = genesis).
	// Build a minimal fake 80-byte header with prev = genesis.
	prev, err := wireHashFromDisplayHex(mainnetGenesisHashHex)
	if err != nil {
		t.Fatal(err)
	}
	h80 := make([]byte, 80)
	copy(h80[4:36], prev) // prev hash in wire order
	binary.LittleEndian.PutUint32(h80[68:72], uint32(time.Now().Unix()))
	hx, isNew := h.RememberHeader80(h80)
	if !isNew || hx == "" {
		t.Fatalf("expected new header")
	}
	if h.TipHeight() != 1 {
		t.Fatalf("after first child height=%d want 1", h.TipHeight())
	}
}

func TestNetworkMagicReboot(t *testing.T) {
	if networkMagic("reboottestnet") != magicRebootTestnet {
		t.Fatalf("reboot magic=0x%x want 0x%x", networkMagic("reboottestnet"), magicRebootTestnet)
	}
	if p2pkhVersionForNetwork("reboottestnet") != rebootTestnetP2PKHVersion {
		t.Fatal("reboot P2PKH version")
	}
}
