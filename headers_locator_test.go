package main

import "testing"

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

func TestNeedsHeaderSync(t *testing.T) {
	h := NewHeaderTracker("")
	if !h.NeedsHeaderSync() {
		t.Fatal("empty tip should need header sync")
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
