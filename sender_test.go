package main

import (
	"encoding/hex"
	"testing"
)

// Minimal legacy P2PKH tx skeleton: version + 1 vin (dummy prevout) with
// scriptSig = <1-byte sig push> <33-byte compressed pubkey> + 1 empty vout + locktime.
func TestExtractSenderAddressesP2PKH(t *testing.T) {
	pubkey, err := hex.DecodeString("02b4632d08485ff1df2db55b9dafd23347d1c47a457072a1e87be26896549a8737")
	if err != nil {
		t.Fatal(err)
	}
	sigPush := []byte{0x01, 0xaa} // OP_PUSH 1 byte
	pkPush := append([]byte{byte(len(pubkey))}, pubkey...)
	scriptSig := append(sigPush, pkPush...)

	raw := make([]byte, 0, 128)
	raw = append(raw, 0x01, 0x00, 0x00, 0x00) // version
	raw = append(raw, 0x01)                    // vin count
	raw = append(raw, make([]byte, 32)...)     // prev hash (non-coinbase: set one byte)
	raw[len(raw)-1] = 0x01
	raw = append(raw, 0x00, 0x00, 0x00, 0x00) // vout
	raw = append(raw, byte(len(scriptSig)))
	raw = append(raw, scriptSig...)
	raw = append(raw, 0xff, 0xff, 0xff, 0xff) // sequence
	raw = append(raw, 0x01)                   // vout count
	raw = append(raw, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	raw = append(raw, 0x00)                   // empty script
	raw = append(raw, 0x00, 0x00, 0x00, 0x00) // locktime

	want := encodeP2PKHAddress(hash160(pubkey), "mainnet")
	got, all := extractSenderAddresses(raw, "mainnet")
	if got != want {
		t.Fatalf("from_address=%q want %q", got, want)
	}
	if len(all) != 1 || all[0] != want {
		t.Fatalf("from_addresses=%v want [%s]", all, want)
	}
}
