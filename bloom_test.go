package main

import "testing"

func TestMurmur3Empty(t *testing.T) {
	if got := murmur3(nil, 0); got != 0 {
		t.Fatalf("murmur3(nil,0)=%#x want 0", got)
	}
}

func TestBloomAddContainsBit(t *testing.T) {
	f := NewBloomFilter(10, 0.001, 0x12345678, BLOOM_UPDATE_ALL)
	h160 := make([]byte, 20)
	for i := range h160 {
		h160[i] = byte(i + 1)
	}
	before := make([]byte, len(f.data))
	copy(before, f.data)
	f.Add(h160)
	changed := false
	for i := range f.data {
		if f.data[i] != before[i] {
			changed = true
			break
		}
	}
	if !changed {
		t.Fatal("bloom Add did not set any bits")
	}
	pl := f.FilterloadPayload()
	if len(pl) < len(f.data)+9 {
		t.Fatalf("filterload payload too short: %d", len(pl))
	}
}

func TestFormatUtxo(t *testing.T) {
	if got := formatUtxo("abcd", 3); got != "abcd:3" {
		t.Fatalf("got %q", got)
	}
}
