package idhider

import (
	"reflect"
	"testing"
)

const testKey = "l3XD0qwLL5nDZQw4"

func TestEncryptID(t *testing.T) {
	key := []byte(testKey)
	var id uint64 = 133742
	hider, _ := NewIDHider(key)

	var want uint64 = 5781761883846612620
	got := hider.PublicID(id)
	if want != got {
		t.Errorf("\nGot %d\nWant %d", got, want)
	}
}

func TestEncryptIDHuman(t *testing.T) {
	key := []byte(testKey)
	var id uint64 = 133742
	hider, _ := NewIDHider(key)

	want := "hgb95qpcy4y50"
	got := hider.HumanPublicID(id)
	if want != got {
		t.Errorf("\nGot %s\nWant %s", got, want)
	}
}

func TestDecryptHumanID(t *testing.T) {
	key := []byte(testKey)
	humanPublicID := "hgb95qpcy4y50"
	hider, _ := NewIDHider(key)

	var want uint64 = 133742
	got := hider.HumanToID(humanPublicID)
	if want != got {
		t.Errorf("\nGot %d\nWant %d", got, want)
	}
}

func TestCrockfordBase32Encode(t *testing.T) {
	var n uint64 = 5781761883846612620
	got := crockfordBase32Encode(uint64ToBytes(n))
	want := "hgb95qpcy4y50"
	if want != got {
		t.Errorf("\nGot %s\nWant %s", got, want)
	}
}

func TestCrockfordBase32Decode(t *testing.T) {
	got := crockfordBase32Decode("hgb95qpcy4y50")
	want := uint64ToBytes(5781761883846612620)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("\nGot %v\nWant %v", got, want)
	}
}

func TestIDEncDec(t *testing.T) {
	key := []byte(testKey)
	hider, _ := NewIDHider(key)

	for id := 0; id < 10000; id++ {
		id := uint64(id)
		humanPublicID := hider.HumanPublicID(id)
		reID := hider.HumanToID(humanPublicID)
		if id != reID {
			t.Errorf("\nGot %d\nWant %d", reID, id)
		}
	}
}

func BenchmarkMakeHumanPublicID(b *testing.B) {
	key := []byte(testKey)
	hider, _ := NewIDHider(key)
	var id uint64 = 133742

	for n := 0; n < b.N; n++ {
		hider.HumanPublicID(id)
	}
}

func BenchmarkReadHumanPublicID(b *testing.B) {
	key := []byte(testKey)
	hider, _ := NewIDHider(key)
	var hid = "hgb95qpcy4y50"

	for n := 0; n < b.N; n++ {
		hider.HumanToID(hid)
	}
}
