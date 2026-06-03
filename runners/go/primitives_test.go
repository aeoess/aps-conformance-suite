// APS conformance runner - Waves 2+3 primitive exercise.
//
// The main runner (main.go) validates canonicalization + verification against
// the fixtures (37/38). This test additionally exercises the new signing core
// and the delegation issuing primitive through the conformance-suite module, so
// a passing conformance build depends on the real Waves 2+3 SDK, not only the
// verify-only surface.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/aeoess/agent-passport-go/delegation"
	"github.com/aeoess/agent-passport-go/jcs"
	"github.com/aeoess/agent-passport-go/keys"
)

// TestSigningCoreReproducesFixtureSignatures re-signs every bilateral vector
// with the SDK signing core under the fixture-derived key and asserts the
// signature equals the TS-recorded value. This exercises keys.Sign end to end
// against the shared fixture (not a hand-written vector).
func TestSigningCoreReproducesFixtureSignatures(t *testing.T) {
	path := filepath.Join(fixturesDir(), "bilateral-delegation", "canonicalize-fixture-v1.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var fx struct {
		SeedInput string `json:"seed_input"`
		Vectors   []struct {
			Name   string          `json:"name"`
			Input  json.RawMessage `json:"input"`
			SigHex string          `json:"ed25519_signature_over_canonical_hex"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("parse: %v", err)
	}
	seed := sha256.Sum256([]byte(fx.SeedInput))
	seedHex := hex.EncodeToString(seed[:])

	matched := 0
	for _, v := range fx.Vectors {
		dec := json.NewDecoder(bytes.NewReader(v.Input))
		dec.UseNumber()
		var input interface{}
		if err := dec.Decode(&input); err != nil {
			t.Fatalf("%s: decode: %v", v.Name, err)
		}
		canon, err := jcs.Canonicalize(input)
		if err != nil {
			t.Errorf("%s: canonicalize: %v", v.Name, err)
			continue
		}
		sig, err := keys.Sign(canon, seedHex)
		if err != nil {
			t.Errorf("%s: sign: %v", v.Name, err)
			continue
		}
		if sig != v.SigHex {
			t.Errorf("%s: re-signed != recorded TS sig", v.Name)
			continue
		}
		matched++
	}
	if matched != len(fx.Vectors) {
		t.Fatalf("signing core matched %d/%d fixture signatures", matched, len(fx.Vectors))
	}
	t.Logf("signing core re-signed %d/%d bilateral vectors == recorded TS signatures", matched, len(fx.Vectors))
}

// TestDelegationIssuingRoundTrip exercises the delegation issuing primitive
// through the conformance module: create a signed delegation, verify it, narrow
// it, verify the child, and reject a widening child.
func TestDelegationIssuingRoundTrip(t *testing.T) {
	seed := sha256.Sum256([]byte("aps-conformance-delegation-key"))
	priv := hex.EncodeToString(seed[:])
	pub, err := keys.PublicKeyFromPrivate(priv)
	if err != nil {
		t.Fatal(err)
	}
	sl := 500.0
	parent, err := delegation.CreateDelegation(delegation.CreateOptions{
		PrivateKey: priv, DelegationID: "del_conf_root", DelegatedBy: pub, DelegatedTo: pub,
		Scope: []string{"data:*"}, SpendLimit: &sl, MaxDepth: 3, CurrentDepth: 0,
		ExpiresAt: "2026-12-31T00:00:00.000Z", NotBefore: "2026-06-03T12:00:00.000Z",
		CreatedAt: "2026-06-03T12:00:00.000Z",
	})
	if err != nil || !delegation.VerifyDelegation(parent) {
		t.Fatalf("parent create/verify failed: %v", err)
	}
	child, err := delegation.SubDelegate(delegation.SubDelegateOptions{
		Parent: parent, PrivateKey: priv, DelegationID: "del_conf_child", DelegatedTo: "did:aps:b",
		Scope: []string{"data:read"}, ExpiresAt: "2026-06-30T00:00:00.000Z",
		NotBefore: "2026-06-03T12:00:00.000Z", CreatedAt: "2026-06-03T12:00:00.000Z",
	})
	if err != nil || !delegation.VerifyDelegation(child) {
		t.Fatalf("child create/verify failed: %v", err)
	}
	if _, err := delegation.SubDelegate(delegation.SubDelegateOptions{
		Parent: parent, PrivateKey: priv, DelegationID: "x", DelegatedTo: "did:aps:b",
		Scope: []string{"commerce:checkout"}, ExpiresAt: "2026-06-30T00:00:00.000Z",
	}); err == nil {
		t.Error("widening child accepted (must reject)")
	}
	t.Log("delegation issuing round-trip: create + verify + narrow + reject-widening all pass")
}
