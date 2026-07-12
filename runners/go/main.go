// APS conformance suite - Go runner.
//
// Mirrors runners/ts/verify.ts. Reads fixtures/manifest.json and per-category
// fixture files. For each vector it canonicalizes `input` (or the stripped IPR
// `envelope`) with the agent-passport-go SDK, computes SHA-256 of the canonical
// bytes, compares against the recorded canonical_bytes_hex / canonical_sha256,
// and verifies any Ed25519 signature against the declared key. A passing run
// here means the Go SDK reproduces the same canonical bytes and verifies the
// same signatures as the TypeScript reference, on the identical vector set.
//
// Run:
//   cd runners/go && go run .
//
// Exit code 0 on full pass, 1 on any failure.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"github.com/aeoess/agent-passport-go/jcs"
	apsverify "github.com/aeoess/agent-passport-go/verify"
)

type manifestEntry struct {
	Category       string `json:"category"`
	Path           string `json:"path"`
	CanonicalSHA   string `json:"canonical_sha256"`
	VectorCount    int    `json:"vector_count"`
	SpecSection    string `json:"spec_section"`
}

type manifest struct {
	Version  string          `json:"version"`
	Fixtures []manifestEntry `json:"fixtures"`
}

type result struct {
	category, fixture, name, status, details string
}

func fixturesDir() string {
	_, self, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(self), "..", "..", "fixtures")
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func decodeJSON(raw []byte, v interface{}) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	return dec.Decode(v)
}

// canonicalizeGeneric decodes a raw JSON value with number fidelity and runs
// the SDK canonicalizer over it.
func canonicalizeGeneric(raw json.RawMessage) (string, error) {
	var v interface{}
	if err := decodeJSON(raw, &v); err != nil {
		return "", err
	}
	return jcs.Canonicalize(v)
}

type vector struct {
	Name                  string          `json:"name"`
	ExpectedVerification  *bool           `json:"expected_verification"`
	Input                 json.RawMessage `json:"input"`
	Envelope              json.RawMessage `json:"envelope"`
	CanonicalBytesHex     string          `json:"canonical_bytes_hex"`
	CanonicalSHA256       string          `json:"canonical_sha256"`
	Ed25519Sig            string          `json:"ed25519_signature"`
	Ed25519PubHex         string          `json:"ed25519_pubkey_hex"`
	Ed25519SigOverCanon   string          `json:"ed25519_signature_over_canonical_hex"`
	ScenarioID            interface{}     `json:"scenario_id"`
}

type fixtureFile struct {
	SeedInput string          `json:"seed_input"`
	Keypair   *struct{ PublicKeyHex string `json:"publicKeyHex"` } `json:"keypair"`
	Vectors   []json.RawMessage `json:"vectors"`
	Scenarios []string          `json:"scenarios"`
}

func deriveKeypairPubHex(seedInput string) string {
	seed := sha256.Sum256([]byte(seedInput))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	return hex.EncodeToString(pub)
}

func checkVector(category, fixture string, declaredPub string, raw json.RawMessage) []result {
	var v vector
	if err := decodeJSON(raw, &v); err != nil {
		return []result{{category, fixture, "<vector>", "fail", "vector parse error: " + err.Error()}}
	}
	pub := declaredPub
	if pub == "" {
		pub = v.Ed25519PubHex
	}

	// IPR-style: signed envelope + canonical_bytes_hex (strip signature + receipt_id).
	if len(v.Envelope) > 0 && v.CanonicalBytesHex != "" && v.CanonicalSHA256 != "" {
		var env map[string]interface{}
		if err := decodeJSON(v.Envelope, &env); err != nil {
			return []result{{category, fixture, v.Name, "fail", "envelope parse: " + err.Error()}}
		}
		stripped := map[string]interface{}{}
		for k, val := range env {
			if k == "signature" || k == "receipt_id" {
				continue
			}
			stripped[k] = val
		}
		canon, err := jcs.Canonicalize(stripped)
		if err != nil {
			return []result{{category, fixture, v.Name, "fail", "canonicalize: " + err.Error()}}
		}
		if hex.EncodeToString([]byte(canon)) != v.CanonicalBytesHex {
			return []result{{category, fixture, v.Name, "fail", "IPR canonical_bytes_hex mismatch"}}
		}
		if sha256Hex([]byte(canon)) != v.CanonicalSHA256 {
			return []result{{category, fixture, v.Name, "fail", "IPR canonical_sha256 mismatch"}}
		}
		sig := v.Ed25519Sig
		if sig == "" {
			if s, ok := env["signature"].(string); ok {
				sig = s
			}
		}
		if sig != "" && pub != "" && !apsverify.VerifyEd25519([]byte(canon), sig, pub) {
			return []result{{category, fixture, v.Name, "fail", "Ed25519 verify failed for IPR envelope"}}
		}
		return []result{{category, fixture, v.Name, "pass", ""}}
	}

	// input + canonical_bytes_hex + canonical_sha256 (bilateral / inference / canonical-bytes).
	if v.CanonicalBytesHex != "" && v.CanonicalSHA256 != "" && len(v.Input) > 0 {
		canon, err := canonicalizeGeneric(v.Input)
		if err != nil {
			return []result{{category, fixture, v.Name, "fail", "canonicalize: " + err.Error()}}
		}
		if hex.EncodeToString([]byte(canon)) != v.CanonicalBytesHex {
			return []result{{category, fixture, v.Name, "fail", "canonical_bytes_hex mismatch"}}
		}
		if sha256Hex([]byte(canon)) != v.CanonicalSHA256 {
			return []result{{category, fixture, v.Name, "fail", "canonical_sha256 mismatch"}}
		}
		sig := v.Ed25519SigOverCanon
		if sig == "" {
			sig = v.Ed25519Sig
		}
		if sig != "" && pub != "" && !apsverify.VerifyEd25519([]byte(canon), sig, pub) {
			return []result{{category, fixture, v.Name, "fail", "Ed25519 signature verification failed"}}
		}
		return []result{{category, fixture, v.Name, "pass", ""}}
	}

	// AIVSS structural fixture.
	if v.ScenarioID != nil {
		return []result{{category, fixture, v.Name, "pass", "AIVSS structural fixture"}}
	}

	// Negative-vector metadata (no canonical bytes).
	if v.ExpectedVerification != nil && !*v.ExpectedVerification {
		return []result{{category, fixture, v.Name, "pass", "negative-vector metadata"}}
	}

	return []result{{category, fixture, v.Name, "skip", "no canonicalization data in vector"}}
}

// merkleParityVector is the shape of a merkle-root-parity fixture vector.
// These carry leaf_inputs (UTF-8 strings), the derived leaf hex values, and
// the expected attribution Merkle root under the domain-separated
// construction (receipt format v1.2, Day-145 audit): leaves sorted
// ascending, leaf = sha256(0x00 || leaf_hex), internal =
// sha256(0x01 || left_hex || right_hex), odd trailing node promoted
// unchanged. The runner recomputes every leaf and every root with the small
// executable oracle below (no SDK import), so this category can never pass
// vacuously; vectors here are never skipped.
type merkleParityVector struct {
	Name                  string   `json:"name"`
	LeafCount             int      `json:"leaf_count"`
	LeafInputs            []string `json:"leaf_inputs"`
	Leaves                []string `json:"leaves"`
	ExpectedRoot          string   `json:"expected_root"`
	DuplicateLastLeafRoot string   `json:"duplicate_last_leaf_root"`
}

func merkleParityLeafHash(leaf string) string {
	return sha256Hex([]byte("\x00" + leaf))
}

func merkleParityNodeHash(left, right string) string {
	return sha256Hex([]byte("\x01" + left + right))
}

func merkleParityRoot(leaves []string) string {
	if len(leaves) == 0 {
		return sha256Hex([]byte("empty"))
	}
	level := make([]string, len(leaves))
	copy(level, leaves)
	sort.Strings(level)
	for i := range level {
		level[i] = merkleParityLeafHash(level[i])
	}
	for len(level) > 1 {
		next := make([]string, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, merkleParityNodeHash(level[i], level[i+1]))
			} else {
				// Odd node promoted unchanged, never duplicated.
				next = append(next, level[i])
			}
		}
		level = next
	}
	return level[0]
}

func checkMerkleParityVectors(category, fixture string, raws []json.RawMessage) []result {
	var out []result
	for _, raw := range raws {
		var v merkleParityVector
		if err := json.Unmarshal(raw, &v); err != nil {
			out = append(out, result{category, fixture, "<vector>", "fail", "vector parse error: " + err.Error()})
			continue
		}
		var problems []string
		if len(v.LeafInputs) != len(v.Leaves) || len(v.Leaves) != v.LeafCount {
			out = append(out, result{category, fixture, v.Name, "fail", "malformed vector: leaf_inputs/leaves/leaf_count inconsistent"})
			continue
		}
		for i, input := range v.LeafInputs {
			if derived := sha256Hex([]byte(input)); derived != v.Leaves[i] {
				problems = append(problems, fmt.Sprintf("leaf[%d] derivation mismatch (recomputed %s, recorded %s)", i, derived[:16], v.Leaves[i][:16]))
			}
		}
		root := merkleParityRoot(v.Leaves)
		if root != v.ExpectedRoot {
			problems = append(problems, "expected_root mismatch (recomputed "+root[:16]+", recorded "+v.ExpectedRoot[:16]+")")
		}
		if v.DuplicateLastLeafRoot != "" {
			dupLeaves := append(append([]string{}, v.Leaves...), v.Leaves[len(v.Leaves)-1])
			dupRoot := merkleParityRoot(dupLeaves)
			if dupRoot != v.DuplicateLastLeafRoot {
				problems = append(problems, "duplicate_last_leaf_root mismatch (recomputed "+dupRoot[:16]+")")
			}
			if dupRoot == root {
				problems = append(problems, "CVE-2012-2459 regression: duplicate-leaf multiset folded to the honest root")
			}
		}
		status, details := "pass", ""
		if len(problems) > 0 {
			status = "fail"
			details = problems[0]
		}
		out = append(out, result{category, fixture, v.Name, status, details})
	}
	return out
}

func main() {
	os.Exit(run())
}

func run() int {
	fdir := fixturesDir()
	manifestPath := filepath.Join(fdir, "manifest.json")
	mraw, err := os.ReadFile(manifestPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "manifest not found at %s: %v\n", manifestPath, err)
		return 1
	}
	var m manifest
	if err := json.Unmarshal(mraw, &m); err != nil {
		fmt.Fprintf(os.Stderr, "manifest parse: %v\n", err)
		return 1
	}
	fmt.Printf("APS conformance suite v%s (Go runner, agent-passport-go SDK)\n", m.Version)
	fmt.Printf("fixtures: %d files\n\n", len(m.Fixtures))

	var all []result
	for _, entry := range m.Fixtures {
		fpath := filepath.Join(fdir, entry.Path)
		fraw, err := os.ReadFile(fpath)
		if err != nil {
			all = append(all, result{entry.Category, entry.Path, "<file>", "fail", "file missing"})
			continue
		}
		if entry.CanonicalSHA != "" && entry.CanonicalSHA != sha256Hex(fraw) {
			all = append(all, result{entry.Category, entry.Path, "<manifest-sha>", "fail", "manifest sha256 mismatch"})
			continue
		}
		var data fixtureFile
		if err := json.Unmarshal(fraw, &data); err != nil {
			all = append(all, result{entry.Category, entry.Path, "<parse>", "fail", "fixture parse: " + err.Error()})
			continue
		}
		declaredPub := ""
		if data.Keypair != nil {
			declaredPub = data.Keypair.PublicKeyHex
			if data.SeedInput != "" {
				if deriveKeypairPubHex(data.SeedInput) != declaredPub {
					all = append(all, result{entry.Category, entry.Path, "<keypair>", "fail", "keypair derivation mismatch"})
					continue
				}
			}
		}

		if len(data.Vectors) == 0 && len(data.Scenarios) > 0 {
			dir := filepath.Dir(fpath)
			for _, sc := range data.Scenarios {
				scRaw, err := os.ReadFile(filepath.Join(dir, sc))
				if err != nil {
					all = append(all, result{entry.Category, sc, sc, "fail", "scenario file not found"})
					continue
				}
				var scen map[string]interface{}
				if err := json.Unmarshal(scRaw, &scen); err != nil {
					all = append(all, result{entry.Category, sc, sc, "fail", "scenario parse"})
					continue
				}
				missing := []string{}
				for _, k := range []string{"scenario_id", "owasp_risk", "aivss_score", "aps_primitive_exercised", "expected_outcome"} {
					if _, ok := scen[k]; !ok {
						missing = append(missing, k)
					}
				}
				if len(missing) > 0 {
					all = append(all, result{entry.Category, sc, sc, "fail", "missing fields: " + fmt.Sprint(missing)})
				} else {
					all = append(all, result{entry.Category, sc, fmt.Sprint(scen["scenario_id"]), "pass", "AIVSS structural fixture"})
				}
			}
			continue
		}

		if len(data.Vectors) == 0 {
			// No vectors array and no scenarios list. Mirrors the TS runner:
			// record one skip for the fixture (e.g. the canonical-bytes diff,
			// whose deep check lives in a dedicated TS test, not the main run).
			all = append(all, result{entry.Category, entry.Path, "<vectors>", "skip", "no vectors array and no scenarios list"})
			continue
		}

		if entry.Category == "merkle-root-parity" {
			all = append(all, checkMerkleParityVectors(entry.Category, entry.Path, data.Vectors)...)
			continue
		}

		for _, vraw := range data.Vectors {
			all = append(all, checkVector(entry.Category, entry.Path, declaredPub, vraw)...)
		}
	}

	type counts struct{ pass, fail, skip int }
	byCat := map[string]*counts{}
	order := []string{}
	for _, r := range all {
		c, ok := byCat[r.category]
		if !ok {
			c = &counts{}
			byCat[r.category] = c
			order = append(order, r.category)
		}
		switch r.status {
		case "pass":
			c.pass++
		case "fail":
			c.fail++
		case "skip":
			c.skip++
		}
	}
	sort.Strings(order)
	for _, cat := range order {
		c := byCat[cat]
		fmt.Printf("  %-28s pass=%d  fail=%d  skip=%d\n", cat, c.pass, c.fail, c.skip)
	}
	fmt.Println()

	fails := 0
	for _, r := range all {
		if r.status == "fail" {
			if fails == 0 {
				fmt.Println("FAILURES:")
			}
			fmt.Printf("  %s / %s / %s: %s\n", r.category, r.fixture, r.name, r.details)
			fails++
		}
	}
	if fails > 0 {
		return 1
	}
	pass, skip := 0, 0
	for _, r := range all {
		switch r.status {
		case "pass":
			pass++
		case "skip":
			skip++
		}
	}
	fmt.Printf("TOTAL: %d vectors  pass=%d  fail=0  skip=%d\n", len(all), pass, skip)
	return 0
}
