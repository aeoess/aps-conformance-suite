module github.com/aeoess/aps-conformance-suite/runners/go

go 1.22

require github.com/aeoess/agent-passport-go v0.1.0-alpha.1

require golang.org/x/text v0.21.0 // indirect

// Local dev wiring to exercise Waves 2+3 primitives (signing core, issuing)
// before they are tagged. Drop this replace once a Wave 2/3 tag is published.
replace github.com/aeoess/agent-passport-go => ../../../agent-passport-go
