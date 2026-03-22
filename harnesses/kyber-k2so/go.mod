module crucible-harness-k2so

go 1.26.1

require (
	github.com/symbolicsoft/kyber-k2so v1.1.0
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
)

replace github.com/symbolicsoft/kyber-k2so => /tmp/kyber-k2so-improved
