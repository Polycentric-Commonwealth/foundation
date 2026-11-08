// Command pcrecord creates keys and signs and verifies Commonwealth signed
// records from the command line.
//
// Usage:
//
//	pcrecord keygen NAME
//	pcrecord sign -priv NAME.key -issuer ID -key KEYID -layer LAYER -type TYPE [-supersedes ID] PAYLOAD.json
//	pcrecord verify -pub NAME.pub ENVELOPE.json
//	pcrecord attest -priv NAME.key -issuer ID -key KEYID -layer LAYER DESCRIPTION.json
//
// The attest command is for a parent instance: it reads a child's signed
// instance description and prints an attestation of every key the child
// lists, for the child to publish (specs/instance-registry.md).
//
// Use "-" in place of a JSON file name to read from standard input. Keys
// are stored as unpadded base64url text: the 32-byte seed in NAME.key and
// the 32-byte public key in NAME.pub. This key file format is a temporary
// convenience until the instance registry specification defines key
// publication.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/polycentric-commonwealth/foundation/record"
	"github.com/polycentric-commonwealth/foundation/registry"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	case "attest":
		err = attest(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pcrecord:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `usage:
  pcrecord keygen NAME
  pcrecord sign -priv NAME.key -issuer ID -key KEYID -layer LAYER -type TYPE [-supersedes ID] PAYLOAD.json
  pcrecord verify -pub NAME.pub ENVELOPE.json
  pcrecord attest -priv NAME.key -issuer ID -key KEYID -layer LAYER DESCRIPTION.json
`)
	os.Exit(2)
}

func keygen(args []string) error {
	if len(args) != 1 {
		usage()
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	name := args[0]
	if err := writeNew(name+".key", base64.RawURLEncoding.EncodeToString(priv.Seed()), 0o600); err != nil {
		return err
	}
	if err := writeNew(name+".pub", base64.RawURLEncoding.EncodeToString(pub), 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s.key (keep private) and %s.pub\n", name, name)
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	privPath := fs.String("priv", "", "private key file written by keygen")
	issuer := fs.String("issuer", "", "issuing instance identifier")
	keyID := fs.String("key", "", "signing key identifier")
	layer := fs.String("layer", "", "issuer layer: commonwealth, region, state or locality")
	typ := fs.String("type", "", "payload type, such as eligibility-count/1")
	supersedes := fs.String("supersedes", "", "optional id of a record this one replaces")
	fs.Parse(args)
	if fs.NArg() != 1 || *privPath == "" {
		usage()
	}

	seed, err := readKey(*privPath, ed25519.SeedSize)
	if err != nil {
		return err
	}
	payload, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}

	e, err := record.New(*issuer, *keyID, record.Layer(*layer), *typ, json.RawMessage(payload))
	if err != nil {
		return err
	}
	e.Supersedes = *supersedes
	if err := e.Sign(ed25519.NewKeyFromSeed(seed)); err != nil {
		return err
	}
	out, err := e.Marshal()
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(out)
	return err
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubPath := fs.String("pub", "", "public key file written by keygen")
	fs.Parse(args)
	if fs.NArg() != 1 || *pubPath == "" {
		usage()
	}

	pub, err := readKey(*pubPath, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	data, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}
	e, err := record.Parse(data)
	if err != nil {
		return err
	}
	if err := e.Verify(ed25519.PublicKey(pub)); err != nil {
		return err
	}
	fmt.Printf("valid: %s %s issued by %s (%s) at %s\n", e.Type, e.ID, e.Issuer, e.Layer, e.IssuedAt)
	return nil
}

func attest(args []string) error {
	fs := flag.NewFlagSet("attest", flag.ExitOnError)
	privPath := fs.String("priv", "", "the parent's private key file written by keygen")
	issuer := fs.String("issuer", "", "the parent's instance identifier")
	keyID := fs.String("key", "", "the parent's signing key identifier")
	layer := fs.String("layer", "", "the parent's layer")
	fs.Parse(args)
	if fs.NArg() != 1 || *privPath == "" {
		usage()
	}
	seed, err := readKey(*privPath, ed25519.SeedSize)
	if err != nil {
		return err
	}
	data, err := readInput(fs.Arg(0))
	if err != nil {
		return err
	}
	env, err := record.Parse(data)
	if err != nil {
		return err
	}
	d, err := registry.ParseDescription(env)
	if err != nil {
		return err
	}
	if d.Parent != *issuer {
		return fmt.Errorf("%s names %q as its parent, not %s", d.Instance, d.Parent, *issuer)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	k, ok := d.Key(env.Key)
	if !ok {
		return fmt.Errorf("description is signed with key %q, which it does not list", env.Key)
	}
	pub, err := registry.DecodePublicKey(k.PublicKey)
	if err == nil {
		err = env.Verify(pub)
	}
	if err != nil {
		return fmt.Errorf("description is not signed by one of its own keys: %w", err)
	}
	a := &registry.Attestation{Subject: d.Instance, SubjectLayer: d.Layer}
	for _, k := range d.Keys {
		if k.RevokedAt == "" {
			a.Keys = append(a.Keys, registry.AttestedKey{ID: k.ID, PublicKey: k.PublicKey})
		}
	}
	out, err := registry.NewAttestation(*issuer, record.Layer(*layer), *keyID, priv, a)
	if err != nil {
		return err
	}
	b, err := out.Marshal()
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "attested %d key(s) of %s; check them with the child out of band before publishing\n", len(a.Keys), d.Instance)
	_, err = os.Stdout.Write(b)
	return err
}

func readKey(path string, size int) ([]byte, error) {
	text, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(text)))
	if err != nil || len(key) != size {
		return nil, fmt.Errorf("%s: not a valid key file", path)
	}
	return key, nil
}

func readInput(path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(path)
}

func writeNew(path, content string, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s already exists; not overwriting", path)
	}
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content + "\n"); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
