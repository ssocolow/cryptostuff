// Problem set 01: Hash based signatures.

// A lot of this lab is set up and templated for you to get used to
// what may be an unfamiliar language (Go).  Go is syntactically
// similar to C / C++ in many ways, including comments.

// In this pset, you need to build a hash based signature system.  We'll use sha256
// as our hash function, and Lamport's simple signature design.

// Currently this compiles but doesn't do much.  You need to implement parts which
// say "your code here".  It also could be useful to make your own functions or
// methods on existing structs, espectially in the forge.go file.

// If you run `go test` and everything passes, you're all set.

// There's probably some way to get it to pass the tests without making an actual
// functioning signature scheme, but I think that would be harder than just doing
// it the right way :)

package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

func main() {

	// Define your message
	textString := "1"
	fmt.Printf("%s\n", textString)

	// convert message into a block
	m := GetMessageFromString(textString)
	// fmt.Printf("%x\n", m[:])
	//fmt.Printf("Message:\n")
	//fmt.Print(m)

	// generate keys
	sec, pub, err := GenerateKey()
	if err != nil {
		panic(err)
	}

	// print pubkey.
	//fmt.Printf("pub:\n%s\n", pub.ToHex())
	//fmt.Printf("pubkey:\n")
	//fmt.Print(pub)

	//simon added
	//print seckey
	//fmt.Printf("seckey:\n")
	//fmt.Print(sec)

	// sign message
	sig1 := Sign(m, sec)
	//fmt.Print("sig1:\n%s\n", sig1.ToHex())
	//fmt.Printf("sig1:\n")
	//fmt.Print(sig1)

	// verify signature
	worked := Verify(m, pub, sig1)

	// done
	fmt.Printf("Verify worked? %v\n", worked)

	// // Forge signature
	// msgString, sig, err := Forge()
	// if err != nil {
	// 	panic(err)
	// }

	// fmt.Printf("forged msg: %s sig: %s\n", msgString, sig.ToHex())

	return
}

// Signature systems have 3 functions: GenerateKey(), Sign(), and Verify().
// We'll also define the data types: SecretKey, PublicKey, Message, Signature.

// --- Types

// A block of data is always 32 bytes long; we're using sha256 and this
// is the size of both the output (defined by the hash function) and our inputs
type Block [32]byte

type SecretKey struct {
	ZeroPre [256]Block
	OnePre  [256]Block
}

type PublicKey struct {
	ZeroHash [256]Block
	OneHash  [256]Block
}

//simon try to randomize Block
//func RandomizeBlock(b Block)


// --- Methods on PublicKey type

// ToHex gives a hex string for a PublicKey. no newline at the end
func (self PublicKey) ToHex() string {
	// format is zerohash 0...255, onehash 0...255
	var s string
	for _, zero := range self.ZeroHash {
		s += zero.ToHex()
	}
	for _, one := range self.OneHash {
		s += one.ToHex()
	}
	return s
}

// HexToPubkey takes a string from PublicKey.ToHex() and turns it into a pubkey
// will return an error if there are non hex characters or if the lenght is wrong.
func HexToPubkey(s string) (PublicKey, error) {
	var p PublicKey

	expectedLength := 256 * 2 * 64 // 256 blocks long, 2 rows, 64 hex char per block

	// first, make sure hex string is of correct length
	if len(s) != expectedLength {
		return p, fmt.Errorf(
			"Pubkey string some characters, expect %d", expectedLength)
	}

	// decode from hex to a byte slice
	bts, err := hex.DecodeString(s)
	if err != nil {
		return p, err
	}
	// we already checked the length of the hex string so don't need to re-check
	buf := bytes.NewBuffer(bts)

	for i, _ := range p.ZeroHash {
		p.ZeroHash[i] = BlockFromByteSlice(buf.Next(32))
	}
	for i, _ := range p.OneHash {
		p.OneHash[i] = BlockFromByteSlice(buf.Next(32))
	}

	return p, nil
}

// A message to be signed is just a block.
type Message Block

// --- Methods on the Block type

// ToHex returns a hex encoded string of the block data, with no newlines.
func (self Block) ToHex() string {
	return fmt.Sprintf("%064x", self[:])
}

// Hash returns the sha256 hash of the block.
func (self Block) Hash() Block {
	return sha256.Sum256(self[:])
}

// IsPreimage returns true if the block is a preimage of the argument.
// For example, if Y = hash(X), then X.IsPreimage(Y) will return true,
// and Y.IsPreimage(X) will return false.
func (self Block) IsPreimage(arg Block) bool {
	return self.Hash() == arg
}

// BlockFromByteSlice returns a block from a variable length byte slice.
// Watch out!  Silently ignores potential errors like the slice being too
// long or too short!
func BlockFromByteSlice(by []byte) Block {
	var bl Block
	copy(bl[:], by)
	return bl
}

// A signature consists of 32 blocks.  It's a selective reveal of the private
// key, according to the bits of the message.
type Signature struct {
	Preimage [256]Block
}

// ToHex returns a hex string of a signature
func (self Signature) ToHex() string {
	var s string
	for _, b := range self.Preimage {
		s += b.ToHex()
	}

	return s
}

// HexToSignature is the same idea as HexToPubkey, but half as big.  Format is just
// every block of the signature in sequence.
func HexToSignature(s string) (Signature, error) {
	var sig Signature

	expectedLength := 256 * 64 // 256 blocks long, 1 row, 64 hex char per block

	// first, make sure hex string is of correct length
	if len(s) != expectedLength {
		return sig, fmt.Errorf(
			"Pubkey string some characters, expect %d", expectedLength)
	}

	// decode from hex to a byte slice
	bts, err := hex.DecodeString(s)
	if err != nil {
		return sig, err
	}
	// we already checked the length of the hex string so don't need to re-check
	buf := bytes.NewBuffer(bts)

	for i, _ := range sig.Preimage {
		sig.Preimage[i] = BlockFromByteSlice(buf.Next(32))
	}
	return sig, nil
}

// GetMessageFromString returns a Message which is the hash of the given string.
func GetMessageFromString(s string) Message {
	return sha256.Sum256([]byte(s))
}

// --- Functions

// GenerateKey takes no arguments, and returns a keypair and potentially an
// error.  It gets randomness from the OS via crypto/rand
// This can return an error if there is a problem with reading random bytes
func GenerateKey() (SecretKey, PublicKey, error) {
	// initialize SecretKey variable 'sec'.  Starts with all 00 bytes.
	var sec SecretKey
	var pub PublicKey

	// Your code here
	// ===
	for i := 0; i < 256; i++ {
		rand.Read(sec.ZeroPre[i][:])
		rand.Read(sec.OnePre[i][:])
	}
	for i := 0; i < 256; i++ {
		pub.ZeroHash[i] = sec.ZeroPre[i].Hash()
		pub.OneHash[i] = sec.OnePre[i].Hash()
	}
	// ===
	return sec, pub, nil
}

// Sign takes a message and secret key, and returns a signature.
func Sign(msg Message, sec SecretKey) Signature {
	var sig Signature

	// Your code here
	// ===
	//walk through each bit in the message
	//based on that bit, put the corresponding secretkey block into the signature
	//a Message is just a Block and a Block is just 32 bytes
	whichbit := 0
	for i := 0; i < 32; i++ {
		for j := 0; j < 8; j++ {
			if msg[i] & 128 >= 128 {
				sig.Preimage[whichbit] = sec.OnePre[whichbit]
				whichbit++
				//fmt.Print(msg[i])
				//fmt.Print("o")
				msg[i] = msg[i]<<1
			} else {
				sig.Preimage[whichbit] = sec.ZeroPre[whichbit]
				whichbit++
				//fmt.Print(msg[i])
				//fmt.Print("z")
				msg[i] = msg[i]<<1
			}
		}

	}
	// ===
	return sig
}

// Verify takes a message, public key and signature, and returns a boolean
// describing the validity of the signature.
func Verify(msg Message, pub PublicKey, sig Signature) bool {

	// Your code here
	// ===
	//go through each bit of the message
	//if it is a 1, hash the corresponding signature block and see if it is the same as the corresponding pubkey block
	//if not, return false
	whichbit := 0
	for i := 0; i < 32; i++ {
		for j := 0; j < 8; j++ {
			if msg[i] & 128 >= 128 {
				if !sig.Preimage[whichbit].IsPreimage(pub.OneHash[whichbit]) {
					return false
				}
				whichbit++
				msg[i] = msg[i]<<1
			} else {
				if !sig.Preimage[whichbit].IsPreimage(pub.ZeroHash[whichbit]) {
					return false
				}
				whichbit++
				msg[i] = msg[i]<<1
			}
		}

	}
	// ===

	return true
}
