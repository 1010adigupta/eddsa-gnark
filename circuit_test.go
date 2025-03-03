package main

import (
	"crypto/rand"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	cryptoeddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/test"
)

func TestEdDSACircuit(t *testing.T) {
	// Choose the curve
	curve := ecc.BN254

	// Create an EdDSA key pair
	privateKey, err := cryptoeddsa.New(twistededwards.BN254, rand.Reader)
	if err != nil {
		t.Fatal("Error creating private key:", err)
	}
	publicKey := privateKey.Public()

	// Define a message to sign
	msg := []byte{0xde, 0xad, 0xf0, 0x0d}

	// Create a MiMC hash function
	hFunc := mimc.NewMiMC()
	
	// Sign the message
	signature, err := privateKey.Sign(msg, hFunc)
	if err != nil {
		t.Fatal("Error signing message:", err)
	}

	// Verify the signature (outside the circuit)
	isValid, err := publicKey.Verify(signature, msg, hFunc)
	if err != nil {
		t.Fatal("Error verifying signature:", err)
	}
	if !isValid {
		t.Fatal("Invalid signature")
	}

	// Create the circuit
	var circuit EdDSACircuit

	// Create the witness assignment
	var validAssignment EdDSACircuit

	// Assign the message value
	validAssignment.Message = msg

	// Assign the public key
	validAssignment.PublicKey.Assign(twistededwards.BN254, publicKey.Bytes())

	// Assign the signature
	validAssignment.Signature.Assign(twistededwards.BN254, signature)

	// Create an invalid assignment with tampered signature
	tamperedSignature := make([]byte, len(signature))
	copy(tamperedSignature, signature)
	tamperedSignature[0] ^= 0x01 // Flip a bit

	var invalidAssignment EdDSACircuit
	invalidAssignment.Message = msg
	invalidAssignment.PublicKey.Assign(twistededwards.BN254, publicKey.Bytes())
	invalidAssignment.Signature.Assign(twistededwards.BN254, tamperedSignature)

	// Run the test
	assert := test.NewAssert(t)
	assert.SolvingSucceeded(&circuit, &validAssignment, test.WithCurves(curve))
	assert.SolvingFailed(&circuit, &invalidAssignment, test.WithCurves(curve))
}
