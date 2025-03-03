package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	cryptoeddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	fmt.Println("EdDSA Signature Verification in ZK-SNARK")
	fmt.Println("----------------------------------------")
	
	// Run the test for valid EdDSA verification
	fmt.Println("\nTesting with valid signature:")
	TestEdDSA()
	
	// Run the test for invalid EdDSA verification
	fmt.Println("\nTesting with invalid signature:")
	TestEdDSAWithInvalidSignature()
}

// TestEdDSA tests the EdDSA signature verification in a zk-SNARK
func TestEdDSA() {
	// Choose the curve
	curve := ecc.BN254

	// Create an EdDSA key pair
	privateKey, err := cryptoeddsa.New(twistededwards.BN254, rand.Reader)
	if err != nil {
		fmt.Println("Error creating private key:", err)
		os.Exit(1)
	}
	publicKey := privateKey.Public()

	// Define a message to sign
	msg := []byte{0xde, 0xad, 0xf0, 0x0d}

	// Create a MiMC hash function
	hFunc := mimc.NewMiMC()
	
	// Sign the message
	signature, err := privateKey.Sign(msg, hFunc)
	if err != nil {
		fmt.Println("Error signing message:", err)
		os.Exit(1)
	}

	// Verify the signature (outside the circuit)
	isValid, err := publicKey.Verify(signature, msg, hFunc)
	if err != nil {
		fmt.Println("Error verifying signature:", err)
		os.Exit(1)
	}
	if !isValid {
		fmt.Println("Invalid signature")
		os.Exit(1)
	}
	fmt.Println("✅ Signature verified successfully outside the circuit")

	// Now verify the signature inside a zk-SNARK circuit
	// Create the circuit
	var circuit EdDSACircuit

	// Compile the circuit
	ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("Error compiling circuit:", err)
		os.Exit(1)
	}

	// Generate the proving and verification keys
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Println("Error in setup:", err)
		os.Exit(1)
	}

	// Create the witness assignment
	var assignment EdDSACircuit

	// Assign the message value
	assignment.Message = msg

	// Assign the public key
	assignment.PublicKey.Assign(twistededwards.BN254, publicKey.Bytes())

	// Assign the signature
	assignment.Signature.Assign(twistededwards.BN254, signature)

	// Create the witness
	witness, err := frontend.NewWitness(&assignment, curve.ScalarField())
	if err != nil {
		fmt.Println("Error creating witness:", err)
		os.Exit(1)
	}
	publicWitness, err := witness.Public()
	if err != nil {
		fmt.Println("Error extracting public witness:", err)
		os.Exit(1)
	}

	// Generate the proof
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		fmt.Println("Error generating proof:", err)
		os.Exit(1)
	}

	// Verify the proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		fmt.Println("Error verifying proof:", err)
		os.Exit(1)
	}
	fmt.Println("✅ Proof verified successfully")
}

// TestEdDSAWithInvalidSignature tests that the verification fails with an invalid signature
func TestEdDSAWithInvalidSignature() {
	// Choose the curve
	curve := ecc.BN254

	// Create an EdDSA key pair
	privateKey, err := cryptoeddsa.New(twistededwards.BN254, rand.Reader)
	if err != nil {
		fmt.Println("Error creating private key:", err)
		os.Exit(1)
	}
	publicKey := privateKey.Public()

	// Define a message to sign
	msg := []byte{0xde, 0xad, 0xf0, 0x0d}

	// Create a MiMC hash function
	hFunc := mimc.NewMiMC()
	
	// Sign the message
	signature, err := privateKey.Sign(msg, hFunc)
	if err != nil {
		fmt.Println("Error signing message:", err)
		os.Exit(1)
	}

	// Tamper with the signature
	tamperedSignature := make([]byte, len(signature))
	copy(tamperedSignature, signature)
	tamperedSignature[0] ^= 0x01 // Flip a bit

	// Verify the tampered signature (outside the circuit)
	isValid, err := publicKey.Verify(tamperedSignature, msg, hFunc)
	if err != nil {
		fmt.Println("Error verifying tampered signature (expected):", err)
		fmt.Println("✅ Tampered signature correctly identified as invalid outside the circuit")
	} else if isValid {
		fmt.Println("Tampered signature verified as valid, which is unexpected")
		os.Exit(1)
	} else {
		fmt.Println("✅ Tampered signature correctly identified as invalid outside the circuit")
	}

	// Create the circuit
	var circuit EdDSACircuit

	// Compile the circuit
	ccs, err := frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &circuit)
	if err != nil {
		fmt.Println("Error compiling circuit:", err)
		os.Exit(1)
	}

	// Generate the proving and verification keys
	pk, _, err := groth16.Setup(ccs)
	if err != nil {
		fmt.Println("Error in setup:", err)
		os.Exit(1)
	}

	// Create the witness assignment
	var assignment EdDSACircuit

	// Assign the message value
	assignment.Message = msg

	// Assign the public key
	assignment.PublicKey.Assign(twistededwards.BN254, publicKey.Bytes())

	// Assign the tampered signature
	assignment.Signature.Assign(twistededwards.BN254, tamperedSignature)

	// Create the witness
	witness, err := frontend.NewWitness(&assignment, curve.ScalarField())
	if err != nil {
		fmt.Println("Error creating witness for tampered signature:", err)
		os.Exit(1)
	}

	// Attempt to generate a proof (this should fail)
	_, err = groth16.Prove(ccs, pk, witness)
	if err == nil {
		fmt.Println("Generated proof with invalid signature, which is unexpected")
		os.Exit(1)
	}
	fmt.Println("✅ Correctly failed to generate proof with invalid signature:", err)
}
