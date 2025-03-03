package main

import (
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	tedwards "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
)

// EdDSACircuit defines the circuit for EdDSA signature verification
type EdDSACircuit struct {
	PublicKey eddsa.PublicKey   `gnark:",public"`
	Signature eddsa.Signature   `gnark:",public"`
	Message   frontend.Variable `gnark:",public"`
}

// Define implements the circuit for EdDSA signature verification
func (circuit *EdDSACircuit) Define(api frontend.API) error {
	// Initialize the twisted Edwards curve for BN254
	curve, err := tedwards.NewEdCurve(api, twistededwards.BN254)
	if err != nil {
		return err
	}

	// Initialize the MiMC hash function
	hash, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Verify the signature in the constraint system
	return eddsa.Verify(curve, circuit.Signature, circuit.Message, circuit.PublicKey, &hash)
}
