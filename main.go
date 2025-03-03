package main

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	cryptomimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/twistededwards"
	cryptoeddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/frontend"
	tedwards "github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/signature/eddsa"

	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo"
	"github.com/PolyhedraZK/ExpanderCompilerCollection/ecgo/test"
	"github.com/consensys/gnark/std/hash/mimc"
)

// EdDSACircuit defines the circuit for EdDSA signature verification
// Using frontend.Variable for all fields to be compatible with ExpanderCompilerCollection
type EdDSACircuit struct {
	// Public inputs
	PublicKeyX frontend.Variable
	PublicKeyY frontend.Variable
	Message    frontend.Variable

	// Private inputs (witnesses)
	SignatureR_X frontend.Variable
	SignatureR_Y frontend.Variable
	SignatureS   frontend.Variable
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

	// Create the public key and signature objects
	publicKey := eddsa.PublicKey{
		A: tedwards.Point{
			X: circuit.PublicKeyX,
			Y: circuit.PublicKeyY,
		},
	}

	signature := eddsa.Signature{
		R: tedwards.Point{
			X: circuit.SignatureR_X,
			Y: circuit.SignatureR_Y,
		},
		S: circuit.SignatureS,
	}

	// Verify the signature in the constraint system
	return eddsa.Verify(curve, signature, circuit.Message, publicKey, &hash)
}

func main() {
	fmt.Println("EdDSA Signature Verification in ZK-SNARK with ExpanderCompilerCollection")
	fmt.Println("------------------------------------------------------------------")

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
	hFunc := cryptomimc.NewMiMC()

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

	// Compile the circuit using ECC
	fmt.Println("Compiling circuit...")
	eccCircuit, err := ecgo.Compile(ecc.BN254.ScalarField(), &EdDSACircuit{})
	if err != nil {
		fmt.Println("Error compiling circuit with ECC:", err)
		os.Exit(1)
	}

	// Get the layered circuit and serialize it to a file
	layeredCircuit := eccCircuit.GetLayeredCircuit()
	err = os.WriteFile("circuit.txt", layeredCircuit.Serialize(), 0644)
	if err != nil {
		fmt.Println("Error writing circuit to file:", err)
		os.Exit(1)
	}
	fmt.Println("✅ Circuit serialized to circuit.txt")

	// Extract public key and signature components
	pubKey := publicKey.Bytes()
	sig := signature

	// Create the witness assignment
	assignment := &EdDSACircuit{
		// Public inputs
		PublicKeyX: pubKey[:32], // X coordinate
		PublicKeyY: pubKey[32:], // Y coordinate
		Message:    msg,

		// Private inputs (witnesses)
		SignatureR_X: sig[:32],   // R.X coordinate
		SignatureR_Y: sig[32:64], // R.Y coordinate
		SignatureS:   sig[64:],   // S value
	}

	// Get the input solver and solve for the witness
	inputSolver := eccCircuit.GetInputSolver()
	witness, err := inputSolver.SolveInputAuto(assignment)
	if err != nil {
		fmt.Println("Error solving for witness:", err)
		os.Exit(1)
	}

	// Serialize the witness to a file
	err = os.WriteFile("witness.txt", witness.Serialize(), 0644)
	if err != nil {
		fmt.Println("Error writing witness to file:", err)
		os.Exit(1)
	}
	fmt.Println("✅ Witness serialized to witness.txt")

	// Check the circuit (this is just a local verification, not a full proof)
	if !test.CheckCircuit(layeredCircuit, witness) {
		fmt.Println("❌ Circuit check failed")
		os.Exit(1)
	}
	fmt.Println("✅ Circuit check passed")
	fmt.Println("To generate and verify the actual proof, supply circuit.txt and witness.txt to Expander")
}
