# EdDSA Signature Verification in ZK-SNARKs

This project demonstrates how to implement EdDSA signature verification in a zero-knowledge proof circuit using the [gnark](https://github.com/consensys/gnark) library.

## Overview

The project implements a zero-knowledge proof circuit that verifies EdDSA signatures without revealing the signature or the message. This is useful for applications where you want to prove that you have a valid signature for a message without revealing the actual signature or message.

## Components

- `circuit.go`: Defines the EdDSA verification circuit
- `main.go`: Contains the main function that demonstrates the circuit with valid and invalid signatures
- `circuit_test.go`: Contains tests for the circuit

## Prerequisites

- Go 1.19 or later
- gnark v0.12.0
- gnark-crypto v0.16.0

## Running the Project

To run the tests:

```bash
go test -v
```

To run the main program:

```bash
go run .
```

## How It Works

1. The circuit initializes a twisted Edwards curve for BN254
2. It creates a MiMC hash function
3. It verifies the EdDSA signature in the constraint system
4. The main program demonstrates:
   - Creating an EdDSA key pair
   - Signing a message
   - Verifying the signature outside the circuit
   - Verifying the signature inside the circuit using a zero-knowledge proof
   - Demonstrating that an invalid signature fails verification

## Notes

- The circuit uses the BN254 curve, which is commonly used in Ethereum-based applications
- The signature verification is performed using the gnark library's implementation of EdDSA
- The circuit demonstrates both successful verification of valid signatures and rejection of invalid signatures
