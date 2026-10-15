package consensushashing_test

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/kaspanet/kaspad/domain/consensus/model/externalapi"
	"github.com/kaspanet/kaspad/domain/consensus/utils/consensushashing"
	"github.com/kaspanet/kaspad/domain/consensus/utils/utxo"
)

// Reference vectors from kaspanet/rusty-kaspa
// 01b532e8b553523216471682649693af92f0fd16, consensus/core/src/hashing/sighash.rs.
// The v0 cases are hash-format controls, not valid v0 user-lane transactions.
func TestToccataSignatureHashRustVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/toccata_sighash.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Version        uint16
		Covenant       bool
		Input          int
		Mode           consensushashing.SigHashType
		Schnorr, ECDSA string
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		t.Run(fmt.Sprintf("v%d/covenant=%t/input=%d/mode=%d", vector.Version, vector.Covenant, vector.Input, vector.Mode), func(t *testing.T) {
			script := &externalapi.ScriptPublicKey{Script: []byte{0x51}}
			tx := &externalapi.DomainTransaction{Version: vector.Version, LockTime: 11,
				SubnetworkID: externalapi.DomainSubnetworkID{0x97, 0xb1}, Payload: []byte{0x93, 1, 2, 3}}
			for i := 0; i < 2; i++ {
				id, err := externalapi.NewDomainTransactionIDFromString(strings.Repeat(fmt.Sprintf("%02x", 0x11*(i+1)), 32))
				if err != nil {
					t.Fatal(err)
				}
				tx.Inputs = append(tx.Inputs, &externalapi.DomainTransactionInput{
					PreviousOutpoint: externalapi.DomainOutpoint{TransactionID: *id, Index: uint32(i)},
					Sequence:         7 + uint64(i), SigOpCount: 3, ComputeBudget: 20 + uint32(i),
					UTXOEntry: utxo.NewUTXOEntry(400010000, script, false, 0)})
			}
			for _, amount := range []uint64{300000000, 300000000, 200000000} {
				tx.Outputs = append(tx.Outputs, &externalapi.DomainTransactionOutput{Value: amount, ScriptPublicKey: script})
			}
			if vector.Covenant {
				tx.Outputs[1].Covenant = &externalapi.DomainTransactionOutputCovenantBinding{AuthorizingInput: 1, CovenantID: strings.Repeat("aa", 32)}
			}
			check := func() {
				t.Helper()
				for _, ecdsa := range []bool{false, true} {
					hashFunc, expected := consensushashing.CalculateSignatureHashSchnorr, vector.Schnorr
					if ecdsa {
						hashFunc, expected = consensushashing.CalculateSignatureHashECDSA, vector.ECDSA
					}
					actual, err := hashFunc(tx, vector.Input, vector.Mode, &consensushashing.SighashReusedValues{})
					if err != nil {
						t.Fatal(err)
					}
					if actual.String() != expected {
						t.Fatalf("ecdsa=%t: got %s, want %s", ecdsa, actual, expected)
					}
				}
			}
			check()
			if vector.Version == 1 {
				// Neither legacy sigops nor the compute budget belongs in the v1 signing hash.
				for _, input := range tx.Inputs {
					input.SigOpCount = 99
					input.ComputeBudget = 123
				}
				check()
			}
		})
	}
}
