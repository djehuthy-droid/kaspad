package serialization_test

import (
	"strings"
	"testing"

	"github.com/kaspanet/kaspad/cmd/kaspawallet/libkaspawallet/serialization"
	"github.com/kaspanet/kaspad/domain/consensus/model/externalapi"
)

func TestToccataPSTRoundTrip(t *testing.T) {
	output := &externalapi.DomainTransactionOutput{Value: 100,
		ScriptPublicKey: &externalapi.ScriptPublicKey{Script: []byte{0x51}},
		Covenant:        &externalapi.DomainTransactionOutputCovenantBinding{AuthorizingInput: 0, CovenantID: strings.Repeat("aa", 32)}}
	pst := &serialization.PartiallySignedTransaction{
		Tx: &externalapi.DomainTransaction{Version: 1, SubnetworkID: externalapi.DomainSubnetworkID{0x97, 0xb1},
			Payload: []byte{0x93, 1, 2, 3},
			Inputs:  []*externalapi.DomainTransactionInput{{ComputeBudget: 20}},
			Outputs: []*externalapi.DomainTransactionOutput{output}},
		PartiallySignedInputs: []*serialization.PartiallySignedInput{{PrevOutput: output, MinimumSignatures: 2, DerivationPath: "m/0/0/1"}},
	}
	data, err := serialization.SerializePartiallySignedTransaction(pst)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := serialization.DeserializePartiallySignedTransaction(data)
	if err != nil {
		t.Fatal(err)
	}
	if !pst.Tx.Equal(restored.Tx) || !output.Equal(restored.PartiallySignedInputs[0].PrevOutput) {
		t.Fatal("PST round trip changed the transaction or previous output")
	}
	for name, mutate := range map[string]func(*serialization.PartiallySignedTransaction){
		"compute budget overflow": func(p *serialization.PartiallySignedTransaction) { p.Tx.Inputs[0].ComputeBudget = 65536 },
		"covenant input overflow": func(p *serialization.PartiallySignedTransaction) { p.Tx.Outputs[0].Covenant.AuthorizingInput = 65536 },
		"invalid covenant ID":     func(p *serialization.PartiallySignedTransaction) { p.Tx.Outputs[0].Covenant.CovenantID = "aa" },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := pst.Clone()
			mutate(invalid)
			data, err := serialization.SerializePartiallySignedTransaction(invalid)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := serialization.DeserializePartiallySignedTransaction(data); err == nil {
				t.Fatal("expected decoding error")
			}
		})
	}
}
