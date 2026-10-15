package libkaspawallet_test

import (
	"bytes"
	"testing"

	"github.com/kaspanet/kaspad/cmd/kaspawallet/libkaspawallet"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/libkaspawallet/serialization"
	"github.com/kaspanet/kaspad/domain/consensus/model/externalapi"
	"github.com/kaspanet/kaspad/domain/consensus/utils/txscript"
	"github.com/kaspanet/kaspad/domain/consensus/utils/utxo"
	"github.com/kaspanet/kaspad/domain/dagconfig"
)

func TestSignToccataPreservesTransaction(t *testing.T) {
	forSchnorrAndECDSA(t, func(t *testing.T, ecdsa bool) {
		params := &dagconfig.MainnetParams
		mnemonics, publicKeys := make([]string, 3), make([]string, 3)
		for i := range mnemonics {
			var err error
			mnemonics[i], err = libkaspawallet.CreateMnemonic()
			if err != nil {
				t.Fatal(err)
			}
			publicKeys[i], err = libkaspawallet.MasterPublicKeyFromMnemonic(params, mnemonics[i], true)
			if err != nil {
				t.Fatal(err)
			}
		}
		address, err := libkaspawallet.Address(params, publicKeys, 2, "m/0/0/1", ecdsa)
		if err != nil {
			t.Fatal(err)
		}
		script, err := txscript.PayToAddrScript(address)
		if err != nil {
			t.Fatal(err)
		}
		pst, err := libkaspawallet.CreateUnsignedTransaction(publicKeys, 2,
			[]*libkaspawallet.Payment{{Address: address, Amount: 190}},
			[]*libkaspawallet.UTXO{
				{Outpoint: &externalapi.DomainOutpoint{Index: 0}, UTXOEntry: utxo.NewUTXOEntry(100, script, false, 0), DerivationPath: "m/0/0/1"},
				{Outpoint: &externalapi.DomainOutpoint{Index: 1}, UTXOEntry: utxo.NewUTXOEntry(100, script, false, 0), DerivationPath: "m/0/0/1"},
			})
		if err != nil {
			t.Fatal(err)
		}
		pst.Tx.Version, pst.Tx.SubnetworkID, pst.Tx.Payload = 1, externalapi.DomainSubnetworkID{0x97, 0xb1}, []byte{0x93, 1, 2, 3}
		for _, input := range pst.Tx.Inputs {
			input.SigOpCount = 0
			input.ComputeBudget = 20
		}
		unsigned, err := serialization.SerializePartiallySignedTransaction(pst)
		if err != nil {
			t.Fatal(err)
		}
		for _, mnemonic := range mnemonics {
			signed, err := libkaspawallet.Sign(params, []string{mnemonic}, unsigned, ecdsa)
			if err != nil {
				t.Fatal(err)
			}
			response, err := serialization.DeserializePartiallySignedTransaction(signed)
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range response.PartiallySignedInputs {
				count := 0
				for _, pair := range input.PubKeySignaturePairs {
					if len(pair.Signature) != 0 {
						count++
					}
					pair.Signature = nil
				}
				if count != 1 {
					t.Fatalf("expected one independent signature per input, got %d", count)
				}
			}
			restored, err := serialization.SerializePartiallySignedTransaction(response)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(unsigned, restored) {
				t.Fatal("signing changed fields other than partial signatures")
			}
		}
	})
}
