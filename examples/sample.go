package main

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"github.com/herumi/bls-eth-go-binary/bls"
)

func sample1() {
	fmt.Printf("sample1\n")
	var sec bls.SecretKey
	sec.SetByCSPRNG()
	msg := []byte("abc")
	pub := sec.GetPublicKey()
	sig := sec.SignByte(msg)
	fmt.Printf("verify=%v\n", sig.VerifyByte(pub, msg))
}

func sample2() {
	fmt.Printf("sample2\n")
	var sec bls.SecretKey
	sec.SetByCSPRNG()
	fmt.Printf("sec:%s\n", sec.SerializeToHexStr())
	pub := sec.GetPublicKey()
	fmt.Printf("1.pub:%s\n", pub.SerializeToHexStr())
	fmt.Printf("1.pub x=%x\n", pub)
	var P *bls.G1 = bls.CastFromPublicKey(pub)
	bls.G1Normalize(P, P)
	fmt.Printf("2.pub:%s\n", pub.SerializeToHexStr())
	fmt.Printf("2.pub x=%x\n", pub)
	fmt.Printf("P.X=%x\n", P.X.Serialize())
	fmt.Printf("P.Y=%x\n", P.Y.Serialize())
	fmt.Printf("P.Z=%x\n", P.Z.Serialize())
}

func sample3() {
	fmt.Printf("sample3\n")
	var sec bls.SecretKey
	b := make([]byte, 64)
	for i := 0; i < len(b); i++ {
		b[i] = 0xff
	}
	err := sec.SetLittleEndianMod(b)
	if err != nil {
		fmt.Printf("err")
		return
	}
	fmt.Printf("sec=%x\n", sec.Serialize())
}

func sample4() {
	fmt.Printf("sample4\n")
	var sec bls.SecretKey
	secByte, _ := hex.DecodeString("4aac41b5cb665b93e031faa751944b1f14d77cb17322403cba8df1d6e4541a4d")
	sec.Deserialize(secByte)
	msg := []byte("message to be signed.")
	fmt.Printf("sec:%x\n", sec.Serialize())
	pub := sec.GetPublicKey()
	fmt.Printf("pub:%x\n", pub.Serialize())
	sig := sec.SignByte(msg)
	fmt.Printf("sig:%x\n", sig.Serialize())
}

func sampleACFTS() {
	fmt.Printf("sample acfts\n")
	n := 100
	sec := make([]bls.SecretKey, n)
	pubs := make([]bls.PublicKey, n)
	sigs := make([]bls.Sign, n)
	msg := []byte("abc")
	for i := 0; i < n; i++ {
		sec[i].SetByCSPRNG()
		pubs[i] = *sec[i].GetPublicKey()
		sigs[i] = *sec[i].SignByte(msg)
	}

	var aggSig bls.Sign
	aggSig.Aggregate(sigs)
	/*
		for _, sig := range sigs {
			aggSig.Add(&sig)
		}
	*/

	valid := aggSig.FastAggregateVerify(pubs, msg)

	if !valid {
		fmt.Println("error")
	}
}

func sampleId() {
	fmt.Println("sampleId")
	var id bls.ID
	fmt.Println(id)
	id.SetLittleEndian([]byte{2, 3, 4, 5, 6, 7, 8, 9, 10})
	fmt.Println(id)
}

func sampleTOfN() {
	fmt.Println("sample t of n")

	n := 10
	k := 7

	// k secret keys erstellen
	secs := make([]bls.SecretKey, k)
	for i := 0; i < k; i++ {
		secs[i].SetByCSPRNG()
	}

	// n shares aus k keys erstellen
	ids := make([]bls.ID, n)
	shares := make([]bls.SecretKey, n)
	for i := 0; i < n; i++ {
		ids[i].SetLittleEndian([]byte{uint8(i+1)})
		shares[i].Set(secs, &ids[i])
	}

	// master public key
	mpk := secs[0].GetPublicKey()

	// generate public keys for each user
	pubs := make([]*bls.PublicKey, n)
	for i := 0; i < n; i++ {
		pubs[i] = shares[i].GetPublicKey()
	}

	// now we have
	// for each user i (total N) we have the sk=shares[i] and the pk=pubs[i]
	msg := []byte("hello")
	sigs := make([]*bls.Sign, n)
	for i := 0; i < n; i++ {
		sigs[i] = shares[i].SignByte(msg)
	}

	// let's randomly choose k out of n signature to recover the master signature
	// initialize an array of indices
	a := make([]int, n)
	for i := range a {
			a[i] = i
	}
	// shuffle
	rand.Shuffle(len(a), func(i, j int) { a[i], a[j] = a[j], a[i] })
	// using first k signatures
	fmt.Printf("using signatures %v for recovery", a[:k])
	recoveringSigs := make([]bls.Sign, k) //{*sigs[1], *sigs[3], *sigs[4]}
	recoveringIds := make([]bls.ID, k) //{ids[1], ids[3], ids[4]}
	// and use the first k signatures for recovery
	for i := range recoveringSigs {
		recoveringSigs[i] = *sigs[i]
		recoveringIds[i] = ids[i]
	}
	var recoveredSig bls.Sign
	recoveredSig.Recover(recoveringSigs, recoveringIds)
	fmt.Printf("recovered sig: %v\n", recoveredSig)

	valid := recoveredSig.VerifyByte(mpk, msg)
	if !valid {
		panic("recovered signature is not valid")
	} else {
		fmt.Println("RECOVERED SIGNATURE IS VALID")
	}
}

func sampleMarshalling() {
	fmt.Println("sample marshalling")
	var sec bls.SecretKey
	sec.SetByCSPRNG()
	serialized := sec.Serialize()
	var sec2 bls.SecretKey
	sec2.Deserialize(serialized)

	fmt.Printf("original: %v\n", sec.SerializeToHexStr())
	fmt.Printf("check: %v\n", sec2.SerializeToHexStr())

	pub := *sec.GetPublicKey()
	sPub := pub.Serialize()
	var pub2 bls.PublicKey
	pub2.Deserialize(sPub)

	fmt.Printf("original: %v\n", pub.SerializeToHexStr())
	fmt.Printf("check: %v\n", pub2.SerializeToHexStr())
}

func sampleMarshalling2() {
	fmt.Println("sample marshalling 2")

	var sec bls.SecretKey
	sec.SetByCSPRNG()
	//serS := sec.SerializeToHexStr()
	serS := fmt.Sprintf("%x", sec.Serialize())
	decS, err := hex.DecodeString(serS)
	if err != nil {
		panic(err)
	}
	var sec2 bls.SecretKey
	sec2.Deserialize(decS)
	fmt.Printf("original: %v\n", sec.SerializeToHexStr())
	fmt.Printf("check: %v\n", sec2.SerializeToHexStr())

	pub := sec.GetPublicKey()
	//serS := sec.SerializeToHexStr()
	serS2 := fmt.Sprintf("%x", pub.Serialize())
	decS2, err := hex.DecodeString(serS2)
	if err != nil {
		panic(err)
	}
	var pub2 bls.PublicKey
	pub2.Deserialize(decS2)
	fmt.Printf("original: %v\n", pub2.SerializeToHexStr())
	fmt.Printf("check: %v\n", pub2.SerializeToHexStr())
}


func main() {
	bls.Init(bls.BLS12_381)
	bls.SetETHmode(bls.EthModeDraft07)
	sample1()
	sample2()
	sample3()
	sample4()
	sampleACFTS()
	sampleId()
	sampleTOfN()
	sampleMarshalling()
	sampleMarshalling2()
}
