package main

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_claim -lff  -lsnark -lstdc++  -lgmp -lgmpxx

#include "claimcgo.hpp"
#include <stdlib.h>
*/
import "C"
import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"unsafe"

	"github.com/ethereum/go-ethereum/common"
)

func NewRandomHash() *common.Hash {
	uuid := make([]byte, 32)
	io.ReadFull(rand.Reader, uuid)
	hash := common.BytesToHash(uuid)
	return &hash
}

func NewRandomAddress() *common.Address {
	uuid := make([]byte, 20)
	io.ReadFull(rand.Reader, uuid)
	addr := common.BytesToAddress(uuid)
	return &addr
}

func NewRandomInt() uint64 {
	uuid := make([]byte, 8)
	io.ReadFull(rand.Reader, uuid)
	uuid[0] = 0
	r := uint64(binary.BigEndian.Uint64(uuid))
	return r
}

func GenCMT(value uint64, sn []byte, r []byte) *common.Hash {
	value_c := C.ulong(value)
	sn_string := common.ToHex(sn[:])
	sn_c := C.CString(sn_string)
	defer C.free(unsafe.Pointer(sn_c))
	r_string := common.ToHex(r[:])
	r_c := C.CString(r_string)
	defer C.free(unsafe.Pointer(r_c))

	cmtA_c := C.genCMT(value_c, sn_c, r_c)
	cmtA_go := C.GoString(cmtA_c)
	res, _ := hex.DecodeString(cmtA_go)
	reshash := common.BytesToHash(res)
	return &reshash
}

func GenCMT2(value uint64, r []byte) *common.Hash {
	value_c := C.ulong(value)
	r_string := common.ToHex(r[:])
	r_c := C.CString(r_string)
	defer C.free(unsafe.Pointer(r_c))

	cmtA_c := C.genCMT2(value_c, r_c)
	cmtA_go := C.GoString(cmtA_c)
	res, _ := hex.DecodeString(cmtA_go)
	reshash := common.BytesToHash(res)
	return &reshash
}

//GenClaimProof function
func GenClaimProof(DS *common.Hash, SNS *common.Hash, RS *common.Hash, CMTS *common.Hash, RR *common.Hash, CMTT *common.Hash,
	Subcost uint64, Cost uint64, Subdist uint64, Dist uint64, FEES uint64, REFUNDI uint64) []byte {

	snS := C.CString(common.ToHex(SNS.Bytes()[:]))
	rS := C.CString(common.ToHex(RS.Bytes()[:]))
	cmtS := C.CString(common.ToHex(CMTS[:]))

	rR := C.CString(common.ToHex(RR.Bytes()[:]))
	cmtt := C.CString(common.ToHex(CMTT[:]))

	ds := C.CString(common.ToHex(DS[:]))

	subdist := C.ulong(Subdist)
	dist := C.ulong(Dist)
	subcost := C.ulong(Subcost)
	cost := C.ulong(Cost)

	fees := C.ulong(FEES)
	refundi := C.ulong(REFUNDI)

	cproof := C.genClaimproof(snS, rS, cmtS, rR, cmtt, cost, subcost, dist, subdist, fees, refundi, ds)
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidClaimProof = errors.New("Verifying claim proof failed!!!")

//VerifyClaimProof function
func VerifyClaimProof(DS *common.Hash, cmts *common.Hash, CMTT *common.Hash, proof []byte) error {
	cproof := C.CString(string(proof))
	cmtS := C.CString(common.ToHex(cmts[:]))

	cmtt := C.CString(common.ToHex(CMTT[:]))
	ds := C.CString(common.ToHex(DS[:]))

	// subdist := C.ulong(Subdist)
	// dist := C.ulong(Dist)
	// fees := C.ulong(FEES)

	tf := C.verifyClaimproof(cproof, cmtS, cmtt, ds)
	if tf == false {
		return InvalidClaimProof
	}
	return nil
}

func main() {

	cost := uint64(10)
	sn_s := NewRandomHash()
	r_s := NewRandomHash()

	//cost_i=cost×dist_i/(Σdist_i)
	//cost = subcost * dist / subdist
	subdist := uint64(50)
	dist := uint64(25)
	subcost := uint64(20)
	r := NewRandomHash()
	cmtt := GenCMT2(subcost, r.Bytes())

	fees := uint64(30)
	refundi := uint64(20)
	cmtS := GenCMT(refundi, sn_s.Bytes(), r_s.Bytes())

	ds := GenCMT2(dist, sn_s.Bytes())

	proof := GenClaimProof(ds, sn_s, r_s, cmtS, r, cmtt, subcost, cost, subdist, dist, fees, refundi)
	// fmt.Println("divide(user) proof=<<<<<<<<<<<<<<<<<<<<<<<", proof)

	VerifyClaimProof(ds, cmtS, cmtt, proof)

}
