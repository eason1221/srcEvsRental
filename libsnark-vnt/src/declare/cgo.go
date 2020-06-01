package main

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_declare -lff  -lsnark -lstdc++  -lgmp -lgmpxx

#include "declarecgo.hpp"
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

//GenDeclareProof function
func GenDeclareProof(SNS *common.Hash, RS *common.Hash, CMTS *common.Hash, RR *common.Hash, CMTT *common.Hash,
	Subcost uint64, Dist uint64, DS *common.Hash) []byte {

	snS := C.CString(common.ToHex(SNS.Bytes()[:]))
	rS := C.CString(common.ToHex(RS.Bytes()[:]))
	cmtS := C.CString(common.ToHex(CMTS[:]))

	rR := C.CString(common.ToHex(RR.Bytes()[:]))
	cmtt := C.CString(common.ToHex(CMTT[:]))

	dist := C.ulong(Dist)
	ds := C.CString(common.ToHex(DS[:]))
	subcost := C.ulong(Subcost)

	cproof := C.genDeclareproof(snS, rS, cmtS, rR, cmtt, subcost, dist, ds)
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidDeclareProof = errors.New("Verifying declare proof failed!!!")

//VerifyDeclareProof function
func VerifyDeclareProof(DS *common.Hash, CMTT *common.Hash, proof []byte) error {

	cproof := C.CString(string(proof))
	cmtt := C.CString(common.ToHex(CMTT[:]))
	ds := C.CString(common.ToHex(DS[:]))

	tf := C.verifyDeclareproof(cproof, cmtt, ds)
	if tf == false {
		return InvalidDeclareProof
	}
	return nil
}

func main() {

	sn_s := NewRandomHash()
	r_s := NewRandomHash()
	r := NewRandomHash()
	subcost := uint64(80)

	dist := uint64(16)
	cmtt := GenCMT2(subcost, r.Bytes())
	cmtS := GenCMT(subcost, sn_s.Bytes(), r_s.Bytes())
	ds := GenCMT2(dist, sn_s.Bytes())

	proof := GenDeclareProof(sn_s, r_s, cmtS, r, cmtt, subcost, dist, ds)

	VerifyDeclareProof(ds, cmtt, proof)

}
