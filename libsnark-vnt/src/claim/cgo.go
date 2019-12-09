package main

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_claim -lff  -lsnark -lstdc++  -lgmp -lgmpxx

#include "claimcgo.hpp"
#include <stdlib.h>
*/
import "C"
import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"unsafe"
	"encoding/binary"

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
	//sn_old_c := C.CString(common.ToHex(SNold[:]))
	value_c := C.ulong(value)
	sn_string := common.ToHex(sn[:])
	sn_c := C.CString(sn_string)
	defer C.free(unsafe.Pointer(sn_c))
	r_string := common.ToHex(r[:])
	r_c := C.CString(r_string)
	defer C.free(unsafe.Pointer(r_c))

	cmtA_c := C.genCMT(value_c, sn_c, r_c)
	cmtA_go := C.GoString(cmtA_c)
	//res := []byte(cmtA_go)
	res, _ := hex.DecodeString(cmtA_go)
	reshash := common.BytesToHash(res)
	return &reshash
}

func GenClaimProof(ValueS uint64, SNS *common.Hash, RS *common.Hash, CMTS *common.Hash) []byte {

	valueS := C.ulong(ValueS)
	snS := C.CString(common.ToHex(SNS.Bytes()[:]))
	rS := C.CString(common.ToHex(RS.Bytes()[:]))
	cmtS := C.CString(common.ToHex(CMTS[:]))

	cproof := C.genClaimproof(snS, rS, cmtS, valueS)
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidClaimProof = errors.New("Verifying claim proof failed!!!")

func VerifyClaimProof(cmts *common.Hash, ValueS uint64, proof []byte) error {
	cproof := C.CString(string(proof))
	valueS := C.ulong(ValueS)
	cmtS := C.CString(common.ToHex(cmts[:]))

	tf := C.verifyClaimproof(cproof, cmtS, valueS)
	if tf == false {
		return InvalidClaimProof
	}
	return nil
}

func main(){

	values := NewRandomInt()
	sn_s := NewRandomHash()
	r_s := NewRandomHash()
	cmtS := GenCMT(values, sn_s.Bytes(), r_s.Bytes())

	proof := GenClaimProof(values, sn_s, r_s, cmtS)

	VerifyClaimProof(cmtS, values , proof)

}