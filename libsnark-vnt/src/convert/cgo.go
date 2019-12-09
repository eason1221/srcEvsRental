package main

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_convert -lff  -lsnark -lstdc++  -lgmp -lgmpxx

#include "convertcgo.hpp"
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

func GenCMT_1(values uint64, sns []byte, rs []byte, sna []byte) *common.Hash {

	values_c := C.ulong(values)
	sns_string := common.ToHex(sns[:])
	sns_c := C.CString(sns_string)
	defer C.free(unsafe.Pointer(sns_c))
	rs_string := common.ToHex(rs[:])
	rs_c := C.CString(rs_string)
	defer C.free(unsafe.Pointer(rs_c))
	sna_string := common.ToHex(sna[:])
	sna_c := C.CString(sna_string)
	defer C.free(unsafe.Pointer(sna_c))
	//uint64_t value_s,char* pk_string,char* sn_s_string,char* r_s_string,char *sn_old_string
	cmtA_c := C.genCMT_1(values_c, sns_c, rs_c, sna_c) //64长度16进制数
	cmtA_go := C.GoString(cmtA_c)
	//res := []byte(cmtA_go)
	res, _ := hex.DecodeString(cmtA_go)
	reshash := common.BytesToHash(res) //32长度byte数组
	return &reshash
}

func GenConvertProof(CMTA *common.Hash, ValueA uint64, RA *common.Hash, ValueS uint64, SNS *common.Hash, RS *common.Hash, SNA *common.Hash, CMTS *common.Hash, ValueAnew uint64, SNAnew *common.Hash, RAnew *common.Hash, CMTAnew *common.Hash) []byte {
	cmtA_c := C.CString(common.ToHex(CMTA[:]))
	valueA_c := C.ulong(ValueA)
	rA_c := C.CString(common.ToHex(RA.Bytes()[:]))
	valueS := C.ulong(ValueS)
	snS := C.CString(common.ToHex(SNS.Bytes()[:]))
	rS := C.CString(common.ToHex(RS.Bytes()[:]))
	snA := C.CString(common.ToHex(SNA.Bytes()[:]))
	cmtS := C.CString(common.ToHex(CMTS[:]))
	valueANew_c := C.ulong(ValueAnew)
	snAnew_c := C.CString(common.ToHex(SNAnew.Bytes()[:]))
	rAnew_c := C.CString(common.ToHex(RAnew.Bytes()[:]))
	cmtAnew_c := C.CString(common.ToHex(CMTAnew[:]))

	cproof := C.genConvertproof(valueA_c, snS, rS, snA, rA_c, cmtS, cmtA_c, valueS, valueANew_c, snAnew_c, rAnew_c, cmtAnew_c)
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidConvertProof = errors.New("Verifying convert proof failed!!!")

func VerifyConvertProof(sna *common.Hash, cmts *common.Hash, proof []byte, cmtAold *common.Hash, cmtAnew *common.Hash) error {
	cproof := C.CString(string(proof))
	snAold_c := C.CString(common.ToHex(sna.Bytes()[:]))
	cmtS := C.CString(common.ToHex(cmts[:]))
	cmtAold_c := C.CString(common.ToHex(cmtAold[:]))
	cmtAnew_c := C.CString(common.ToHex(cmtAnew[:]))

	tf := C.verifyConvertproof(cproof, cmtAold_c, snAold_c, cmtS, cmtAnew_c)
	if tf == false {
		return InvalidConvertProof
	}
	return nil
}

func main(){

	value_old := uint64(10000)
	sn_old := NewRandomHash()
	r_old := NewRandomHash()
	
	values := uint64(1000)
	sn_s := NewRandomHash()
	r_s := NewRandomHash()

	value := uint64(9000)
	sn := NewRandomHash()
	r := NewRandomHash()

	cmtA_old := GenCMT(value_old, sn_old.Bytes(), r_old.Bytes())
	cmtA := GenCMT(value, sn.Bytes(), r.Bytes())
	cmtS := GenCMT_1(values, sn_s.Bytes(), r_s.Bytes(), sn_old.Bytes())

	proof := GenConvertProof(cmtA_old, value_old, r_old, values, sn_s, r_s, sn_old, cmtS, value, sn, r, cmtA)

	VerifyConvertProof(sn_old, cmtS, proof, cmtA_old, cmtA)

}