package main

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_commit -lff  -lsnark -lstdc++  -lgmp -lgmpxx

#include "commitcgo.hpp"
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

func GenCMT(value uint64, sn []byte, r []byte, snA []byte) *common.Hash {
	//sn_old_c := C.CString(common.ToHex(SNold[:]))
	value_c := C.ulong(value)
	sn_string := common.ToHex(sn[:])
	sn_c := C.CString(sn_string)
	defer C.free(unsafe.Pointer(sn_c))
	r_string := common.ToHex(r[:])
	r_c := C.CString(r_string)
	defer C.free(unsafe.Pointer(r_c))
	snA_string := common.ToHex(snA[:])
	snA_c := C.CString(snA_string)
	defer C.free(unsafe.Pointer(snA_c))

	cmtA_c := C.genCMT(value_c, sn_c, r_c, snA_c)
	cmtA_go := C.GoString(cmtA_c)
	//res := []byte(cmtA_go)
	res, _ := hex.DecodeString(cmtA_go)
	reshash := common.BytesToHash(res)
	return &reshash
}

//GenRT 返回merkel树的hash  --zy
func GenRT(CMTSForMerkle []*common.Hash) common.Hash {
	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(common.ToHex(CMTSForMerkle[i][:]))
		cmtArray += s
	}
	cmtsM := C.CString(cmtArray)
	rtC := C.genRoot(cmtsM, C.int(len(CMTSForMerkle))) //--zy
	rtGo := C.GoString(rtC)

	res, _ := hex.DecodeString(rtGo)   //返回32长度 []byte  一个byte代表两位16进制数
	reshash := common.BytesToHash(res) //32长度byte数组
	return reshash
}

func GenCommitProof(ValueS uint64, SNS *common.Hash, RS *common.Hash, SNA *common.Hash, CMTS *common.Hash, RT []byte, CMTSForMerkle []*common.Hash) []byte {

	valueS := C.ulong(ValueS)
	snS := C.CString(common.ToHex(SNS.Bytes()[:]))
	rS := C.CString(common.ToHex(RS.Bytes()[:]))
	snA := C.CString(common.ToHex(SNA.Bytes()[:]))
	cmtS := C.CString(common.ToHex(CMTS[:]))
	rt := C.CString(common.ToHex(RT))

	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(common.ToHex(CMTSForMerkle[i][:]))
		cmtArray += s
	}
	cmtsM := C.CString(cmtArray)
	nC := C.int(len(CMTSForMerkle))

	cproof := C.genCommitproof( snS, rS, snA, valueS, cmtS, cmtsM, nC, rt)
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidCommitProof = errors.New("Verifying commit proof failed!!!")

func VerifyCommitProof( ValueS uint64, SN_S *common.Hash, RT []byte, proof []byte) error {
	cproof := C.CString(string(proof))
	valueS := C.ulong(ValueS)
	snS := C.CString(common.ToHex(SN_S[:]))
	rt := C.CString(common.ToHex(RT))

	tf := C.verifyCommitproof(cproof, rt, snS, valueS)
	if tf == false {
		return InvalidCommitProof
	}
	return nil
}

func main(){

	values := NewRandomInt()
	sn_s := NewRandomHash()
	r_s := NewRandomHash()
	snA := NewRandomHash()
	cmtS := GenCMT(values, sn_s.Bytes(), r_s.Bytes(), snA.Bytes())

	var cmtarray []*common.Hash
	for i := 0; i < 32; i++ {
		if i==9 {
			cmtarray = append(cmtarray, cmtS)
		} else{
			cmt := NewRandomHash()
			cmtarray = append(cmtarray, cmt)
		}
	}

	RT := GenRT(cmtarray)

	proof := GenCommitProof(values, sn_s, r_s, snA, cmtS, RT.Bytes(), cmtarray)

	VerifyCommitProof(values, sn_s, RT.Bytes(), proof)

}