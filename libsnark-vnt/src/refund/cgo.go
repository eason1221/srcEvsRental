package main

/*
#cgo LDFLAGS: -L/usr/local/lib  -lzk_refund -lff  -lsnark -lstdc++  -lgmp -lgmpxx

#include "refundcgo.hpp"
#include <stdlib.h>
*/
import "C"
import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
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

func GenRefundProof(ValueB uint64, ValueBOld uint64, SNB *common.Hash, RB *common.Hash, SNBnew *common.Hash, RBnew *common.Hash,
	SNS *common.Hash, RS *common.Hash, CMTBOLD *common.Hash, CMTBnew *common.Hash, ValueS uint64,
	CMTS *common.Hash, CMTSForMerkle []*common.Hash, RTcmt []byte, fees uint64, cost uint64) []byte {

	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(common.ToHex(CMTSForMerkle[i][:]))
		cmtArray += s
	}

	valueBNew_c := C.ulong(ValueB)
	valueBOld_c := C.ulong(ValueBOld)
	SNOld_c := C.CString(common.ToHex(SNB.Bytes()[:]))
	ROld_c := C.CString(common.ToHex(RB.Bytes()[:]))
	SNBNew_c := C.CString(common.ToHex(SNBnew.Bytes()[:]))
	RBNew_c := C.CString(common.ToHex(RBnew.Bytes()[:]))
	SNS_c := C.CString(common.ToHex(SNS.Bytes()[:]))
	RS_c := C.CString(common.ToHex(RS.Bytes()[:]))
	cmtBOld_c := C.CString(common.ToHex(CMTBOLD[:]))
	cmtBNew_c := C.CString(common.ToHex(CMTBnew[:]))
	valueS_c := C.ulong(ValueS)
	cmtS_c := C.CString(common.ToHex(CMTS[:]))
	cmtsM := C.CString(cmtArray)
	nC := C.int(len(CMTSForMerkle))
	RT_c := C.CString(common.ToHex(RTcmt))
	Fees_c := C.ulong(fees)
	Cost_c := C.ulong(cost)

	cproof := C.genRefundproof(valueBNew_c, valueBOld_c, SNOld_c, ROld_c, SNBNew_c, RBNew_c, SNS_c, RS_c,
		cmtBOld_c, cmtBNew_c, valueS_c, cmtS_c, cmtsM, nC, RT_c, Fees_c, Cost_c)
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidRefundProof = errors.New("Verifying refund(user) proof failed!!!")

func VerifyRefundProof(fees uint64, sns *common.Hash, rtcmt common.Hash, cmtb *common.Hash, snb *common.Hash, cmtbnew *common.Hash, proof []byte) error {

	cproof := C.CString(string(proof))
	rtmCmt := C.CString(common.ToHex(rtcmt[:]))
	cmtB := C.CString(common.ToHex(cmtb[:]))
	SNB_c := C.CString(common.ToHex(snb.Bytes()[:]))
	cmtBnew := C.CString(common.ToHex(cmtbnew[:]))
	SNS_c := C.CString(common.ToHex(sns.Bytes()[:]))
	Fees := C.ulong(fees)

	tf := C.verifyRefundproof(cproof, rtmCmt, cmtB, SNB_c, cmtBnew, SNS_c, Fees)
	if tf == false {
		return InvalidRefundProof
	}
	return nil
}

func main() {

	value_old := uint64(20)
	values := uint64(20)
	value := value_old + values //更新后的零知识余额对应的明文余额

	fees := uint64(50)
	cost := uint64(30)

	sn_old := NewRandomHash()
	sn := NewRandomHash()
	sn_s := NewRandomHash()

	r_old := NewRandomHash()
	r := NewRandomHash()
	r_s := NewRandomHash()

	cmtB_old := GenCMT(value_old, sn_old.Bytes(), r_old.Bytes())
	cmtB := GenCMT(value, sn.Bytes(), r.Bytes())
	cmtS := GenCMT(values, sn_s.Bytes(), r_s.Bytes())

	var cmtarray []*common.Hash
	for i := 0; i < 32; i++ { //5层
		if i == 9 {
			cmtarray = append(cmtarray, cmtS)
		} else {
			cmt := NewRandomHash()
			cmtarray = append(cmtarray, cmt)
		}
	}

	RT := GenRT(cmtarray)

	proof := GenRefundProof(value, value_old, sn_old, r_old, sn, r, sn_s, r_s, cmtB_old, cmtB, values, cmtS, cmtarray, RT.Bytes(), fees, cost)

	fmt.Println("refund(user) Proof=====", proof)

	VerifyRefundProof(fees, sn_s, RT, cmtB_old, sn_old, cmtB, proof)

}
