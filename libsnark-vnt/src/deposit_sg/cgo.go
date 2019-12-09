package main

/*
#cgo LDFLAGS: -L/usr/local/lib  -lzk_deposit_sg -lzk_mint  -lzk_send  -lzk_deposit -lzk_redeem -lzk_convert -lzk_commit  -lzk_claim -lff  -lsnark -lstdc++  -lgmp -lgmpxx

#include "deposit_sgcgo.hpp"
#include "mintcgo.hpp"
#include "sendcgo.hpp"
#include "redeemcgo.hpp"
#include "convertcgo.hpp"
#include "commitcgo.hpp"
#include "claimcgo.hpp"

#include <stdlib.h>
*/
import "C"
import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
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

func GenDepositsgProof(CMTS *common.Hash, ValueS uint64, SNS *common.Hash, RS *common.Hash, ValueB uint64, RB *common.Hash, SNBnew *common.Hash, RBnew *common.Hash, RTcmt []byte, CMTB *common.Hash, SNB *common.Hash, CMTBnew *common.Hash, CMTSForMerkle []*common.Hash) []byte {
	cmtS_c := C.CString(common.ToHex(CMTS[:]))
	valueS_c := C.ulong(ValueS)
	SNS_c := C.CString(common.ToHex(SNS.Bytes()[:])) //--zy
	RS_c := C.CString(common.ToHex(RS.Bytes()[:]))   //--zy
	valueB_c := C.ulong(ValueB)
	RB_c := C.CString(common.ToHex(RB.Bytes()[:])) //rA_c := C.CString(string(RA.Bytes()[:]))
	SNB_c := C.CString(common.ToHex(SNB.Bytes()[:]))
	SNBnew_c := C.CString(common.ToHex(SNBnew.Bytes()[:]))
	RBnew_c := C.CString(common.ToHex(RBnew.Bytes()[:]))
	cmtB_c := C.CString(common.ToHex(CMTB[:]))
	RT_c := C.CString(common.ToHex(RTcmt)) //--zy   rt

	cmtBnew_c := C.CString(common.ToHex(CMTBnew[:]))
	valueBNew_c := C.ulong(ValueB + ValueS)

	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(common.ToHex(CMTSForMerkle[i][:]))
		cmtArray += s
	}
	cmtsM := C.CString(cmtArray)
	nC := C.int(len(CMTSForMerkle))

	cproof := C.genDepositsgproof(valueBNew_c, valueB_c, SNB_c, RB_c, SNBnew_c, RBnew_c, SNS_c, RS_c, cmtB_c, cmtBnew_c, valueS_c, cmtS_c, cmtsM, nC, RT_c)
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidDepositProof = errors.New("Verifying Deposit_sg proof failed!!!")

func VerifyDepositsgProof(sns *common.Hash, rtcmt common.Hash, cmtb *common.Hash, snb *common.Hash, cmtbnew *common.Hash, proof []byte) error {
	SNS_c := C.CString(common.ToHex(sns.Bytes()[:]))
	cproof := C.CString(string(proof))
	rtmCmt := C.CString(common.ToHex(rtcmt[:]))
	cmtB := C.CString(common.ToHex(cmtb[:]))
	cmtBnew := C.CString(common.ToHex(cmtbnew[:]))
	SNB_c := C.CString(common.ToHex(snb.Bytes()[:]))
	tf := C.verifyDepositsgproof(cproof, rtmCmt, SNS_c, cmtB, SNB_c, cmtBnew)
	if tf == false {
		return InvalidDepositProof
	}
	return nil
}

func main(){

	value_old := NewRandomInt()
	values := NewRandomInt()
	value := value_old + values

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
	for i := 0; i < 32; i++ {
		if i==9 {
			cmtarray = append(cmtarray, cmtS)
		} else{
			cmt := NewRandomHash()
			cmtarray = append(cmtarray, cmt)
		}
	}

	RT := GenRT(cmtarray)

	proof := GenDepositsgProof(cmtS, values, sn_s, r_s, value_old, r_old, sn, r, RT.Bytes(), cmtB_old, sn_old, cmtB, cmtarray)

	result := VerifyDepositsgProof(sn_s, RT, cmtB_old, sn_old, cmtB, proof)

	if result != nil{
		fmt.Println(result)
	}else{
		fmt.Println("Vertify deposit_sg successfully!")
	}

}