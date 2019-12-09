package zktx

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_mint -lzk_redeem -lzk_convert -lzk_commit -lzk_claim -lzk_deposit_sg -lff  -lsnark -lstdc++  -lgmp -lgmpxx


#include "mintcgo.hpp"
#include "redeemcgo.hpp"
#include "convertcgo.hpp"
#include "commitcgo.hpp"
#include "claimcgo.hpp"
#include "deposit_sgcgo.hpp"

#include <stdlib.h>
*/
import "C"
import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/ethereum/go-ethereum/log"

	"github.com/ethereum/go-ethereum/crypto/ecies"

	"github.com/ethereum/go-ethereum/rlp"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

type Sequence struct {
	SN     *common.Hash
	CMT    *common.Hash
	Random *common.Hash
	Value  uint64
	Valid  bool
	Lock   sync.Mutex
}

type WriteSn struct {
	SNumber      *Sequence
	SNumberAfter *Sequence
}
type SequenceS struct {
	Suquence1 Sequence
	Suquence2 Sequence
	SNS       *Sequence
	PKBX      *big.Int
	PKBY      *big.Int
	Stage     uint8
}

const (
	Origin = iota
	Mint
	Send
	Update
	Deposit
	Redeem
	Convert
	Commit
	Claim
	Depositsg
)

var SNfile *os.File
var FileLine uint8

var Stage uint8
var SequenceNumber = InitializeSN()                //--zy
var SequenceNumberAfter *Sequence = InitializeSN() //--zy
var SNS *Sequence = nil
var ZKTxAddress = common.HexToAddress("ffffffffffffffffffffffffffffffffffffffff")

var ZKCMTNODES = 1 // max is 32  because of merkle leaves in libnsark is 32

var ErrSequence = errors.New("invalid sequence")
var RandomReceiverPK *ecdsa.PublicKey = nil

func InitializeSN() *Sequence {
	sn := &common.Hash{}
	r := &common.Hash{}
	cmt := GenCMT(0, sn.Bytes(), r.Bytes())
	return &Sequence{
		SN:     sn,
		CMT:    cmt,
		Random: r,
		Value:  0,
	}
}

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

func NewRandomInt() *big.Int {
	uuid := make([]byte, 32)
	io.ReadFull(rand.Reader, uuid)
	r := big.NewInt(0)
	r.SetBytes(uuid)
	return r
}

func VerifyDepositSIG(x *big.Int, y *big.Int, sig []byte) error {
	return nil
}

//GenCMT生成CMT 调用c的sha256函数  （go的sha256函数与c有一些区别）
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

//GenCMT生成CMT 调用c的sha256函数  （go的sha256函数与c有一些区别）
// func GenCMTS(values uint64, pk *ecdsa.PublicKey, sns []byte, rs []byte, sna []byte) *common.Hash {

// 	values_c := C.ulong(values)
// 	PK := crypto.PubkeyToAddress(*pk) //--zy
// 	pk_c := C.CString(common.ToHex(PK[:]))
// 	sns_string := common.ToHex(sns[:])
// 	sns_c := C.CString(sns_string)
// 	defer C.free(unsafe.Pointer(sns_c))
// 	rs_string := common.ToHex(rs[:])
// 	rs_c := C.CString(rs_string)
// 	defer C.free(unsafe.Pointer(rs_c))
// 	sna_string := common.ToHex(sna[:])
// 	sna_c := C.CString(sna_string)
// 	defer C.free(unsafe.Pointer(sna_c))
// 	//uint64_t value_s,char* pk_string,char* sn_s_string,char* r_s_string,char *sn_old_string
// 	cmtA_c := C.genCMTS(values_c, pk_c, sns_c, rs_c, sna_c) //64长度16进制数
// 	cmtA_go := C.GoString(cmtA_c)
// 	//res := []byte(cmtA_go)
// 	res, _ := hex.DecodeString(cmtA_go)
// 	reshash := common.BytesToHash(res) //32长度byte数组
// 	return &reshash
// }

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
	//uint64_t value_s,char* sn_s_string,char* r_s_string,char *sn_old_string
	cmtA_c := C.genCMT_1(values_c, sns_c, rs_c, sna_c) //64长度16进制数
	cmtA_go := C.GoString(cmtA_c)
	//res := []byte(cmtA_go)
	res, _ := hex.DecodeString(cmtA_go)
	reshash := common.BytesToHash(res) //32长度byte数组
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

func ComputeR(sk *big.Int) *ecdsa.PublicKey {
	return &ecdsa.PublicKey{} //tbd
}

func Encrypt(pub *ecdsa.PublicKey, m []byte) ([]byte, error) {
	P := ecies.ImportECDSAPublic(pub)
	ke := P.X.Bytes()
	ke = ke[:16]
	ct, err := ecies.SymEncrypt(rand.Reader, P.Params, ke, m)

	return ct, err
}

func Decrypt(pub *ecdsa.PublicKey, ct []byte) ([]byte, error) {
	P := ecies.ImportECDSAPublic(pub)
	ke := P.X.Bytes()
	ke = ke[:16]
	m, err := ecies.SymDecrypt(P.Params, ke, ct)
	return m, err
}

type AUX struct {
	Value uint64
	SNs   *common.Hash
	Rs    *common.Hash
	SNa   *common.Hash
}

func ComputeAUX(randomReceiverPK *ecdsa.PublicKey, value uint64, SNs *common.Hash, Rs *common.Hash, SNa *common.Hash) []byte {
	aux := AUX{
		Value: value,
		SNs:   SNs,
		Rs:    Rs,
		SNa:   SNa,
	}
	bytes, _ := rlp.EncodeToBytes(aux)
	encbytes, _ := Encrypt(randomReceiverPK, bytes)
	return encbytes
}

func DecAUX(key *ecdsa.PublicKey, data []byte) (uint64, *common.Hash, *common.Hash, *common.Hash) {
	decdata, _ := Decrypt(key, data)
	aux := AUX{}
	r := bytes.NewReader(decdata)

	s := rlp.NewStream(r, 128)
	if err := s.Decode(&aux); err != nil {
		fmt.Println("Decode aux error: ", err)
		return 0, nil, nil, nil
	}
	return aux.Value, aux.SNs, aux.Rs, aux.SNa
}

func GenerateKeyForRandomB(R *ecdsa.PublicKey, kB *ecdsa.PrivateKey) *ecdsa.PrivateKey {
	//skB*R
	c := kB.PublicKey.Curve
	tx, ty := c.ScalarMult(R.X, R.Y, kB.D.Bytes())
	tmp := tx.Bytes()
	tmp = append(tmp, ty.Bytes()...)

	//生成hash值H(skB*R)
	h := sha256.New()
	h.Write([]byte(tmp))
	bs := h.Sum(nil)
	bs[0] = bs[0] % 128
	i := new(big.Int)
	i = i.SetBytes(bs)

	//生成公钥
	sx, sy := c.ScalarBaseMult(bs)
	sskB := new(ecdsa.PrivateKey)
	sskB.PublicKey.X, sskB.PublicKey.Y = c.Add(sx, sy, kB.PublicKey.X, kB.PublicKey.Y)
	sskB.Curve = c
	//生成私钥
	sskB.D = i.Add(i, kB.D)
	return sskB
}

func GenR() *ecdsa.PrivateKey {
	Ka, err := crypto.GenerateKey()
	if err != nil {
		return nil
	}
	return Ka
}

func NewRandomPubKey(sA *big.Int, pkB ecdsa.PublicKey) *ecdsa.PublicKey {
	//sA*pkB
	c := pkB.Curve
	tx, ty := c.ScalarMult(pkB.X, pkB.Y, sA.Bytes())
	tmp := tx.Bytes()
	tmp = append(tmp, ty.Bytes()...)

	//生成hash值H(sA*pkB)
	h := sha256.New()
	h.Write([]byte(tmp))
	bs := h.Sum(nil)
	bs[0] = bs[0] % 128

	//生成用于加密的公钥H(sA*pkB)P+pkB
	sx, sy := c.ScalarBaseMult(bs)
	spkB := new(ecdsa.PublicKey)
	spkB.X, spkB.Y = c.Add(sx, sy, pkB.X, pkB.Y)
	spkB.Curve = c
	return spkB
}

//V2G

func GenMintProof(ValueOld uint64, RAold *common.Hash, SNAnew *common.Hash, RAnew *common.Hash, CMTold *common.Hash, SNold *common.Hash, CMTnew *common.Hash, ValueNew uint64) []byte {
	value_c := C.ulong(ValueNew)     //转换后零知识余额对应的明文余额
	value_old_c := C.ulong(ValueOld) //转换前零知识余额对应的明文余额

	sn_old_c := C.CString(common.ToHex(SNold[:]))
	r_old_c := C.CString(common.ToHex(RAold[:]))
	sn_c := C.CString(common.ToHex(SNAnew[:]))
	r_c := C.CString(common.ToHex(RAnew[:]))

	cmtA_old_c := C.CString(common.ToHex(CMTold[:])) //对于CMT  需要将每一个byte拆为两个16进制字符
	cmtA_c := C.CString(common.ToHex(CMTnew[:]))

	value_s_c := C.ulong(ValueNew - ValueOld) //需要被转换的明文余额
	t1 := time.Now()
	cproof := C.genMintproof(value_c, value_old_c, sn_old_c, r_old_c, sn_c, r_c, cmtA_old_c, cmtA_c, value_s_c)
	t2 := time.Now()
	genMintproof_time := t2.Sub(t1)
	log.Info("---------------------------------genMintproof_time---------------------------------")
	log.Info(fmt.Sprintf("genMintproof_time = %v ", genMintproof_time))

	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidMintProof = errors.New("Verifying mint proof failed!!!")

func VerifyMintProof(cmtold *common.Hash, snaold *common.Hash, cmtnew *common.Hash, value uint64, proof []byte) error {
	cproof := C.CString(string(proof))
	cmtA_old_c := C.CString(common.ToHex(cmtold[:]))
	cmtA_c := C.CString(common.ToHex(cmtnew[:]))
	sn_old_c := C.CString(common.ToHex(snaold.Bytes()[:]))
	value_s_c := C.ulong(value)
	t1 := time.Now()
	tf := C.verifyMintproof(cproof, cmtA_old_c, sn_old_c, cmtA_c, value_s_c)
	t2 := time.Now()
	veriftMintproof_time := t2.Sub(t1)
	log.Info("---------------------------------veriftMintproof_time---------------------------------")
	log.Info(fmt.Sprintf("veriftMintproof_time = %v ", veriftMintproof_time))
	if tf == false {
		return InvalidMintProof
	}
	return nil
}

func GenRedeemProof(ValueOld uint64, RAold *common.Hash, SNAnew *common.Hash, RAnew *common.Hash, CMTold *common.Hash, SNold *common.Hash, CMTnew *common.Hash, ValueNew uint64) []byte {
	value_c := C.ulong(ValueNew)     //转换后零知识余额对应的明文余额
	value_old_c := C.ulong(ValueOld) //转换前零知识余额对应的明文余额

	sn_old_c := C.CString(common.ToHex(SNold.Bytes()[:]))
	r_old_c := C.CString(common.ToHex(RAold.Bytes()[:]))
	sn_c := C.CString(common.ToHex(SNAnew.Bytes()[:]))
	r_c := C.CString(common.ToHex(RAnew.Bytes()[:]))

	cmtA_old_c := C.CString(common.ToHex(CMTold[:])) //对于CMT  需要将每一个byte拆为两个16进制字符
	cmtA_c := C.CString(common.ToHex(CMTnew[:]))

	value_s_c := C.ulong(ValueOld - ValueNew) //需要被转换的明文余额
	t1 := time.Now()
	cproof := C.genRedeemproof(value_c, value_old_c, sn_old_c, r_old_c, sn_c, r_c, cmtA_old_c, cmtA_c, value_s_c)
	t2 := time.Now()
	genRedeemproof_time := t2.Sub(t1)
	log.Info("---------------------------------genRedeemproof_time---------------------------------")
	log.Info(fmt.Sprintf("genRedeemproof_time = %v ", genRedeemproof_time))

	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidRedeemProof = errors.New("Verifying redeem proof failed!!!")

func VerifyRedeemProof(cmtold *common.Hash, snaold *common.Hash, cmtnew *common.Hash, value uint64, proof []byte) error {
	cproof := C.CString(string(proof))
	cmtA_old_c := C.CString(common.ToHex(cmtold[:]))
	cmtA_c := C.CString(common.ToHex(cmtnew[:]))
	sn_old_c := C.CString(common.ToHex(snaold.Bytes()[:]))
	value_s_c := C.ulong(value)
	t1 := time.Now()
	tf := C.verifyRedeemproof(cproof, cmtA_old_c, sn_old_c, cmtA_c, value_s_c)
	t2 := time.Now()
	veriftRedeemproof_time := t2.Sub(t1)
	log.Info("---------------------------------veriftRedeemproof_time---------------------------------")
	log.Info(fmt.Sprintf("veriftRedeemproof_time = %v ", veriftRedeemproof_time))
	if tf == false {
		return InvalidRedeemProof
	}
	return nil
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
	t1 := time.Now()
	cproof := C.genConvertproof(valueA_c, snS, rS, snA, rA_c, cmtS, cmtA_c, valueS, valueANew_c, snAnew_c, rAnew_c, cmtAnew_c)
	t2 := time.Now()
	genConvertproof_time := t2.Sub(t1)
	log.Info("---------------------------------genConvertproof_time---------------------------------")
	log.Info(fmt.Sprintf("genConvertproof_time = %v ", genConvertproof_time))
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
	t1 := time.Now()
	tf := C.verifyConvertproof(cproof, cmtAold_c, snAold_c, cmtS, cmtAnew_c)
	t2 := time.Now()
	verifyConvertproof_time := t2.Sub(t1)
	log.Info("---------------------------------verifyConvertproof_time---------------------------------")
	log.Info(fmt.Sprintf("verifyConvertproof_time = %v ", verifyConvertproof_time))
	if tf == false {
		return InvalidConvertProof
	}
	return nil
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
	t1 := time.Now()
	cproof := C.genCommitproof(snS, rS, snA, valueS, cmtS, cmtsM, nC, rt)
	t2 := time.Now()
	genCommitproof_time := t2.Sub(t1)
	log.Info("---------------------------------genCommitproof_time---------------------------------")
	log.Info(fmt.Sprintf("genCommitproof_time = %v ", genCommitproof_time))
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidCommitProof = errors.New("Verifying commit proof failed!!!")

func VerifyCommitProof(ValueS uint64, SN_S *common.Hash, RT []byte, proof []byte) error {
	cproof := C.CString(string(proof))
	valueS := C.ulong(ValueS)
	snS := C.CString(common.ToHex(SN_S[:]))
	rt := C.CString(common.ToHex(RT))
	t1 := time.Now()
	tf := C.verifyCommitproof(cproof, rt, snS, valueS)
	t2 := time.Now()
	verifyCommitproof_time := t2.Sub(t1)
	log.Info("---------------------------------verifyCommitproof_time---------------------------------")
	log.Info(fmt.Sprintf("verifyCommitproof_time = %v ", verifyCommitproof_time))
	if tf == false {
		return InvalidCommitProof
	}
	return nil
}

func GenClaimProof(ValueS uint64, SNS *common.Hash, RS *common.Hash, CMTS *common.Hash) []byte {

	valueS := C.ulong(ValueS)
	snS := C.CString(common.ToHex(SNS.Bytes()[:]))
	rS := C.CString(common.ToHex(RS.Bytes()[:]))
	cmtS := C.CString(common.ToHex(CMTS[:]))
	t1 := time.Now()
	cproof := C.genClaimproof(snS, rS, cmtS, valueS)
	t2 := time.Now()
	genClaimRefundproof_time := t2.Sub(t1)
	log.Info("---------------------------------genClaimRefundproof_time---------------------------------")
	log.Info(fmt.Sprintf("genClaimRefundproof_time = %v ", genClaimRefundproof_time))
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidClaimProof = errors.New("Verifying claim proof failed!!!")

func VerifyClaimProof(cmts *common.Hash, ValueS uint64, proof []byte) error {
	cproof := C.CString(string(proof))
	valueS := C.ulong(ValueS)
	cmtS := C.CString(common.ToHex(cmts[:]))
	t1 := time.Now()
	tf := C.verifyClaimproof(cproof, cmtS, valueS)
	t2 := time.Now()
	verifyClaimRefundproof_time := t2.Sub(t1)
	log.Info("---------------------------------verifyClaimRefundproof_time---------------------------------")
	log.Info(fmt.Sprintf("verifyClaimRefundproof_time = %v ", verifyClaimRefundproof_time))
	if tf == false {
		return InvalidClaimProof
	}
	return nil
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
	t1 := time.Now()
	cproof := C.genDepositsgproof(valueBNew_c, valueB_c, SNB_c, RB_c, SNBnew_c, RBnew_c, SNS_c, RS_c, cmtB_c, cmtBnew_c, valueS_c, cmtS_c, cmtsM, nC, RT_c)
	t2 := time.Now()
	genDepositsgproof_time := t2.Sub(t1)
	log.Info("---------------------------------genDepositsgproof_time---------------------------------")
	log.Info(fmt.Sprintf("genDepositsgproof_time = %v ", genDepositsgproof_time))
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidDepositsgProof = errors.New("Verifying Deposit_sg proof failed!!!")

func VerifyDepositsgProof(sns *common.Hash, rtcmt common.Hash, cmtb *common.Hash, snb *common.Hash, cmtbnew *common.Hash, proof []byte) error {
	SNS_c := C.CString(common.ToHex(sns.Bytes()[:]))
	cproof := C.CString(string(proof))
	rtmCmt := C.CString(common.ToHex(rtcmt[:]))
	cmtB := C.CString(common.ToHex(cmtb[:]))
	cmtBnew := C.CString(common.ToHex(cmtbnew[:]))
	SNB_c := C.CString(common.ToHex(snb.Bytes()[:]))
	t1 := time.Now()
	tf := C.verifyDepositsgproof(cproof, rtmCmt, SNS_c, cmtB, SNB_c, cmtBnew)
	t2 := time.Now()
	verifyDepositsgproof_time := t2.Sub(t1)
	log.Info("---------------------------------verifyDepositsgproof_time---------------------------------")
	log.Info(fmt.Sprintf("verifyDepositsgproof_time = %v ", verifyDepositsgproof_time))
	if tf == false {
		return InvalidDepositsgProof
	}
	return nil
}
