package zktx

/*
#cgo LDFLAGS: -L/usr/local/lib -lzk_deposit_sg -lzk_refund -lzk_claim -lzk_declare -lzk_convert -lzk_commit -lzk_mint -lzk_redeem -lff  -lsnark -lstdc++  -lgmp -lgmpxx

#include "mintcgo.hpp"
#include "redeemcgo.hpp"
#include "convertcgo.hpp"
#include "commitcgo.hpp"
#include "declarecgo.hpp"
#include "claimcgo.hpp"
#include "deposit_sgcgo.hpp"
#include "refundcgo.hpp"

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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/ecies"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rlp"
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
	res, _ := hex.DecodeString(cmtA_go)
	reshash := common.BytesToHash(res)
	return &reshash
}

func GenCMT2(values uint64, rs []byte) *common.Hash {

	values_c := C.ulong(values)
	rs_string := common.ToHex(rs[:])
	rs_c := C.CString(rs_string)
	defer C.free(unsafe.Pointer(rs_c))
	cmtA_c := C.genCMT2(values_c, rs_c) //64长度16进制数
	cmtA_go := C.GoString(cmtA_c)
	res, _ := hex.DecodeString(cmtA_go)
	reshash := common.BytesToHash(res) //32长度byte数组
	return &reshash
}

//GenRT 返回merkle树的hash  --zy
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

//Ev Rental

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
	log.Info("---------------------------------genCost(user)proof_time---------------------------------")
	log.Info(fmt.Sprintf("genCost(user)proof_time = %v ", genConvertproof_time))
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidConvertProof = errors.New("Verifying Cost(user) proof failed!!!")

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
	log.Info("---------------------------------verifyCost(user)proof_time---------------------------------")
	log.Info(fmt.Sprintf("verifyCost(user)proof_time = %v ", verifyConvertproof_time))
	if tf == false {
		return InvalidConvertProof
	}
	return nil
}

func GenCommitProof(ValueS uint64, SNS *common.Hash, RS *common.Hash, CMTS *common.Hash, RT common.Hash, CMTSForMerkle []*common.Hash) []byte {

	valueS := C.ulong(ValueS)
	snS := C.CString(common.ToHex(SNS.Bytes()[:]))
	rS := C.CString(common.ToHex(RS.Bytes()[:]))
	cmtS := C.CString(common.ToHex(CMTS.Bytes()[:]))

	rt := C.CString(common.ToHex(RT[:]))

	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(common.ToHex(CMTSForMerkle[i][:]))
		cmtArray += s
	}
	cmtsM := C.CString(cmtArray)
	nC := C.int(len(CMTSForMerkle))
	t1 := time.Now()
	cproof := C.genCommitproof(snS, rS, valueS, cmtS, cmtsM, nC, rt)
	t2 := time.Now()
	genCommitproof_time := t2.Sub(t1)
	log.Info("---------------------------------genCommit(user)proof_time---------------------------------")
	log.Info(fmt.Sprintf("genCommit(user)proof_time = %v ", genCommitproof_time))
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidCommitProof = errors.New("Verifying commit proof failed!!!")

func VerifyCommitProof(SN_S *common.Hash, RT common.Hash, proof []byte) error {
	cproof := C.CString(string(proof))
	snS := C.CString(common.ToHex(SN_S[:]))
	rt := C.CString(common.ToHex(RT[:]))
	t1 := time.Now()
	tf := C.verifyCommitproof(cproof, rt, snS)
	t2 := time.Now()
	verifyCommitproof_time := t2.Sub(t1)
	log.Info("---------------------------------verifyCommit(user)userproof_time---------------------------------")
	log.Info(fmt.Sprintf("verifyCommit(user)proof_time = %v ", verifyCommitproof_time))
	if tf == false {
		return InvalidCommitProof
	}
	return nil
}

func GenDeclareProof(DS *common.Hash, RC *common.Hash, CMTTC *common.Hash, subcost uint64, dist uint64, SNS *common.Hash, RS *common.Hash, CMTS *common.Hash) []byte {

	subcost_c := C.ulong(subcost)
	dist_c := C.ulong(dist)
	SNS_c := C.CString(common.ToHex(SNS.Bytes()[:]))
	RS_c := C.CString(common.ToHex(RS.Bytes()[:]))
	cmtS_c := C.CString(common.ToHex(CMTS[:]))

	R_c := C.CString(common.ToHex(RC.Bytes()[:]))
	cmtt_C := C.CString(common.ToHex(CMTTC.Bytes()[:]))

	ds_c := C.CString(common.ToHex(DS[:]))

	t1 := time.Now()
	cproof := C.genDeclareproof(SNS_c, RS_c, cmtS_c, R_c, cmtt_C, subcost_c, dist_c, ds_c)
	t2 := time.Now()
	genDepositsgproof_time := t2.Sub(t1)
	log.Info("---------------------------------genDeclare(owner)proof_time---------------------------------")
	log.Info(fmt.Sprintf("genDeclare(owner)proof_time = %v ", genDepositsgproof_time))
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidDeclareProof = errors.New("Verifying verifyDeclare(owner) proof failed!!!")

func VerifyDeclareProof(ds *common.Hash, cmtt *common.Hash, proof []byte) error {

	cproof := C.CString(string(proof))
	cmtt_C := C.CString(common.ToHex(cmtt[:]))
	ds_C := C.CString(common.ToHex(ds[:]))
	t1 := time.Now()
	tf := C.verifyDeclareproof(cproof, cmtt_C, ds_C)
	t2 := time.Now()
	verifyDepositsgproof_time := t2.Sub(t1)
	log.Info("---------------------------------verifyDeclare(owner)_time---------------------------------")
	log.Info(fmt.Sprintf("verifyDeclare(owner)_time = %v ", verifyDepositsgproof_time))
	if tf == false {
		return InvalidDeclareProof
	}
	return nil
}

func GenClaimProof(cost uint64, subcost uint64, dist uint64, subdist uint64, fees uint64, refundi uint64, SNS *common.Hash, RS *common.Hash, CMTS *common.Hash, RC *common.Hash, CMTT *common.Hash, DS *common.Hash) []byte {

	snS := C.CString(common.ToHex(SNS.Bytes()[:]))
	defer C.free(unsafe.Pointer(snS))
	rS := C.CString(common.ToHex(RS.Bytes()[:]))
	defer C.free(unsafe.Pointer(rS))
	cmtS := C.CString(common.ToHex(CMTS[:]))
	defer C.free(unsafe.Pointer(cmtS))
	rC := C.CString(common.ToHex(RC.Bytes()[:]))
	defer C.free(unsafe.Pointer(rC))
	cmtT := C.CString(common.ToHex(CMTT[:]))
	defer C.free(unsafe.Pointer(cmtT))
	ds := C.CString(common.ToHex(DS[:]))
	costC := C.ulong(cost)
	subcostC := C.ulong(subcost)
	distC := C.ulong(dist)
	subdistC := C.ulong(subdist)
	feesC := C.ulong(fees)
	refundiC := C.ulong(refundi)

	t1 := time.Now()
	cproof := C.genClaimproof(snS, rS, cmtS, rC, cmtT, costC, subcostC, distC, subdistC, feesC, refundiC, ds)
	t2 := time.Now()
	genClaimRefundproof_time := t2.Sub(t1)
	log.Info("---------------------------------genDivide(user)proof_time---------------------------------")
	log.Info(fmt.Sprintf("genDivide(user)proof_time = %v ", genClaimRefundproof_time))
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidClaimProof = errors.New("Verifying Divide(user) proof failed!!!")

func VerifyClaimProof(cmts *common.Hash, cmtt *common.Hash, DS *common.Hash, proof []byte) error {

	cproof := C.CString(string(proof))
	defer C.free(unsafe.Pointer(cproof))
	cmtS := C.CString(common.ToHex(cmts[:]))
	defer C.free(unsafe.Pointer(cmtS))
	cmtT := C.CString(common.ToHex(cmtt[:]))
	defer C.free(unsafe.Pointer(cmtT))
	ds := C.CString(common.ToHex(DS[:]))

	// subdistC := C.ulong(subdist)
	// distC := C.ulong(dist) uint64, dist
	// feesC := C.ulong(fees)
	t1 := time.Now()
	tf := C.verifyClaimproof(cproof, cmtS, cmtT, ds)
	t2 := time.Now()
	verifyClaimRefundproof_time := t2.Sub(t1)
	log.Info("---------------------------------verifyDivide(user)proof_time---------------------------------")
	log.Info(fmt.Sprintf("verifyDivide(user)proof_time = %v ", verifyClaimRefundproof_time))
	if tf == false {
		return InvalidClaimProof
	}
	return nil
}

func GenDepositsgProof(RC *common.Hash, CMTTC *common.Hash, ValueS uint64, SNS *common.Hash, RS *common.Hash, CMTS *common.Hash,
	ValueB uint64, SNB *common.Hash, RB *common.Hash, CMTB *common.Hash,
	SNBnew *common.Hash, RBnew *common.Hash, CMTBnew *common.Hash,
	RTcmt []byte, CMTSForMerkle []*common.Hash) []byte {

	valueS_c := C.ulong(ValueS)
	SNS_c := C.CString(common.ToHex(SNS.Bytes()[:])) //--zy
	defer C.free(unsafe.Pointer(SNS_c))
	RS_c := C.CString(common.ToHex(RS.Bytes()[:])) //--zy
	defer C.free(unsafe.Pointer(RS_c))
	cmtS_c := C.CString(common.ToHex(CMTS[:]))
	defer C.free(unsafe.Pointer(cmtS_c))
	valueB_c := C.ulong(ValueB)
	SNB_c := C.CString(common.ToHex(SNB.Bytes()[:]))
	defer C.free(unsafe.Pointer(SNB_c))
	RB_c := C.CString(common.ToHex(RB.Bytes()[:]))
	defer C.free(unsafe.Pointer(RB_c))
	cmtB_c := C.CString(common.ToHex(CMTB[:]))
	defer C.free(unsafe.Pointer(cmtB_c))
	valueBNew_c := C.ulong(ValueB + ValueS)
	SNBnew_c := C.CString(common.ToHex(SNBnew.Bytes()[:]))
	defer C.free(unsafe.Pointer(SNBnew_c))
	RBnew_c := C.CString(common.ToHex(RBnew.Bytes()[:]))
	defer C.free(unsafe.Pointer(RBnew_c))
	cmtBnew_c := C.CString(common.ToHex(CMTBnew[:]))
	defer C.free(unsafe.Pointer(cmtBnew_c))
	RT_c := C.CString(common.ToHex(RTcmt)) //--zy   rt
	defer C.free(unsafe.Pointer(RT_c))
	R_c := C.CString(common.ToHex(RC.Bytes()[:]))
	defer C.free(unsafe.Pointer(R_c))
	cmtt_C := C.CString(common.ToHex(CMTTC.Bytes()[:]))
	defer C.free(unsafe.Pointer(cmtt_C))

	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(common.ToHex(CMTSForMerkle[i][:]))
		cmtArray += s
	}
	cmtsM := C.CString(cmtArray)
	nC := C.int(len(CMTSForMerkle))
	t1 := time.Now()
	cproof := C.genDepositsgproof(valueBNew_c, valueB_c, SNB_c, RB_c, SNBnew_c, RBnew_c, SNS_c, RS_c, cmtB_c, cmtBnew_c, valueS_c, cmtS_c, cmtsM, nC, RT_c, R_c, cmtt_C)
	t2 := time.Now()
	genDepositsgproof_time := t2.Sub(t1)
	log.Info("---------------------------------genCollect(owner)proof_time---------------------------------")
	log.Info(fmt.Sprintf("genCollect(owner)proof_time = %v ", genDepositsgproof_time))
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidDepositsgProof = errors.New("Verifying verifyCollect(owner) proof failed!!!")

func VerifyDepositsgProof(cmtt *common.Hash, sns *common.Hash, rtcmt common.Hash, cmtb *common.Hash, snb *common.Hash, cmtbnew *common.Hash, proof []byte) error {
	SNS_c := C.CString(common.ToHex(sns.Bytes()[:]))
	defer C.free(unsafe.Pointer(SNS_c))
	cproof := C.CString(string(proof))
	defer C.free(unsafe.Pointer(cproof))
	rtmCmt := C.CString(common.ToHex(rtcmt[:]))
	defer C.free(unsafe.Pointer(rtmCmt))
	cmtB := C.CString(common.ToHex(cmtb[:]))
	defer C.free(unsafe.Pointer(cmtB))
	cmtBnew := C.CString(common.ToHex(cmtbnew[:]))
	defer C.free(unsafe.Pointer(cmtBnew))
	SNB_c := C.CString(common.ToHex(snb.Bytes()[:]))
	defer C.free(unsafe.Pointer(SNB_c))
	cmtt_C := C.CString(common.ToHex(cmtt[:]))
	defer C.free(unsafe.Pointer(cmtt_C))
	t1 := time.Now()
	tf := C.verifyDepositsgproof(cproof, rtmCmt, SNS_c, cmtB, SNB_c, cmtBnew, cmtt_C)
	t2 := time.Now()
	verifyDepositsgproof_time := t2.Sub(t1)
	log.Info("---------------------------------verifyCollect(owner)_time---------------------------------")
	log.Info(fmt.Sprintf("verifyCollect(owner)_time = %v ", verifyDepositsgproof_time))
	if tf == false {
		return InvalidDepositsgProof
	}
	return nil
}

func GenDepositProof(fees uint64, cost uint64, ValueS uint64, SNS *common.Hash, RS *common.Hash, CMTS *common.Hash,
	ValueB uint64, SNB *common.Hash, RB *common.Hash, CMTB *common.Hash,
	SNBnew *common.Hash, RBnew *common.Hash, CMTBnew *common.Hash,
	RTcmt []byte, CMTSForMerkle []*common.Hash) []byte {

	valueS_c := C.ulong(ValueS)
	SNS_c := C.CString(common.ToHex(SNS.Bytes()[:]))
	RS_c := C.CString(common.ToHex(RS.Bytes()[:]))
	cmtS_c := C.CString(common.ToHex(CMTS[:]))
	valueB_c := C.ulong(ValueB)
	SNB_c := C.CString(common.ToHex(SNB.Bytes()[:]))
	RB_c := C.CString(common.ToHex(RB.Bytes()[:]))
	cmtB_c := C.CString(common.ToHex(CMTB[:]))
	valueBNew_c := C.ulong(ValueB + ValueS)
	SNBnew_c := C.CString(common.ToHex(SNBnew.Bytes()[:]))
	RBnew_c := C.CString(common.ToHex(RBnew.Bytes()[:]))
	cmtBnew_c := C.CString(common.ToHex(CMTBnew[:]))
	RT_c := C.CString(common.ToHex(RTcmt))
	fees_C := C.ulong(fees)
	cost_C := C.ulong(cost)

	var cmtArray string
	for i := 0; i < len(CMTSForMerkle); i++ {
		s := string(common.ToHex(CMTSForMerkle[i][:]))
		cmtArray += s
	}
	cmtsM := C.CString(cmtArray)
	nC := C.int(len(CMTSForMerkle))
	t1 := time.Now()
	cproof := C.genRefundproof(valueBNew_c, valueB_c, SNB_c, RB_c, SNBnew_c, RBnew_c, SNS_c, RS_c, cmtB_c, cmtBnew_c, valueS_c, cmtS_c, cmtsM, nC, RT_c, fees_C, cost_C)
	t2 := time.Now()
	genDepositsgproof_time := t2.Sub(t1)
	log.Info("---------------------------------genRefund(user)proof_time---------------------------------")
	log.Info(fmt.Sprintf("genRefund(user)proof_time = %v ", genDepositsgproof_time))
	var goproof string
	goproof = C.GoString(cproof)
	return []byte(goproof)
}

var InvalidDepositProof = errors.New("Verifying verifyRefund(user) proof failed!!!")

func VerifyDepositProof(fees uint64, sns *common.Hash, rtcmt common.Hash, cmtb *common.Hash, snb *common.Hash, cmtbnew *common.Hash, proof []byte) error {

	cproof := C.CString(string(proof))
	rtmCmt := C.CString(common.ToHex(rtcmt[:]))
	cmtB := C.CString(common.ToHex(cmtb[:]))
	snold_C := C.CString(common.ToHex(snb.Bytes()[:]))
	cmtBnew := C.CString(common.ToHex(cmtbnew[:]))
	SNS_c := C.CString(common.ToHex(sns.Bytes()[:]))
	fees_C := C.ulong(fees)
	t1 := time.Now()
	tf := C.verifyRefundproof(cproof, rtmCmt, cmtB, snold_C, cmtBnew, SNS_c, fees_C)
	t2 := time.Now()
	verifyDepositsgproof_time := t2.Sub(t1)
	log.Info("---------------------------------verifyRefund(user)_time---------------------------------")
	log.Info(fmt.Sprintf("verifyRefund(user)_time = %v ", verifyDepositsgproof_time))
	if tf == false {
		return InvalidDepositProof
	}
	return nil
}

//---------data for test------------------

//初始化余额cmt
var CmtA_old = common.HexToHash("0x5481b30e41acc0611fcf055617c29247c776dbca03ea7a4566ee618b3a38319c")

var Sn_old = common.HexToHash("0x364d3f5af0cc140746b48072ff1ba28c12d84106bdcdf66e7a26c68f70e5f04c")

var R_old = common.HexToHash("0x80f10f96535550f7be47e0f7477ddec9d2d94b0df3bff810a97f9fd383104d3f")

//mint更新后余额
var CmtA = common.HexToHash("0xf9e4641a63b76a99306361826c26580e746c9f3f7756065cf789b97cf7f46385")

var Sn = common.HexToHash("0xbdba1ea395c9bfc41f666440c1030e1d705f77572f2a29c53d8a7ce8d9448579")

var R = common.HexToHash("0x706bb444aae459a509b5f694c1138c2d2a8b81802747e3d5989bb828fde50af1")

//mint proof
var Mint_proof = []byte("19b17abf3f3876ed49378fddaa026c148bba042e3834e2a73f4ad6bfbe088df60203ea3b66c308970621e574bc17468818c9d590670787ea0187d8c957f3f30014540f443bd963e32e7c20533527d53532f01c964d51b832ed8cfcb824f262610c5a10182387d2f043ca5b8e9c211d64708924cd9039ed372446e8f71a90c7a703015c4d022e6b235749d87361265be896023fd7e25ccca3d5d13fabbb1e2ffb25773a91c22cd20903d2913535263150ab5c89f0d5d5e80122697db30a1a33c515446a8ffe3ae311d4a15286eb247bfcf5149fcb476ba7ae34ffc371e60c0d2e1e7ad586b2d3675430f21c60de40d40c5fbafae88f98b6f894fd5a4ef9cc2baa0620247318d6929c2da136883daad5f708e0daf3165b02fb094c9461b7a20a1309e72435805d59d8df421a0eca2874c680309cd49ffbd617bfea963c2b6a93d82cbedc4f9a15bb65c3bc96dbd2345954f038a3cded52b10a73e68cb8a08c838e03c5824becc6c7bd42419ab8be15960bf57ebdebca07d18f73043e77c99ae89c23d87218abec65616d0c3abfd22b293d4a746b888569b809936517271cfa586a29830e1c20406f091c098d3911eafc9e6ed4e4444c444b3926f8b67c9aeb78c201b3ed6b210c3e164fc28a341b36b42ace9c881239c7e6b1432bda38fbbd0dfe1fc2f67581eee16909eb580786a5c49ad580e6dcce84067924ff61ce3e5dd1301a37f00087edb5c03e89a3d462fcf0d2bc1ab8590559f36215139676182fee412b8d60bc7014ee5e8e1ea01a2cbb9e3223196437cb68d28481220bafedeae08a")

//convert转账金额
var CmtS = common.HexToHash("0x1c15a7710d1baff53034d0b6c8f79114e295c85e51f0d152e1daa94780e2c99b")

var Sn_s = common.HexToHash("0x5d1c0fbf86236d396ff8dd7b9c326cfd1b421dbf12bd6d6933f5921a283360c2")

var R_s = common.HexToHash("0xcdcca9150ef5a38737e3f59ccda6f4b569ce13c7b691b0db1cd2327f2da5e384")

//convert更新后金额
var CmtA_new = common.HexToHash("0x0f2d410bbbd9c1daf445cae124c8a4dcfe13fe2f67dd45eea6ac6d192e4bbee1")

var Sn_new = common.HexToHash("0xc782038add929164795c2002ba28b02a0669b78ffbfe0bc0deafee97e4691392")

var R_new = common.HexToHash("0x3f023847309a25bf89ca757d3c12d39c15f2f11670e74efe9a17f304acecdb0d")

//convert proof
var Convert_proof = []byte("23e3233322a634dd0167535d16053150be4f2421746088e10899cec46c90b4c80980c4de4a3326690cd895b821edb19d9b8971cdf61507c0f60efb39bddf45552a9c39a3bb67b9be9eeeb141e432060cb1e8e71d70c142d8868855f5d555723b2abc8328b0ae639c4ae9155bb62df70a78e3f5cef70a04d8e3161c083445a9b60e586bf73766aeef5bafec789b72fc1623716a55236ece0a6386347f06ddc23a1cc75604bd3480a656ae8bd084b2866ca700c29baec36a473a6da4e8712b2c9225e9196bb8861f7f14b20e006632f58f02e8466450e21dda8c044f2fdd6d29d50fe2c0060c6057af06357953b8be09f946a8a1902d476721a686789e96562aec1ebd934d31841d9e207b920741b668a5afe3f81f55acc17fb49852890f4f92fb0bdf99ddd4b210a7864ad49d8678720449a386c0d374af79275b1c2cd60c7ed62a0731e19007d23d8a7eff5c93b33e4871a603ae68c2cd9548790e01497b3ce025937f02ae1b664e4cb83daa03fedca4812b11fdea76243ecefd09507164e52518318f2936706aa2a6eaf04f3f2b56fc4184aa17e361b4174f011f390398518706515d94ddbff89337ef16aba20249905d3117eaaae25f6efa2a54246f6c5b37300dff2040a803426ef05a64ad0db8438143d658f6bb8364fe02c873a0921e422fc90fe13bab00f9c95255bc8790048644f7080959df2ac3448f3b53a37746a029fa84964330a564bd00458ffc290bb706c5bb3dd34e4b6d75b0c544434d6cd804313cf446ca717dde4652830f98166cea2577b214fd8401034334b04dbf65fd")

//默克尔树数组
var Cmt_str = []string{"0xf1c5065347fbc8b09870327031cee307223e47f6b0635e8f31f148217c5d57e9",
	"0x456eebc47c43b9af0f4f6c7b1d7093fa379931e0ef7170019eb58dee215d1f1d",
	"0xed29100dbf744254e89e5396432cc20a3abe101e4853e33efd0edb0637189453",
	"0xdfd71424f1153ab24a9995b05f4c9cbbde080055bf2774a69ba58a8be409f872",
	"0x558841935e39af07d58b8cfe2a1b2ef92af119535bd44e9698a25adcaad1b4e3",
	"0x35b08ba7feb31de2a64853548650ac7e6506642c76d36ccc95c50ca9b1d7f205",
	"0x91e878c71a9b575080d6a5d525a5426876b83bc7e52f30937809bcb4024bc15a",
	"0x4f60392c9b6f78b6181555aed80242b22170ac78397646bee1baa27f9f768197",
	"0x13e4c77f676c91e806b499e2ef2bd16cd5438c39c3d87f2423d6e4a30fe2ef83",
	"0x0dd5da0b3efc5a79f7f9a75fa1e02083f79360f3bbe979eda2d49f7c26bc1b5a",
	"0x655550e8bd26504717a965c47f32f93bb0b0e002936b0b9d5e6583e6bd2fbd18",
	"0xf844a59228ed5432c692ac4e895ff430df5e0e2c72e0a9c2b5d3dbccdfe54e3d",
	"0x7c1c156ebf74633eb44b461178dc0d107db847b9710e313f4f5d2a816608c3ad",
	"0x2f06ed56305c54117aa689018874b4bf478baefbf940c67bd19a18e9f023e0e6",
	"0x919ecd9f9cc6d65f509b1823f65e47264e2212eefc198dedc0ede98026bdb7af",
	"0xb55b09f47918b7da9faca6799b6ec37b89834f8410ee5ac41d831d94d4b4debd",
	"0x413af06bb40c504eb3dd6df0834e92966ce095b5ea567be7ac0013973733e41f",
	"0xe63180a113959e3d79e1089d6b13e69097f91d70834a1b237e7121548276caed",
	"0xf90c0c7265b8741c48e5c88c5a62ae8654c11064816879ddaf33c6a9495a4e06",
	"0x91fe621985723a0cf52c24171c6a75d4822e087a9d1834316a50154e55666c86",
	"0x6b414f98c4a6bea1d19554b0312df5c9ee57436fdbabbb20ef5e50a12a38688f",
	"0x2efd7d45e2a1afb305494ba6c5689b51577abf651d3f2a14dd027dba234314cd",
	"0x172852c8fbc078fcb7f6538072c542c738b803d62b3f7d977d64a5096cc07c56",
	"0x2ee2033ce2389e7fe22a454665d8a128f5cfc7a6f63cd8af862f76b817f8ada9",
	"0x8c4b0ba5a2be9e5d0aa2cb957e0e12d8e761c03f3b37059220ce9d7a1f415fc5",
	"0x9ad4707baa3a5ecc8b0d05f9ded057629a1037c96343ccfde596b3668e0ec1dd",
	"0x83fd662d7ebed9cd307a6d981b19053822bf5115c571c2c18424e163bffe6258",
	"0xd75e4b40b1599c3dc43bc6cf0770582ff7e7cd2b87ddf7720bb859238b967fcc",
	"0x70f2fe589f31ed8d9b23d604d4f042425a1c06d598a70977454fb1e1b94f4e5d",
	"0x3070f2e966ce43fb4b6128b43cb65b65be00df5af1e3af6f2bcbefc323772ffc",
	"0xd2e7968ec0c91ac5e445e7c4b7a614f1898ee36753bdb1178a9be9bd9f743013",
	"0xaadc0030c6e7106f79ff05419493d41fc52d6aa8eb922e6149c942e917459836"}

//commit rtcmt
var RT = common.HexToHash("0x549db31dd091837d7bb80b89d4bff28be9080011a18fe5773e7a2689912768ea")

//存储在智能合约中凭证
var CmtC = common.HexToHash("0xd9bd22c7f6d35ddacad64374db2246bd42cf43f04fbe18647099d254fd6ad3e1")

var R_c = common.HexToHash("0xcf33d584ecf0034fd749ddae0df8c58e16a387fa1078697c3bc0b67a6e889553")

//commit proof
var Commit_proof = []byte("1dbe55723caec233620dd45167b3dcee117dab2bb2ae40c63a6a7f0f87b84a9e15cb7fcdb08fa0c3fd02ec2e4ba8db0046feb996afbbe25040625fad68ea5eb411e409cfef5f2b22048efd6f72e25b80bb30c7a1a93553e44fb8db7ee7756f120b6f383208319a4a88fda83d74481f7a7dec0c2fda26383dba270f8a2efb772601194fee11855e3635bde1b2f2bb227eb5d712faa2b92f6250c4712aaaa6338c1b1767db4e0d601ed02abea1e38ccd201899055dd8b9d9ffcc4e6a9b70bab3f61b2b20baa5542b7ca9d01e0f82c3bae66e9cdabb6385a458de771572d70beab202921435ee95f9e733f1a0f1b4961fea64cac346c81c07808171438ab9622be7077b6f50600ecdd1dea9dbd374ec59c14c99505d7c5af9f3d990768696388d7226ce845b5afc36d635fb94816698d0ab063d5d08837a168ce5804bbaaadde42926e8e2c3d6cffbadc0d6d8afaf185deaa10f9277c59bc678b6b4b1e0144f16a60b443851e438742f4de5daee08d75d12bce98582249f698e477d5e3cd142bc5d070b1c02a3b7656b44c1eac9921cd6321bff86b51a432396bc1e6a4f758ec47c21e8365cbc5251ea9a9eaace331e709a6c378184de8dc35ead6636354fe13fd520b0bdf94555aa40ac518595edfa378e560c6e6941803de91a15a8b492e63dd3217c478c38752d85347a5e2538fcbe304735e240f6096f43d5b525d37c6cc0ec260f99389c32b80d22d7ec9d495e6c2dd58538e8eff8ee2ff53aaf56414b555d00dbcf7fac9359bac0edbf316579323a071c7669f15659911c91b1d71a9b9f91")

//claim转账金额
var Cmtv = common.HexToHash("0x08b90f281509a8961b943c74b87c0547c9164b729849f22d9b12ad5d799e2c49")

var Sn_v = common.HexToHash("0x482c99c2421dfbc8517ab8a2d971e365cd32f34eb37f17bd7af342b22790a6f4")

var R_v = common.HexToHash("0x3206e16b56b0f6f0d6bcd2ca5999bc93b3f57dd8932bb67ce5c47a4b3862e77c")

//claim proof
var Claim_proof = []byte("2cdcb1b98b3c40412a18caa318b18eeafcc5a64818b0f6e2f26144c1f7ab0e66294ffa756573bd69ee58b3e3591fd90312b8c89335aa07435b0bbdf855457136020bdc92b62327963339ca545284b35fc7123164a3fc62f499d6dfd598e96f8428a7634be98541a2f9f08f64499405f1979b3970bc8e1fb4f9ee6079de2fd80b06267fd25637ecd529b3034d071824e70718783ad186386e2c7701c190a775ee0320f6c8a82c1e60d262d36c5ec43c81505392e5d93b430c56c81fb47b60b25b1bc34a30068c10b8c5d552806fe0921c38f05e1a546ee757124783678711dcb627e5bc27430f2c3063357251c7ba73d5e64a8e6b5473a9c3037146787a17f7d60dbab3c74091be630a116a3601375775db660a6f6fc2ef3620604ee5365a308b21be05db666297caf29db513df78cceaba2c0b9eccdc91dc1aff50edd64a7ac32b2abe500463904fadfaea473c80107c99a54d5844abf0fd1904d6aad50bfe0f259eb8a71a69e434ca2bf8fe3e3da2247ff369f36797dfb729d75ab3f1f14d1d2d41cc460aa8801cfbb31f04ac8c89a427c0b91009fd8ef31caf93fb7839a32630624982b8bba19b20b52b2f3ec5b21b3c0b26dd7a18d1918ed56a28dd31c231284320fc835179149a9bfae2fa4a472d6231fe8583c4efe486bf353fd71e9f552b36984ebf2f3b76df93d2c0a1dc3fba993b6bc75c006f14b54aad73730e377905df1658503cdf61414db99b7c9dc1910c77139e36961f2ca7f9684f275166fd078cf7090a35433ebe659790c4a6015ea4f363c6e6048e3336616dbc43ae6ae0")

//refund转账金额
var Cmtr = common.HexToHash("0x89d7665dfb0512bbae245cda0bf423cab0de6f3445070ccc17dee262cc5083e1")

var Sn_r = common.HexToHash("0x5a8e160331744a86c408f152bc51c3637395faa5dbdd672beecdf85dc3ebcd1b")

var R_r = common.HexToHash("0xc9646ac65155b1326b5f94c2e1bdb19f2f34ecf950561e4a976785cc74450b77")

//refund proof
var Refund_proof = []byte("1464ff6bf53538ba8aeda194c04aa136a6695b1abddaa89c3830056d4d3d828708c51040ea98710a2c49c4dbf3d136c3b60bcff8a97e9a3c2333516ec514d40927e9513b75fea026cd56f621ec5de80b37833e8493f64aa85ec751dfb6c5661a29517c84e248a6baea1419896d3f0c02a5f40771f32630f06f92681da625c62c2797437a746c4fbaaedd82bb94ae15c63b27ffeee87d6d5e7d7fbf4e6bf2831b302227ec900bcc9896a49e435427d4842defbc288b7f45de86b6fe3ebed11b442b196a77933ec18479468f6016e4e9c39c2fb62d16ce3d341fcf557bf7f360dd25755c72dede834061c801714f45fa8347e5c5444fd3cd59872bd43f4e2801e62654f708fbb4cd8f9c760283ba0c87dfebb73f81921295eb6edbd0a2bf247df1292eba623af696681a7eb23764d264e412ad1b4a0caec03520871d184fd447492370cae8af0d49020beb58d750996df89db16121ead649816e1d6a79e08e32c721d737748b56b471c68b604d437a3e3f4ca7d51cfd40937c7ad95b284db470d502f98ae16bf5e20106b5176216ef57daa088bdea20d6170da61ce352e19de8720d63b634ff8c1aab209ed17f17b743222f3bba5592a680cd20d733c9314a32721cb3295e78ed5546ed4b3517a6fed01a411c257ec0a3418aadba6a941197924e23d02e512bafffd2989c781e23b192f852374af82a17e26d0aa92fd6d12547762bd63ac3c7b1dee2d7b6d6aadf701f5ef2b294aeda9e276e4e7539bc694f029d2f6c33e837f7fb9291de175dc0f52d2a3f74a59538db68fc096d0018810950c2")

//B deposit更新金额
var CmtB_D = common.HexToHash("0xc2abf183e15f67b13156ef0781d6b1a906efe53ca99946722c5f12bc9b27f081")

var Sn_B_new = common.HexToHash("0x7792f54a0b68234ed2a8d3dfaf82ae6fd2b715d5997d0300f7f11b77d8a2c278")

var R_B_new = common.HexToHash("0xc0c7ea0dfd6de3183896bdca10dcd5b1881817f66d24b6ce18330018e4f21793")

//B deposit rtcmt
var RT_1 = common.HexToHash("0x5a490bcc72db75df82be1eb8505eeeda80a86b210183d321c8763e909fe4d074")

//B deposit proof
var Deposit_B_proof = []byte("0aa3a7269121027a42cd9762f4d4bac579d15847a54f35c9d4c678a9775cc62f2f4b72e4b8031e04caaaff8b016d4599061e1f4cc91ac550dd782b21618255640f71b70c18b22d676a1f83cb1c76498b7023d64596a7470565e07e95cebdf0ee0650992ef1c492a7451f3a2a52b0d8d68f9b7ac8fb1d61e52429e063115f1d16293a64f1a1fddce9bacb69ca81c6d9a462bdb3bbc63da59e64cba34913f23fc212a5263f918852c6bd6a68ad7a29843089627cff7f2fc1cba6a097efbcf09f2214da03c77f5d2727862ed3550a58e3fe18bd2b5f6a14f0e123cdb5ca8f3c67db1ce8b3930ce73a47992077a004f7a675436739cced3dd642cd2fed33b7110e1a04cab9611c380e2ef11a8fb6f7a8ff5fe15e71178db533e339bfcaae52e82e6e1a72ef9b33a5e34e3f4a5e01070c09944ed7a22e75a877ea16502fa5f99eac432017212a068b9390ef1d62a7766703bb592d3015746ae7c825731c3d111bf0ba1174661d3ba7a5d46e91e4de393ed4cc070fc4817a392be4bf3a4ca441b96bd4133ee38d5356cc3b806b790869e9404e867225c8428c969aa60a4336b742da840377e7fd8ea9cdb985a3628688844bdef8c691dca568a20b46871d7cea2e843713ebd332216ba15d47dca6202546cdb9a0522d1117ea7466ac1703e981090f351827f834313d9001696c19d9224150cd6be7ec6c30d4311ef55e645d657c55b52f91b1253ddae2c5e4787c89c8015dc214dc5de93da89e093309d5925665790c29acd5a48df3143a8aa8c8458edd26b9aead24f2dcfaa864d41b2c94b444682b")

//A deposit更新金额
var CmtA_D = common.HexToHash("0xff22ffc68185ce056f6113b365c86ca7999dab7f16675d1f25ef6a282ac38829")

var Sn_A_new = common.HexToHash("0x7792f54a0b68234ed2a8d3dfaf82ae6fd2b715d5997d0300f7f11b77d8a2c278")

var R_A_new = common.HexToHash("0xc0c7ea0dfd6de3183896bdca10dcd5b1881817f66d24b6ce18330018e4f21793")

//A deposit rtcmt
var RT_2 = common.HexToHash("0x882f273e346157ea2a86a68d2ec937ca20ec6b3339dba9024adbefec2ec6b63f")

//A deposit proof
var Deposit_A_proof = []byte("1726321182b536b8eb1adc576330aee746d53ba376cf62ad49d148e44cadfab01c314226cd667e5f6f1d5a2d2de3364b4ae4fe44de155eff12d7b038e7ad5bb5188bf11db3be029e157dfffea7394411fc632bd33e8244377f808f59d723158f008a7d1e45e2f8ca82b8b501623dd1c0f4dd0d888024e6f4d60d61c3536345392ef0f147b1e46e0ff002d5102340f6d85226517e61d8d7163da6b8c9f7efd70a13a3026b8f7f0ea48d2bb453e88b0614e9d51470b5b7fb715124dcc21f31b85a04f07b59672030936146419cefb4e7b768829dc2e96a229e3f23d1a1b810f1bc0fa766cde2510e91791e1ae63a2faa095474251b3a4557f01b4d30708e272cc4053bebacb113fb785001f423e6eab21e6a6b68dc139953ea09df7692baf1b9bd067b28b266a3561d9d62d907e66196b77a72309bdca779b3847de793e0fe906809894fb912cb713a07ae814a2b9de652b9737507d3b9f5a47d15197f963c1652059a469d6e8676406618c78035f9616fbb5cc37500d7ec15817d1ff0d2ffe5e204a4d71a9bb7599197f57fec19f45b14c9429781da5abcdca28cec37db4df40715a8e1bc628c43ab1ea4dba5fe3071484e9d3b5d98cf285ff8364a514faafaab090133fa11c9fe9ae2c8e1a3ddcc1602f957d839c73f7ee501db76c74535c5bb0b91a079251903328055f0d9f51e1a1e6e666f2f086886e5c06cf143612bcd170e18f71f806bb9b821dee5d1df026eb8cf1572d00504fae1e1c109c63018c6a31239244c75ea4b2bad2fc2a33b32ff7e114c9e343401e919f540f5f3932b6230")

var H0 = common.HexToHash("0x41f45b3e32e1e343db9c5d516a1fef38266c0dac56a98c2c304cb2f53cc0079f")

var Hi = common.HexToHash("0x10c43061e59e2522565c4eddc6b8e843304e35670d3dbbcd76b71ed8d3ca0c8f")

func AppendToFile(fileName string, content string) error {
	// 以只写的模式，打开文件
	f, err := os.OpenFile(fileName, os.O_WRONLY, 0644)
	if err != nil {
		fmt.Println("cacheFileList.yml file create failed. err: " + err.Error())
	} else {
		// 查找文件末尾的偏移量
		n, _ := f.Seek(0, os.SEEK_END)
		// 从末尾的偏移量开始写入内容
		_, err = f.WriteAt([]byte(content), n)
	}
	defer f.Close()
	return err
}
