package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	//"github.com/ethereum/go-ethereum/crypto"
	//"encoding/hex"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/zktx"
)

func main() {

	/*
	*test convert
	 */
	// value_old := uint64(10000)
	// sn_old := zktx.NewRandomHash()
	// r_old := zktx.NewRandomHash()

	// values := uint64(1000)
	// sn_s := zktx.NewRandomHash()
	// r_s := zktx.NewRandomHash()

	// value := uint64(9000)
	// sn := zktx.NewRandomHash()
	// r := zktx.NewRandomHash()

	// cmtA_old := zktx.GenCMT(value_old, sn_old.Bytes(), r_old.Bytes())
	// cmtA := zktx.GenCMT(value, sn.Bytes(), r.Bytes())
	// cmtS := zktx.GenCMT_1(values, sn_s.Bytes(), r_s.Bytes(), sn_old.Bytes())

	// proof := zktx.GenConvertProof(cmtA_old, value_old, r_old, values, sn_s, r_s, sn_old, cmtS, value, sn, r, cmtA)

	// zktx.VerifyConvertProof(sn_old, cmtS, proof, cmtA_old, cmtA)

	/*
	*test commit
	 */
	// values := uint64(100)
	// sn_s := zktx.NewRandomHash()
	// r_s := zktx.NewRandomHash()
	// snA := zktx.NewRandomHash()
	// cmtS := zktx.GenCMT_1(values, sn_s.Bytes(), r_s.Bytes(), snA.Bytes())

	// var cmtarray []*common.Hash
	// for i := 0; i < 32; i++ {
	// 	if i == 9 {
	// 		cmtarray = append(cmtarray, cmtS)
	// 	} else {
	// 		cmt := zktx.NewRandomHash()
	// 		cmtarray = append(cmtarray, cmt)
	// 	}
	// }

	// RT := zktx.GenRT(cmtarray)

	// proof := zktx.GenCommitProof(values, sn_s, r_s, snA, cmtS, RT.Bytes(), cmtarray)

	// zktx.VerifyCommitProof(values, sn_s, RT.Bytes(), proof)

	/*
	*test claim
	 */
	// values := uint64(200)
	// sn_s := zktx.NewRandomHash()
	// r_s := zktx.NewRandomHash()
	// cmtS := zktx.GenCMT(values, sn_s.Bytes(), r_s.Bytes())

	// proof := zktx.GenClaimProof(values, sn_s, r_s, cmtS)

	// zktx.VerifyClaimProof(cmtS, values, proof)

	/*
	*test deposit_sg
	 */
	// value_old := uint64(2000)
	// values := uint64(1000)
	// value := value_old + values

	// sn_old := zktx.NewRandomHash()
	// sn := zktx.NewRandomHash()
	// sn_s := zktx.NewRandomHash()

	// r_old := zktx.NewRandomHash()
	// r := zktx.NewRandomHash()
	// r_s := zktx.NewRandomHash()

	// cmtB_old := zktx.GenCMT(value_old, sn_old.Bytes(), r_old.Bytes())
	// cmtB := zktx.GenCMT(value, sn.Bytes(), r.Bytes())
	// cmtS := zktx.GenCMT(values, sn_s.Bytes(), r_s.Bytes())
	// // cmtS_1 := zktx.NewRandomHash()

	// var cmtarray []*common.Hash
	// for i := 0; i < 32; i++ {
	// 	if i == 9 {
	// 		cmtarray = append(cmtarray, cmtS)
	// 	} else {
	// 		cmt := zktx.NewRandomHash()
	// 		cmtarray = append(cmtarray, cmt)
	// 	}
	// }

	// RT := zktx.GenRT(cmtarray)

	// proof := zktx.GenDepositsgProof(cmtS, values, sn_s, r_s, value_old, r_old, sn, r, RT.Bytes(), cmtB_old, sn_old, cmtB, cmtarray)

	// zktx.VerifyDepositsgProof(sn_s, RT, cmtB_old, sn_old, cmtB, proof)

	/*
	*test mint
	 */
	// value_old := uint64(1000)
	// value := uint64(2000)
	// value_m := value - value_old

	// sn_old := zktx.NewRandomHash()
	// sn := zktx.NewRandomHash()

	// r_old := zktx.NewRandomHash()
	// r := zktx.NewRandomHash()

	// cmtA_old := zktx.GenCMT(value_old, sn_old.Bytes(), r_old.Bytes())
	// cmtA := zktx.GenCMT(value, sn.Bytes(), r.Bytes())

	// proof := zktx.GenMintProof(value_old,r_old,sn,r,cmtA_old,sn_old,cmtA,value)

	// zktx.VerifyMintProof(cmtA_old,sn_old,cmtA,value_m,proof)

	/*
	*test redeem
	 */
	// value_old := uint64(2000)
	// value := uint64(1000)
	// value_m := value_old - value

	// sn_old := zktx.NewRandomHash()
	// sn := zktx.NewRandomHash()

	// r_old := zktx.NewRandomHash()
	// r := zktx.NewRandomHash()

	// cmtA_old := zktx.GenCMT(value_old, sn_old.Bytes(), r_old.Bytes())
	// cmtA := zktx.GenCMT(value, sn.Bytes(), r.Bytes())

	// proof := zktx.GenRedeemProof(value_old,r_old,sn,r,cmtA_old,sn_old,cmtA,value)

	// zktx.VerifyRedeemProof(cmtA_old,sn_old,cmtA,value_m,proof)

	//byte connect
	// i := []byte("asd")
	// j := []byte("fgh")
	// var buffer bytes.Buffer
	// buffer.Write(i)
	// buffer.Write(j)
	// fmt.Println(buffer.Bytes())

	//hash chain
	// hChain := GenHashChain(100)

	// NumberOfHash(hChain[0], hChain[100], 100)
}

func NumberOfHash(root common.Hash, hi common.Hash, N uint64) uint64 {
	n := uint64(0)
	for h := hi.Bytes(); !bytes.Equal(h, root.Bytes()) && n <= N; n++ {
		hash := sha256.New()
		hash.Write(h)
		h = hash.Sum(nil)
	}
	if n > N {
		fmt.Println("invaild hash")
		return 0
	}
	fmt.Println(n)
	return n
}

func GenHashChain(N uint64) []common.Hash {
	h_N := *zktx.NewRandomHash()
	hashList := make([]common.Hash, N+1)

	for n, h := (int)(N), h_N; n >= 0; n-- {
		hashList[n] = h
		hash := sha256.New()
		hash.Write(h.Bytes())
		h = common.BytesToHash(hash.Sum(nil))
	}
	return hashList
}
