// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package ethapi

import (
	"bufio"
	"bytes"
	"context"

	//"crypto/ecdsa"

	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"github.com/ethereum/go-ethereum/zktx"
	"github.com/syndtr/goleveldb/leveldb"
	"github.com/syndtr/goleveldb/leveldb/util"
)

const (
	defaultGasPrice = 50 * params.Shannon
	PubKeySize      = 68
)

// PublicEthereumAPI provides an API to access Ethereum related information.
// It offers only methods that operate on public data that is freely available to anyone.
type PublicEthereumAPI struct {
	b Backend
}

// NewPublicEthereumAPI creates a new Ethereum protocol API.
func NewPublicEthereumAPI(b Backend) *PublicEthereumAPI {
	return &PublicEthereumAPI{b}
}

// GasPrice returns a suggestion for a gas price.
func (s *PublicEthereumAPI) GasPrice(ctx context.Context) (*hexutil.Big, error) {
	price, err := s.b.SuggestPrice(ctx)
	return (*hexutil.Big)(price), err
}

// ProtocolVersion returns the current Ethereum protocol version this node supports
func (s *PublicEthereumAPI) ProtocolVersion() hexutil.Uint {
	return hexutil.Uint(s.b.ProtocolVersion())
}

// Syncing returns false in case the node is currently not syncing with the network. It can be up to date or has not
// yet received the latest block headers from its pears. In case it is synchronizing:
// - startingBlock: block number this node started to synchronise from
// - currentBlock:  block number this node is currently importing
// - highestBlock:  block number of the highest block header this node has received from peers
// - pulledStates:  number of state entries processed until now
// - knownStates:   number of known state entries that still need to be pulled
func (s *PublicEthereumAPI) Syncing() (interface{}, error) {
	progress := s.b.Downloader().Progress()

	// Return not syncing if the synchronisation already completed
	if progress.CurrentBlock >= progress.HighestBlock {
		return false, nil
	}
	// Otherwise gather the block sync stats
	return map[string]interface{}{
		"startingBlock": hexutil.Uint64(progress.StartingBlock),
		"currentBlock":  hexutil.Uint64(progress.CurrentBlock),
		"highestBlock":  hexutil.Uint64(progress.HighestBlock),
		"pulledStates":  hexutil.Uint64(progress.PulledStates),
		"knownStates":   hexutil.Uint64(progress.KnownStates),
	}, nil
}

// PublicTxPoolAPI offers and API for the transaction pool. It only operates on data that is non confidential.
type PublicTxPoolAPI struct {
	b Backend
}

// NewPublicTxPoolAPI creates a new tx pool service that gives information about the transaction pool.
func NewPublicTxPoolAPI(b Backend) *PublicTxPoolAPI {
	return &PublicTxPoolAPI{b}
}

// Content returns the transactions contained within the transaction pool.
func (s *PublicTxPoolAPI) Content() map[string]map[string]map[string]*RPCTransaction {
	content := map[string]map[string]map[string]*RPCTransaction{
		"pending": make(map[string]map[string]*RPCTransaction),
		"queued":  make(map[string]map[string]*RPCTransaction),
	}
	pending, queue := s.b.TxPoolContent()

	// Flatten the pending transactions
	for account, txs := range pending {
		dump := make(map[string]*RPCTransaction)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = newRPCPendingTransaction(tx)
		}
		content["pending"][account.Hex()] = dump
	}
	// Flatten the queued transactions
	for account, txs := range queue {
		dump := make(map[string]*RPCTransaction)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = newRPCPendingTransaction(tx)
		}
		content["queued"][account.Hex()] = dump
	}
	return content
}

// Status returns the number of pending and queued transaction in the pool.
func (s *PublicTxPoolAPI) Status() map[string]hexutil.Uint {
	pending, queue := s.b.Stats()
	return map[string]hexutil.Uint{
		"pending": hexutil.Uint(pending),
		"queued":  hexutil.Uint(queue),
	}
}

// Inspect retrieves the content of the transaction pool and flattens it into an
// easily inspectable list.
func (s *PublicTxPoolAPI) Inspect() map[string]map[string]map[string]string {
	content := map[string]map[string]map[string]string{
		"pending": make(map[string]map[string]string),
		"queued":  make(map[string]map[string]string),
	}
	pending, queue := s.b.TxPoolContent()

	// Define a formatter to flatten a transaction into a string
	var format = func(tx *types.Transaction) string {
		if to := tx.To(); to != nil {
			return fmt.Sprintf("%s: %v wei + %v gas × %v wei", tx.To().Hex(), tx.Value(), tx.Gas(), tx.GasPrice())
		}
		return fmt.Sprintf("contract creation: %v wei + %v gas × %v wei", tx.Value(), tx.Gas(), tx.GasPrice())
	}
	// Flatten the pending transactions
	for account, txs := range pending {
		dump := make(map[string]string)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = format(tx)
		}
		content["pending"][account.Hex()] = dump
	}
	// Flatten the queued transactions
	for account, txs := range queue {
		dump := make(map[string]string)
		for _, tx := range txs {
			dump[fmt.Sprintf("%d", tx.Nonce())] = format(tx)
		}
		content["queued"][account.Hex()] = dump
	}
	return content
}

// PublicAccountAPI provides an API to access accounts managed by this node.
// It offers only methods that can retrieve accounts.
type PublicAccountAPI struct {
	am *accounts.Manager
}

// NewPublicAccountAPI creates a new PublicAccountAPI.
func NewPublicAccountAPI(am *accounts.Manager) *PublicAccountAPI {
	return &PublicAccountAPI{am: am}
}

// Accounts returns the collection of accounts this node manages
func (s *PublicAccountAPI) Accounts() []common.Address {
	addresses := make([]common.Address, 0) // return [] instead of nil if empty
	for _, wallet := range s.am.Wallets() {
		for _, account := range wallet.Accounts() {
			addresses = append(addresses, account.Address)
		}
	}
	return addresses
}

// PrivateAccountAPI provides an API to access accounts managed by this node.
// It offers methods to create, (un)lock en list accounts. Some methods accept
// passwords and are therefore considered private by default.
type PrivateAccountAPI struct {
	am        *accounts.Manager
	nonceLock *AddrLocker
	b         Backend
}

// NewPrivateAccountAPI create a new PrivateAccountAPI.
func NewPrivateAccountAPI(b Backend, nonceLock *AddrLocker) *PrivateAccountAPI {
	return &PrivateAccountAPI{
		am:        b.AccountManager(),
		nonceLock: nonceLock,
		b:         b,
	}
}

// ListAccounts will return a list of addresses for accounts this node manages.
func (s *PrivateAccountAPI) ListAccounts() []common.Address {
	addresses := make([]common.Address, 0) // return [] instead of nil if empty
	for _, wallet := range s.am.Wallets() {
		for _, account := range wallet.Accounts() {
			addresses = append(addresses, account.Address)
		}
	}
	return addresses
}

// rawWallet is a JSON representation of an accounts.Wallet interface, with its
// data contents extracted into plain fields.
type rawWallet struct {
	URL      string             `json:"url"`
	Status   string             `json:"status"`
	Failure  string             `json:"failure,omitempty"`
	Accounts []accounts.Account `json:"accounts,omitempty"`
}

// ListWallets will return a list of wallets this node manages.
func (s *PrivateAccountAPI) ListWallets() []rawWallet {
	wallets := make([]rawWallet, 0) // return [] instead of nil if empty
	for _, wallet := range s.am.Wallets() {
		status, failure := wallet.Status()

		raw := rawWallet{
			URL:      wallet.URL().String(),
			Status:   status,
			Accounts: wallet.Accounts(),
		}
		if failure != nil {
			raw.Failure = failure.Error()
		}
		wallets = append(wallets, raw)
	}
	return wallets
}

// OpenWallet initiates a hardware wallet opening procedure, establishing a USB
// connection and attempting to authenticate via the provided passphrase. Note,
// the method may return an extra challenge requiring a second open (e.g. the
// Trezor PIN matrix challenge).
func (s *PrivateAccountAPI) OpenWallet(url string, passphrase *string) error {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return err
	}
	pass := ""
	if passphrase != nil {
		pass = *passphrase
	}
	return wallet.Open(pass)
}

// DeriveAccount requests a HD wallet to derive a new account, optionally pinning
// it for later reuse.
func (s *PrivateAccountAPI) DeriveAccount(url string, path string, pin *bool) (accounts.Account, error) {
	wallet, err := s.am.Wallet(url)
	if err != nil {
		return accounts.Account{}, err
	}
	derivPath, err := accounts.ParseDerivationPath(path)
	if err != nil {
		return accounts.Account{}, err
	}
	if pin == nil {
		pin = new(bool)
	}
	return wallet.Derive(derivPath, *pin)
}

// NewAccount will create a new account and returns the address for the new account.
func (s *PrivateAccountAPI) NewAccount(password string) (common.Address, error) {
	acc, err := fetchKeystore(s.am).NewAccount(password)
	if err == nil {
		return acc.Address, nil
	}
	return common.Address{}, err
}

// NewAccounts will create n new accounts and returns the address array.
func (s *PrivateAccountAPI) NewAccounts(ctx context.Context, n int) ([]common.Address, error) {
	state, _, err := s.b.StateAndHeaderByNumber(ctx, rpc.LatestBlockNumber)
	var unlockTime uint64 = 1000 * 60 * 60
	if state == nil || err != nil {
		return []common.Address{}, err
	}
	addr_arr := make([]common.Address, n)
	for i := 0; i < n; i++ {
		addr, err := s.NewAccount("")
		if err != nil {
			return nil, err
		}
		addr_arr[i] = addr
		state.SetCMT(addr, &zktx.CmtA_old)
		s.UnlockAccount(addr, "", &unlockTime)
	}
	return addr_arr, nil
}

//UnlockAccounts will unlock some account
func (s *PrivateAccountAPI) UnlockAccounts(ctx context.Context, arr []common.Address) {
	var unlockTime uint64 = 1000 * 60 * 60
	for i := 0; i < len(arr); i++ {
		s.UnlockAccount(arr[i], "", &unlockTime)
	}
}

// fetchKeystore retrives the encrypted keystore from the account manager.
func fetchKeystore(am *accounts.Manager) *keystore.KeyStore {
	return am.Backends(keystore.KeyStoreType)[0].(*keystore.KeyStore)
}

// ImportRawKey stores the given hex encoded ECDSA key into the key directory,
// encrypting it with the passphrase.
func (s *PrivateAccountAPI) ImportRawKey(privkey string, password string) (common.Address, error) {
	key, err := crypto.HexToECDSA(privkey)
	if err != nil {
		return common.Address{}, err
	}
	acc, err := fetchKeystore(s.am).ImportECDSA(key, password)
	return acc.Address, err
}

// UnlockAccount will unlock the account associated with the given address with
// the given password for duration seconds. If duration is nil it will use a
// default of 300 seconds. It returns an indication if the account was unlocked.
func (s *PrivateAccountAPI) UnlockAccount(addr common.Address, password string, duration *uint64) (bool, error) {
	const max = uint64(time.Duration(math.MaxInt64) / time.Second)
	var d time.Duration
	if duration == nil {
		d = 300 * time.Second
	} else if *duration > max {
		return false, errors.New("unlock duration too large")
	} else {
		d = time.Duration(*duration) * time.Second
	}
	err := fetchKeystore(s.am).TimedUnlock(accounts.Account{Address: addr}, password, d)
	return err == nil, err
}

// LockAccount will lock the account associated with the given address when it's unlocked.
func (s *PrivateAccountAPI) LockAccount(addr common.Address) bool {
	return fetchKeystore(s.am).Lock(addr) == nil
}

// signTransactions sets defaults and signs the given transaction
// NOTE: the caller needs to ensure that the nonceLock is held, if applicable,
// and release it after the transaction has been submitted to the tx pool
func (s *PrivateAccountAPI) signTransaction(ctx context.Context, args SendTxArgs, passwd string) (*types.Transaction, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}
	wallet, err := s.am.Find(account)
	if err != nil {
		return nil, err
	}
	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return nil, err
	}
	// Assemble the transaction and sign with the wallet
	tx := args.toTransaction()

	var chainID *big.Int
	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
		chainID = config.ChainID
	}
	return wallet.SignTxWithPassphrase(account, passwd, tx, chainID)
}

// SendPublicTransaction will create a transaction from the given arguments and
// tries to sign it with the key associated with args.To. If the given passwd isn't
// able to decrypt the key it fails.
func (s *PrivateAccountAPI) SendPublicTransaction(ctx context.Context, args SendTxArgs, passwd string) (common.Hash, error) {
	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}
	signed, err := s.signTransaction(ctx, args, passwd)
	if err != nil {
		return common.Hash{}, err
	}
	return submitTransaction(ctx, s.b, signed)
}

// SignTransaction will create a transaction from the given arguments and
// tries to sign it with the key associated with args.To. If the given passwd isn't
// able to decrypt the key it fails. The transaction is returned in RLP-form, not broadcast
// to other nodes
func (s *PrivateAccountAPI) SignTransaction(ctx context.Context, args SendTxArgs, passwd string) (*SignTransactionResult, error) {
	// No need to obtain the noncelock mutex, since we won't be sending this
	// tx into the transaction pool, but right back to the user
	if args.Gas == nil {
		return nil, fmt.Errorf("gas not specified")
	}
	if args.GasPrice == nil {
		return nil, fmt.Errorf("gasPrice not specified")
	}
	if args.Nonce == nil {
		return nil, fmt.Errorf("nonce not specified")
	}
	signed, err := s.signTransaction(ctx, args, passwd)
	if err != nil {
		return nil, err
	}
	data, err := rlp.EncodeToBytes(signed)
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, signed}, nil
}

// signHash is a helper function that calculates a hash for the given message that can be
// safely used to calculate a signature from.
//
// The hash is calulcated as
//   keccak256("\x19Ethereum Signed Message:\n"${message length}${message}).
//
// This gives context to the signed message and prevents signing of transactions.
func signHash(data []byte) []byte {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256([]byte(msg))
}

// Sign calculates an Ethereum ECDSA signature for:
// keccack256("\x19Ethereum Signed Message:\n" + len(message) + message))
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons.
//
// The key used to calculate the signature is decrypted with the given password.
//
// https://github.com/ethereum/go-ethereum/wiki/Management-APIs#personal_sign
func (s *PrivateAccountAPI) Sign(ctx context.Context, data hexutil.Bytes, addr common.Address, passwd string) (hexutil.Bytes, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Assemble sign the data with the wallet
	signature, err := wallet.SignHashWithPassphrase(account, passwd, signHash(data))
	if err != nil {
		return nil, err
	}
	signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	return signature, nil
}

// EcRecover returns the address for the account that was used to create the signature.
// Note, this function is compatible with eth_sign and personal_sign. As such it recovers
// the address of:
// hash = keccak256("\x19Ethereum Signed Message:\n"${message length}${message})
// addr = ecrecover(hash, signature)
//
// Note, the signature must conform to the secp256k1 curve R, S and V values, where
// the V value must be be 27 or 28 for legacy reasons.
//
// https://github.com/ethereum/go-ethereum/wiki/Management-APIs#personal_ecRecover
func (s *PrivateAccountAPI) EcRecover(ctx context.Context, data, sig hexutil.Bytes) (common.Address, error) {
	if len(sig) != 65 {
		return common.Address{}, fmt.Errorf("signature must be 65 bytes long")
	}
	if sig[64] != 27 && sig[64] != 28 {
		return common.Address{}, fmt.Errorf("invalid Ethereum signature (V is not 27 or 28)")
	}
	sig[64] -= 27 // Transform yellow paper V from 27/28 to 0/1

	rpk, err := crypto.SigToPub(signHash(data), sig)
	if err != nil {
		return common.Address{}, err
	}
	return crypto.PubkeyToAddress(*rpk), nil
}

// SignAndSendTransaction was renamed to SendPublicTransaction. This method is deprecated
// and will be removed in the future. It primary goal is to give clients time to update.
func (s *PrivateAccountAPI) SignAndSendTransaction(ctx context.Context, args SendTxArgs, passwd string) (common.Hash, error) {
	return s.SendPublicTransaction(ctx, args, passwd)
}

// PublicBlockChainAPI provides an API to access the Ethereum blockchain.
// It offers only methods that operate on public data that is freely available to anyone.
type PublicBlockChainAPI struct {
	b Backend
}

// NewPublicBlockChainAPI creates a new Ethereum blockchain API.
func NewPublicBlockChainAPI(b Backend) *PublicBlockChainAPI {
	return &PublicBlockChainAPI{b}
}

// BlockNumber returns the block number of the chain head.
func (s *PublicBlockChainAPI) BlockNumber() hexutil.Uint64 {
	header, _ := s.b.HeaderByNumber(context.Background(), rpc.LatestBlockNumber) // latest header should always be available
	return hexutil.Uint64(header.Number.Uint64())
}

type Balance struct {
	Value *hexutil.Big
	CMT   common.Hash
}

// GetBalance returns the amount of wei for the given address in the state of the
// given block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta
// block numbers are also allowed.
func (s *PublicBlockChainAPI) GetBalance(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (*hexutil.Big, error) {
	state, _, err := s.b.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	return (*hexutil.Big)(state.GetBalance(address)), state.Error()
}

func (s *PublicBlockChainAPI) GetBalance2(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (*Balance, error) {
	state, _, err := s.b.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	return &Balance{Value: (*hexutil.Big)(state.GetBalance(address)), CMT: state.GetCMTBalance(address)}, state.Error()
}

// GetBlockByNumber returns the requested block. When blockNr is -1 the chain head is returned. When fullTx is true all
// transactions in the block are returned in full detail, otherwise only the transaction hash is returned.
func (s *PublicBlockChainAPI) GetBlockByNumber(ctx context.Context, blockNr rpc.BlockNumber, fullTx bool) (map[string]interface{}, error) {
	block, err := s.b.BlockByNumber(ctx, blockNr)
	if block != nil {
		response, err := s.rpcOutputBlock(block, true, fullTx)
		if err == nil && blockNr == rpc.PendingBlockNumber {
			// Pending blocks need to nil out a few fields
			for _, field := range []string{"hash", "nonce", "miner"} {
				response[field] = nil
			}
		}
		return response, err
	}
	return nil, err
}

// GetBlockByHash returns the requested block. When fullTx is true all transactions in the block are returned in full
// detail, otherwise only the transaction hash is returned.
func (s *PublicBlockChainAPI) GetBlockByHash(ctx context.Context, blockHash common.Hash, fullTx bool) (map[string]interface{}, error) {
	block, err := s.b.GetBlock(ctx, blockHash)
	if block != nil {
		return s.rpcOutputBlock(block, true, fullTx)
	}
	return nil, err
}

// GetUncleByBlockNumberAndIndex returns the uncle block for the given block hash and index. When fullTx is true
// all transactions in the block are returned in full detail, otherwise only the transaction hash is returned.
func (s *PublicBlockChainAPI) GetUncleByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := s.b.BlockByNumber(ctx, blockNr)
	if block != nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			log.Debug("Requested uncle not found", "number", blockNr, "hash", block.Hash(), "index", index)
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return s.rpcOutputBlock(block, false, false)
	}
	return nil, err
}

// GetUncleByBlockHashAndIndex returns the uncle block for the given block hash and index. When fullTx is true
// all transactions in the block are returned in full detail, otherwise only the transaction hash is returned.
func (s *PublicBlockChainAPI) GetUncleByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) (map[string]interface{}, error) {
	block, err := s.b.GetBlock(ctx, blockHash)
	if block != nil {
		uncles := block.Uncles()
		if index >= hexutil.Uint(len(uncles)) {
			log.Debug("Requested uncle not found", "number", block.Number(), "hash", blockHash, "index", index)
			return nil, nil
		}
		block = types.NewBlockWithHeader(uncles[index])
		return s.rpcOutputBlock(block, false, false)
	}
	return nil, err
}

// GetUncleCountByBlockNumber returns number of uncles in the block for the given block number
func (s *PublicBlockChainAPI) GetUncleCountByBlockNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}
	return nil
}

// GetUncleCountByBlockHash returns number of uncles in the block for the given block hash
func (s *PublicBlockChainAPI) GetUncleCountByBlockHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, _ := s.b.GetBlock(ctx, blockHash); block != nil {
		n := hexutil.Uint(len(block.Uncles()))
		return &n
	}
	return nil
}

// GetCode returns the code stored at the given address in the state for the given block number.
func (s *PublicBlockChainAPI) GetCode(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (hexutil.Bytes, error) {
	state, _, err := s.b.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	code := state.GetCode(address)
	return code, state.Error()
}

// GetStorageAt returns the storage from the state at the given address, key and
// block number. The rpc.LatestBlockNumber and rpc.PendingBlockNumber meta block
// numbers are also allowed.
func (s *PublicBlockChainAPI) GetStorageAt(ctx context.Context, address common.Address, key string, blockNr rpc.BlockNumber) (hexutil.Bytes, error) {
	state, _, err := s.b.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	res := state.GetState(address, common.HexToHash(key))
	return res[:], state.Error()
}

// CallArgs represents the arguments for a call.
type CallArgs struct {
	From     common.Address  `json:"from"`
	To       *common.Address `json:"to"`
	Gas      hexutil.Uint64  `json:"gas"`
	GasPrice hexutil.Big     `json:"gasPrice"`
	Value    hexutil.Big     `json:"value"`
	Data     hexutil.Bytes   `json:"data"`
}

func (s *PublicBlockChainAPI) doCall(ctx context.Context, args CallArgs, blockNr rpc.BlockNumber, vmCfg vm.Config, timeout time.Duration) ([]byte, uint64, bool, error) {
	defer func(start time.Time) { log.Debug("Executing EVM call finished", "runtime", time.Since(start)) }(time.Now())

	state, header, err := s.b.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, 0, false, err
	}
	// Set sender address or use a default if none specified
	addr := args.From
	if addr == (common.Address{}) {
		if wallets := s.b.AccountManager().Wallets(); len(wallets) > 0 {
			if accounts := wallets[0].Accounts(); len(accounts) > 0 {
				addr = accounts[0].Address
			}
		}
	}
	// Set default gas & gas price if none were set
	gas, gasPrice := uint64(args.Gas), args.GasPrice.ToInt()
	if gas == 0 {
		gas = math.MaxUint64 / 2
	}
	if gasPrice.Sign() == 0 {
		gasPrice = new(big.Int).SetUint64(defaultGasPrice)
	}

	// Create new call message
	msg := types.NewMessage(addr, args.To, 0, 0, args.Value.ToInt(), gas, gasPrice, args.Data, false)

	// Setup context so it may be cancelled the call has completed
	// or, in case of unmetered gas, setup a context with a timeout.
	var cancel context.CancelFunc
	if timeout > 0 {
		ctx, cancel = context.WithTimeout(ctx, timeout)
	} else {
		ctx, cancel = context.WithCancel(ctx)
	}
	// Make sure the context is cancelled when the call has completed
	// this makes sure resources are cleaned up.
	defer cancel()

	// Get a new instance of the EVM.
	evm, vmError, err := s.b.GetEVM(ctx, msg, state, header, vmCfg)
	if err != nil {
		return nil, 0, false, err
	}
	// Wait for the context to be done and cancel the evm. Even if the
	// EVM has finished, cancelling may be done (repeatedly)
	go func() {
		<-ctx.Done()
		evm.Cancel()
	}()

	// Setup the gas pool (also for unmetered requests)
	// and apply the message.
	gp := new(core.GasPool).AddGas(math.MaxUint64)
	res, gas, failed, err := core.ApplyMessage(evm, msg, gp)
	if err := vmError(); err != nil {
		return nil, 0, false, err
	}
	return res, gas, failed, err
}

// Call executes the given transaction on the state for the given block number.
// It doesn't make and changes in the state/blockchain and is useful to execute and retrieve values.
func (s *PublicBlockChainAPI) Call(ctx context.Context, args CallArgs, blockNr rpc.BlockNumber) (hexutil.Bytes, error) {
	result, _, _, err := s.doCall(ctx, args, blockNr, vm.Config{}, 5*time.Second)
	return (hexutil.Bytes)(result), err
}

// EstimateGas returns an estimate of the amount of gas needed to execute the
// given transaction against the current pending block.
func (s *PublicBlockChainAPI) EstimateGas(ctx context.Context, args CallArgs) (hexutil.Uint64, error) {
	// Binary search the gas requirement, as it may be higher than the amount used
	var (
		lo  uint64 = params.TxGas - 1
		hi  uint64
		cap uint64
	)
	if uint64(args.Gas) >= params.TxGas {
		hi = uint64(args.Gas)
	} else {
		// Retrieve the current pending block to act as the gas ceiling
		block, err := s.b.BlockByNumber(ctx, rpc.PendingBlockNumber)
		if err != nil {
			return 0, err
		}
		hi = block.GasLimit()
	}
	cap = hi

	// Create a helper to check if a gas allowance results in an executable transaction
	executable := func(gas uint64) bool {
		args.Gas = hexutil.Uint64(gas)

		_, _, failed, err := s.doCall(ctx, args, rpc.PendingBlockNumber, vm.Config{}, 0)
		if err != nil || failed {
			return false
		}
		return true
	}
	// Execute the binary search and hone in on an executable gas limit
	for lo+1 < hi {
		mid := (hi + lo) / 2
		if !executable(mid) {
			lo = mid
		} else {
			hi = mid
		}
	}
	// Reject the transaction as invalid if it still fails at the highest allowance
	if hi == cap {
		if !executable(hi) {
			return 0, fmt.Errorf("gas required exceeds allowance or always failing transaction")
		}
	}
	return hexutil.Uint64(hi), nil
}

// ExecutionResult groups all structured logs emitted by the EVM
// while replaying a transaction in debug mode as well as transaction
// execution status, the amount of gas used and the return value
type ExecutionResult struct {
	Gas         uint64         `json:"gas"`
	Failed      bool           `json:"failed"`
	ReturnValue string         `json:"returnValue"`
	StructLogs  []StructLogRes `json:"structLogs"`
}

// StructLogRes stores a structured log emitted by the EVM while replaying a
// transaction in debug mode
type StructLogRes struct {
	Pc      uint64             `json:"pc"`
	Op      string             `json:"op"`
	Gas     uint64             `json:"gas"`
	GasCost uint64             `json:"gasCost"`
	Depth   int                `json:"depth"`
	Error   error              `json:"error,omitempty"`
	Stack   *[]string          `json:"stack,omitempty"`
	Memory  *[]string          `json:"memory,omitempty"`
	Storage *map[string]string `json:"storage,omitempty"`
}

// FormatLogs formats EVM returned structured logs for json output
func FormatLogs(logs []vm.StructLog) []StructLogRes {
	formatted := make([]StructLogRes, len(logs))
	for index, trace := range logs {
		formatted[index] = StructLogRes{
			Pc:      trace.Pc,
			Op:      trace.Op.String(),
			Gas:     trace.Gas,
			GasCost: trace.GasCost,
			Depth:   trace.Depth,
			Error:   trace.Err,
		}
		if trace.Stack != nil {
			stack := make([]string, len(trace.Stack))
			for i, stackValue := range trace.Stack {
				stack[i] = fmt.Sprintf("%x", math.PaddedBigBytes(stackValue, 32))
			}
			formatted[index].Stack = &stack
		}
		if trace.Memory != nil {
			memory := make([]string, 0, (len(trace.Memory)+31)/32)
			for i := 0; i+32 <= len(trace.Memory); i += 32 {
				memory = append(memory, fmt.Sprintf("%x", trace.Memory[i:i+32]))
			}
			formatted[index].Memory = &memory
		}
		if trace.Storage != nil {
			storage := make(map[string]string)
			for i, storageValue := range trace.Storage {
				storage[fmt.Sprintf("%x", i)] = fmt.Sprintf("%x", storageValue)
			}
			formatted[index].Storage = &storage
		}
	}
	return formatted
}

// RPCMarshalBlock converts the given block to the RPC output which depends on fullTx. If inclTx is true transactions are
// returned. When fullTx is true the returned block contains full transaction details, otherwise it will only contain
// transaction hashes.
func RPCMarshalBlock(b *types.Block, inclTx bool, fullTx bool) (map[string]interface{}, error) {
	head := b.Header() // copies the header once
	fields := map[string]interface{}{
		"number":           (*hexutil.Big)(head.Number),
		"hash":             b.Hash(),
		"parentHash":       head.ParentHash,
		"nonce":            head.Nonce,
		"mixHash":          head.MixDigest,
		"sha3Uncles":       head.UncleHash,
		"logsBloom":        head.Bloom,
		"stateRoot":        head.Root,
		"miner":            head.Coinbase,
		"difficulty":       (*hexutil.Big)(head.Difficulty),
		"extraData":        hexutil.Bytes(head.Extra),
		"size":             hexutil.Uint64(b.Size()),
		"gasLimit":         hexutil.Uint64(head.GasLimit),
		"gasUsed":          hexutil.Uint64(head.GasUsed),
		"timestamp":        (*hexutil.Big)(head.Time),
		"transactionsRoot": head.TxHash,
		"receiptsRoot":     head.ReceiptHash,
	}

	if inclTx {
		formatTx := func(tx *types.Transaction) (interface{}, error) {
			return tx.Hash(), nil
		}
		if fullTx {
			formatTx = func(tx *types.Transaction) (interface{}, error) {
				return newRPCTransactionFromBlockHash(b, tx.Hash()), nil
			}
		}
		txs := b.Transactions()
		transactions := make([]interface{}, len(txs))
		var err error
		for i, tx := range txs {
			if transactions[i], err = formatTx(tx); err != nil {
				return nil, err
			}
		}
		fields["transactions"] = transactions
	}

	uncles := b.Uncles()
	uncleHashes := make([]common.Hash, len(uncles))
	for i, uncle := range uncles {
		uncleHashes[i] = uncle.Hash()
	}
	fields["uncles"] = uncleHashes

	return fields, nil
}

// rpcOutputBlock uses the generalized output filler, then adds the total difficulty field, which requires
// a `PublicBlockchainAPI`.
func (s *PublicBlockChainAPI) rpcOutputBlock(b *types.Block, inclTx bool, fullTx bool) (map[string]interface{}, error) {
	fields, err := RPCMarshalBlock(b, inclTx, fullTx)
	if err != nil {
		return nil, err
	}
	fields["totalDifficulty"] = (*hexutil.Big)(s.b.GetTd(b.Hash()))
	return fields, err
}

// RPCTransaction represents a transaction that will serialize to the RPC representation of a transaction
type RPCTransaction struct {
	BlockHash        common.Hash     `json:"blockHash"`
	BlockNumber      *hexutil.Big    `json:"blockNumber"`
	From             common.Address  `json:"from"`
	Gas              hexutil.Uint64  `json:"gas"`
	GasPrice         *hexutil.Big    `json:"gasPrice"`
	Hash             common.Hash     `json:"hash"`
	Input            hexutil.Bytes   `json:"input"`
	Code             string          `json:"code"` // differ txs --Agzs 09.18
	Nonce            hexutil.Uint64  `json:"nonce"`
	To               *common.Address `json:"to"`
	TransactionIndex hexutil.Uint    `json:"transactionIndex"`
	Value            *hexutil.Big    `json:"value"`
	V                *hexutil.Big    `json:"v"`
	R                *hexutil.Big    `json:"r"`
	S                *hexutil.Big    `json:"s"`
}

// newRPCTransaction returns a transaction that will serialize to the RPC
// representation, with the given location metadata set (if available).
func newRPCTransaction(tx *types.Transaction, blockHash common.Hash, blockNumber uint64, index uint64) *RPCTransaction {
	var signer types.Signer = types.FrontierSigner{}
	if tx.Protected() {
		signer = types.NewEIP155Signer(tx.ChainId())
	}
	from, _ := types.Sender(signer, tx)
	v, r, s := tx.RawSignatureValues()

	result := &RPCTransaction{
		From:     from,
		Gas:      hexutil.Uint64(tx.Gas()),
		GasPrice: (*hexutil.Big)(tx.GasPrice()),
		Hash:     tx.Hash(),
		Input:    hexutil.Bytes(tx.Data()),
		Nonce:    hexutil.Uint64(tx.Nonce()),
		Code:     tx.GetTxCodeStr(), // differ txs --Agzs 09.18
		To:       tx.To(),
		Value:    (*hexutil.Big)(tx.Value()),
		V:        (*hexutil.Big)(v),
		R:        (*hexutil.Big)(r),
		S:        (*hexutil.Big)(s),
	}
	if blockHash != (common.Hash{}) {
		result.BlockHash = blockHash
		result.BlockNumber = (*hexutil.Big)(new(big.Int).SetUint64(blockNumber))
		result.TransactionIndex = hexutil.Uint(index)
	}
	return result
}

// newRPCPendingTransaction returns a pending transaction that will serialize to the RPC representation
func newRPCPendingTransaction(tx *types.Transaction) *RPCTransaction {
	return newRPCTransaction(tx, common.Hash{}, 0, 0)
}

// newRPCTransactionFromBlockIndex returns a transaction that will serialize to the RPC representation.
func newRPCTransactionFromBlockIndex(b *types.Block, index uint64) *RPCTransaction {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	return newRPCTransaction(txs[index], b.Hash(), b.NumberU64(), index)
}

// newRPCRawTransactionFromBlockIndex returns the bytes of a transaction given a block and a transaction index.
func newRPCRawTransactionFromBlockIndex(b *types.Block, index uint64) hexutil.Bytes {
	txs := b.Transactions()
	if index >= uint64(len(txs)) {
		return nil
	}
	blob, _ := rlp.EncodeToBytes(txs[index])
	return blob
}

// newRPCTransactionFromBlockHash returns a transaction that will serialize to the RPC representation.
func newRPCTransactionFromBlockHash(b *types.Block, hash common.Hash) *RPCTransaction {
	for idx, tx := range b.Transactions() {
		if tx.Hash() == hash {
			return newRPCTransactionFromBlockIndex(b, uint64(idx))
		}
	}
	return nil
}

// PublicTransactionPoolAPI exposes methods for the RPC interface
type PublicTransactionPoolAPI struct {
	b         Backend
	nonceLock *AddrLocker
}

// NewPublicTransactionPoolAPI creates a new RPC service with methods specific for the transaction pool.
func NewPublicTransactionPoolAPI(b Backend, nonceLock *AddrLocker) *PublicTransactionPoolAPI {
	return &PublicTransactionPoolAPI{b, nonceLock}
}

// GetBlockTransactionCountByNumber returns the number of transactions in the block with the given block number.
func (s *PublicTransactionPoolAPI) GetBlockTransactionCountByNumber(ctx context.Context, blockNr rpc.BlockNumber) *hexutil.Uint {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}
	return nil
}

// GetBlockTransactionCountByHash returns the number of transactions in the block with the given hash.
func (s *PublicTransactionPoolAPI) GetBlockTransactionCountByHash(ctx context.Context, blockHash common.Hash) *hexutil.Uint {
	if block, _ := s.b.GetBlock(ctx, blockHash); block != nil {
		n := hexutil.Uint(len(block.Transactions()))
		return &n
	}
	return nil
}

// GetTransactionByBlockNumberAndIndex returns the transaction for the given block number and index.
func (s *PublicTransactionPoolAPI) GetTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) *RPCTransaction {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetTransactionByBlockHashAndIndex returns the transaction for the given block hash and index.
func (s *PublicTransactionPoolAPI) GetTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) *RPCTransaction {
	if block, _ := s.b.GetBlock(ctx, blockHash); block != nil {
		return newRPCTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetRawTransactionByBlockNumberAndIndex returns the bytes of the transaction for the given block number and index.
func (s *PublicTransactionPoolAPI) GetRawTransactionByBlockNumberAndIndex(ctx context.Context, blockNr rpc.BlockNumber, index hexutil.Uint) hexutil.Bytes {
	if block, _ := s.b.BlockByNumber(ctx, blockNr); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetRawTransactionByBlockHashAndIndex returns the bytes of the transaction for the given block hash and index.
func (s *PublicTransactionPoolAPI) GetRawTransactionByBlockHashAndIndex(ctx context.Context, blockHash common.Hash, index hexutil.Uint) hexutil.Bytes {
	if block, _ := s.b.GetBlock(ctx, blockHash); block != nil {
		return newRPCRawTransactionFromBlockIndex(block, uint64(index))
	}
	return nil
}

// GetTransactionCount returns the number of transactions the given address has sent for the given block number
func (s *PublicTransactionPoolAPI) GetTransactionCount(ctx context.Context, address common.Address, blockNr rpc.BlockNumber) (*hexutil.Uint64, error) {
	state, _, err := s.b.StateAndHeaderByNumber(ctx, blockNr)
	if state == nil || err != nil {
		return nil, err
	}
	nonce := state.GetNonce(address)
	return (*hexutil.Uint64)(&nonce), state.Error()
}

// GetTransactionByHash returns the transaction for the given hash
func (s *PublicTransactionPoolAPI) GetTransactionByHash(ctx context.Context, hash common.Hash) *RPCTransaction {
	// Try to return an already finalized transaction
	if tx, blockHash, blockNumber, index := rawdb.ReadTransaction(s.b.ChainDb(), hash); tx != nil {
		return newRPCTransaction(tx, blockHash, blockNumber, index)
	}
	// No finalized transaction, try to retrieve it from the pool
	if tx := s.b.GetPoolTransaction(hash); tx != nil {
		return newRPCPendingTransaction(tx)
	}
	// Transaction unknown, return as such
	return nil
}

// GetTransactionByHash returns the transaction for the given hash
func (s *PublicTransactionPoolAPI) GetTransactionByHash2(ctx context.Context, hash common.Hash) *types.Transaction {
	// Try to return an already finalized transaction
	if tx, _, _, _ := rawdb.ReadTransaction(s.b.ChainDb(), hash); tx != nil {
		return tx
	}
	// No finalized transaction, try to retrieve it from the pool
	if tx := s.b.GetPoolTransaction(hash); tx != nil {
		return tx
	}
	// Transaction unknown, return as such
	return nil
}

// GetRawTransactionByHash returns the bytes of the transaction for the given hash.
func (s *PublicTransactionPoolAPI) GetRawTransactionByHash(ctx context.Context, hash common.Hash) (hexutil.Bytes, error) {
	var tx *types.Transaction

	// Retrieve a finalized transaction, or a pooled otherwise
	if tx, _, _, _ = rawdb.ReadTransaction(s.b.ChainDb(), hash); tx == nil {
		if tx = s.b.GetPoolTransaction(hash); tx == nil {
			// Transaction not found anywhere, abort
			return nil, nil
		}
	}
	// Serialize to RLP and return
	return rlp.EncodeToBytes(tx)
}

// GetTransactionReceipt returns the transaction receipt for the given transaction hash.
func (s *PublicTransactionPoolAPI) GetTransactionReceipt(ctx context.Context, hash common.Hash) (map[string]interface{}, error) {
	tx, blockHash, blockNumber, index := rawdb.ReadTransaction(s.b.ChainDb(), hash)
	if tx == nil {
		return nil, nil
	}
	receipts, err := s.b.GetReceipts(ctx, blockHash)
	if err != nil {
		return nil, err
	}
	if len(receipts) <= int(index) {
		return nil, nil
	}
	receipt := receipts[index]

	var signer types.Signer = types.FrontierSigner{}
	if tx.Protected() {
		signer = types.NewEIP155Signer(tx.ChainId())
	}
	from, _ := types.Sender(signer, tx)

	fields := map[string]interface{}{
		"blockHash":         blockHash,
		"blockNumber":       hexutil.Uint64(blockNumber),
		"transactionHash":   hash,
		"transactionIndex":  hexutil.Uint64(index),
		"from":              from,
		"to":                tx.To(),
		"gasUsed":           hexutil.Uint64(receipt.GasUsed),
		"cumulativeGasUsed": hexutil.Uint64(receipt.CumulativeGasUsed),
		"contractAddress":   nil,
		"logs":              receipt.Logs,
		"logsBloom":         receipt.Bloom,
	}

	// Assign receipt status or post state.
	if len(receipt.PostState) > 0 {
		fields["root"] = hexutil.Bytes(receipt.PostState)
	} else {
		fields["status"] = hexutil.Uint(receipt.Status)
	}
	if receipt.Logs == nil {
		fields["logs"] = [][]*types.Log{}
	}
	// If the ContractAddress is 20 0x0 bytes, assume it is not a contract creation
	if receipt.ContractAddress != (common.Address{}) {
		fields["contractAddress"] = receipt.ContractAddress
	}
	return fields, nil
}

// sign is a helper function that signs a transaction with the private key of the given address.
func (s *PublicTransactionPoolAPI) sign(addr common.Address, tx *types.Transaction) (*types.Transaction, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Request the wallet to sign the transaction
	var chainID *big.Int
	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
		chainID = config.ChainID
	}
	return wallet.SignTx(account, tx, chainID)
}

// SendTxArgs represents the arguments to sumbit a new transaction into the transaction pool.
type SendTxArgs struct {
	From     common.Address  `json:"from"`
	To       *common.Address `json:"to"`
	Gas      *hexutil.Uint64 `json:"gas"`
	GasPrice *hexutil.Big    `json:"gasPrice"`
	Value    *hexutil.Big    `json:"value"`
	Nonce    *hexutil.Uint64 `json:"nonce"`
	PubKey   *hexutil.Bytes  `json:"pubKey"`
	// We accept "data" and "input" for backwards-compatibility reasons. "input" is the
	// newer name and should be preferred by clients.
	Data  *hexutil.Bytes `json:"data"`
	Input *hexutil.Bytes `json:"input"`
	//add
	Key    string      `json:"key"`
	TxHash common.Hash `json:"txHash"`
	// parameters of contract function
	Fees         *hexutil.Big   `json:"fees"`      //user租车所用押金
	Subcosts     *hexutil.Big   `json:"subcosts"`  //总租车费用
	Subdists     *hexutil.Big   `json:"subdists"`  //所有user总租车里程
	Disti        *hexutil.Big   `json:"disti"`     //单个user的租车里程
	Costi        *hexutil.Big   `json:"costi"`     //单个user的租车费用
	Refundi      *hexutil.Big   `json:"refundi"`   //单个user需要认领的剩余租车押金
	addressowner common.Address `json:"addrowner"` //owner的账户地址
	Cmtt         common.Hash    `json:"cmtt"`
	//not used
	H0     common.Hash      `json:"h0"`
	Hi     common.Hash      `json:"hi"`
	N      *hexutil.Big     `json:"N"`
	HN     common.Hash      `json:"hN"`
	AddrA  common.Address   `json:"addrA"`
	SigA   *hexutil.Bytes   `json:"sigA"`
	Froms  []common.Address `json:"froms"`
	AddrAs []common.Address `json:"addrAs"`
}

// setDefaults is a helper function that fills in default values for unspecified tx fields.
func (args *SendTxArgs) setDefaults(ctx context.Context, b Backend) error {
	if args.Gas == nil {
		args.Gas = new(hexutil.Uint64)
		*(*uint64)(args.Gas) = 90000
	}
	if args.GasPrice == nil {
		price, err := b.SuggestPrice(ctx)
		if err != nil {
			return err
		}
		args.GasPrice = (*hexutil.Big)(price)
	}
	if args.Value == nil {
		args.Value = new(hexutil.Big)
	}
	if args.Nonce == nil {
		nonce, err := b.GetPoolNonce(ctx, args.From)
		if err != nil {
			return err
		}
		args.Nonce = (*hexutil.Uint64)(&nonce)
	}
	if args.Data != nil && args.Input != nil && !bytes.Equal(*args.Data, *args.Input) {
		return errors.New(`Both "data" and "input" are set and not equal. Please use "input" to pass transaction call data.`)
	}
	if args.To == nil {
		// Contract creation
		var input []byte
		if args.Data != nil {
			input = *args.Data
		} else if args.Input != nil {
			input = *args.Input
		}
		if len(input) == 0 {
			return errors.New(`contract creation without any data provided`)
		}
	}

	return nil
}

func (args *SendTxArgs) toTransaction() *types.Transaction {
	var input []byte
	if args.Data != nil {
		input = *args.Data
	} else if args.Input != nil {
		input = *args.Input
	}
	if args.To == nil {
		return types.NewContractCreation(uint64(*args.Nonce), (*big.Int)(args.Value), uint64(*args.Gas), (*big.Int)(args.GasPrice), input)
	}
	return types.NewTransaction(uint64(*args.Nonce), *args.To, (*big.Int)(args.Value), uint64(*args.Gas), (*big.Int)(args.GasPrice), input)
}

// submitTransaction is a helper function that submits tx to txPool and logs a message.
func submitTransaction(ctx context.Context, b Backend, tx *types.Transaction) (common.Hash, error) {
	if err := b.SendTx(ctx, tx); err != nil {
		return common.Hash{}, err
	}
	if tx.To() == nil {
		signer := types.MakeSigner(b.ChainConfig(), b.CurrentBlock().Number())
		from, err := types.Sender(signer, tx)
		if err != nil {
			return common.Hash{}, err
		}
		addr := crypto.CreateAddress(from, tx.Nonce())
		log.Info("Submitted contract creation", "fullhash", tx.Hash().Hex(), "contract", addr.Hex())
	} else {
		log.Info("Submitted transaction", "fullhash", tx.Hash().Hex(), "recipient", tx.To())
	}
	return tx.Hash(), nil
}

// SendPublicTransaction creates a transaction for the given argument, sign it and submit it to the
// transaction pool.
func (s *PublicTransactionPoolAPI) SendPublicTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {

	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return common.Hash{}, err
	}

	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}

	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}
	// Assemble the transaction and sign with the wallet
	tx := args.toTransaction()
	tx.SetTxCode(types.PublicTx)

	var chainID *big.Int
	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
		chainID = config.ChainID
	}
	signed, err := wallet.SignTx(account, tx, chainID)
	if err != nil {
		return common.Hash{}, err
	}
	return submitTransaction(ctx, s.b, signed)
}

//SetBalance Set balance for a group of accounts.
func (s *PublicTransactionPoolAPI) SetBalance(ctx context.Context, from common.Address, to []common.Address, value *hexutil.Big) error {
	var args SendTxArgs
	args.From = from
	args.Value = value
	for i := 0; i < len(to); i++ {
		args.To = &to[i]
		_, err := s.SendPublicTransaction(ctx, args)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *PublicTransactionPoolAPI) StateDB(ctx context.Context) (*state.StateDB, error) {
	currentBlock := s.b.CurrentBlock()
	state, _, err := s.b.StateAndHeaderByNumber(ctx, rpc.BlockNumber(currentBlock.NumberU64()))
	return state, err
}

//GenHashChain Generate a hashchain and return a string array including hash value No.0~N.
func (s *PublicTransactionPoolAPI) GenHashChain(ctx context.Context, N uint64) []string {
	h_N := *zktx.NewRandomHash()
	hashList := make([]string, N+1)

	for n, h := (int)(N), h_N; n >= 0; n-- {
		hashList[n] = h.String()
		h = crypto.Keccak256Hash(h.Bytes())

	}
	return hashList
}

func (s *PublicTransactionPoolAPI) GetKey(ctx context.Context, address common.Address, passwd string) (*accounts.Key, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: address}
	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}

	var chainID *big.Int
	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
		chainID = config.ChainID
	}
	return wallet.GetKeyByAccount(account, passwd, chainID)
}

func (s *PublicTransactionPoolAPI) GetPubKeyRLP(ctx context.Context, address common.Address, passwd string) (string, error) {
	key, err := s.GetKey(ctx, address, passwd)
	if err != nil {
		return "", err
	}
	type pub struct {
		X *big.Int
		Y *big.Int
	}
	pubkey := pub{key.X, key.Y}

	pp, err := rlp.EncodeToBytes(pubkey)

	return common.ToHex(pp), err
}

//------------Blockchain performance test------------
func (s *PublicTransactionPoolAPI) TestBlockByHash(ctx context.Context, hash common.Hash) {

	for true {
		receipt, _ := s.GetTransactionReceipt(ctx, hash)
		if receipt != nil && receipt["blockNumber"] != nil {
			t := time.Now()
			f := fmt.Sprintf("%d:%d:%d.%.3d\n", t.Hour(), t.Minute(), t.Second(), t.Nanosecond()/1000000)
			zktx.AppendToFile("end_time.txt", f)
			return
		}
	}
}

func (s *PublicTransactionPoolAPI) TestBlock(ctx context.Context, hashList []common.Hash) {
	for i := 0; i < len(hashList); i++ {
		go s.TestBlockByHash(ctx, hashList[i])
	}
}

// //SendMultiTransactions function
// func (s *PublicTransactionPoolAPI) SendMultiTransactions(ctx context.Context, number int, args SendTxArgs) ([]common.Hash, error) {
// 	var hashList []common.Hash
// 	switch number {
// 	case 1:
// 		for i := 0; i < len(args.Froms); i++ {
// 			args.From = args.Froms[i]
// 			hash, err := s.SendConvertTransaction(ctx, args)
// 			hashList = append(hashList, hash)
// 			if err != nil {
// 				return nil, err
// 			}
// 		}
// 	case 21:
// 		// bi-test
// 		for i := 0; i < len(args.Froms); i++ {
// 			args.From = args.Froms[i]
// 			hash, err := s.SendCommitTransaction(ctx, args)
// 			hashList = append(hashList, hash)
// 			if err != nil {
// 				return nil, err
// 			}
// 		}
// 	case 22:
// 		// uni-test
// 		h0 := zktx.H0
// 		amount := big.NewInt(1000)
// 		N := big.NewInt(1000)

// 		//turn params to input of contract
// 		func_name := "Commit(bytes32,uint256,uint256)"
// 		func_keccak256 := crypto.Keccak256([]byte(func_name))[:4]
// 		h0_bytes := h0.Bytes()
// 		amount_bytes := common.BigToHash(amount).Bytes()
// 		N_bytes := common.BigToHash(N).Bytes()

// 		var buffer bytes.Buffer
// 		buffer.Write(func_keccak256)
// 		buffer.Write(h0_bytes)
// 		buffer.Write(amount_bytes)
// 		buffer.Write(N_bytes)

// 		input := buffer.Bytes()
// 		args.Input = (*hexutil.Bytes)(&input)
// 		args.Gas = new(hexutil.Uint64)
// 		*(*uint64)(args.Gas) = 200000

// 		args.Value = (*hexutil.Big)(big.NewInt(1000))

// 		for i := 0; i < len(args.Froms); i++ {
// 			args.From = args.Froms[i]
// 			hash, err := s.SendPublicTransaction(ctx, args)
// 			hashList = append(hashList, hash)
// 			if err != nil {
// 				return nil, err
// 			}
// 		}
// 	case 3:
// 		for i := 0; i < len(args.Froms); i++ {
// 			args.From = args.Froms[i]
// 			args.AddrA = args.AddrAs[i]
// 			hash, err := s.SendClaimTransaction(ctx, args)
// 			hashList = append(hashList, hash)
// 			if err != nil {
// 				return nil, err
// 			}
// 		}
// 	case 4:
// 		for i := 0; i < len(args.Froms); i++ {
// 			args.From = args.Froms[i]
// 			hash, err := s.SendRefundTransaction(ctx, args)
// 			hashList = append(hashList, hash)
// 			if err != nil {
// 				return nil, err
// 			}
// 		}
// 	case 5:
// 		for i := 0; i < len(args.Froms); i++ {
// 			args.From = args.Froms[i]
// 			hash, err := s.SendDepositsgTransaction(ctx, args)
// 			hashList = append(hashList, hash)
// 			if err != nil {
// 				return nil, err
// 			}
// 		}
// 	}

// 	return hashList, nil
// }

//SendMintTransaction function
func (s *PublicTransactionPoolAPI) SendMintTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {

	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}
	wallet, err := s.b.AccountManager().Find(account)

	if err != nil {
		return common.Hash{}, err
	}
	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}
	args.To = zktx.NewRandomAddress()
	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}

	tx := args.toTransaction()
	tx.SetTxCode(types.MintTx)
	tx.SetZKValue(uint64(10000)) //Mint 要转化的零知识金额对应的明文金额value
	tx.SetPrice(big.NewInt(0))
	tx.SetValue(big.NewInt(0))
	tx.SetZKAddress(&zktx.ZKTxAddress)

	tx.SetZKSN(&zktx.Sn_old) //SN_old
	tx.SetZKCMTOLD(&zktx.CmtA_old)
	tx.SetZKCMT(&zktx.CmtA)
	tx.SetZKProof(zktx.Mint_proof)

	var chainID *big.Int
	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
		chainID = config.ChainID
	}
	signed, err := wallet.SignTx(account, tx, chainID)
	if err != nil {
		return common.Hash{}, err
	}
	hash, err := submitTransaction(ctx, s.b, signed)
	return hash, err
}

//SendInitTransaction function
func (s *PublicTransactionPoolAPI) SendInitTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {

	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}
	wallet, err := s.b.AccountManager().Find(account)

	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}
	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}
	//sendTransaction 所需参数
	// fees := big.NewInt(args.Fees.ToInt().Int64())
	// subcosts := big.NewInt(args.Subcosts.ToInt().Int64())
	// subdists := big.NewInt(args.Subdists.ToInt().Int64())
	// cmtt := common.HexToHash(args.Cmtt.String())

	fees := big.NewInt(100)
	subcosts := big.NewInt(80)
	subdists := big.NewInt(20)
	cmtt := common.HexToHash("0x89d7665dfb0512bbae245cda0bf423cab0de6f3445070ccc17dee262cc5083e1")

	//turn params to input of contract
	func_name := "Init(uint256,uint256,uint256,bytes32)"
	func_keccak256 := crypto.Keccak256([]byte(func_name))[:4]
	fees_bytes := common.BigToHash(fees).Bytes()
	subcosts_bytes := common.BigToHash(subcosts).Bytes()
	subdists_bytes := common.BigToHash(subdists).Bytes()
	cmtt_bytes := cmtt.Bytes()

	var buffer bytes.Buffer
	buffer.Write(func_keccak256)
	buffer.Write(fees_bytes)
	buffer.Write(subcosts_bytes)
	buffer.Write(subdists_bytes)
	buffer.Write(cmtt_bytes)

	input := buffer.Bytes()
	args.Input = (*hexutil.Bytes)(&input)

	*args.Gas = hexutil.Uint64(200000)
	tx := args.toTransaction()
	tx.SetTxCode(types.PublicTx)
	tx.SetValue(big.NewInt(0))
	// tx.SetZKAddress(&args.From)

	var chainID *big.Int
	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
		chainID = config.ChainID
	}
	signed, err := wallet.SignTx(account, tx, chainID)
	if err != nil {
		return common.Hash{}, err
	}

	hash, err := submitTransaction(ctx, s.b, signed)
	return hash, err
}

// SendConvertTransaction function ||  Cost function
func (s *PublicTransactionPoolAPI) SendConvertTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {

	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}
	wallet, err := s.b.AccountManager().Find(account)

	if err != nil {
		return common.Hash{}, err
	}
	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}
	args.To = zktx.NewRandomAddress()
	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}

	tx := args.toTransaction()
	tx.SetTxCode(types.ConvertTx)
	tx.SetPrice(big.NewInt(0))
	tx.SetValue(big.NewInt(0))
	tx.SetZKAddress(&zktx.ZKTxAddress)

	//生成cmtold
	valueold := big.NewInt(1000)
	snold := zktx.NewRandomHash()
	rold := zktx.NewRandomHash()
	CMTold := zktx.GenCMT(valueold.Uint64(), snold.Bytes(), rold.Bytes())

	//生成cmts
	SNs := zktx.NewRandomHash()
	newRs := zktx.NewRandomHash()
	CMTs := zktx.GenCMT(args.Value.ToInt().Uint64(), SNs.Bytes(), newRs.Bytes())

	//生成cmt
	newSNA := zktx.NewRandomHash()
	newRandomA := zktx.NewRandomHash()
	newValueA := valueold.Uint64() - args.Value.ToInt().Uint64()
	newCMTA := zktx.GenCMT(newValueA, newSNA.Bytes(), newRandomA.Bytes())

	//验证proof用的参数
	tx.SetZKCMTOLD(CMTold)
	tx.SetZKCMTS(CMTs)
	tx.SetZKCMT(newCMTA)
	tx.SetZKSNS(SNs)
	tx.SetZKSN(snold) //SN_old

	zkProof := zktx.GenConvertProof(CMTold, valueold.Uint64(), rold, args.Value.ToInt().Uint64(), SNs, newRs, snold, CMTs, newValueA, newSNA, newRandomA, newCMTA)
	if string(zkProof[0:10]) == "0000000000" {
		return common.Hash{}, errors.New("can't generate proof")
	}
	tx.SetZKProof(zkProof)

	// 	zktx.SNS = &zktx.Sequence{SN: SNs, CMT: CMTs, Random: newRs, Value: args.Value.ToInt().Uint64()}
	var chainID *big.Int
	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
		chainID = config.ChainID
	}
	signed, err := wallet.SignTx(account, tx, chainID)
	if err != nil {
		return common.Hash{}, err
	}
	hash, err := submitTransaction(ctx, s.b, signed)
	return hash, err
}

// //SendCommitTransaction function
// func (s *PublicTransactionPoolAPI) SendCommitTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {

// 	if args.Nonce == nil {
// 		// Hold the addresse's mutex around signing to prevent concurrent assignment of
// 		// the same nonce to multiple accounts.
// 		s.nonceLock.LockAddr(args.From)
// 		defer s.nonceLock.UnlockAddr(args.From)
// 	}
// 	// Set some sanity defaults and terminate on failure
// 	if err := args.setDefaults(ctx, s.b); err != nil {
// 		return common.Hash{}, err
// 	}

// 	h0 := zktx.H0
// 	cmtC := zktx.CmtC
// 	N := big.NewInt(1000)

// 	//turn params to input of contract
// 	func_name := "Commit(bytes32,bytes32,uint256)"
// 	func_keccak256 := crypto.Keccak256([]byte(func_name))[:4]
// 	h0_bytes := h0.Bytes()
// 	cmtC_bytes := cmtC.Bytes()
// 	N_bytes := common.BigToHash(N).Bytes()

// 	var buffer bytes.Buffer
// 	buffer.Write(func_keccak256)
// 	buffer.Write(h0_bytes)
// 	buffer.Write(cmtC_bytes)
// 	buffer.Write(N_bytes)

// 	input := buffer.Bytes()
// 	args.Input = (*hexutil.Bytes)(&input)

// 	*args.Gas = hexutil.Uint64(200000)
// 	tx := args.toTransaction()
// 	tx.SetTxCode(types.CommitTx)
// 	tx.SetValue(big.NewInt(0))
// 	tx.SetZKAddress(&args.From) //?

// 	var cmtarray []common.Hash
// 	for i := 0; i < 32; i++ {
// 		if i == 9 {
// 			cmtarray = append(cmtarray, zktx.CmtS)
// 		} else {
// 			cmt := common.HexToHash(zktx.Cmt_str[i])
// 			cmtarray = append(cmtarray, cmt)
// 		}
// 	}

// 	tx.SetCmtarr(cmtarray)
// 	tx.SetRTcmt(zktx.RT)
// 	tx.SetZKSNS(&zktx.Sn_s)
// 	tx.SetZKCMT(&zktx.CmtC)
// 	tx.SetZKProof(zktx.Commit_proof)
// 	hash, err := submitTransaction(ctx, s.b, tx)
// 	return hash, err
// }

//SendClaimTransaction function || user divide
func (s *PublicTransactionPoolAPI) SendClaimTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {

	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}
	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}

	disti := big.NewInt(args.Disti.ToInt().Int64())
	costi := big.NewInt(80 * args.Disti.ToInt().Int64() / 20) //subdist ==  20
	refundi := big.NewInt(100 - 80*args.Disti.ToInt().Int64()/20)

	//turn params to input of contract
	func_name := "Divide(uint256,uint256,address)"
	func_keccak256 := crypto.Keccak256([]byte(func_name))[:4]
	disti_bytes := common.BigToHash(disti).Bytes()
	refund_bytes := common.BigToHash(refundi).Bytes()
	addr_bytes := args.addressowner.Hash().Bytes()

	var buffer bytes.Buffer
	buffer.Write(func_keccak256)
	buffer.Write(disti_bytes)
	buffer.Write(refund_bytes)
	buffer.Write(addr_bytes)

	input := buffer.Bytes()
	args.Input = (*hexutil.Bytes)(&input)

	*args.Gas = hexutil.Uint64(200000)
	tx := args.toTransaction()
	tx.SetTxCode(types.ClaimTx)
	tx.SetValue(big.NewInt(0))
	tx.SetZKAddress(&args.From)

	//生成cmts = sha(refundi | sns |  rs)
	SNs := zktx.NewRandomHash()
	newRs := zktx.NewRandomHash()
	CMTs := zktx.GenCMT(refundi.Uint64(), SNs.Bytes(), newRs.Bytes())

	//生成cmtt = sha(cost | r)
	rC := zktx.NewRandomHash()
	cmtT := zktx.GenCMT2(uint64(80), rC.Bytes())

	zkProof := zktx.GenClaimProof(costi.Uint64(), uint64(80), disti.Uint64(), uint64(20), uint64(100), refundi.Uint64(), SNs, newRs, CMTs, rC, cmtT)
	if string(zkProof[0:10]) == "0000000000" {
		return common.Hash{}, errors.New("can't generate proof")
	}

	tx.SetZKProof(zkProof) //proof tbd
	tx.SetZKValue(refundi.Uint64())
	tx.SetZKCMTS(CMTs) //cmtc
	tx.SetZKCMT(cmtT)  //cmtt
	hash, err := submitTransaction(ctx, s.b, tx)
	return hash, err
}

// SendDepositsgTransaction function || owner collect
func (s *PublicTransactionPoolAPI) SendDepositsgTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {

	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}
	wallet, err := s.b.AccountManager().Find(account)

	if err != nil {
		return common.Hash{}, err
	}

	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment ofnil
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}
	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}

	subcost := big.NewInt(args.Value.ToInt().Int64()) //subcost ==  80
	cmtso := common.HexToHash("0x89d7665dfb0512bbae245cda0bf423cab0de6f3445070ccc17dee262cc5083e1")

	//turn params to input of contract
	func_name := "Collect(uint256,bytes32)"
	func_keccak256 := crypto.Keccak256([]byte(func_name))[:4]
	cost_bytes := common.BigToHash(subcost).Bytes()
	cmtso_bytes := cmtso.Bytes()

	var buffer bytes.Buffer
	buffer.Write(func_keccak256)
	buffer.Write(cost_bytes)
	buffer.Write(cmtso_bytes)

	input := buffer.Bytes()
	args.Input = (*hexutil.Bytes)(&input)
	*args.Gas = hexutil.Uint64(200000)

	// Assemble the transaction and sign with the wallet
	tx := args.toTransaction()
	tx.SetTxCode(types.DepositsgTx)
	tx.SetPrice(big.NewInt(0))
	tx.SetValue(big.NewInt(0))
	tx.SetZKAddress(&args.From)

	//生成cmtold
	valueold := big.NewInt(1000)
	snold := zktx.NewRandomHash()
	rold := zktx.NewRandomHash()
	CMTold := zktx.GenCMT(valueold.Uint64(), snold.Bytes(), rold.Bytes())

	//生成cmts
	SNs := zktx.NewRandomHash()
	newRs := zktx.NewRandomHash()
	CMTs := zktx.GenCMT(args.Value.ToInt().Uint64(), SNs.Bytes(), newRs.Bytes())

	//生成cmt,混淆cmts
	VALUES := big.NewInt(100)
	SNS := zktx.NewRandomHash()
	RS := zktx.NewRandomHash()
	CMTS := zktx.GenCMT(VALUES.Uint64(), SNS.Bytes(), RS.Bytes())

	//生成cmt
	newSNA := zktx.NewRandomHash()
	newRandomA := zktx.NewRandomHash()
	newValueA := valueold.Uint64() + args.Value.ToInt().Uint64()
	newCMTA := zktx.GenCMT(newValueA, newSNA.Bytes(), newRandomA.Bytes())

	//生成cmtt
	newRandom := zktx.NewRandomHash()
	newValue := args.Value.ToInt().Uint64()
	newCMTT := zktx.GenCMT2(newValue, newRandom.Bytes())

	var cmtarray []*common.Hash
	for i := 0; i < 32; i++ {
		if i == 9 {
			cmts := common.HexToHash(CMTs.String())
			cmtarray = append(cmtarray, &cmts)
		} else {
			cmt := common.HexToHash(CMTS.String())
			cmtarray = append(cmtarray, &cmt)
		}
	}

	var cmtarr []common.Hash
	for i := 0; i < 32; i++ {
		if i == 9 {
			cmts := common.HexToHash(CMTs.String())
			cmtarr = append(cmtarr, cmts)
		} else {
			cmt := common.HexToHash(CMTS.String())
			cmtarr = append(cmtarr, cmt)
		}
	}

	NewRT := zktx.GenRT(cmtarray)

	zkProof := zktx.GenDepositsgProof(newRandom, newCMTT, args.Value.ToInt().Uint64(), SNs, newRs, CMTs, valueold.Uint64(), snold, rold, CMTold, newSNA, newRandomA, newCMTA, NewRT.Bytes(), cmtarray)
	if string(zkProof[0:10]) == "0000000000" {
		return common.Hash{}, errors.New("can't generate proof")
	}
	tx.SetZKProof(zkProof) //proof tbd
	tx.SetZKSNS(SNs)
	tx.SetZKCMTS(CMTs)
	tx.SetZKSN(snold)
	tx.SetZKCMTOLD(CMTold)
	tx.SetZKCMT(newCMTA)
	tx.SetZKCMTT(newCMTT)
	tx.SetRTcmt(NewRT)
	tx.SetCmtarr(cmtarr)

	var chainID *big.Int
	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
		chainID = config.ChainID
	}
	signed, err := wallet.SignTx(account, tx, chainID)
	if err != nil {
		return common.Hash{}, err
	}
	hash, err := submitTransaction(ctx, s.b, signed)
	return hash, err
}

//SendRefundTransaction function || user refund
func (s *PublicTransactionPoolAPI) SendRefundTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}
	wallet, err := s.b.AccountManager().Find(account)

	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}
	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}

	refundi := big.NewInt(args.Value.ToInt().Int64()) //refundi
	cmtsu := common.HexToHash("0x89d7665dfb0512bbae245cda0bf423cab0de6f3445070ccc17dee262cc5083e1")

	//turn params to input of contract
	func_name := "Refund(uint256,bytes32)"
	func_keccak256 := crypto.Keccak256([]byte(func_name))[:4]
	refundi_bytes := common.BigToHash(refundi).Bytes()
	cmtsu_bytes := cmtsu.Bytes()

	var buffer bytes.Buffer
	buffer.Write(func_keccak256)
	buffer.Write(refundi_bytes)
	buffer.Write(cmtsu_bytes)

	input := buffer.Bytes()
	args.Input = (*hexutil.Bytes)(&input)

	*args.Gas = hexutil.Uint64(200000)
	tx := args.toTransaction()
	tx.SetTxCode(types.RefundTx)
	tx.SetPrice(big.NewInt(0))
	tx.SetValue(big.NewInt(0))
	// tx.SetZKAddress(&args.From)

	//生成cmtold
	valueold := big.NewInt(1000)
	snold := zktx.NewRandomHash()
	rold := zktx.NewRandomHash()
	CMTold := zktx.GenCMT(valueold.Uint64(), snold.Bytes(), rold.Bytes())

	//生成cmts
	SNs := zktx.NewRandomHash()
	newRs := zktx.NewRandomHash()
	CMTs := zktx.GenCMT(args.Value.ToInt().Uint64(), SNs.Bytes(), newRs.Bytes())

	//生成cmt,混淆cmts
	VALUES := big.NewInt(100)
	SNS := zktx.NewRandomHash()
	RS := zktx.NewRandomHash()
	CMTS := zktx.GenCMT(VALUES.Uint64(), SNS.Bytes(), RS.Bytes())

	//生成cmt
	newSNA := zktx.NewRandomHash()
	newRandomA := zktx.NewRandomHash()
	newValueA := valueold.Uint64() + args.Value.ToInt().Uint64()
	newCMTA := zktx.GenCMT(newValueA, newSNA.Bytes(), newRandomA.Bytes())

	var cmtarray []*common.Hash
	for i := 0; i < 32; i++ {
		if i == 9 {
			cmts := common.HexToHash(CMTs.String())
			cmtarray = append(cmtarray, &cmts)
		} else {
			cmt := common.HexToHash(CMTS.String())
			cmtarray = append(cmtarray, &cmt)
		}
	}

	var cmtarr []common.Hash
	for i := 0; i < 32; i++ {
		if i == 9 {
			cmts := common.HexToHash(CMTs.String())
			cmtarr = append(cmtarr, cmts)
		} else {
			cmt := common.HexToHash(CMTS.String())
			cmtarr = append(cmtarr, cmt)
		}
	}

	NewRT := zktx.GenRT(cmtarray)

	zkProof := zktx.GenDepositProof(uint64(100), uint64(32), args.Value.ToInt().Uint64(), SNs, newRs, CMTs, valueold.Uint64(), snold, rold, CMTold, newSNA, newRandomA, newCMTA, NewRT.Bytes(), cmtarray)
	if string(zkProof[0:10]) == "0000000000" {
		return common.Hash{}, errors.New("can't generate proof")
	}

	tx.SetZKValue(args.Value.ToInt().Uint64())
	tx.SetZKCMTS(CMTs)
	tx.SetZKSNS(SNs)
	tx.SetZKCMT(newCMTA)
	tx.SetZKSN(snold)
	tx.SetZKCMTOLD(CMTold)
	tx.SetRTcmt(NewRT)
	tx.SetCmtarr(cmtarr)
	tx.SetZKProof(zkProof)
	tx.SetZKAddress(&args.From)

	var chainID *big.Int
	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
		chainID = config.ChainID
	}
	signed, err := wallet.SignTx(account, tx, chainID)
	if err != nil {
		return common.Hash{}, err
	}

	hash, err := submitTransaction(ctx, s.b, signed)
	return hash, err
}

//--------------------------Blockchain performance test-----------------------

// SendRedeemTransaction creates a Redeem transaction for the given argument, sign it and submit it to the
// transaction pool.
func (s *PublicTransactionPoolAPI) SendRedeemTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {
	// if zktx.Stage == zktx.Send {
	// 	fmt.Println("cannot send Redeem after sendTx")
	// 	return common.Hash{}, nil
	// }
	if zktx.SNfile == nil {
		fmt.Println("SNfile does not exist")
		return common.Hash{}, nil
	}
	if zktx.SequenceNumber == nil || zktx.SequenceNumberAfter == nil {
		fmt.Println("SequenceNumber or SequenceNumberAfter nil")
		return common.Hash{}, nil
	}
	state, _, err := s.b.StateAndHeaderByNumber(ctx, rpc.LatestBlockNumber)
	if state == nil || err != nil {
		return common.Hash{}, err
	}

	//check whether sn can be used
	exist := state.Exist(common.BytesToAddress(zktx.SequenceNumberAfter.SN.Bytes()))

	if exist == true && *(zktx.SequenceNumberAfter.SN) != *(zktx.InitializeSN().SN) {
		fmt.Println("sn is lost")
		return common.Hash{}, nil
	}

	//check whether last tx is processed successfully
	exist = state.Exist(common.BytesToAddress(zktx.SequenceNumber.SN.Bytes()))

	if exist == false && *(zktx.SequenceNumber.SN) != *(zktx.InitializeSN().SN) { //if last transaction is not processed successfully, the corresponding SN is not in the database,and we use SN before  last unprocessed transaction
		// if zktx.Stage == zktx.Update {
		// 	fmt.Println("last transaction is update,but it is not well processed,please send updateTx firstly")
		// 	return common.Hash{}, nil
		// }
		zktx.SequenceNumberAfter = zktx.SequenceNumber
	}

	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: args.From}
	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return common.Hash{}, err
	}

	if args.Nonce == nil {
		// Hold the addresse's mutex around signing to prevent concurrent assignment of
		// the same nonce to multiple accounts.
		s.nonceLock.LockAddr(args.From)
		defer s.nonceLock.UnlockAddr(args.From)
	}
	args.To = &zktx.ZKTxAddress
	// Set some sanity defaults and terminate on failure
	if err := args.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}
	// Assemble the transaction and sign with the wallet
	tx := args.toTransaction()
	tx.SetTxCode(types.RedeemTx)
	tx.SetValue(big.NewInt(0))
	tx.SetZKValue(args.Value.ToInt().Uint64())
	tx.SetPrice(big.NewInt(0))
	tx.SetZKAddress(&zktx.ZKTxAddress)
	SN := zktx.SequenceNumberAfter

	tx.SetZKSN(SN.SN) //SN

	tx.SetZKProof([]byte{}) //proof tbd

	newSN := zktx.NewRandomHash()
	newRandom := zktx.NewRandomHash()
	newValue := SN.Value - args.Value.ToInt().Uint64()

	newCMT := zktx.GenCMT(newValue, newSN.Bytes(), newRandom.Bytes()) //tbd
	tx.SetZKCMT(newCMT)                                               //cmt

	zkProof := zktx.GenRedeemProof(SN.Value, SN.Random, newSN, newRandom, SN.CMT, SN.SN, newCMT, newValue)
	if string(zkProof[0:10]) == "0000000000" {
		return common.Hash{}, errors.New("can't generate proof")
	}
	tx.SetZKProof(zkProof)

	var chainID *big.Int
	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
		chainID = config.ChainID
	}

	signed, err := wallet.SignTx(account, tx, chainID)
	if err != nil {
		return common.Hash{}, err
	}

	hash, err := submitTransaction(ctx, s.b, signed)
	if err == nil {
		zktx.SequenceNumber = zktx.SequenceNumberAfter
		zktx.SequenceNumberAfter = &zktx.Sequence{SN: newSN, CMT: newCMT, Random: newRandom, Value: newValue}
		zktx.Stage = zktx.Redeem
		SNS := zktx.SequenceS{*zktx.SequenceNumber, *zktx.SequenceNumberAfter, zktx.SNS, nil, nil, zktx.Redeem}

		SNSBytes, err := rlp.EncodeToBytes(SNS)
		if err != nil {
			fmt.Println("encode sns error")
			return common.Hash{}, nil
		}
		SNSString := hex.EncodeToString(SNSBytes)
		zktx.SNfile.Seek(0, 0) //write in the first line of the file
		wt := bufio.NewWriter(zktx.SNfile)

		wt.WriteString(SNSString)
		wt.WriteString("\n") //write a line
		wt.Flush()
	}
	return hash, err
}

// SendConvertTransaction creates a convert transaction for the given argument, sign it and submit it to the
// transaction pool.
// func (s *PublicTransactionPoolAPI) SendConvertTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) { //tbd

// 	if zktx.SNfile == nil {
// 		fmt.Println("SNfile does not exist")
// 		return common.Hash{}, nil
// 	}

// 	if zktx.SequenceNumber == nil || zktx.SequenceNumberAfter == nil {
// 		fmt.Println("SequenceNumber or SequenceNumberAfter nil")
// 		return common.Hash{}, nil
// 	}
// 	state, _, err := s.b.StateAndHeaderByNumber(ctx, rpc.LatestBlockNumber)
// 	if state == nil || err != nil {
// 		return common.Hash{}, err
// 	}

// 	//check whether sn can be used
// 	exist := state.Exist(common.BytesToAddress(zktx.SequenceNumberAfter.SN.Bytes()))

// 	if exist == true && *(zktx.SequenceNumberAfter.SN) != *(zktx.InitializeSN().SN) {
// 		fmt.Println("sn is lost")
// 		return common.Hash{}, nil
// 	}

// 	//check whether last tx is processed successfully
// 	exist = state.Exist(common.BytesToAddress(zktx.SequenceNumber.SN.Bytes()))

// 	if exist == false && *(zktx.SequenceNumber.SN) != *(zktx.InitializeSN().SN) { //if last transaction is not processed successfully, the corresponding SN is not in the database,and we use SN before  last unprocessed transaction

// 		zktx.SequenceNumberAfter = zktx.SequenceNumber
// 	}

// 	// Look up the wallet containing the requested signer
// 	account := accounts.Account{Address: args.From}
// 	wallet, err := s.b.AccountManager().Find(account)
// 	if err != nil {
// 		return common.Hash{}, err
// 	}
// 	_, err = s.b.AccountManager().Find(account)
// 	if err != nil {
// 		return common.Hash{}, err
// 	}

// 	if args.Nonce == nil {
// 		// Hold the addresse's mutex around signing to prevent concurrent assignment of
// 		// the same nonce to multiple accounts.
// 		s.nonceLock.LockAddr(args.From)
// 		defer s.nonceLock.UnlockAddr(args.From)
// 	}
// 	args.To = &zktx.ZKTxAddress
// 	// Set some sanity defaults and terminate on failure
// 	if err := args.setDefaults(ctx, s.b); err != nil {
// 		return common.Hash{}, err
// 	}
// 	// Assemble the transaction and sign with the wallet
// 	tx := args.toTransaction()
// 	tx.SetTxCode(types.ConvertTx)
// 	tx.SetPrice(big.NewInt(0))
// 	tx.SetValue(big.NewInt(0))
// 	tx.SetZKAddress(&zktx.ZKTxAddress)

// 	SN := zktx.SequenceNumberAfter
// 	tx.SetZKSN(SN.SN) //SN

// 	type pub struct {
// 		X *big.Int
// 		Y *big.Int
// 	}

// 	SNs := zktx.NewRandomHash()
// 	newRs := zktx.NewRandomHash()

// 	CMTs := zktx.GenCMT_1(args.Value.ToInt().Uint64(), SNs.Bytes(), newRs.Bytes(), SN.SN.Bytes()) //生成cmts
// 	tx.SetZKCMTS(CMTs)

// 	newSNA := zktx.NewRandomHash()                                        //A新sn
// 	newRandomA := zktx.NewRandomHash()                                    //A 新 r
// 	newValueA := SN.Value - args.Value.ToInt().Uint64()                   //convert后 A新value
// 	newCMTA := zktx.GenCMT(newValueA, newSNA.Bytes(), newRandomA.Bytes()) //A 新 cmt
// 	tx.SetZKCMT(newCMTA)

// 	zkProof := zktx.GenConvertProof(SN.CMT, SN.Value, SN.Random, args.Value.ToInt().Uint64(), SNs, newRs, SN.SN, CMTs, newValueA, newSNA, newRandomA, newCMTA)
// 	if string(zkProof[0:10]) == "0000000000" {
// 		return common.Hash{}, errors.New("can't generate proof")
// 	}
// 	tx.SetZKProof(zkProof) //proof tbd

// 	zktx.SNS = &zktx.Sequence{SN: SNs, CMT: CMTs, Random: newRs, Value: args.Value.ToInt().Uint64()}

// 	var chainID *big.Int
// 	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
// 		chainID = config.ChainID
// 	}

// 	signed, err := wallet.SignTx(account, tx, chainID)
// 	if err != nil {
// 		return common.Hash{}, err
// 	}

// 	hash, err := submitTransaction(ctx, s.b, signed)

// 	if err == nil {
// 		zktx.Stage = zktx.Convert
// 		zktx.SequenceNumber = zktx.SequenceNumberAfter
// 		zktx.SequenceNumberAfter = &zktx.Sequence{SN: newSNA, CMT: newCMTA, Random: newRandomA, Value: newValueA}
// 		SNS := zktx.SequenceS{*zktx.SequenceNumber, *zktx.SequenceNumberAfter, zktx.SNS, nil, nil, zktx.Convert}
// 		SNSBytes, err := rlp.EncodeToBytes(SNS)
// 		if err != nil {
// 			fmt.Println("encode sns error")
// 			return common.Hash{}, nil
// 		}
// 		SNSString := hex.EncodeToString(SNSBytes)
// 		zktx.SNfile.Seek(0, 0) //write in the first line of the file
// 		wt := bufio.NewWriter(zktx.SNfile)

// 		wt.WriteString(SNSString)
// 		wt.WriteString("\n") //write a line
// 		wt.Flush()
// 	}
// 	return hash, err

// }

// SendCommitTransaction creates a Commit transaction for the given argument, sign it and submit it to the
// transaction pool.
// func (s *PublicTransactionPoolAPI) SendCommitTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {

// 	if zktx.SNfile == nil {
// 		fmt.Println("SNfile does not exist")
// 		return common.Hash{}, nil
// 	}
// 	if zktx.SequenceNumber == nil || zktx.SequenceNumberAfter == nil {
// 		fmt.Println("SequenceNumber or SequenceNumberAfter nil")
// 		return common.Hash{}, nil
// 	}
// 	state, _, err := s.b.StateAndHeaderByNumber(ctx, rpc.LatestBlockNumber)
// 	if state == nil || err != nil {
// 		return common.Hash{}, err
// 	}

// 	//check whether sn can be used
// 	exist := state.Exist(common.BytesToAddress(zktx.SequenceNumberAfter.SN.Bytes()))

// 	if exist == true && *(zktx.SequenceNumberAfter.SN) != *(zktx.InitializeSN().SN) {
// 		fmt.Println("sn is lost")
// 		return common.Hash{}, nil
// 	}

// 	//check whether last tx is processed successfully
// 	exist = state.Exist(common.BytesToAddress(zktx.SequenceNumber.SN.Bytes()))

// 	if exist == false && *(zktx.SequenceNumber.SN) != *(zktx.InitializeSN().SN) { //if last transaction is not processed successfully, the corresponding SN is not in the database,and we use SN before  last unprocessed transaction
// 		// if zktx.Stage == zktx.Update {
// 		// 	fmt.Println("last transaction is update,but it is not well processed,please send updateTx firstly")
// 		// 	return common.Hash{}, nil
// 		// }
// 		zktx.SequenceNumberAfter = zktx.SequenceNumber
// 	}

// 	// Look up the wallet containing the requested signer
// 	account := accounts.Account{Address: args.From}
// 	_, err = s.b.AccountManager().Find(account)
// 	if err != nil {
// 		return common.Hash{}, err
// 	}

// 	if args.Nonce == nil {
// 		// Hold the addresse's mutex around signing to prevent concurrent assignment ofnil
// 		// the same nonce to multiple accounts.
// 		s.nonceLock.LockAddr(args.From)
// 		defer s.nonceLock.UnlockAddr(args.From)
// 	}

// 	// Set some sanity defaults and terminate on failure
// 	if err := args.setDefaults(ctx, s.b); err != nil {
// 		return common.Hash{}, err
// 	}

// 	h0 := args.H0
// 	amount := args.Value
// 	N := args.N
// 	addrA := args.AddrA

// 	//turn params to input of contract
// 	func_name := "Commit(bytes32,uint256,uint256,address)"
// 	func_keccak256 := crypto.Keccak256([]byte(func_name))[:4]
// 	h0_bytes := h0.Bytes()
// 	amount_bytes := common.HexToHash(amount.String()).Bytes()
// 	N_bytes := common.HexToHash(N.String()).Bytes()
// 	addrA_bytes := addrA.Hash().Bytes()

// 	var buffer bytes.Buffer
// 	buffer.Write(func_keccak256)
// 	buffer.Write(h0_bytes)
// 	buffer.Write(amount_bytes)
// 	buffer.Write(N_bytes)
// 	buffer.Write(addrA_bytes)

// 	input := buffer.Bytes()
// 	args.Input = (*hexutil.Bytes)(&input)

// 	// Assemble the transaction
// 	*(*uint64)(args.Gas) = 200000
// 	tx := args.toTransaction()
// 	tx.SetTxCode(types.CommitTx)
// 	args.Gas = new(hexutil.Uint64)
// 	tx.SetPrice(big.NewInt(1))
// 	tx.SetValue(big.NewInt(0))

// 	//randAddr := zktx.NewRandomAddress()
// 	tx.SetZKAddress(&args.From)

// 	txSend := s.GetTransactionByHash2(ctx, args.TxHash)
// 	if txSend == nil {
// 		return common.Hash{}, errors.New("there does not exist a transaction" + args.TxHash.String())
// 	} else if txSend.Code() != types.ConvertTx {
// 		return common.Hash{}, errors.New("Wrong transaction, the inputed transaction is not a Convert transaction!" + args.TxHash.String())
// 	}

// 	RPCtx := s.GetTransactionByHash(ctx, args.TxHash)
// 	if RPCtx == nil {
// 		return common.Hash{}, errors.New("there does not exist a transaction" + args.TxHash.String())
// 	}

// 	cmtBlockNumber := (*big.Int)(RPCtx.BlockNumber)
// 	var cmtBlockNumbers []uint64
// 	var CMTSForMerkle []*common.Hash
// 	BlockToCmt := make(map[uint64][]*common.Hash)

// 	block, err := s.b.BlockByNumber(ctx, rpc.LatestBlockNumber)
// 	if block == nil {
// 		return common.Hash{}, err
// 	}

// 	cmtBlockNumbers = append(cmtBlockNumbers, cmtBlockNumber.Uint64())
// 	block2, err := s.b.BlockByNumber(ctx, rpc.BlockNumber(cmtBlockNumber.Uint64()))
// 	BlockToCmt[cmtBlockNumber.Uint64()] = block2.CMTS()

// 	// latest header should always be available
// 	latestBlockNumber := block.NumberU64()
// 	count := len(block2.CMTS())
// loop:
// 	for count < zktx.ZKCMTNODES {
// 		if len(cmtBlockNumbers) > int(latestBlockNumber) {
// 			return common.Hash{}, errors.New("insufficient cmts for merkle tree")
// 		}
// 		blockNum := uint64(rand.Int63n(int64(latestBlockNumber + 1)))
// 		for i, _ := range cmtBlockNumbers {
// 			if cmtBlockNumbers[i] == blockNum {
// 				goto loop
// 			}
// 		}
// 		block, err = s.b.BlockByNumber(ctx, rpc.BlockNumber(blockNum))
// 		if block == nil {
// 			return common.Hash{}, err
// 		}
// 		cmts := block.CMTS()
// 		BlockToCmt[blockNum] = cmts
// 		//	CMTSForMerkle = append(CMTSForMerkle, cmts...)
// 		cmtBlockNumbers = append(cmtBlockNumbers, blockNum)
// 		count += len(cmts)
// 	}

// 	merkle.QuickSortUint64(cmtBlockNumbers)

// 	for i, _ := range cmtBlockNumbers {
// 		index := cmtBlockNumbers[i]
// 		CMTSForMerkle = append(CMTSForMerkle, BlockToCmt[index]...)
// 	}

// 	RTcmt := zktx.GenRT(CMTSForMerkle)
// 	tx.SetRTcmt(RTcmt)

// 	tx.SetCMTBlocks(cmtBlockNumbers)

// 	valueS := args.Value.ToInt().Uint64()
// 	tx.SetZKValue(valueS)

// 	//cmts from local
// 	selfCmts := zktx.SNS
// 	sns := selfCmts.SN
// 	rs := selfCmts.Random
// 	tx.SetZKSNS(sns)

// 	SNa := zktx.SequenceNumber
// 	snA := SNa.SN

// 	// newSN := zktx.NewRandomHash()
// 	// newRandom := zktx.NewRandomHash()
// 	// newValue := SNb.Value + valueS
// 	// newCMTB := zktx.GenCMT(newValue, newSN.Bytes(), newRandom.Bytes())
// 	// tx.SetZKCMT(newCMTB)

// 	zkProof := zktx.GenCommitProof(valueS, sns, rs, snA, txSend.ZKCMTS(), RTcmt.Bytes(), CMTSForMerkle)
// 	if string(zkProof[0:10]) == "0000000000" {
// 		return common.Hash{}, errors.New("can't generate proof")
// 	}
// 	tx.SetZKProof(zkProof) //proof tbd

// 	//fmt.Println("randomKeyB:", randomKeyB.D.BitLen())
// 	//signedTx, errSignedTx := types.SignTx(tx, types.HomesteadSigner{}, randomKeyB)

// 	// if errSignedTx != nil {
// 	// 	fmt.Println("sign depost tx failed: ", errSignedTx)
// 	// 	return common.Hash{}, errSignedTx
// 	// }

// 	hash, err := submitTransaction(ctx, s.b, tx)
// 	if err == nil {
// 		zktx.Stage = zktx.Commit
// 		SNS := zktx.SequenceS{*(zktx.InitializeSN()), *(zktx.InitializeSN()), zktx.SNS, nil, nil, zktx.Commit}
// 		SNSBytes, err := rlp.EncodeToBytes(SNS)
// 		if err != nil {
// 			fmt.Println("encode sns error")
// 			return common.Hash{}, nil
// 		}
// 		SNSString := hex.EncodeToString(SNSBytes)
// 		zktx.SNfile.Seek(0, 0) //write in the first line of the file
// 		wt := bufio.NewWriter(zktx.SNfile)

// 		wt.WriteString(SNSString)
// 		wt.WriteString("\n") //write a line
// 		wt.Flush()
// 	}
// 	return hash, err
// }

// SendClaimTransaction creates a Claim transaction for the given argument.
// func (s *PublicTransactionPoolAPI) SendClaimTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) { //tbd

// 	if zktx.SNfile == nil {
// 		fmt.Println("SNfile does not exist")
// 		return common.Hash{}, nil
// 	}

// 	if zktx.SequenceNumber == nil || zktx.SequenceNumberAfter == nil {
// 		fmt.Println("SequenceNumber or SequenceNumberAfter nil")
// 		return common.Hash{}, nil
// 	}
// 	state, _, err := s.b.StateAndHeaderByNumber(ctx, rpc.LatestBlockNumber)
// 	if state == nil || err != nil {
// 		return common.Hash{}, err
// 	}

// 	//check whether sn can be used
// 	exist := state.Exist(common.BytesToAddress(zktx.SequenceNumberAfter.SN.Bytes()))

// 	if exist == true && *(zktx.SequenceNumberAfter.SN) != *(zktx.InitializeSN().SN) {
// 		fmt.Println("sn is lost")
// 		return common.Hash{}, nil
// 	}

// 	//check whether last tx is processed successfully
// 	exist = state.Exist(common.BytesToAddress(zktx.SequenceNumber.SN.Bytes()))

// 	if exist == false && *(zktx.SequenceNumber.SN) != *(zktx.InitializeSN().SN) { //if last transaction is not processed successfully, the corresponding SN is not in the database,and we use SN before  last unprocessed transaction

// 		zktx.SequenceNumberAfter = zktx.SequenceNumber
// 	}

// 	if args.Nonce == nil {
// 		// Hold the addresse's mutex around signing to prevent concurrent assignment of
// 		// the same nonce to multiple accounts.
// 		s.nonceLock.LockAddr(args.From)
// 		defer s.nonceLock.UnlockAddr(args.From)
// 	}
// 	// Set some sanity defaults and terminate on failure
// 	if err := args.setDefaults(ctx, s.b); err != nil {
// 		return common.Hash{}, err
// 	}

// 	hi := args.Hi
// 	values := args.Value

// 	h0 := args.H0
// 	hN := args.HN
// 	N := args.N
// 	sigA := ([]byte)(*args.SigA)

// 	SNs := zktx.NewRandomHash()
// 	newRs := zktx.NewRandomHash()
// 	CMTs := zktx.GenCMT(args.Value.ToInt().Uint64(), SNs.Bytes(), newRs.Bytes()) //生成cmts

// 	//turn params to input of contract
// 	func_name := "Claim(bytes32,uint256,bytes32,bytes32,bytes32,uint256,uint8,bytes32,bytes32)"
// 	func_keccak256 := crypto.Keccak256([]byte(func_name))[:4]
// 	hi_bytes := hi.Bytes()
// 	value_bytes := common.HexToHash(values.String()).Bytes()
// 	cmts_bytes := CMTs.Bytes()
// 	h0_bytes := h0.Bytes()
// 	hN_bytes := hN.Bytes()
// 	N_bytes := common.HexToHash(N.String()).Bytes()

// 	if len(sigA) != 65 {
// 		return common.Hash{}, errors.New("Wrong Signature length!")
// 	}
// 	sig_v := make([]byte, 32)
// 	sig_v[31] = sigA[64] + 27
// 	sig_r := sigA[0:32]
// 	sig_s := sigA[32:64]

// 	var buffer bytes.Buffer
// 	buffer.Write(func_keccak256)
// 	buffer.Write(hi_bytes)
// 	buffer.Write(value_bytes)
// 	buffer.Write(cmts_bytes)
// 	buffer.Write(h0_bytes)
// 	buffer.Write(hN_bytes)
// 	buffer.Write(N_bytes)
// 	buffer.Write(sig_v)
// 	buffer.Write(sig_r)
// 	buffer.Write(sig_s)

// 	input := buffer.Bytes()
// 	args.Input = (*hexutil.Bytes)(&input)

// 	// Assemble the transaction
// 	*(*uint64)(args.Gas) = 900000
// 	tx := args.toTransaction()
// 	tx.SetTxCode(types.ClaimTx)
// 	tx.SetPrice(big.NewInt(1))
// 	tx.SetValue(big.NewInt(0))
// 	tx.SetZKValue(args.Value.ToInt().Uint64())
// 	tx.SetZKCMTS(CMTs)

// 	//randAddr := zktx.NewRandomAddress()
// 	tx.SetZKAddress(&args.From)

// 	zkProof := zktx.GenClaimProof(args.Value.ToInt().Uint64(), SNs, newRs, CMTs)
// 	if string(zkProof[0:10]) == "0000000000" {
// 		return common.Hash{}, errors.New("can't generate proof")
// 	}
// 	tx.SetZKProof(zkProof) //proof tbd

// 	zktx.SNS = &zktx.Sequence{SN: SNs, CMT: CMTs, Random: newRs, Value: args.Value.ToInt().Uint64()}

// 	// var chainID *big.Int
// 	// if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
// 	// 	chainID = config.ChainID
// 	// }

// 	//signed, err := wallet.SignTx(account, tx, chainID)
// 	if err != nil {
// 		return common.Hash{}, err
// 	}

// 	hash, err := submitTransaction(ctx, s.b, tx)

// 	if err == nil {
// 		zktx.Stage = zktx.Claim
// 		SNS := zktx.SequenceS{*zktx.SequenceNumber, *zktx.SequenceNumberAfter, zktx.SNS, nil, nil, zktx.Claim}
// 		SNSBytes, err := rlp.EncodeToBytes(SNS)
// 		if err != nil {
// 			fmt.Println("encode sns error")
// 			return common.Hash{}, nil
// 		}
// 		SNSString := hex.EncodeToString(SNSBytes)
// 		zktx.SNfile.Seek(0, 0) //write in the first line of the file
// 		wt := bufio.NewWriter(zktx.SNfile)

// 		wt.WriteString(SNSString)
// 		wt.WriteString("\n") //write a line
// 		wt.Flush()
// 	}
// 	return hash, err

// }

// SendRefundTransaction creates a Refund transaction for the given argument.
// func (s *PublicTransactionPoolAPI) SendRefundTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) { //tbd

// 	if zktx.SNfile == nil {
// 		fmt.Println("SNfile does not exist")
// 		return common.Hash{}, nil
// 	}

// 	if zktx.SequenceNumber == nil || zktx.SequenceNumberAfter == nil {
// 		fmt.Println("SequenceNumber or SequenceNumberAfter nil")
// 		return common.Hash{}, nil
// 	}
// 	state, _, err := s.b.StateAndHeaderByNumber(ctx, rpc.LatestBlockNumber)
// 	if state == nil || err != nil {
// 		return common.Hash{}, err
// 	}

// 	//check whether sn can be used
// 	exist := state.Exist(common.BytesToAddress(zktx.SequenceNumberAfter.SN.Bytes()))

// 	if exist == true && *(zktx.SequenceNumberAfter.SN) != *(zktx.InitializeSN().SN) {
// 		fmt.Println("sn is lost")
// 		return common.Hash{}, nil
// 	}

// 	//check whether last tx is processed successfully
// 	exist = state.Exist(common.BytesToAddress(zktx.SequenceNumber.SN.Bytes()))

// 	if exist == false && *(zktx.SequenceNumber.SN) != *(zktx.InitializeSN().SN) { //if last transaction is not processed successfully, the corresponding SN is not in the database,and we use SN before  last unprocessed transaction

// 		zktx.SequenceNumberAfter = zktx.SequenceNumber
// 	}

// 	if args.Nonce == nil {
// 		// Hold the addresse's mutex around signing to prevent concurrent assignment of
// 		// the same nonce to multiple accounts.
// 		s.nonceLock.LockAddr(args.From)
// 		defer s.nonceLock.UnlockAddr(args.From)
// 	}
// 	// Set some sanity defaults and terminate on failure
// 	if err := args.setDefaults(ctx, s.b); err != nil {
// 		return common.Hash{}, err
// 	}

// 	values := args.Value

// 	SNs := zktx.NewRandomHash()
// 	newRs := zktx.NewRandomHash()
// 	CMTs := zktx.GenCMT(args.Value.ToInt().Uint64(), SNs.Bytes(), newRs.Bytes()) //生成cmts

// 	//turn params to input of contract
// 	func_name := "Refund(uint256,bytes32)"
// 	func_keccak256 := crypto.Keccak256([]byte(func_name))[:4]
// 	value_bytes := common.HexToHash(values.String()).Bytes()
// 	cmts_bytes := CMTs.Bytes()

// 	var buffer bytes.Buffer
// 	buffer.Write(func_keccak256)
// 	buffer.Write(value_bytes)
// 	buffer.Write(cmts_bytes)

// 	input := buffer.Bytes()
// 	args.Input = (*hexutil.Bytes)(&input)

// 	// Assemble the transaction and sign with the wallet
// 	*(*uint64)(args.Gas) = 100000
// 	tx := args.toTransaction()
// 	tx.SetTxCode(types.RefundTx)
// 	tx.SetPrice(big.NewInt(1))
// 	tx.SetValue(big.NewInt(0))
// 	tx.SetZKValue(args.Value.ToInt().Uint64())
// 	tx.SetZKCMTS(CMTs)

// 	//randAddr := zktx.NewRandomAddress()
// 	tx.SetZKAddress(&args.From)

// 	zkProof := zktx.GenClaimProof(args.Value.ToInt().Uint64(), SNs, newRs, CMTs)
// 	if string(zkProof[0:10]) == "0000000000" {
// 		return common.Hash{}, errors.New("can't generate proof")
// 	}
// 	tx.SetZKProof(zkProof) //proof tbd

// 	zktx.SNS = &zktx.Sequence{SN: SNs, CMT: CMTs, Random: newRs, Value: args.Value.ToInt().Uint64()}

// 	// var chainID *big.Int
// 	// if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
// 	// 	chainID = config.ChainID
// 	// }

// 	//signed, err := wallet.SignTx(account, tx, chainID)
// 	if err != nil {
// 		return common.Hash{}, err
// 	}

// 	hash, err := submitTransaction(ctx, s.b, tx)

// 	if err == nil {
// 		zktx.Stage = zktx.Claim
// 		SNS := zktx.SequenceS{*zktx.SequenceNumber, *zktx.SequenceNumberAfter, zktx.SNS, nil, nil, zktx.Claim}
// 		SNSBytes, err := rlp.EncodeToBytes(SNS)
// 		if err != nil {
// 			fmt.Println("encode sns error")
// 			return common.Hash{}, nil
// 		}
// 		SNSString := hex.EncodeToString(SNSBytes)
// 		zktx.SNfile.Seek(0, 0) //write in the first line of the file
// 		wt := bufio.NewWriter(zktx.SNfile)

// 		wt.WriteString(SNSString)
// 		wt.WriteString("\n") //write a line
// 		wt.Flush()
// 	}
// 	return hash, err

// }

// SendDepositsgTransaction creates a Deposit transaction for the given argument, sign it and submit it to the
// transaction pool.
// func (s *PublicTransactionPoolAPI) SendDepositsgTransaction(ctx context.Context, args SendTxArgs) (common.Hash, error) {

// 	if zktx.SNfile == nil {
// 		fmt.Println("SNfile does not exist")
// 		return common.Hash{}, nil
// 	}
// 	if zktx.SequenceNumber == nil || zktx.SequenceNumberAfter == nil {
// 		fmt.Println("SequenceNumber or SequenceNumberAfter nil")
// 		return common.Hash{}, nil
// 	}
// 	state, _, err := s.b.StateAndHeaderByNumber(ctx, rpc.LatestBlockNumber)
// 	if state == nil || err != nil {
// 		return common.Hash{}, err
// 	}

// 	//check whether sn can be used
// 	exist := state.Exist(common.BytesToAddress(zktx.SequenceNumberAfter.SN.Bytes()))

// 	if exist == true && *(zktx.SequenceNumberAfter.SN) != *(zktx.InitializeSN().SN) {
// 		fmt.Println("sn is lost")
// 		return common.Hash{}, nil
// 	}

// 	//check whether last tx is processed successfully
// 	exist = state.Exist(common.BytesToAddress(zktx.SequenceNumber.SN.Bytes()))

// 	if exist == false && *(zktx.SequenceNumber.SN) != *(zktx.InitializeSN().SN) { //if last transaction is not processed successfully, the corresponding SN is not in the database,and we use SN before  last unprocessed transaction
// 		// if zktx.Stage == zktx.Update {
// 		// 	fmt.Println("last transaction is update,but it is not well processed,please send updateTx firstly")
// 		// 	return common.Hash{}, nil
// 		// }
// 		zktx.SequenceNumberAfter = zktx.SequenceNumber
// 	}

// 	// Look up the wallet containing the requested signer
// 	account := accounts.Account{Address: args.From}
// 	wallet, err := s.b.AccountManager().Find(account)

// 	if err != nil {
// 		return common.Hash{}, err
// 	}

// 	if args.Nonce == nil {
// 		// Hold the addresse's mutex around signing to prevent concurrent assignment ofnil
// 		// the same nonce to multiple accounts.
// 		s.nonceLock.LockAddr(args.From)
// 		defer s.nonceLock.UnlockAddr(args.From)
// 	}
// 	//Take cmts from contract
// 	txSend := s.GetTransactionByHash2(ctx, args.TxHash)
// 	if txSend == nil {
// 		return common.Hash{}, errors.New("there does not exist a transaction" + args.TxHash.String())
// 	}
// 	contractAddr := args.To
// 	sp := NewPublicBlockChainAPI(s.b)
// 	var cmt hexutil.Bytes

// 	//Reset the contract state
// 	if txSend.Code() == types.ClaimTx {
// 		// func_name := "Claimreset()"
// 		// func_keccak256 := crypto.Keccak256([]byte(func_name))[:4]
// 		// args.Input = (*hexutil.Bytes)(&func_keccak256)
// 		cmt, _ = sp.GetStorageAt(ctx, *contractAddr, "0x0", rpc.LatestBlockNumber)
// 	}
// 	if txSend.Code() == types.RefundTx {
// 		// func_name := "Refundreset()"
// 		// func_keccak256 := crypto.Keccak256([]byte(func_name))[:4]
// 		// args.Input = (*hexutil.Bytes)(&func_keccak256)
// 		cmt, _ = sp.GetStorageAt(ctx, *contractAddr, "0x1", rpc.LatestBlockNumber)
// 	}
// 	fmt.Println(cmt.String())
// 	if cmt.String() != txSend.ZKCMTS().String() {
// 		return common.Hash{}, errors.New("Wrong cmtS!")
// 	}

// 	// Set some sanity defaults and terminate on failure
// 	if err := args.setDefaults(ctx, s.b); err != nil {
// 		return common.Hash{}, err
// 	}
// 	// Assemble the transaction and sign with the wallet
// 	// *(*uint64)(args.Gas) = 2000000
// 	tx := args.toTransaction()
// 	tx.SetTxCode(types.DepositsgTx)
// 	tx.SetPrice(big.NewInt(0))
// 	tx.SetValue(big.NewInt(0))
// 	tx.SetZKAddress(&args.From)

// 	//Generate cmt array for Merkle tree
// 	RPCtx := s.GetTransactionByHash(ctx, args.TxHash)
// 	if RPCtx == nil {
// 		return common.Hash{}, errors.New("there does not exist a transaction" + args.TxHash.String())
// 	} else if RPCtx.Code != types.ClaimTxStr && RPCtx.Code != types.RefundTxStr {
// 		return common.Hash{}, errors.New("Wrong transaction, the inputed transaction is not a Claim/Refund transaction!" + args.TxHash.String())
// 	}

// 	cmtBlockNumber := (*big.Int)(RPCtx.BlockNumber)
// 	var cmtBlockNumbers []uint64
// 	var CMTSForMerkle []*common.Hash
// 	BlockToCmt := make(map[uint64][]*common.Hash)

// 	block, err := s.b.BlockByNumber(ctx, rpc.LatestBlockNumber)
// 	if block == nil {
// 		return common.Hash{}, err
// 	}

// 	cmtBlockNumbers = append(cmtBlockNumbers, cmtBlockNumber.Uint64())
// 	block2, err := s.b.BlockByNumber(ctx, rpc.BlockNumber(cmtBlockNumber.Uint64()))
// 	BlockToCmt[cmtBlockNumber.Uint64()] = block2.CMTS()

// 	// latest header should always be available
// 	latestBlockNumber := block.NumberU64()
// 	count := len(block2.CMTS())
// loop:
// 	for count < zktx.ZKCMTNODES {
// 		if len(cmtBlockNumbers) > int(latestBlockNumber) {
// 			return common.Hash{}, errors.New("insufficient cmts for merkle tree")
// 		}
// 		blockNum := uint64(rand.Int63n(int64(latestBlockNumber + 1)))
// 		for i, _ := range cmtBlockNumbers {
// 			if cmtBlockNumbers[i] == blockNum {
// 				goto loop
// 			}
// 		}
// 		block, err = s.b.BlockByNumber(ctx, rpc.BlockNumber(blockNum))
// 		if block == nil {
// 			return common.Hash{}, err
// 		}
// 		cmts := block.CMTS()
// 		BlockToCmt[blockNum] = cmts
// 		//	CMTSForMerkle = append(CMTSForMerkle, cmts...)
// 		cmtBlockNumbers = append(cmtBlockNumbers, blockNum)
// 		count += len(cmts)
// 	}

// 	merkle.QuickSortUint64(cmtBlockNumbers)

// 	for i, _ := range cmtBlockNumbers {
// 		index := cmtBlockNumbers[i]
// 		CMTSForMerkle = append(CMTSForMerkle, BlockToCmt[index]...)
// 	}

// 	RTcmt := zktx.GenRT(CMTSForMerkle)
// 	tx.SetRTcmt(RTcmt)

// 	tx.SetCMTBlocks(cmtBlockNumbers)

// 	//cmts from local
// 	selfCmts := zktx.SNS
// 	valueS := selfCmts.Value
// 	sns := selfCmts.SN
// 	rs := selfCmts.Random
// 	tx.SetZKSNS(sns)

// 	//trusted cmts from contract
// 	cmtS := common.BytesToHash(cmt)

// 	if valueS <= 0 {
// 		return common.Hash{}, errors.New("transfer amount must be larger than 0")
// 	}

// 	SNb := zktx.SequenceNumberAfter
// 	tx.SetZKSN(SNb.SN)

// 	newSN := zktx.NewRandomHash()
// 	newRandom := zktx.NewRandomHash()
// 	newValue := SNb.Value + valueS
// 	newCMTB := zktx.GenCMT(newValue, newSN.Bytes(), newRandom.Bytes())
// 	tx.SetZKCMT(newCMTB)

// 	zkProof := zktx.GenDepositsgProof(&cmtS, valueS, sns, rs, SNb.Value, SNb.Random, newSN, newRandom, RTcmt.Bytes(), SNb.CMT, SNb.SN, newCMTB, CMTSForMerkle)
// 	if string(zkProof[0:10]) == "0000000000" {
// 		return common.Hash{}, errors.New("can't generate proof")
// 	}
// 	tx.SetZKProof(zkProof) //proof tbd

// 	// address := crypto.PubkeyToAddress(randomKeyB.PublicKey)
// 	// exist = state.Exist(address)
// 	// if exist == true {
// 	// 	fmt.Println("pubkeyb cat not be used for a second time")
// 	// 	return common.Hash{}, nil
// 	// }
// 	//fmt.Println("randomKeyB:", randomKeyB.D.BitLen())

// 	var chainID *big.Int
// 	if config := s.b.ChainConfig(); config.IsEIP155(s.b.CurrentBlock().Number()) {
// 		chainID = config.ChainID
// 	}

// 	signed, err := wallet.SignTx(account, tx, chainID)
// 	if err != nil {
// 		return common.Hash{}, err
// 	}

// 	hash, err := submitTransaction(ctx, s.b, signed)
// 	if err == nil {
// 		zktx.SequenceNumber = zktx.SequenceNumberAfter
// 		zktx.SequenceNumberAfter = &zktx.Sequence{SN: newSN, CMT: newCMTB, Random: newRandom, Value: newValue}
// 		zktx.Stage = zktx.Deposit
// 		SNS := zktx.SequenceS{*zktx.SequenceNumber, *zktx.SequenceNumberAfter, zktx.SNS, nil, nil, zktx.Deposit}
// 		SNSBytes, err := rlp.EncodeToBytes(SNS)
// 		if err != nil {
// 			fmt.Println("encode sns error")
// 			return common.Hash{}, nil
// 		}
// 		SNSString := hex.EncodeToString(SNSBytes)
// 		zktx.SNfile.Seek(0, 0) //write in the first line of the file
// 		wt := bufio.NewWriter(zktx.SNfile)

// 		wt.WriteString(SNSString)
// 		wt.WriteString("\n") //write a line
// 		wt.Flush()
// 	}
// 	return hash, err
// }

//=============================================================================

// SendRawTransaction will add the signed transaction to the transaction pool.
// The sender is responsible for signing the transaction and using the correct nonce.
func (s *PublicTransactionPoolAPI) SendRawTransaction(ctx context.Context, encodedTx hexutil.Bytes) (common.Hash, error) {
	tx := new(types.Transaction)
	if err := rlp.DecodeBytes(encodedTx, tx); err != nil {
		return common.Hash{}, err
	}
	return submitTransaction(ctx, s.b, tx)
}

// Sign calculates an ECDSA signature for:
// keccack256("\x19Ethereum Signed Message:\n" + len(message) + message).
//
// Note, the produced signature conforms to the secp256k1 curve R, S and V values,
// where the V value will be 27 or 28 for legacy reasons.
//
// The account associated with addr must be unlocked.
//
// https://github.com/ethereum/wiki/wiki/JSON-RPC#eth_sign
func (s *PublicTransactionPoolAPI) Sign(addr common.Address, data hexutil.Bytes) (hexutil.Bytes, error) {
	// Look up the wallet containing the requested signer
	account := accounts.Account{Address: addr}

	wallet, err := s.b.AccountManager().Find(account)
	if err != nil {
		return nil, err
	}
	// Sign the requested hash with the wallet
	signature, err := wallet.SignHash(account, signHash(data))
	if err == nil {
		signature[64] += 27 // Transform V from 0/1 to 27/28 according to the yellow paper
	}
	return signature, err
}

// SignTransactionResult represents a RLP encoded signed transaction.
type SignTransactionResult struct {
	Raw hexutil.Bytes      `json:"raw"`
	Tx  *types.Transaction `json:"tx"`
}

// SignTransaction will sign the given transaction with the from account.
// The node needs to have the private key of the account corresponding with
// the given from address and it needs to be unlocked.
func (s *PublicTransactionPoolAPI) SignTransaction(ctx context.Context, args SendTxArgs) (*SignTransactionResult, error) {
	if args.Gas == nil {
		return nil, fmt.Errorf("gas not specified")
	}
	if args.GasPrice == nil {
		return nil, fmt.Errorf("gasPrice not specified")
	}
	if args.Nonce == nil {
		return nil, fmt.Errorf("nonce not specified")
	}
	if err := args.setDefaults(ctx, s.b); err != nil {
		return nil, err
	}
	tx, err := s.sign(args.From, args.toTransaction())
	if err != nil {
		return nil, err
	}
	data, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return nil, err
	}
	return &SignTransactionResult{data, tx}, nil
}

// PendingTransactions returns the transactions that are in the transaction pool
// and have a from address that is one of the accounts this node manages.
func (s *PublicTransactionPoolAPI) PendingTransactions() ([]*RPCTransaction, error) {
	pending, err := s.b.GetPoolTransactions()
	if err != nil {
		return nil, err
	}
	accounts := make(map[common.Address]struct{})
	for _, wallet := range s.b.AccountManager().Wallets() {
		for _, account := range wallet.Accounts() {
			accounts[account.Address] = struct{}{}
		}
	}
	transactions := make([]*RPCTransaction, 0, len(pending))
	for _, tx := range pending {
		var signer types.Signer = types.HomesteadSigner{}
		if tx.Protected() {
			signer = types.NewEIP155Signer(tx.ChainId())
		}
		from, _ := types.Sender(signer, tx)
		if _, exists := accounts[from]; exists {
			transactions = append(transactions, newRPCPendingTransaction(tx))
		}
	}
	return transactions, nil
}

// Resend accepts an existing transaction and a new gas price and limit. It will remove
// the given transaction from the pool and reinsert it with the new gas price and limit.
func (s *PublicTransactionPoolAPI) Resend(ctx context.Context, sendArgs SendTxArgs, gasPrice *hexutil.Big, gasLimit *hexutil.Uint64) (common.Hash, error) {
	if sendArgs.Nonce == nil {
		return common.Hash{}, fmt.Errorf("missing transaction nonce in transaction spec")
	}
	if err := sendArgs.setDefaults(ctx, s.b); err != nil {
		return common.Hash{}, err
	}
	matchTx := sendArgs.toTransaction()
	pending, err := s.b.GetPoolTransactions()
	if err != nil {
		return common.Hash{}, err
	}

	for _, p := range pending {
		var signer types.Signer = types.HomesteadSigner{}
		if p.Protected() {
			signer = types.NewEIP155Signer(p.ChainId())
		}
		wantSigHash := signer.Hash(matchTx)

		if pFrom, err := types.Sender(signer, p); err == nil && pFrom == sendArgs.From && signer.Hash(p) == wantSigHash {
			// Match. Re-sign and send the transaction.
			if gasPrice != nil && (*big.Int)(gasPrice).Sign() != 0 {
				sendArgs.GasPrice = gasPrice
			}
			if gasLimit != nil && *gasLimit != 0 {
				sendArgs.Gas = gasLimit
			}
			signedTx, err := s.sign(sendArgs.From, sendArgs.toTransaction())
			if err != nil {
				return common.Hash{}, err
			}
			if err = s.b.SendTx(ctx, signedTx); err != nil {
				return common.Hash{}, err
			}
			return signedTx.Hash(), nil
		}
	}

	return common.Hash{}, fmt.Errorf("Transaction %#x not found", matchTx.Hash())
}

// PublicDebugAPI is the collection of Ethereum APIs exposed over the public
// debugging endpoint.
type PublicDebugAPI struct {
	b Backend
}

// NewPublicDebugAPI creates a new API definition for the public debug methods
// of the Ethereum service.
func NewPublicDebugAPI(b Backend) *PublicDebugAPI {
	return &PublicDebugAPI{b: b}
}

// GetBlockRlp retrieves the RLP encoded for of a single block.
func (api *PublicDebugAPI) GetBlockRlp(ctx context.Context, number uint64) (string, error) {
	block, _ := api.b.BlockByNumber(ctx, rpc.BlockNumber(number))
	if block == nil {
		return "", fmt.Errorf("block #%d not found", number)
	}
	encoded, err := rlp.EncodeToBytes(block)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", encoded), nil
}

// PrintBlock retrieves a block and returns its pretty printed form.
func (api *PublicDebugAPI) PrintBlock(ctx context.Context, number uint64) (string, error) {
	block, _ := api.b.BlockByNumber(ctx, rpc.BlockNumber(number))
	if block == nil {
		return "", fmt.Errorf("block #%d not found", number)
	}
	return spew.Sdump(block), nil
}

// SeedHash retrieves the seed hash of a block.
func (api *PublicDebugAPI) SeedHash(ctx context.Context, number uint64) (string, error) {
	block, _ := api.b.BlockByNumber(ctx, rpc.BlockNumber(number))
	if block == nil {
		return "", fmt.Errorf("block #%d not found", number)
	}
	return fmt.Sprintf("0x%x", ethash.SeedHash(number)), nil
}

// PrivateDebugAPI is the collection of Ethereum APIs exposed over the private
// debugging endpoint.
type PrivateDebugAPI struct {
	b Backend
}

// NewPrivateDebugAPI creates a new API definition for the private debug methods
// of the Ethereum service.
func NewPrivateDebugAPI(b Backend) *PrivateDebugAPI {
	return &PrivateDebugAPI{b: b}
}

// ChaindbProperty returns leveldb properties of the chain database.
func (api *PrivateDebugAPI) ChaindbProperty(property string) (string, error) {
	ldb, ok := api.b.ChainDb().(interface {
		LDB() *leveldb.DB
	})
	if !ok {
		return "", fmt.Errorf("chaindbProperty does not work for memory databases")
	}
	if property == "" {
		property = "leveldb.stats"
	} else if !strings.HasPrefix(property, "leveldb.") {
		property = "leveldb." + property
	}
	return ldb.LDB().GetProperty(property)
}

func (api *PrivateDebugAPI) ChaindbCompact() error {
	ldb, ok := api.b.ChainDb().(interface {
		LDB() *leveldb.DB
	})
	if !ok {
		return fmt.Errorf("chaindbCompact does not work for memory databases")
	}
	for b := byte(0); b < 255; b++ {
		log.Info("Compacting chain database", "range", fmt.Sprintf("0x%0.2X-0x%0.2X", b, b+1))
		err := ldb.LDB().CompactRange(util.Range{Start: []byte{b}, Limit: []byte{b + 1}})
		if err != nil {
			log.Error("Database compaction failed", "err", err)
			return err
		}
	}
	return nil
}

// SetHead rewinds the head of the blockchain to a previous block.
func (api *PrivateDebugAPI) SetHead(number hexutil.Uint64) {
	api.b.SetHead(uint64(number))
}

// PublicNetAPI offers network related RPC methods
type PublicNetAPI struct {
	net            *p2p.Server
	networkVersion uint64
}

// NewPublicNetAPI creates a new net API instance.
func NewPublicNetAPI(net *p2p.Server, networkVersion uint64) *PublicNetAPI {
	return &PublicNetAPI{net, networkVersion}
}

// Listening returns an indication if the node is listening for network connections.
func (s *PublicNetAPI) Listening() bool {
	return true // always listening
}

// PeerCount returns the number of connected peers
func (s *PublicNetAPI) PeerCount() hexutil.Uint {
	return hexutil.Uint(s.net.PeerCount())
}

// Version returns the current ethereum protocol version.
func (s *PublicNetAPI) Version() string {
	return fmt.Sprintf("%d", s.networkVersion)
}
