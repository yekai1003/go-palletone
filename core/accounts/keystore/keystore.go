// Copyright 2017 The go-ethereum Authors
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

// Package keystore implements encrypted storage of secp256k1 private keys.
//
// Keys are stored as encrypted JSON files according to the Web3 Secret Storage specification.
// See https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition for more information.
package keystore

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"errors"
	"fmt"
	"github.com/palletone/go-palletone/common"
	"github.com/palletone/go-palletone/common/crypto"
	"github.com/palletone/go-palletone/common/event"
	"github.com/palletone/go-palletone/common/log"
	"github.com/palletone/go-palletone/common/math"
	"github.com/palletone/go-palletone/common/util"
	"github.com/palletone/go-palletone/core/accounts"
	"github.com/palletone/go-palletone/dag/modules"
	"github.com/tjfoc/gmsm/sm2"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"time"
)

var (
	ErrLocked  = accounts.NewAuthNeededError("password or unlock")
	ErrNoMatch = errors.New("no key for given address or file")
	ErrDecrypt = errors.New("could not decrypt key with given passphrase")
)

// KeyStoreType is the reflect type of a keystore backend.
var KeyStoreType = reflect.TypeOf(&KeyStore{})

var KeyStoreTypeSm2 = reflect.TypeOf(&Sm2KeyStore{})

// KeyStoreScheme is the protocol scheme prefixing account and wallet URLs.
var KeyStoreScheme = "keystore"

// Maximum time between wallet refreshes (if filesystem notifications don't work).
const walletRefreshCycle = 3 * time.Second

// KeyStore manages a key storage directory on disk.
type KeyStore struct {
	storage  keyStore                     // Storage backend, might be cleartext or encrypted
	cache    *accountCache                // In-memory account cache over the filesystem storage
	changes  chan struct{}                // Channel receiving change notifications from the cache
	unlocked map[common.Address]*unlocked // Currently unlocked account (decrypted private keys)

	wallets     []accounts.Wallet       // Wallet wrappers around the individual key files
	updateFeed  event.Feed              // Event feed to notify wallet additions/removals
	updateScope event.SubscriptionScope // Subscription scope tracking current live listeners
	updating    bool                    // Whether the event notification loop is running

	mu sync.RWMutex
}

type unlocked struct {
	*Key
	abort chan struct{}
}

// KeyStore manages a key storage directory on disk.
type Sm2KeyStore struct {
	storage     sm2keyStore                     // Storage backend, might be cleartext or encrypted
	cache       *accountCache                   // In-memory account cache over the filesystem storage
	changes     chan struct{}                   // Channel receiving change notifications from the cache
	sm2unlocked map[common.Address]*sm2unlocked // Currently unlocked account (decrypted private keys)

	wallets     []accounts.Wallet       // Wallet wrappers around the individual key files
	updateFeed  event.Feed              // Event feed to notify wallet additions/removals
	updateScope event.SubscriptionScope // Subscription scope tracking current live listeners
	updating    bool                    // Whether the event notification loop is running

	mu sync.RWMutex
}

type sm2unlocked struct {
	Key   *sm2.PrivateKey
	abort chan struct{}
}

// NewKeyStore creates a keystore for the given directory.
func NewKeyStore(keydir string, scryptN, scryptP int) *KeyStore {
	keydir, _ = filepath.Abs(keydir)
	ks := &KeyStore{storage: &keyStorePassphrase{keydir, scryptN, scryptP}}
	ks.init(keydir)
	return ks
}
// NewKeyStore creates a keystore for the given directory.
func NewKeyStoreSm2(keydir string, scryptN, scryptP int) *Sm2KeyStore {
	keydir, _ = filepath.Abs(keydir)
	ks := &Sm2KeyStore{storage: &keyStorePassphrase{keydir, scryptN, scryptP}}
	ks.init(keydir)
	return ks
}
// NewPlaintextKeyStore creates a keystore for the given directory.
// Deprecated: Use NewKeyStore.
func NewPlaintextKeyStore(keydir string) *KeyStore {
	keydir, _ = filepath.Abs(keydir)
	ks := &KeyStore{storage: &keyStorePlain{keydir}}
	ks.init(keydir)
	return ks
}

func (ks *KeyStore) init(keydir string) {
	// Lock the mutex since the account cache might call back with events
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Initialize the set of unlocked keys and the account cache
	ks.unlocked = make(map[common.Address]*unlocked)
	ks.cache, ks.changes = newAccountCache(keydir)

	// TODO: In order for this finalizer to work, there must be no references
	// to ks. addressCache doesn't keep a reference but unlocked keys do,
	// so the finalizer will not trigger until all timed unlocks have expired.
	runtime.SetFinalizer(ks, func(m *KeyStore) {
		m.cache.close()
	})
	// Create the initial list of wallets from the cache
	accs := ks.cache.accounts()
	ks.wallets = make([]accounts.Wallet, len(accs))
	for i := 0; i < len(accs); i++ {
		ks.wallets[i] = &keystoreWallet{account: accs[i], keystore: ks}
	}
}
func (ks *Sm2KeyStore) init(keydir string) {
	// Lock the mutex since the account cache might call back with events
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Initialize the set of unlocked keys and the account cache
	ks.sm2unlocked = make(map[common.Address]*sm2unlocked)
	ks.cache, ks.changes = newAccountCache(keydir)
	// TODO: In order for this finalizer to work, there must be no references
	// to ks. addressCache doesn't keep a reference but unlocked keys do,
	// so the finalizer will not trigger until all timed unlocks have expired.
	runtime.SetFinalizer(ks, func(m *Sm2KeyStore) {
		m.cache.close()
	})
	// Create the initial list of wallets from the cache
	accs := ks.cache.accounts()
	ks.wallets = make([]accounts.Wallet, len(accs))
	for i := 0; i < len(accs); i++ {
		ks.wallets[i] = &sm2keystoreWallet{account: accs[i], keystore: ks}
	}
}
// Wallets implements accounts.Backend, returning all single-key wallets from the
// keystore directory.
func (ks *KeyStore) Wallets() []accounts.Wallet {
	// Make sure the list of wallets is in sync with the account cache
	ks.refreshWallets()

	ks.mu.RLock()
	defer ks.mu.RUnlock()

	cpy := make([]accounts.Wallet, len(ks.wallets))
	copy(cpy, ks.wallets)
	return cpy
}
func (ks *Sm2KeyStore) Wallets() []accounts.Wallet {
	// Make sure the list of wallets is in sync with the account cache
	ks.refreshWallets()

	ks.mu.RLock()
	defer ks.mu.RUnlock()

	cpy := make([]accounts.Wallet, len(ks.wallets))
	copy(cpy, ks.wallets)
	return cpy
}

// refreshWallets retrieves the current account list and based on that does any
// necessary wallet refreshes.
func (ks *KeyStore) refreshWallets() {
	// Retrieve the current list of accounts
	ks.mu.Lock()
	accs := ks.cache.accounts()

	// Transform the current list of wallets into the new one
	wallets := make([]accounts.Wallet, 0, len(accs))
	events := []accounts.WalletEvent{}

	for _, account := range accs {
		// Drop wallets while they were in front of the next account
		for len(ks.wallets) > 0 && ks.wallets[0].URL().Cmp(account.URL) < 0 {
			events = append(events, accounts.WalletEvent{Wallet: ks.wallets[0], Kind: accounts.WalletDropped})
			ks.wallets = ks.wallets[1:]
		}
		// If there are no more wallets or the account is before the next, wrap new wallet
		if len(ks.wallets) == 0 || ks.wallets[0].URL().Cmp(account.URL) > 0 {
			wallet := &keystoreWallet{account: account, keystore: ks}

			events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletArrived})
			wallets = append(wallets, wallet)
			continue
		}
		// If the account is the same as the first wallet, keep it
		if ks.wallets[0].Accounts()[0] == account {
			wallets = append(wallets, ks.wallets[0])
			ks.wallets = ks.wallets[1:]
			continue
		}
	}
	// Drop any leftover wallets and set the new batch
	for _, wallet := range ks.wallets {
		events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletDropped})
	}
	ks.wallets = wallets
	ks.mu.Unlock()

	// Fire all wallet events and return
	for _, event := range events {
		ks.updateFeed.Send(event)
	}
}

// refreshWallets retrieves the current account list and based on that does any
// necessary wallet refreshes.
func (ks *Sm2KeyStore) refreshWallets() {
	// Retrieve the current list of accounts
	ks.mu.Lock()
	accs := ks.cache.accounts()

	// Transform the current list of wallets into the new one
	wallets := make([]accounts.Wallet, 0, len(accs))
	events := []accounts.WalletEvent{}

	for _, account := range accs {
		// Drop wallets while they were in front of the next account
		for len(ks.wallets) > 0 && ks.wallets[0].URL().Cmp(account.URL) < 0 {
			events = append(events, accounts.WalletEvent{Wallet: ks.wallets[0], Kind: accounts.WalletDropped})
			ks.wallets = ks.wallets[1:]
		}
		// If there are no more wallets or the account is before the next, wrap new wallet
		if len(ks.wallets) == 0 || ks.wallets[0].URL().Cmp(account.URL) > 0 {
			wallet := &sm2keystoreWallet{account: account, keystore: ks}

			events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletArrived})
			wallets = append(wallets, wallet)
			continue
		}
		// If the account is the same as the first wallet, keep it
		if ks.wallets[0].Accounts()[0] == account {
			wallets = append(wallets, ks.wallets[0])
			ks.wallets = ks.wallets[1:]
			continue
		}
	}
	// Drop any leftover wallets and set the new batch
	for _, wallet := range ks.wallets {
		events = append(events, accounts.WalletEvent{Wallet: wallet, Kind: accounts.WalletDropped})
	}
	ks.wallets = wallets
	ks.mu.Unlock()

	// Fire all wallet events and return
	for _, event := range events {
		ks.updateFeed.Send(event)
	}
}

// Subscribe implements accounts.Backend, creating an async subscription to
// receive notifications on the addition or removal of keystore wallets.
func (ks *KeyStore) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	// We need the mutex to reliably start/stop the update loop
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Subscribe the caller and track the subscriber count
	sub := ks.updateScope.Track(ks.updateFeed.Subscribe(sink))

	// Subscribers require an active notification loop, start it
	if !ks.updating {
		ks.updating = true
		go ks.updater()
	}
	return sub
}

// Subscribe implements accounts.Backend, creating an async subscription to
// receive notifications on the addition or removal of keystore wallets.
func (ks *Sm2KeyStore) Subscribe(sink chan<- accounts.WalletEvent) event.Subscription {
	// We need the mutex to reliably start/stop the update loop
	ks.mu.Lock()
	defer ks.mu.Unlock()

	// Subscribe the caller and track the subscriber count
	sub := ks.updateScope.Track(ks.updateFeed.Subscribe(sink))

	// Subscribers require an active notification loop, start it
	if !ks.updating {
		ks.updating = true
		go ks.updater()
	}
	return sub
}

// updater is responsible for maintaining an up-to-date list of wallets stored in
// the keystore, and for firing wallet addition/removal events. It listens for
// account change events from the underlying account cache, and also periodically
// forces a manual refresh (only triggers for systems where the filesystem notifier
// is not running).
func (ks *KeyStore) updater() {
	for {
		// Wait for an account update or a refresh timeout
		select {
		case <-ks.changes:
		case <-time.After(walletRefreshCycle):
		}
		// Run the wallet refresher
		ks.refreshWallets()

		// If all our subscribers left, stop the updater
		ks.mu.Lock()
		if ks.updateScope.Count() == 0 {
			ks.updating = false
			ks.mu.Unlock()
			return
		}
		ks.mu.Unlock()
	}
}

func (ks *Sm2KeyStore) updater() {
	for {
		// Wait for an account update or a refresh timeout
		select {
		case <-ks.changes:
		case <-time.After(walletRefreshCycle):
		}
		// Run the wallet refresher
		ks.refreshWallets()

		// If all our subscribers left, stop the updater
		ks.mu.Lock()
		if ks.updateScope.Count() == 0 {
			ks.updating = false
			ks.mu.Unlock()
			return
		}
		ks.mu.Unlock()
	}
}

// HasAddress reports whether a key with the given address is present.
func (ks *KeyStore) HasAddress(addr common.Address) bool {
	return ks.cache.hasAddress(addr)
}

// HasAddress reports whether a key with the given address is present.
func (ks *Sm2KeyStore) HasAddress(addr common.Address) bool {
	return ks.cache.hasAddress(addr)
}

// Accounts returns all key files present in the directory.
func (ks *KeyStore) Accounts() []accounts.Account {
	return ks.cache.accounts()
}

// Accounts returns all key files present in the directory.
func (ks *Sm2KeyStore) Accounts() []accounts.Account {
	return ks.cache.accounts()
}

// Delete deletes the key matched by account if the passphrase is correct.
// If the account contains no filename, the address must match a unique key.
func (ks *KeyStore) Delete(a accounts.Account, passphrase string) error {
	// Decrypting the key isn't really necessary, but we do
	// it anyway to check the password and zero out the key
	// immediately afterwards.
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if key != nil {
		ZeroKey(key.PrivateKey)
	}
	if err != nil {
		return err
	}
	// The order is crucial here. The key is dropped from the
	// cache after the file is gone so that a reload happening in
	// between won't insert it into the cache again.
	err = os.Remove(a.URL.Path)
	if err == nil {
		ks.cache.delete(a)
		ks.refreshWallets()
	}
	return err
}
func (ks *Sm2KeyStore) Delete(a accounts.Account, passphrase string) error {
	// Decrypting the key isn't really necessary, but we do
	// it anyway to check the password and zero out the key
	// immediately afterwards.
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if key != nil {
		//ZeroKey(key.PrivateKey)
	}
	if err != nil {
		return err
	}
	// The order is crucial here. The key is dropped from the
	// cache after the file is gone so that a reload happening in
	// between won't insert it into the cache again.
	err = os.Remove(a.URL.Path)
	if err == nil {
		ks.cache.delete(a)
		ks.refreshWallets()
	}
	return err
}

// SignHash calculates a ECDSA signature for the given hash. The produced
// signature is in the [R || S || V] format where V is 0 or 1.
func (ks *KeyStore) SignHash(addr common.Address, hash []byte) ([]byte, error) {
	// Look up the key to sign with and abort if it cannot be found
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	unlockedKey, found := ks.unlocked[addr]
	if !found {
		return nil, ErrLocked
	}
	// Sign the hash using plain ECDSA operations
	return crypto.Sign(hash, unlockedKey.PrivateKey)
}

// SignHash calculates a ECDSA signature for the given hash. The produced
// signature is in the [R || S || V] format where V is 0 or 1.
func (ks *Sm2KeyStore) SignHash(addr common.Address, hash []byte) ([]byte, error) {
	// Look up the key to sign with and abort if it cannot be found
	ks.mu.RLock()
	defer ks.mu.RUnlock()

	unlockedKey, found := ks.sm2unlocked[addr]
	if !found {
		return nil, ErrLocked
	}
	unlockedKey = unlockedKey
	// Sign the hash using plain ECDSA operations
	return nil, ErrLocked
}

// SignTx signs the given transaction with the requested account.
func (ks *KeyStore) SignTx(a accounts.Account, tx *modules.Transaction, chainID *big.Int) (*modules.Transaction, error) {
	//R, S, V, err := ks.SigTX(tx, a.Address)
	//if err != nil {
	//	return nil, err
	//}
	//// publicKey, err1 := ks.GetPublicKey(a.Address)
	//// if err1 != nil {
	//// 	return nil, err1
	//// }
	//
	//if tx.From == nil {
	//	tx.From = new(modules.Authentifier)
	//}
	//tx.From.Address = a.Address.String()
	//tx.From.R = R
	//tx.From.S = S
	//tx.From.V = V
	return tx, nil
}

// SignTx signs the given transaction with the requested account.
func (ks *Sm2KeyStore) SignTx(a accounts.Account, tx *modules.Transaction, chainID *big.Int) (*modules.Transaction, error) {

	return tx, nil
}

// SignHashWithPassphrase signs hash if the private key matching the given address
// can be decrypted with the given passphrase. The produced signature is in the
// [R || S || V] format where V is 0 or 1.
func (ks *KeyStore) SignHashWithPassphrase(a accounts.Account, passphrase string, hash []byte) (signature []byte, err error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	defer ZeroKey(key.PrivateKey)
	return crypto.Sign(hash, key.PrivateKey)
}

func (ks *Sm2KeyStore) SignHashWithPassphrase(a accounts.Account, passphrase string, hash []byte) (signature []byte, err error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	key = key
	//defer ZeroKey(key.PrivateKey)
	return nil, err
}
func (ks *KeyStore) VerifySignatureWithPassphrase(a accounts.Account, passphrase string, hash []byte, signature []byte) (pass bool, err error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return false, err
	}
	defer ZeroKey(key.PrivateKey)
	pk := key.PrivateKey.PublicKey
	sig := signature[:len(signature)-1] // remove recovery id
	return crypto.VerifySignature(crypto.FromECDSAPub(&pk), hash, sig), nil
}

// SignTxWithPassphrase signs the transaction if the private key matching the
// given address can be decrypted with the given passphrase.
func (ks *KeyStore) SignTxWithPassphrase(a accounts.Account, passphrase string, tx *modules.Transaction, chainID *big.Int) (*modules.Transaction, error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	defer ZeroKey(key.PrivateKey)

	//authen, err := ks.SigTXWithPwd(tx, key.PrivateKey)
	//if err != nil {
	//	return nil, err
	//}
	// publicKey := crypto.FromECDSAPub(&key.PrivateKey.PublicKey)

	//if tx.From == nil {
	//	tx.From = new(modules.Authentifier)
	//}
	//
	//tx.From.Address = a.Address.String()
	//tx.From.R = authen[:32]
	//tx.From.S = authen[32:64]
	//tx.From.V = authen[64:]
	return tx, nil
}
func (ks *Sm2KeyStore) SignTxWithPassphrase(a accounts.Account, passphrase string, tx *modules.Transaction, chainID *big.Int) (*modules.Transaction, error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	key = key
	if err != nil {
		return nil, err
	}
	//defer ZeroKey(key.PrivateKey)
	return tx, nil
}

// Unlock unlocks the given account indefinitely.
func (ks *KeyStore) Unlock(a accounts.Account, passphrase string) error {
	return ks.TimedUnlock(a, passphrase, 0)
}

// Unlock unlocks the given account indefinitely.
func (ks *Sm2KeyStore) UnlockSm2(a accounts.Account, passphrase string) error {
	return ks.TimedUnlock(a, passphrase, 0)
}

// Lock removes the private key with the given address from memory.
func (ks *KeyStore) Lock(addr common.Address) error {
	ks.mu.Lock()
	if unl, found := ks.unlocked[addr]; found {
		ks.mu.Unlock()
		ks.expire(addr, unl, time.Duration(0)*time.Nanosecond)
	} else {
		ks.mu.Unlock()
	}
	return nil
}

// Lock removes the private key with the given address from memory.
func (ks *Sm2KeyStore) Lock(addr common.Address) error {
	ks.mu.Lock()
	if unl, found := ks.sm2unlocked[addr]; found {
		ks.mu.Unlock()
		ks.expire(addr, unl, time.Duration(0)*time.Nanosecond)
	} else {
		ks.mu.Unlock()
	}
	return nil
}

// TimedUnlock unlocks the given account with the passphrase. The account
// stays unlocked for the duration of timeout. A timeout of 0 unlocks the account
// until the program exits. The account must match a unique key file.
//
// If the account address is already unlocked for a duration, TimedUnlock extends or
// shortens the active unlock timeout. If the address was previously unlocked
// indefinitely the timeout is not altered.
func (ks *KeyStore) TimedUnlock(a accounts.Account, passphrase string, timeout time.Duration) error {
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()
	u, found := ks.unlocked[a.Address]
	if found {
		if u.abort == nil {
			// The address was unlocked indefinitely, so unlocking
			// it with a timeout would be confusing.
			ZeroKey(key.PrivateKey)
			return nil
		}
		// Terminate the expire goroutine and replace it below.
		close(u.abort)
	}
	if timeout > 0 {
		u = &unlocked{Key: key, abort: make(chan struct{})}
		go ks.expire(a.Address, u, timeout)
	} else {
		u = &unlocked{Key: key}
	}
	ks.unlocked[a.Address] = u
	return nil
}
func (ks *Sm2KeyStore) TimedUnlock(a accounts.Account, passphrase string, timeout time.Duration) error {
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}

	ks.mu.Lock()
	defer ks.mu.Unlock()
	u, found := ks.sm2unlocked[a.Address]
	if found {
		if u.abort == nil {
			// The address was unlocked indefinitely, so unlocking
			// it with a timeout would be confusing.
			//ZeroKey(key.PrivateKey)
			return nil
		}
		// Terminate the expire goroutine and replace it below.
		close(u.abort)
	}
	if timeout > 0 {
		u = &sm2unlocked{Key: key, abort: make(chan struct{})}
		go ks.expire(a.Address, u, timeout)
	} else {
		u = &sm2unlocked{Key: key}
	}
	ks.sm2unlocked[a.Address] = u
	return nil
}
func (ks *KeyStore) IsUnlock(addr common.Address) bool {
	_, found := ks.unlocked[addr]
	return found
}
func (ks *Sm2KeyStore) IsUnlock(addr common.Address) bool {
	_, found := ks.sm2unlocked[addr]

	return found
}

// Find resolves the given account into a unique entry in the keystore.
func (ks *KeyStore) Find(a accounts.Account) (accounts.Account, error) {
	ks.cache.maybeReload()
	ks.cache.mu.Lock()
	a, err := ks.cache.find(a)
	ks.cache.mu.Unlock()
	return a, err
}

// Find resolves the given account into a unique entry in the keystore.
func (ks *Sm2KeyStore) Find(a accounts.Account) (accounts.Account, error) {
	//report err when find
	ks.cache.maybeReload()
	ks.cache.mu.Lock()
	a, err := ks.cache.findsm2(a)
	ks.cache.mu.Unlock()
	return a, err
}
func (ks *KeyStore) getDecryptedKey(a accounts.Account, auth string) (accounts.Account, *Key, error) {
	a, err := ks.Find(a)
	if err != nil {
		return a, nil, err
	}
	key, err := ks.storage.GetKey(a.Address, a.URL.Path, auth)
	return a, key, err
}

func (ks *Sm2KeyStore) getDecryptedKey(a accounts.Account, auth string) (accounts.Account, *sm2.PrivateKey, error) {
	a, err := ks.Find(a)
	//b := accounts.Account{Address: a.Address, URL: accounts.URL{Scheme: KeyStoreScheme, Path: ks.JoinPath(keyFileName(a.Address))}}
	if err != nil {
		return a, nil, err
	}
	key, err := ks.storage.GetKeySm2(a.Address, a.URL.Path, auth)
	return a, key, err
}

func (ks *KeyStore) expire(addr common.Address, u *unlocked, timeout time.Duration) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-u.abort:
		// just quit
	case <-t.C:
		ks.mu.Lock()
		// only drop if it's still the same key instance that dropLater
		// was launched with. we can check that using pointer equality
		// because the map stores a new pointer every time the key is
		// unlocked.
		if ks.unlocked[addr] == u {
			ZeroKey(u.PrivateKey)
			delete(ks.unlocked, addr)
		}
		ks.mu.Unlock()
	}
}

func (ks *Sm2KeyStore) expire(addr common.Address, u *sm2unlocked, timeout time.Duration) {
	t := time.NewTimer(timeout)
	defer t.Stop()
	select {
	case <-u.abort:
		// just quit
	case <-t.C:
		ks.mu.Lock()
		// only drop if it's still the same key instance that dropLater
		// was launched with. we can check that using pointer equality
		// because the map stores a new pointer every time the key is
		// unlocked.
		if ks.sm2unlocked[addr] == u {
			//ZeroKey(u.PrivateKey)
			delete(ks.sm2unlocked, addr)
		}
		ks.mu.Unlock()
	}
}

// NewAccount generates a new key and stores it into the key directory,
// encrypting it with the passphrase.
func (ks *KeyStore) NewAccount(passphrase string) (accounts.Account, error) {
	_, account, err := storeNewKey(ks.storage, crand.Reader, passphrase)
	if err != nil {
		return accounts.Account{}, err
	}
	// Add the account to the cache immediately rather
	// than waiting for file system notifications to pick it up.
	ks.cache.add(account)
	ks.refreshWallets()
	return account, nil
}

// NewAccount generates a new key and stores it into the key directory,
// encrypting it with the passphrase.
func (ks *Sm2KeyStore) NewAccount(passphrase string) (accounts.Account, error) {
	_, account, err := sm2storeNewKey(ks.storage, crand.Reader, passphrase)
	if err != nil {
		return accounts.Account{}, err
	}
	// Add the account to the cache immediately rather
	// than waiting for file system notifications to pick it up.
	ks.cache.add(account)
	ks.refreshWallets()
	return account, nil
}

// Export exports as a JSON key, encrypted with newPassphrase.
func (ks *KeyStore) Export(a accounts.Account, passphrase, newPassphrase string) (keyJSON []byte, err error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	var N, P int
	if store, ok := ks.storage.(*keyStorePassphrase); ok {
		N, P = store.scryptN, store.scryptP
	} else {
		N, P = StandardScryptN, StandardScryptP
	}
	return EncryptKey(key, newPassphrase, N, P)
}

// Export exports as a JSON key, encrypted with newPassphrase.
func (ks *Sm2KeyStore) Export(a accounts.Account, passphrase, newPassphrase string) (keyJSON []byte, err error) {

	return nil, err
}
func (ks *KeyStore) DumpKey(a accounts.Account, passphrase string) (privateKey []byte, err error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	return crypto.FromECDSA(key.PrivateKey), nil

}
func (ks *Sm2KeyStore) DumpKey(a accounts.Account, passphrase string) (privateKey []byte, err error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	return math.PaddedBigBytes(key.D, key.Params().BitSize/8), nil
}

func (ks *KeyStore) DumpPrivateKey(a accounts.Account, passphrase string) (privateKey *ecdsa.PrivateKey, err error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	return key.PrivateKey, nil

}
func (ks *Sm2KeyStore) DumpPrivateKey(a accounts.Account, passphrase string) (privateKey *sm2.PrivateKey, err error) {
	_, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return nil, err
	}
	return key, nil

}

// Import stores the given encrypted JSON key into the key directory.
func (ks *KeyStore) Import(keyJSON []byte, passphrase, newPassphrase string) (accounts.Account, error) {
	key, err := DecryptKey(keyJSON, passphrase)
	if key != nil && key.PrivateKey != nil {
		defer ZeroKey(key.PrivateKey)
	}
	if err != nil {
		return accounts.Account{}, err
	}
	return ks.importKey(key, newPassphrase)
}

// Import stores the given encrypted JSON key into the key directory.
func (ks *Sm2KeyStore) Import(keyJSON []byte, passphrase, newPassphrase string) (accounts.Account, error) {

	return accounts.Account{}, nil
}

// ImportECDSA stores the given key into the key directory, encrypting it with the passphrase.
func (ks *KeyStore) ImportECDSA(priv *ecdsa.PrivateKey, passphrase string) (accounts.Account, error) {
	key := newKeyFromECDSA(priv)
	if ks.cache.hasAddress(key.Address) {
		return accounts.Account{}, fmt.Errorf("account already exists")
	}
	return ks.importKey(key, passphrase)
}

func (ks *KeyStore) importKey(key *Key, passphrase string) (accounts.Account, error) {
	a := accounts.Account{Address: key.Address, URL: accounts.URL{Scheme: KeyStoreScheme, Path: ks.storage.JoinPath(keyFileName(key.Address))}}
	if err := ks.storage.StoreKey(a.URL.Path, key, passphrase); err != nil {
		return accounts.Account{}, err
	}
	ks.cache.add(a)
	ks.refreshWallets()
	return a, nil
}

// Update changes the passphrase of an existing account.
func (ks *KeyStore) Update(a accounts.Account, passphrase, newPassphrase string) error {
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}
	return ks.storage.StoreKey(a.URL.Path, key, newPassphrase)
}

// Update changes the passphrase of an existing account.
func (ks *Sm2KeyStore) Update(a accounts.Account, passphrase, newPassphrase string) error {
	a, key, err := ks.getDecryptedKey(a, passphrase)
	if err != nil {
		return err
	}
	return ks.storage.StoreKeySm2(a.URL.Path, key, newPassphrase)
}

// ZeroKey zeroes a private key in memory.
func ZeroKey(k *ecdsa.PrivateKey) {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

func (ks *KeyStore) getPrivateKey(address common.Address) (*ecdsa.PrivateKey, error) {
	// Look up the key to sign with and abort if it cannot be found
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	unlockedKey, found := ks.unlocked[address]
	if !found {
		return nil, ErrLocked
	}
	return unlockedKey.PrivateKey, nil
}

func (ks *Sm2KeyStore) getPrivateKey(address common.Address) (*sm2.PrivateKey,  error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	unlockedKey, found := ks.sm2unlocked[address]
	if !found {
		return nil, ErrLocked
	}
	return unlockedKey.Key, nil
}
func (ks *KeyStore) GetPublicKey(address common.Address) ([]byte, error) {
	// Look up the key to sign with and abort if it cannot be found
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	unlockedKey, found := ks.unlocked[address]
	if !found {
		return nil, ErrLocked
	}
	return crypto.CompressPubkey(&unlockedKey.PrivateKey.PublicKey), nil
}

func (ks *Sm2KeyStore) GetPublicKey(address common.Address) ([]byte, error) {
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	unlockedKey, found := ks.sm2unlocked[address]
	if !found {
		return nil, ErrLocked
	}
	ukey := unlockedKey.Key.PublicKey
	return crypto.CompressPubkeySm2(&ukey), nil
}

func (ks *KeyStore) SigUnit(unitHeader *modules.Header, address common.Address) ([]byte, error) {
	emptyHeader := modules.CopyHeader(unitHeader)
	emptyHeader.Authors = modules.Authentifier{} //Clear exist sign
	emptyHeader.GroupSign = make([]byte, 0)      //Clear group sign
	return ks.SigData(emptyHeader, address)
}
func (ks *Sm2KeyStore) SigUnit(unitHeader *modules.Header, address common.Address) ([]byte, error) {
	emptyHeader := modules.CopyHeader(unitHeader)
	emptyHeader.Authors = modules.Authentifier{} //Clear exist sign
	emptyHeader.GroupSign = make([]byte, 0)      //Clear group sign
	return ks.SigData(emptyHeader, address)
}
func (ks *KeyStore) SigData(data interface{}, address common.Address) ([]byte, error) {
	privateKey, err := ks.getPrivateKey(address)
	if err != nil {
		return nil, err
	}
	//defer ZeroKey(privateKey)
	hash := crypto.HashResult(util.RHashBytes(data))
	if err != nil {
		return nil, err
	}
	sign, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}
	return sign, nil
}

func (ks *Sm2KeyStore) SigData(data interface{}, address common.Address) ([]byte, error) {
	privateKey, err := ks.getPrivateKey(address)
	if err != nil {
		return nil, err
	}

	//defer ZeroKey(privateKey)
	hash := crypto.HashResult(util.RHashBytes(data))
	if err != nil {
		return nil, err
	}

	sign, err := privateKey.Sign(crand.Reader, hash.Bytes(), nil) // 签名
	if err != nil {
		return nil, err
	}
	return sign, nil
}
func (ks *KeyStore) SigUnitWithPwd(unit interface{}, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := crypto.HashResult(util.RHashBytes(unit))
	//unit signature
	sign, err := crypto.Sign(hash.Bytes(), privateKey)
	if err != nil {
		return nil, err
	}
	return sign, nil
}

func VerifyUnitWithPK(sign []byte, unit interface{}, publicKey []byte) bool {
	hash := crypto.HashResult(util.RHashBytes(unit))
	// s, err := hexutil.Decode(sign)
	// if err != nil {
	// 	return false
	// }
	if len(sign) <= 0 {
		log.Error("Unit sigature is none.")
		return false
	}
	sig := sign[:len(sign)-1] // remove recovery id
	return crypto.VerifySignature(publicKey, hash.Bytes(), sig)
}

//tx:TxMessages   []Message
func (ks *KeyStore) SigTX(tx interface{}, address common.Address) (R, S, V []byte, e error) {
	sig, err := ks.SigData(tx, address)
	if err != nil {
		e = err
		return
	}

	R = sig[:32]
	S = sig[32:64]
	V = append(V, sig[64])
	e = nil
	return
}

func VerifyTXWithPK(sign []byte, tx interface{}, publicKey []byte) bool {
	return VerifyUnitWithPK(sign, tx, publicKey)
}

func (ks *KeyStore) SigTXWithPwd(tx interface{}, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	return ks.SigUnitWithPwd(tx, privateKey)
}
