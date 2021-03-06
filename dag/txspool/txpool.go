/*
   This file is part of go-palletone.
   go-palletone is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   go-palletone is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   You should have received a copy of the GNU General Public License
   along with go-palletone.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * @author PalletOne core developers <dev@pallet.one>
 * @date 2018
 */

package txspool

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/palletone/go-palletone/common"
	"github.com/palletone/go-palletone/common/event"
	"github.com/palletone/go-palletone/common/log"
	"github.com/palletone/go-palletone/dag/dagconfig"
	"github.com/palletone/go-palletone/dag/errors"
	"github.com/palletone/go-palletone/dag/modules"
	"github.com/palletone/go-palletone/tokenengine"
	"github.com/palletone/go-palletone/validator"
	"gopkg.in/karalabe/cookiejar.v2/collections/prque"
)

const (
	// chainHeadChanSize is the size of channel listening to ChainHeadEvent.
	chainHeadChanSize = 10
	// rmTxChanSize is the size of channel listening to RemovedTransactionEvent.
	rmTxChanSize = 10
	DaoPerPtn    = 1e8
	MaxDao       = 10e8 * DaoPerPtn
	Raised       = 1e8
)

var (
	evictionInterval         = time.Minute     // Time interval to check for evictable transactions
	statsReportInterval      = 8 * time.Second // Time interval to report transaction pool stats
	orphanExpireScanInterval = time.Minute * 5 //The minimum amount of time in between scans of the orphan pool to evict expired transactions.
)
var (
	// ErrInvalidSender is returned if the transaction contains an invalid signature.
	ErrInvalidSender = errors.New("invalid sender")

	// ErrNonceTooLow is returned if the nonce of a transaction is lower than the
	// one present in the local chain.
	ErrNonceTooLow = errors.New("nonce too low")

	// ErrTxFeeTooLow is returned if a transaction's tx_fee is below the value of TXFEE.
	ErrTxFeeTooLow = errors.New("txfee too low")

	// ErrUnderpriced is returned if a transaction's gas price is below the minimum
	// configured for the transaction pool.
	ErrUnderpriced = errors.New("transaction underpriced")

	// ErrReplaceUnderpriced is returned if a transaction is attempted to be replaced
	// with a different one without the required price bump.
	ErrReplaceUnderpriced = errors.New("replacement transaction underpriced")

	// ErrInsufficientFunds is returned if the total cost of executing a transaction
	// is higher than the balance of the user's account.
	ErrInsufficientFunds = errors.New("insufficient funds for gas * price + value")

	// ErrNegativeValue is a sanity error to ensure noone is able to specify a
	// transaction with a negative value.
	ErrNegativeValue = errors.New("negative value")

	// ErrOversizedData is returned if the input data of a transaction is greater
	// than some meaningful limit a user might use. This is not a consensus error
	// making the transaction invalid, rather a DOS protection.
	ErrOversizedData = errors.New("oversized data")
)

type dags interface {
	CurrentUnit(token modules.AssetId) *modules.Unit
	GetUnitByHash(hash common.Hash) (*modules.Unit, error)
	GetTxFromAddress(tx *modules.Transaction) ([]common.Address, error)
	// GetTransaction(hash common.Hash) (*modules.Transaction, common.Hash, uint64, uint64, error)
	GetTransactionOnly(hash common.Hash) (*modules.Transaction, error)
	IsTransactionExist(hash common.Hash) (bool, error)
	GetHeaderByHash(common.Hash) (*modules.Header, error)
	GetUtxoEntry(outpoint *modules.OutPoint) (*modules.Utxo, error)
	//GetUtxoView(tx *modules.Transaction) (*UtxoViewpoint, error)
	SubscribeChainHeadEvent(ch chan<- modules.ChainHeadEvent) event.Subscription
	// getTxfee
	GetTxFee(pay *modules.Transaction) (*modules.AmountAsset, error)
	//GetTxHashByReqId(reqid common.Hash) (common.Hash, error)

	GetContractTpl(tplId []byte) (*modules.ContractTemplate, error)
	GetMinFee() (*modules.AmountAsset, error)
	GetContractJury(contractId []byte) ([]modules.ElectionInf, error)
}

// TxPoolConfig are the configuration parameters of the transaction pool.
type TxPoolConfig struct {
	NoLocals  bool          // Whether local transaction handling should be disabled
	Journal   string        // Journal of local transactions to survive node restarts
	Rejournal time.Duration // Time interval to regenerate the local transaction journal

	FeeLimit  uint64 // Minimum tx's fee  to enforce for acceptance into the pool
	PriceBump uint64 // Minimum price bump percentage to replace an already existing transaction (nonce)

	GlobalSlots uint64 // Maximum number of executable transaction slots for all accounts
	GlobalQueue uint64 // Maximum number of non-executable transaction slots for all accounts

	Lifetime   time.Duration // Maximum amount of time non-executable transaction are queued
	Removetime time.Duration // Maximum amount of time txpool transaction are removed
	OrphanTTL  time.Duration // Orpthan expriation
	// MaxOrphanTxs is the maximum number of orphan transactions
	// that can be queued.
	MaxOrphanTxs int

	// MaxOrphanTxSize is the maximum size allowed for orphan transactions.
	// This helps prevent memory exhaustion attacks from sending a lot of
	// of big orphans.
	MaxOrphanTxSize int
}

// DefaultTxPoolConfig contains the default configurations for the transaction
// pool.
var DefaultTxPoolConfig = TxPoolConfig{
	NoLocals:  false,
	Journal:   "transactions.rlp",
	Rejournal: time.Hour,

	FeeLimit:  1,
	PriceBump: 10,

	GlobalSlots: 48192,
	GlobalQueue: 12048,

	Lifetime:        3 * time.Hour,
	Removetime:      30 * time.Minute,
	OrphanTTL:       15 * time.Minute,
	MaxOrphanTxs:    10000,
	MaxOrphanTxSize: 2000000,
}

// sanitize checks the provided user configurations and changes anything that's
// unreasonable or unworkable.
func (config *TxPoolConfig) sanitize() TxPoolConfig {
	conf := *config
	if conf.Rejournal < time.Second {
		log.Warn("Sanitizing invalid txpool journal time", "provided", conf.Rejournal, "updated", time.Second)
		conf.Rejournal = time.Second
	}
	if conf.PriceBump < 1 {
		log.Warn("Sanitizing invalid txpool price bump", "provided", conf.PriceBump, "updated", DefaultTxPoolConfig.PriceBump)
		conf.PriceBump = DefaultTxPoolConfig.PriceBump
	}
	return conf
}

type TxPool struct {
	config TxPoolConfig
	unit   dags
	txFeed event.Feed
	scope  event.SubscriptionScope
	//chainHeadCh  chan modules.ChainHeadEvent
	//chainHeadSub event.Subscription
	txValidator validator.Validator
	journal     *txJournal // Journal of local transaction to back up to disk

	all             sync.Map          // All transactions to allow lookups
	priority_sorted *txPrioritiedList // All transactions sorted by price and priority
	outpoints       sync.Map          // utxo标记池  map[modules.OutPoint]*modules.TxPoolTransaction
	orphans         sync.Map          // 孤儿交易缓存池
	outputs         sync.Map          // 缓存 交易的outputs
	sequenTxs       *modules.SequeueTxPoolTxs

	mu             *sync.RWMutex
	wg             sync.WaitGroup // for shutdown sync
	quit           chan struct{}  // used for exit
	nextExpireScan time.Time
}

type sTxDesc struct {
	// Tx is the transaction associated with the entry.
	Tx *modules.Transaction
	// Added is the time when the entry was added to the source pool.
	Added time.Time
	// Height is the block height when the entry was added to the the source
	// pool.
	Height int32
	// Fee is the total fee the transaction associated with the entry pays.
	Fee int64
	// FeePerKB is the fee the transaction pays in Satoshi per 1000 bytes.
	FeePerKB int64
}

// TxDesc is a descriptor containing a transaction in the mempool along with
// additional metadata.
type TxDesc struct {
	sTxDesc
	// StartingPriority is the priority of the transaction when it was added
	// to the pool.
	StartingPriority float64
}

// NewTxPool creates a new transaction pool to gather, sort and filter inbound
// transactions from the network.
func NewTxPool(config TxPoolConfig, unit dags) *TxPool { // chainconfig *params.ChainConfig,
	// Sanitize the input to ensure no vulnerable gas prices are set
	config = (&config).sanitize()
	// Create the transaction pool with its initial settings
	pool := &TxPool{
		config:    config,
		unit:      unit,
		all:       sync.Map{},
		sequenTxs: new(modules.SequeueTxPoolTxs),
		//chainHeadCh:    make(chan modules.ChainHeadEvent, chainHeadChanSize),
		outpoints:      sync.Map{},
		nextExpireScan: time.Now().Add(config.OrphanTTL),
		orphans:        sync.Map{},
		outputs:        sync.Map{},
	}
	pool.mu = new(sync.RWMutex)
	pool.priority_sorted = newTxPrioritiedList(&pool.all)
	pool.txValidator = validator.NewValidate(unit, pool, unit, nil)
	// If local transactions and journaling is enabled, load from disk
	if !config.NoLocals && config.Journal != "" {
		log.Info("Journal path:" + config.Journal)
		pool.journal = newTxJournal(config.Journal)

		if err := pool.journal.load(pool.AddLocal); err != nil {
			log.Warn("Failed to load transaction journal", "err", err)
		}
		if err := pool.journal.rotate(pool.local()); err != nil {
			log.Warn("Failed to rotate transaction journal", "err", err)
		}
	}
	// Subscribe events from blockchain
	// pool.chainHeadSub = pool.unit.SubscribeChainHeadEvent(pool.chainHeadCh)
	// Start the event loop and return
	pool.wg.Add(1)
	go pool.loop()

	return pool
}
func (pool *TxPool) GetUtxoEntry(outpoint *modules.OutPoint) (*modules.Utxo, error) {
	if inter, ok := pool.outputs.Load(*outpoint); ok {
		utxo := inter.(*modules.Utxo)
		log.Debugf("Get UTXO from txpool by Outpoint:%s", outpoint.String())
		return utxo, nil
	}
	//log.Debugf("Outpoint[%s] and Utxo not in pool. query from db", outpoint.String())
	return pool.unit.GetUtxoEntry(outpoint)
}

// loop is the transaction pool's main event loop, waiting for and reacting to
// outside blockchain events as well as for various reporting and transaction
// eviction events.
func (pool *TxPool) loop() {
	defer pool.wg.Done()

	// Start the stats reporting and transaction eviction tickers
	var prevPending, prevQueued int

	report := time.NewTicker(statsReportInterval)
	defer report.Stop()

	evict := time.NewTicker(evictionInterval)
	defer evict.Stop()

	journal := time.NewTicker(pool.config.Rejournal)
	defer journal.Stop()
	// delete txspool's confirmed tx
	deleteTxTimer := time.NewTicker(10 * time.Minute)
	defer deleteTxTimer.Stop()

	orphanExpireScan := time.NewTicker(orphanExpireScanInterval)
	defer orphanExpireScan.Stop()

	// Track the previous head headers for transaction reorgs
	// TODO 分区后 按token类型 loop 交易池。
	//gasToken := dagconfig.DagConfig.GetGasToken()
	//head := pool.unit.CurrentUnit(gasToken)
	// Keep waiting for and reacting to the various events
	for {
		select {
		// Handle stats reporting ticks
		case <-report.C:
			pending, queued, _ := pool.stats()

			if pending != prevPending || queued != prevQueued {
				log.Debug("Transaction pool status report", "executable", pending, "queued", queued)
				prevPending, prevQueued = pending, queued
			}

			// Handle inactive account transaction eviction
		case <-evict.C:

			// Handle local transaction journal rotation ----- once a honr -----
		case <-journal.C:
			if pool.journal != nil {
				pool.mu.Lock()
				if err := pool.journal.rotate(pool.local()); err != nil {
					log.Warn("Failed to rotate local tx journal", "err", err)
				}
				pool.mu.Unlock()
			}
			// delete tx
		case <-deleteTxTimer.C:
			go pool.DeleteTx()

			// quit
		case <-orphanExpireScan.C:
			pool.mu.Lock()
			pool.limitNumberOrphans()
			pool.mu.Unlock()
		case <-pool.quit:
			log.Info("txspool are quit now", "time", time.Now().String())
			return
		}

	}
}

// Stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
func (pool *TxPool) Stats() (int, int, int) {
	return pool.stats()
}

// stats retrieves the current pool stats, namely the number of pending and the
// number of queued (non-executable) transactions.
func (pool *TxPool) stats() (int, int, int) {
	p_count, q_count := 0, 0
	poolTxs := pool.AllTxpoolTxs()
	orphanTxs := pool.AllOrphanTxs()
	for _, tx := range poolTxs {
		if tx.Pending {
			p_count++
		}
		if !tx.Pending && !tx.Confirmed {
			q_count++
		}
	}
	for _, tx := range orphanTxs {
		if !tx.Pending {
			q_count++
		}
	}
	return p_count, q_count, len(orphanTxs)
}

// Content retrieves the data content of the transaction pool, returning all the
// pending as well as queued transactions, grouped by account and sorted by nonce.
func (pool *TxPool) Content() (map[common.Hash]*modules.Transaction, map[common.Hash]*modules.Transaction) {
	pending := make(map[common.Hash]*modules.Transaction)
	queue := make(map[common.Hash]*modules.Transaction)

	alltxs := pool.AllTxpoolTxs()
	orphanTxs := pool.AllOrphanTxs()
	for hash, tx := range alltxs {
		if tx.Pending {
			pending[hash] = tx.Tx
		}
		if !tx.Pending && !tx.Confirmed {
			queue[hash] = tx.Tx
		}
	}
	for hash, tx := range orphanTxs {
		if !tx.Pending {
			queue[hash] = tx.Tx
		}
	}
	return pending, queue
}

// Pending retrieves all currently processable transactions, groupped by origin
// account and sorted by priority level. The returned transaction set is a copy and can be
// freely modified by calling code.
func (pool *TxPool) Pending() (map[common.Hash][]*modules.TxPoolTransaction, error) {
	return pool.pending()
}
func (pool *TxPool) pending() (map[common.Hash][]*modules.TxPoolTransaction, error) {
	pending := make(map[common.Hash][]*modules.TxPoolTransaction)
	txs := pool.AllTxpoolTxs()
	for _, tx := range txs {
		if tx.Pending {
			pending[tx.UnitHash] = append(pending[tx.UnitHash], tx)
		}
	}
	return pending, nil
}

// Queued txs
func (pool *TxPool) Queued() ([]*modules.TxPoolTransaction, error) {
	queue := make([]*modules.TxPoolTransaction, 0)
	txs := pool.AllTxpoolTxs()
	for _, tx := range txs {
		if !tx.Pending {
			queue = append(queue, tx)
		}
	}
	return queue, nil
}

// AllHashs returns a slice of hashes for all of the transactions in the txpool.
func (pool *TxPool) AllHashs() []*common.Hash {
	hashs := make([]common.Hash, 0)
	pool.all.Range(func(k, v interface{}) bool {
		hash := k.(common.Hash)
		hashs = append(hashs, hash)
		return true
	})
	phashs := make([]*common.Hash, 0)
	for _, hash := range hashs {
		var p common.Hash
		p.SetBytes(hash.Bytes())
		phashs = append(phashs, &p)
	}
	return phashs
}
func (pool *TxPool) AllLength() int {
	var count int
	pool.all.Range(func(k, v interface{}) bool {
		count++
		return true
	})
	return count
}
func (pool *TxPool) AllTxpoolTxs() map[common.Hash]*modules.TxPoolTransaction {
	txs := make(map[common.Hash]*modules.TxPoolTransaction)
	pool.all.Range(func(k, v interface{}) bool {
		hash := k.(common.Hash)
		tx := v.(*modules.TxPoolTransaction)
		tx_hash := tx.Tx.Hash()
		if hash != tx_hash {
			pool.all.Delete(hash)
			pool.all.Store(tx_hash, tx)
		}
		txs[tx_hash] = tx
		return true
	})
	return txs
}
func (pool *TxPool) AllOrphanTxs() map[common.Hash]*modules.TxPoolTransaction {
	txs := make(map[common.Hash]*modules.TxPoolTransaction)
	pool.orphans.Range(func(k, v interface{}) bool {
		tx := v.(*modules.TxPoolTransaction)
		txs[tx.Tx.Hash()] = tx
		return true
	})
	return txs
}

//
func (pool *TxPool) AllTxs() []*modules.Transaction {
	txs := make([]*modules.Transaction, 0)
	pooltxs := pool.AllTxpoolTxs()
	for _, txcopy := range pooltxs {
		txs = append(txs, txcopy.Tx)
	}
	return txs
}
func (pool *TxPool) Count() int {
	return pool.AllLength()
}

// local retrieves all currently known local transactions, groupped by origin
// account and sorted by price. The returned transaction set is a copy and can be
// freely modified by calling code.
func (pool *TxPool) local() map[common.Hash]*modules.TxPoolTransaction {
	txs := make(map[common.Hash]*modules.TxPoolTransaction)
	pending, _ := pool.pending()
	for _, list := range pending {
		for _, tx := range list {
			if tx != nil {
				txs[tx.Tx.Hash()] = tx
			}
		}
	}
	return txs
}

// validateTx checks whether a transaction is valid according to the consensus
// rules and adheres to some heuristic limits of the local node (price and size).
func (pool *TxPool) validateTx(tx *modules.TxPoolTransaction, local bool) error {
	// 交易池不需要验证交易存不存在。
	if tx == nil || tx.Tx == nil {
		return errors.New("This transaction is invalide.")
	}
	err := pool.txValidator.ValidateTx(tx.Tx, false, true)
	return err
}

// This function MUST be called with the txpool lock held (for reads).
func (pool *TxPool) isTransactionInPool(hash common.Hash) bool {
	if _, exist := pool.all.Load(hash); exist {
		return true
	}
	if _, exist := pool.orphans.Load(hash); exist {
		return true
	}
	return false
}

// IsTransactionInPool returns whether or not the passed transaction already exists in the main pool.
func (pool *TxPool) IsTransactionInPool(hash common.Hash) bool {
	return pool.isTransactionInPool(hash)
}

//
func TxtoTxpoolTx(txpool ITxPool, tx *modules.Transaction) *modules.TxPoolTransaction {
	txpool_tx := new(modules.TxPoolTransaction)
	txpool_tx.Tx = tx

	for _, msgcopy := range tx.TxMessages {
		if msgcopy.App == modules.APP_PAYMENT {
			if msg, ok := msgcopy.Payload.(*modules.PaymentPayload); ok {
				for _, script := range msg.Inputs {
					if script.PreviousOutPoint != nil {
						txpool_tx.From = append(txpool_tx.From, script.PreviousOutPoint)
					}
				}
			}
		}
	}

	txpool_tx.CreationDate = time.Now()
	// 孤兒交易和非孤兒的交易費分开计算。
	if ok, err := txpool.ValidateOrphanTx(tx); ok || err != nil {
		// 孤兒交易的交易费暂时设置20dao, 以便计算优先级
		txpool_tx.TxFee = &modules.AmountAsset{Amount: 20, Asset: tx.Asset()}
	} else {
		txpool_tx.TxFee, _ = txpool.GetTxFee(tx)
	}
	txpool_tx.Priority_lvl = txpool_tx.GetPriorityLvl()

	return txpool_tx
}

func PooltxToTx(pooltx *modules.TxPoolTransaction) *modules.Transaction {
	return pooltx.Tx
}

// add validates a transaction and inserts it into the non-executable queue for
// later pending promotion and execution. If the transaction is a replacement for
// an already pending or queued one, it overwrites the previous and returns this
// so outer code doesn't uselessly call promote.
//
// If a newly added transaction is marked as local, its sending account will be
// whitelisted, preventing any associated transaction from being dropped out of
// the pool due to pricing constraints.
func (pool *TxPool) add(tx *modules.TxPoolTransaction, local bool) (bool, error) {

	msgs := tx.Tx.Messages()
	if msgs[0].Payload.(*modules.PaymentPayload).IsCoinbase() {
		return true, nil
	}
	// Don't accept the transaction if it already in the pool .
	hash := tx.Tx.Hash()
	if has, _ := pool.unit.IsTransactionExist(hash); has {
		return false, fmt.Errorf("the transactionx: %s has been packaged.", hash.String())
	}
	if _, has := pool.all.Load(hash); has {
		log.Trace("Discarding already known transaction", "hash", hash)
		return false, fmt.Errorf("known transaction: %#x", hash)
	}
	if pool.isOrphanInPool(hash) {
		return false, fmt.Errorf("know orphanTx: %#x", hash)
	}

	if ok, err := pool.ValidateOrphanTx(tx.Tx); err != nil {
		log.Debug("validateOrphantx occurred error.", "info", err.Error())
		return false, err
	} else {
		if ok {
			log.Debug("validated the orphanTx", "hash", hash.String())
			pool.addOrphan(tx, 0)
			return true, nil
		}
	}

	// If the transaction fails basic validation, discard it
	if err := pool.validateTx(tx, local); err != nil {
		log.Trace("Discarding invalid transaction", "hash", hash, "err", err.Error())
		return false, err
	}

	if err := pool.checkPoolDoubleSpend(tx); err != nil {
		return false, err
	}

	// 计算交易费和优先级
	tx.TxFee, _ = pool.GetTxFee(tx.Tx)
	tx.Priority_lvl = tx.GetPriorityLvl()

	utxoview, err := pool.FetchInputUtxos(tx.Tx)
	if err != nil {
		log.Errorf("fetchInputUtxos by txid[%s] failed:%s", tx.Tx.Hash().String(), err)
		return false, err
	}

	// Check the transaction if it exists in the main chain and is not already fully spent.
	preout := modules.OutPoint{TxHash: hash}
	for i, msgcopy := range msgs {
		if msgcopy.App == modules.APP_PAYMENT {
			if msg, ok := msgcopy.Payload.(*modules.PaymentPayload); ok {
				for j := range msg.Outputs {
					preout.MessageIndex = uint32(i)
					preout.OutIndex = uint32(j)
					// get utxo entry , if the utxo entry is spent, then return  error.
					utxo := utxoview.LookupUtxo(preout)
					if utxo != nil && !utxo.IsSpent() {
						return false, errors.New("transaction already exists.")
					}
					utxoview.RemoveUtxo(preout)
				}
			}
		}
	}

	// If the transaction pool is full, discard underpriced transactions
	length := pool.AllLength()
	if uint64(length) >= pool.config.GlobalSlots+pool.config.GlobalQueue {
		// If the new transaction is underpriced, don't accept it
		if pool.priority_sorted.Underpriced(tx) {
			log.Trace("Discarding underpriced transaction", "hash", hash, "price", tx.GetTxFee().Int64())
			return false, ErrUnderpriced
		}
		// New transaction is better than our worse ones, make room for it
		count := length - int(pool.config.GlobalSlots+pool.config.GlobalQueue-1)
		if count > 0 {
			drop := pool.priority_sorted.Discard(count)
			for _, tx := range drop {
				log.Trace("Discarding freshly underpriced transaction", "hash", tx.Tx.Hash(), "price", tx.GetTxFee().Int64())
				pool.removeTransaction(tx, true)
			}
		}
	}
	// Add the transaction to the pool  and mark the referenced outpoints as spent by the pool.
	log.Debugf("Add Tx[%s] to txpool.", tx.Tx.Hash().String())
	pool.priority_sorted.Put(tx)
	pool.all.Store(hash, tx)
	pool.addCache(tx)
	//go pool.journalTx(tx)

	// We've directly injected a replacement transaction, notify subsystems
	go pool.txFeed.Send(modules.TxPreEvent{tx.Tx})

	return true, nil
}

// enqueueTx inserts a new transaction into the non-executable transaction queue.
//
// Note, this method assumes the pool lock is held!
func (pool *TxPool) enqueueTx(hash common.Hash, tx *modules.TxPoolTransaction) (bool, error) {
	// Try to insert the transaction into the future queue
	interTx, has := pool.all.Load(hash)
	if has {
		old, ok := interTx.(*modules.TxPoolTransaction)
		if ok {
			if !old.Pending && !old.Discarded {
				// An older transaction was better, discard this
				if old.GetPriorityfloat64() > tx.GetPriorityfloat64() {
					return false, ErrReplaceUnderpriced
				}
				pool.all.Delete(hash)
				pool.priority_sorted.Removed()
			}
		}
	}
	pool.all.Store(hash, tx)
	pool.priority_sorted.Put(tx)
	return true, nil
}

// journalTx adds the specified transaction to the local disk journal if it is
// deemed to have been sent from a local account.
func (pool *TxPool) journalTx(tx *modules.TxPoolTransaction) {
	// Only journal if it's enabled and the transaction is local
	if len(tx.From) > 0 {
		if pool.journal == nil {
			log.Trace("Pool journal is nil.", "journal", pool.journal.path)
			return
		}
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if err := pool.journal.insert(tx); err != nil {
		log.Warn("Failed to journal local transaction", "err", err)
	}
}

// promoteTx adds a transaction to the pending (processable) list of transactions.
//
// Note, this method assumes the pool lock is held!
func (pool *TxPool) promoteTx(hash common.Hash, tx *modules.TxPoolTransaction) {
	// Try to insert the transaction into the pending queue
	tx_hash := tx.Tx.Hash()
	interTx, has := pool.all.Load(tx_hash)
	if has {
		if this, ok := interTx.(*modules.TxPoolTransaction); ok {
			if this.Pending || this.Confirmed {
				// An older transaction was better, discard this
				this.Pending = true
				this.Discarded = true
				pool.all.Store(hash, this)
				//pool.priority_sorted.Removed()
				return
			}
		} else {
			pool.all.Delete(tx_hash)
			pool.priority_sorted.Removed()
		}
	}
	// Failsafe to work around direct pending inserts (tests)
	tx.Pending = true
	tx.Discarded = false
	tx.Confirmed = false
	tx.UnitHash = hash
	pool.all.Store(hash, tx)
}

// AddLocal enqueues a single transaction into the pool if it is valid, marking
// the sender as a local one in the mean time, ensuring it goes around the local
// pricing constraints.
func (pool *TxPool) AddLocal(tx *modules.TxPoolTransaction) error {
	//tx.SetPriorityLvl(tx.GetPriorityLvl())
	return pool.addTx(tx, !pool.config.NoLocals)
}

// AddRemote enqueues a single transaction into the pool if it is valid. If the
// sender is not among the locally tracked ones, full pricing constraints will
// apply.
func (pool *TxPool) AddRemote(tx *modules.Transaction) error {
	if tx.TxMessages[0].Payload.(*modules.PaymentPayload).IsCoinbase() {
		return nil
	}
	pool_tx := TxtoTxpoolTx(pool, tx)
	return pool.addTx(pool_tx, false)
}

// AddLocals enqueues a batch of transactions into the pool if they are valid,
// marking the senders as a local ones in the mean time, ensuring they go around
// the local pricing constraints.
func (pool *TxPool) AddLocals(txs []*modules.TxPoolTransaction) []error {
	return pool.addTxs(txs, !pool.config.NoLocals)
}

// AddRemotes enqueues a batch of transactions into the pool if they are valid.
// If the senders are not among the locally tracked ones, full pricing constraints
// will apply.
func (pool *TxPool) AddRemotes(txs []*modules.Transaction) []error {
	pool_txs := make([]*modules.TxPoolTransaction, 0)
	for _, tx := range txs {
		pool_txs = append(pool_txs, TxtoTxpoolTx(pool, tx))
	}
	return pool.addTxs(pool_txs, false)
}
func (pool *TxPool) AddSequenTx(tx *modules.Transaction) error {
	p_tx := TxtoTxpoolTx(pool, tx)
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.addSequenTx(p_tx)
}
func (pool *TxPool) AddSequenTxs(txs []*modules.Transaction) error {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	for _, tx := range txs {
		p_tx := TxtoTxpoolTx(pool, tx)
		if err := pool.addSequenTx(p_tx); err != nil {
			return err
		}
		break
	}
	return nil
}
func (pool *TxPool) addSequenTx(p_tx *modules.TxPoolTransaction) error {
	// Don't accept the transaction if it already in the pool .
	msgs := p_tx.Tx.Messages()
	hash := p_tx.Tx.Hash()
	if has, _ := pool.unit.IsTransactionExist(hash); has {
		return fmt.Errorf("the transactionx: %s has been packaged.", hash.String())
	}
	if _, has := pool.all.Load(hash); has {
		log.Trace("Discarding already known transaction", "hash", hash)
		return fmt.Errorf("known transaction: %#x", hash)
	}
	if pool.isOrphanInPool(hash) {
		return fmt.Errorf("know orphanTx: %#x", hash)
	}

	// If the transaction fails basic validation, discard it
	if err := pool.validateTx(p_tx, false); err != nil {
		log.Trace("Discarding invalid transaction", "hash", hash, "err", err.Error())
		return err
	}

	if err := pool.checkPoolDoubleSpend(p_tx); err != nil {
		return err
	}

	// 计算交易费和优先级
	p_tx.TxFee, _ = pool.GetTxFee(p_tx.Tx)
	p_tx.Priority_lvl = p_tx.GetPriorityLvl()

	utxoview, err := pool.FetchInputUtxos(p_tx.Tx)
	if err != nil {
		log.Errorf("fetchInputUtxos by txid[%s] failed:%s", p_tx.Tx.Hash().String(), err)
		return err
	}
	// Check the transaction if it exists in the main chain and is not already fully spent.
	preout := modules.OutPoint{TxHash: hash}
	for i, msgcopy := range msgs {
		if msgcopy.App == modules.APP_PAYMENT {
			if msg, ok := msgcopy.Payload.(*modules.PaymentPayload); ok {
				for j := range msg.Outputs {
					preout.MessageIndex = uint32(i)
					preout.OutIndex = uint32(j)
					// get utxo entry , if the utxo entry is spent, then return  error.
					utxo := utxoview.LookupUtxo(preout)
					if utxo != nil && !utxo.IsSpent() {
						return errors.New("transaction is invalidate(utxo is illegal).")
					}
					utxoview.RemoveUtxo(preout)
				}
			}
		}
	}

	// Add the transaction to the pool  and mark the referenced outpoints as spent by the pool.
	log.Debugf("Add Tx[%s] to sequen txpool.", p_tx.Tx.Hash().String())
	pool.sequenTxs.Add(p_tx)
	pool.all.Store(hash, p_tx)
	pool.addCache(p_tx)
	//go pool.journalTx(p_tx)

	// We've directly injected a replacement transaction, notify subsystems
	go pool.txFeed.Send(modules.TxPreEvent{p_tx.Tx})
	return nil
}

type Tag uint64

func (pool *TxPool) ProcessTransaction(tx *modules.Transaction, allowOrphan bool, rateLimit bool, tag Tag) ([]*TxDesc, error) {

	// Potentially accept the transaction to the memory pool.
	_, _, err := pool.maybeAcceptTransaction(tx, true, rateLimit, false)
	if err != nil {
		log.Info("txpool", "accept transaction err:", err)
		return nil, err
	}
	return nil, nil
}

func IsCoinBase(tx *modules.Transaction) bool {
	if len(tx.TxMessages) != 1 {
		return false
	}
	msg, ok := tx.TxMessages[0].Payload.(*modules.PaymentPayload)
	if !ok {
		return false
	}
	return msg.IsCoinbase()
}

// maybeAcceptTransaction is the internal function which implements the public
// MaybeAcceptTransaction.  See the comment for MaybeAcceptTransaction for
// more details.
//
// This function MUST be called with the mempool lock held (for writes).
func (pool *TxPool) maybeAcceptTransaction(tx *modules.Transaction, isNew, rateLimit, rejectDupOrphans bool) ([]*common.Hash, *TxDesc, error) {
	txHash := tx.Hash()
	// Don't accept the transaction if it already exists in the pool.  This
	// applies to orphan transactions as well when the reject duplicate
	// orphans flag is set.  This check is intended to be a quick check to
	// weed out duplicates.
	if pool.isTransactionInPool(txHash) {
		str := fmt.Sprintf("already have transaction %s", txHash.String())
		log.Info("txpool", "info", str)
		return nil, nil, nil
	}

	// Perform preliminary sanity checks on the transaction.  This makes
	// use of blockchain which contains the invariant rules for what
	// transactions are allowed into blocks.
	err := CheckTransactionSanity(tx)
	if err != nil {
		log.Info("Check Transaction Sanity err:", "error", err)
		return nil, nil, err
	}

	// A standalone transaction must not be a coinbase transaction.
	if IsCoinBase(tx) {
		str := fmt.Sprintf("transaction %s is an individual coinbase",
			txHash.String())
		log.Info("txpool check coinbase tx.", "info", str)
		return nil, nil, nil
	}
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	p_tx := TxtoTxpoolTx(pool, tx)
	err = pool.checkPoolDoubleSpend(p_tx)
	if err != nil {
		log.Info("txpool check PoolDoubleSpend", "error", err, "p_tx", txHash.String())
		return nil, nil, err
	}
	_, err1 := pool.add(p_tx, !pool.config.NoLocals)
	log.Debug("accepted tx and add pool.", "info", err1)
	// NOTE: if you modify this code to accept non-standard transactions,
	return nil, nil, err
}

// addTx enqueues a single transaction into the pool if it is valid.
func (pool *TxPool) addTx(tx *modules.TxPoolTransaction, local bool) error {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	log.Debugf("Try to add tx[%s] to txpool local:%t", tx.Tx.Hash().String(), local)
	// Try to inject the transaction and update any state
	replace, err := pool.add(tx, local)
	if err != nil {
		return err
	}
	// If we added a new transaction, run promotion checks and return
	if !replace {
		pool.promoteExecutables()
	}
	return nil
}

// addTxs attempts to queue a batch of transactions if they are valid.
func (pool *TxPool) addTxs(txs []*modules.TxPoolTransaction, local bool) []error {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	return pool.addTxsLocked(txs, local)
}

// addTxsLocked attempts to queue a batch of transactions if they are valid,
// whilst assuming the transaction pool lock is already held.
func (pool *TxPool) addTxsLocked(txs []*modules.TxPoolTransaction, local bool) []error {
	// Add the batch of transaction, tracking the accepted ones
	errs := make([]error, len(txs))
	var replace bool
	for i, tx := range txs {
		if replace, errs[i] = pool.add(tx, local); errs[i] != nil {
			break
		}
	}

	if !replace {
		pool.promoteExecutables()
	}
	return errs
}

type TxStatus uint

const (
	TxStatusNotIncluded TxStatus = iota
	TxStatusIncluded
	TxStatusQueued
	TxStatusPending
	TxStatusConfirmed
	TxStatusUnKnow
)

// Status returns the status (unknown/pending/queued) of a batch of transactions
// identified by their hashes.
func (pool *TxPool) Status(hashes []common.Hash) []TxStatus {
	status := make([]TxStatus, len(hashes))
	poolTxs := pool.AllTxpoolTxs()
	for i, hash := range hashes {
		if tx, has := poolTxs[hash]; has {
			if tx != nil {
				if tx.Pending {
					status[i] = TxStatusPending
				} else if tx.Confirmed {
					status[i] = TxStatusConfirmed
				} else if !tx.Discarded {
					status[i] = TxStatusQueued
				} else {
					status[i] = TxStatusIncluded
				}
			} else {
				status[i] = TxStatusUnKnow
			}
		} else {
			status[i] = TxStatusNotIncluded
		}
	}
	return status
}

// GetPoolTxsByAddr returns all tx by addr.
func (pool *TxPool) GetPoolTxsByAddr(addr string) ([]*modules.TxPoolTransaction, error) {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	return pool.getPoolTxsByAddr(addr)
}

func (pool *TxPool) getPoolTxsByAddr(addr string) ([]*modules.TxPoolTransaction, error) {
	txs := make(map[string][]*modules.TxPoolTransaction)
	// 将交易按地址分类
	poolTxs := pool.AllTxpoolTxs()
	for _, tx := range poolTxs {
		if !tx.Confirmed {
			for _, msg := range tx.Tx.Messages() {
				if msg.App == modules.APP_PAYMENT {
					payment, ok := msg.Payload.(*modules.PaymentPayload)
					if ok {
						if addrs, err := pool.unit.GetTxFromAddress(tx.Tx); err == nil {
							for _, addr := range addrs {
								addr1 := addr.String()
								txs[addr1] = append(txs[addr1], tx)
							}
						}
						for _, out := range payment.Outputs {
							address, err1 := tokenengine.GetAddressFromScript(out.PkScript[:])
							if err1 == nil {
								txs[address.String()] = append(txs[address.String()], tx)
							} else {
								log.Error("PKSCript to address failed.", "error", err1)
							}
						}
					}
				}
			}
		}
	}
	orphans := pool.AllOrphanTxs()
	for or_hash, tx := range orphans {
		if _, exist := pool.all.Load(or_hash); exist {
			continue
		}
		for _, msg := range tx.Tx.Messages() {
			if msg.App == modules.APP_PAYMENT {
				payment, ok := msg.Payload.(*modules.PaymentPayload)
				if ok {
					if addrs, err := pool.unit.GetTxFromAddress(tx.Tx); err == nil {
						for _, addr := range addrs {
							addr1 := addr.String()
							txs[addr1] = append(txs[addr1], tx)
						}
					}
					for _, out := range payment.Outputs {
						address, err1 := tokenengine.GetAddressFromScript(out.PkScript[:])
						if err1 == nil {
							txs[address.String()] = append(txs[address.String()], tx)
						} else {
							log.Error("PKSCript to address failed.", "error", err1)
						}
					}
				}
			}
		}
	}
	result := make([]*modules.TxPoolTransaction, 0)
	if re, has := txs[addr]; has {
		for i, tx := range re {
			if i == 0 {
				result = append(result, tx)
			} else {
				var exist bool
				for _, old := range result {
					if old.Tx.Hash() == tx.Tx.Hash() {
						exist = true
						break
					}
				}
				if !exist {
					result = append(result, tx)
				}
			}
		}
		return result, nil
	}
	return result, nil //nil, errors.New(fmt.Sprintf("not found txs by addr:(%s).", addr))
}

// Get returns a transaction if it is contained in the pool
// and nil otherwise.
func (pool *TxPool) Get(hash common.Hash) (*modules.TxPoolTransaction, common.Hash) {
	var u_hash common.Hash
	tx := new(modules.TxPoolTransaction)
	interTx, has := pool.all.Load(hash)
	if has {
		tx = interTx.(*modules.TxPoolTransaction)
		if tx.Tx.Hash() != hash {
			pool.all.Delete(hash)
			pool.priority_sorted.Removed()
			return nil, u_hash
		}
		if tx.Pending {
			log.Debug("get tx info by hash in txpool... tx in unit hash:", "unit_hash", tx.UnitHash, "p_tx", tx)
			return tx, tx.UnitHash
		}
		return tx, u_hash
	} else {
		if itx, exist := pool.orphans.Load(hash); exist {
			tx := itx.(*modules.TxPoolTransaction)
			log.Debug("get tx info by hash in orphan txpool... ", "txhash", tx.Tx.Hash(), "info", tx)
			return tx, u_hash
		}
	}
	return tx, u_hash
}

// DeleteTx
func (pool *TxPool) DeleteTx() error {
	txs := pool.AllTxpoolTxs()
	for hash, tx := range txs {
		if tx.Discarded {
			// delete Discarded tx
			log.Debug("delete the status of Discarded tx.", "tx_hash", hash.String())
			pool.DeleteTxByHash(hash)
			continue
		}
		if tx.Confirmed {
			if tx.CreationDate.Add(pool.config.Removetime).Before(time.Now()) {
				// delete
				log.Debug("delete the confirmed tx.", "tx_hash", hash)
				pool.DeleteTxByHash(hash)
				continue
			}
		}
		if tx.CreationDate.Add(pool.config.Lifetime).Before(time.Now()) {
			// delete
			log.Debug("delete the tx(overtime).", "tx_hash", hash)
			pool.DeleteTxByHash(hash)
			continue
		}
	}
	return nil
}

func (pool *TxPool) DeleteTxByHash(hash common.Hash) error {
	inter, has := pool.all.Load(hash)
	if !has {
		return errors.New(fmt.Sprintf("the tx(%s) isn't exist in pool.", hash.String()))
	}
	tx := inter.(*modules.TxPoolTransaction)
	pool.all.Delete(hash)
	pool.priority_sorted.Removed()

	if tx != nil {
		for i, msg := range tx.Tx.Messages() {
			if msg.App == modules.APP_PAYMENT {
				payment, ok := msg.Payload.(*modules.PaymentPayload)
				if ok {
					for _, input := range payment.Inputs {
						if input.PreviousOutPoint == nil {
							continue
						}
						go pool.outpoints.Delete(*input.PreviousOutPoint)
					}
					// delete outputs's utxo
					preout := modules.OutPoint{TxHash: hash}
					for j := range payment.Outputs {
						preout.MessageIndex = uint32(i)
						preout.OutIndex = uint32(j)
						go pool.deleteOrphanTxOutputs(preout)
					}
				}
			}
		}
	}
	return nil
}

// removeTx removes a single transaction from the queue, moving all subsequent
// transactions back to the future queue.
func (pool *TxPool) removeTx(hash common.Hash) {
	// Fetch the transaction we wish to delete
	interTx, has := pool.all.Load(hash)
	if !has {
		return
	}
	tx, ok := interTx.(*modules.TxPoolTransaction)
	if !ok {
		return
	}
	// Remove it from the list of known transactions
	// pool.priority_sorted.Removed(hash)
	tx.Confirmed = true
	pool.all.Store(hash, tx)

	for i, msg := range tx.Tx.Messages() {
		if msg.App == modules.APP_PAYMENT {
			payment, ok := msg.Payload.(*modules.PaymentPayload)
			if ok {
				for _, input := range payment.Inputs {
					// 排除手续费的输入为nil
					if input.PreviousOutPoint != nil {
						go pool.outpoints.Delete(*input.PreviousOutPoint)
					}
				}
				// delete outputs's utxo
				preout := modules.OutPoint{TxHash: hash}
				for j := range payment.Outputs {
					preout.MessageIndex = uint32(i)
					preout.OutIndex = uint32(j)
					pool.deleteOrphanTxOutputs(preout)
				}
			}
		}
	}
}
func (pool *TxPool) RemoveTxs(hashs []common.Hash) {
	for _, hash := range hashs {
		pool.removeTx(hash)
	}
}

func (pool *TxPool) removeTransaction(tx *modules.TxPoolTransaction, removeRedeemers bool) {
	hash := tx.Tx.Hash()
	if removeRedeemers {
		// Remove any transactions whitch rely on this one.
		for i, msgcopy := range tx.Tx.TxMessages {
			if msgcopy.App == modules.APP_PAYMENT {
				if msg, ok := msgcopy.Payload.(*modules.PaymentPayload); ok {
					for j := uint32(0); j < uint32(len(msg.Outputs)); j++ {
						preout := modules.OutPoint{TxHash: hash, MessageIndex: uint32(i), OutIndex: j}
						if pooltxRedeemer, exist := pool.outpoints.Load(preout); exist {
							pool.removeTransaction(pooltxRedeemer.(*modules.TxPoolTransaction), true)
						}
					}
				}
			}
		}
	}
	// Remove the transaction if needed.
	interTx, has := pool.all.Load(hash)
	if !has {
		return
	}
	if pooltx, ok := interTx.(*modules.TxPoolTransaction); ok {
		// mark the referenced outpoints as unspent by the pool.
		for _, msgcopy := range pooltx.Tx.TxMessages {
			if msgcopy.App == modules.APP_PAYMENT {
				if msg, ok := msgcopy.Payload.(*modules.PaymentPayload); ok {
					for _, input := range msg.Inputs {
						go pool.outpoints.Delete(*input.PreviousOutPoint)
					}
				}
			}
		}
		tx.Discarded = true
		pool.all.Store(hash, tx)
		//pool.priority_sorted.Removed(hash)
	}
}
func (pool *TxPool) RemoveTransaction(hash common.Hash, removeRedeemers bool) {
	if interTx, has := pool.all.Load(hash); has {
		go pool.removeTransaction(interTx.(*modules.TxPoolTransaction), removeRedeemers)
	} else {
		go pool.removeTx(hash)
	}
}

// RemoveDoubleSpends removes all transactions whitch spend outpoints spent by the passed
// transaction from the memory pool. Removing those transactions then leads to removing all
// transaction whitch rely on them, recursively. This is necessary when a blocks is connected
// to the main chain because the block may contain transactions whitch were previously unknow to
// the memory pool.
func (pool *TxPool) RemoveDoubleSpends(tx *modules.Transaction) {
	for _, msg := range tx.TxMessages {
		if msg.App == modules.APP_PAYMENT {
			inputs := msg.Payload.(*modules.PaymentPayload)
			for _, input := range inputs.Inputs {
				if tx, ok := pool.outpoints.Load(*input.PreviousOutPoint); ok {
					ptx := tx.(*modules.TxPoolTransaction)
					go pool.removeTransaction(ptx, true)
				}
			}
		}
	}
}

func (pool *TxPool) checkPoolDoubleSpend(tx *modules.TxPoolTransaction) error {
	for _, msg := range tx.Tx.TxMessages {
		if msg.App == modules.APP_PAYMENT {
			inputs, ok := msg.Payload.(*modules.PaymentPayload)
			if !ok {
				continue
			}
			if inputs != nil {
				for _, input := range inputs.Inputs {
					if input == nil {
						break
					}

					if _, err := pool.OutPointIsSpend(input.PreviousOutPoint); err != nil {
						return err
					}
				}
			}
		}
	}

	return nil
}

func (pool *TxPool) OutPointIsSpend(outPoint *modules.OutPoint) (bool, error) {
	if tx, ok := pool.outpoints.Load(*outPoint); ok {
		str := fmt.Sprintf("output %v already spent by "+
			"transaction %x in the txpool",
			outPoint, tx.(*modules.TxPoolTransaction).Tx.Hash())
		return true, errors.New(str)
	}
	return false, nil
}

// CheckSpend checks whether the passed outpoint is already spent by a transaction in the txpool
func (pool *TxPool) CheckSpend(output modules.OutPoint) *modules.Transaction {
	tx, has := pool.outpoints.Load(output)
	if has {
		return tx.(*modules.TxPoolTransaction).Tx
	}
	return nil
}
func (pool *TxPool) GetUtxoView(tx *modules.Transaction) (*UtxoViewpoint, error) {
	neededSet := make(map[modules.OutPoint]struct{})

	for _, msgcopy := range tx.TxMessages {
		if msgcopy.App == modules.APP_PAYMENT {
			if msg, ok := msgcopy.Payload.(*modules.PaymentPayload); ok {
				if !msg.IsCoinbase() {
					for _, in := range msg.Inputs {
						neededSet[*in.PreviousOutPoint] = struct{}{}
					}
				}
			}
		}
	}

	view := NewUtxoViewpoint()
	err := view.FetchUtxos(pool, neededSet)
	return view, err
}

func (pool *TxPool) FetchInputUtxos(tx *modules.Transaction) (*UtxoViewpoint, error) {
	utxoView, err := pool.GetUtxoView(tx)
	if err != nil {
		fmt.Println("getUtxoView is error,", err)
		return nil, err
	}
	// spent input utxo, and add output utxo.
	for _, utxo := range utxoView.entries {
		utxo.Spend()
	}
	// Attempt to populate any missing inputs from the transaction pool.
	for i, msgcopy := range tx.TxMessages {
		if msgcopy.App == modules.APP_PAYMENT {
			if msg, ok := msgcopy.Payload.(*modules.PaymentPayload); ok {
				for _, txIn := range msg.Inputs {
					preout := txIn.PreviousOutPoint
					utxo := utxoView.LookupUtxo(*preout)
					if utxo != nil && utxo.IsSpent() {
						continue
					}
					// attempt to populate any missing inputs form the tx pool.
					if pooltx, exist := pool.all.Load(preout.TxHash); exist {
						this := pooltx.(*modules.TxPoolTransaction)
						utxoView.AddTxOut(this.Tx, uint32(i), preout.OutIndex)
					}
				}
			}
		}
	}
	return utxoView, nil
}

// promoteExecutables moves transactions that have become processable from the
// future queue to the set of pending transactions. During this process, all
// invalidated transactions (low nonce, low balance) are deleted.
func (pool *TxPool) promoteExecutables() {
	// If the pending limit is overflown, start equalizing allowances
	pendingTxs := make([]*modules.TxPoolTransaction, 0)
	poolTxs := pool.AllTxpoolTxs()
	for _, tx := range poolTxs {
		if !tx.Pending {
			pendingTxs = append(pendingTxs, tx)
		}
	}
	pending := len(pendingTxs)
	if uint64(pending) > pool.config.GlobalSlots {
		// Assemble a spam order to penalize large transactors first
		spammers := prque.New()
		for i, tx := range pendingTxs {
			// Only evict transactions from high rollers
			spammers.Push(tx.Tx.Hash(), float32(i))
		}
		// Gradually drop transactions from offenders
		offenders := []common.Hash{}
		for uint64(pending) > pool.config.GlobalSlots && !spammers.Empty() {
			// Retrieve the next offender if not local address
			offender, _ := spammers.Pop()
			offenders = append(offenders, offender.(common.Hash))

			// Equalize balances until all the same or below threshold
			if len(offenders) > 1 {
				// Iteratively reduce all offenders until below limit or threshold reached
				for uint64(pending) > pool.config.GlobalSlots {
					for i := 0; i < len(offenders)-1; i++ {
						for _, tx := range pendingTxs {
							hash := tx.Tx.Hash()
							if offenders[i].String() == hash.String() {
								// Drop the transaction from the global pools too
								pool.all.Delete(hash)
								pool.priority_sorted.Removed()
								log.Trace("Removed fairness-exceeding pending transaction", "hash", hash)
								pending--
								break
							}
						}
					}
				}
			}
		}
		// If still above threshold, reduce to limit or min allowance
		if uint64(pending) > pool.config.GlobalSlots && len(offenders) > 0 {
			for uint64(pending) > pool.config.GlobalSlots {
				for _, addr := range offenders {
					for _, tx := range pendingTxs {
						hash := tx.Tx.Hash()
						if addr.String() == hash.String() {
							pool.all.Delete(hash)
							pool.priority_sorted.Removed()
							log.Trace("Removed fairness-exceeding pending transaction", "hash", hash)
							pending--
							break
						}
					}
				}
			}
		}
	}
}

// demoteUnexecutables removes invalid and processed transactions from the pools
// executable/pending queue and any subsequent transactions that become unexecutable
// are moved back into the future queue.
func (pool *TxPool) demoteUnexecutables() {
	// Iterate over all accounts and demote any non-executable transactions
	pool.all.Range(func(k, v interface{}) bool {
		if tx, ok := v.(*modules.TxPoolTransaction); tx == nil || !ok {
			pool.all.Delete(k)
			pool.priority_sorted.Removed()
		}
		return true
	})
}

// Stop terminates the transaction pool.
func (pool *TxPool) Stop() {
	pool.scope.Close()
	// Unsubscribe subscriptions registered from blockchain
	// pool.chainHeadSub.Unsubscribe()
	// pool.wg.Wait()
	if pool.journal != nil {
		pool.journal.close()
	}
	log.Info("Transaction pool stopped")
}

func (pool *TxPool) SendStoredTxs(hashs []common.Hash) error {
	pool.RemoveTxs(hashs)
	return nil
}

// 打包后的没有被最终确认的交易，废弃处理
func (pool *TxPool) DiscardTxs(hashs []common.Hash) error {
	for _, hash := range hashs {
		err := pool.discardTx(hash)
		if err != nil {
			return err
		}
	}
	return nil
}
func (pool *TxPool) DiscardTx(hash common.Hash) error {
	return pool.discardTx(hash)
}
func (pool *TxPool) discardTx(hash common.Hash) error {
	if pool.isTransactionInPool(hash) {
		// in orphan pool
		if pool.isOrphanInPool(hash) {
			interOtx, has := pool.orphans.Load(hash)
			if has {
				otx := interOtx.(*modules.TxPoolTransaction)
				otx.Discarded = true
				pool.orphans.Store(hash, otx)
			}
		}
		// in all pool
		interTx, has := pool.all.Load(hash)
		if has {
			tx := interTx.(*modules.TxPoolTransaction)
			tx.Discarded = true
			pool.all.Store(hash, tx)
		}
	}
	// not in pool
	return nil
}
func (pool *TxPool) SetPendingTxs(unit_hash common.Hash, txs []*modules.Transaction) error {
	for _, tx := range txs {
		if tx.Messages()[0].Payload.(*modules.PaymentPayload).IsCoinbase() {
			continue
		}
		err := pool.setPendingTx(unit_hash, tx)
		if err != nil {
			return err
		}
	}
	if len(txs) > 0 {
		pool.priority_sorted.Removed()
	}
	return nil
}
func (pool *TxPool) setPendingTx(unit_hash common.Hash, tx *modules.Transaction) error {
	hash := tx.Hash()
	if pool.isTransactionInPool(hash) {
		// in orphan pool
		if pool.isOrphanInPool(hash) {
			interOtx, _ := pool.orphans.Load(hash)
			otx := interOtx.(*modules.TxPoolTransaction)
			otx.Pending = true
			otx.Confirmed = false
			otx.Discarded = false
			otx.IsOrphan = true
			pool.orphans.Store(hash, otx)
		} else {
			// in all pool
			interTx, _ := pool.all.Load(hash)
			tx := interTx.(*modules.TxPoolTransaction)
			tx.Pending = true
			tx.Confirmed = false
			tx.Discarded = false
			pool.all.Store(hash, tx)
			return nil
		}
	}
	// add in pool
	p_tx := TxtoTxpoolTx(pool, tx)
	// 将该交易的输入输出缓存到交易池
	pool.addCache(p_tx)
	pool.promoteTx(unit_hash, p_tx)
	return nil
}
func (pool *TxPool) addCache(tx *modules.TxPoolTransaction) {
	if tx == nil {
		return
	}
	for i, msgcopy := range tx.Tx.TxMessages {
		if msgcopy.App == modules.APP_PAYMENT {
			if msg, ok := msgcopy.Payload.(*modules.PaymentPayload); ok {
				for _, txin := range msg.Inputs {
					if txin.PreviousOutPoint != nil {
						pool.outpoints.Store(*txin.PreviousOutPoint, tx)
					}
				}
				// add  outputs
				preout := modules.OutPoint{TxHash: tx.Tx.Hash()}
				for j, out := range msg.Outputs {
					preout.MessageIndex = uint32(i)
					preout.OutIndex = uint32(j)
					utxo := &modules.Utxo{Amount: out.Value, Asset: &modules.Asset{out.Asset.AssetId, out.Asset.UniqueId},
						PkScript: out.PkScript[:]}
					pool.outputs.Store(preout, utxo)
				}
			}
		}
	}
}
func (pool *TxPool) ResetPendingTxs(txs []*modules.Transaction) error {
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	for _, tx := range txs {
		if tx.TxMessages[0].Payload.(*modules.PaymentPayload).IsCoinbase() {
			continue
		}
		pool.resetPendingTx(tx)
	}
	return nil
}
func (pool *TxPool) resetPendingTx(tx *modules.Transaction) error {
	hash := tx.Hash()
	err := pool.DeleteTxByHash(hash)
	if err != nil {
		log.Info(err.Error())
	}
	pool.add(TxtoTxpoolTx(pool, tx), !pool.config.NoLocals)
	return nil
}

/******  end utxoSet  *****/
// GetSortedTxs returns 根据优先级返回list
func (pool *TxPool) GetSortedTxs(hash common.Hash) ([]*modules.TxPoolTransaction, common.StorageSize) {
	t0 := time.Now()
	var total common.StorageSize
	list := make([]*modules.TxPoolTransaction, 0)

	// get sequenTxs
	stxs := pool.GetSequenTxs()
	pool.mu.RLock()
	defer pool.mu.RUnlock()
	poolTxs := pool.AllTxpoolTxs()
	orphanTxs := pool.AllOrphanTxs()
	unit_size := common.StorageSize(dagconfig.DagConfig.UnitTxSize)
	for _, tx := range stxs {
		list = append(list, tx)
		total += tx.Tx.Size()
	}
	for {
		if time.Since(t0) > time.Second*2 {
			log.Infof("get sorted timeout spent times: %s , count: %d ", time.Since(t0), len(list))
			break
		}
		if total >= unit_size {
			break
		}
		tx := pool.priority_sorted.Get()
		if tx == nil {
			log.Infof("The task of txspool get priority_pricedtx has been finished,count:%d", len(list))
			break
		} else {
			if !tx.Pending {
				if has, _ := pool.unit.IsTransactionExist(tx.Tx.Hash()); has {
					continue
				}
				// add precusorTxs 获取该交易的前驱交易列表
				p_txs, _ := pool.getPrecusorTxs(tx, poolTxs, orphanTxs)
				if len(p_txs) > 0 {
					for _, ptx := range p_txs {
						if has, _ := pool.unit.IsTransactionExist(ptx.Tx.Hash()); !has {
							list = append(list, ptx)
							total += ptx.Tx.Size()
						}
					}
				}
				list = append(list, tx)
				total += tx.Tx.Size()
			}
		}
	}
	t2 := time.Now()
	//  验证孤儿交易
	or_list := make(orList, 0)
	for _, tx := range orphanTxs {
		or_list = append(or_list, tx)
	}
	// 按入池时间排序
	if len(or_list) > 1 {
		sort.Sort(or_list)
	}
	for _, tx := range or_list {
		txhash := tx.Tx.Hash()
		if has, _ := pool.unit.IsTransactionExist(txhash); has {
			go pool.orphans.Delete(txhash)
			continue
		}
		ok, err := pool.ValidateOrphanTx(tx.Tx)
		if !ok && err == nil {
			//  更改孤儿交易的状态
			tx.Pending = true
			tx.UnitHash = hash
			go pool.all.Store(txhash, tx)
			go pool.orphans.Delete(txhash)
			//pool.orphans.Store(tx.Tx.Hash(), tx)
			list = append(list, tx)
			total += tx.Tx.Size()
			if total > unit_size {
				break
			}
		}
	}

	// 	去重
	m := make(map[common.Hash]*modules.TxPoolTransaction)
	indexL := make(map[int]common.Hash)
	for i, tx := range list {
		hash := tx.Tx.Hash()
		tx.Index = i
		indexL[i] = hash
		m[hash] = tx
	}
	list = make([]*modules.TxPoolTransaction, 0)
	for i := 0; i < len(indexL); i++ {
		hash, _ := indexL[i]
		if tx, has := m[hash]; has {
			delete(m, hash)
			list = append(list, tx)
			go pool.promoteTx(hash, tx)
		}
	}
	// if time.Since(t2) > time.Second*1 {
	log.Infof("get sorted and rm Orphan txs spent times: %s , count: %d ,t2: %s , txs_size %s,  total_size %s", time.Since(t0), len(list), time.Since(t2), total.String(), unit_size.String())

	return list, total
}
func (pool *TxPool) getPrecusorTxs(tx *modules.TxPoolTransaction, poolTxs, orphanTxs map[common.Hash]*modules.TxPoolTransaction) ([]*modules.TxPoolTransaction, error) {
	pretxs := make([]*modules.TxPoolTransaction, 0)
	for _, msg := range tx.Tx.Messages() {
		if msg.App == modules.APP_PAYMENT {
			payment, ok := msg.Payload.(*modules.PaymentPayload)
			if ok {
				for _, input := range payment.Inputs {
					if input.PreviousOutPoint != nil {
						utxo, err := pool.GetUtxoEntry(input.PreviousOutPoint)
						if utxo.IsSpent() {
							continue
						}
						if err != nil { //  若该utxo在db里找不到
							queue_tx, has := poolTxs[input.PreviousOutPoint.TxHash]
							queue_otx, has1 := orphanTxs[input.PreviousOutPoint.TxHash]
							if !has || queue_tx == nil {
								if has1 {
									queue_tx = queue_otx
								} else {
									continue
								}
							}
							if !queue_tx.Pending {
								list, _ := pool.getPrecusorTxs(queue_tx, poolTxs, orphanTxs)
								if len(list) > 0 {
									pretxs = append(pretxs, list...)
								}
								pretxs = append(pretxs, queue_tx)
							}
						}
					}
				}
			}
		}
	}
	return pretxs, nil
}

//func (pool *TxPool) GetSequenTx() *modules.TxPoolTransaction {
//	pool.mu.Lock()
//	defer pool.mu.Unlock()
//	return pool.sequenTxs.Get()
//}
func (pool *TxPool) GetSequenTxs() []*modules.TxPoolTransaction {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	return pool.getSequenTxs()
}
func (pool *TxPool) getSequenTxs() []*modules.TxPoolTransaction {
	return pool.sequenTxs.All()
}

type orList []*modules.TxPoolTransaction

func (ol orList) Len() int {
	return len(ol)
}
func (ol orList) Swap(i, j int) {
	ol[i], ol[j] = ol[j], ol[i]
}
func (ol orList) Less(i, j int) bool {
	return ol[i].CreationDate.Unix() < ol[j].CreationDate.Unix()
}

// SubscribeTxPreEvent registers a subscription of TxPreEvent and
// starts sending event to the given channel.
func (pool *TxPool) SubscribeTxPreEvent(ch chan<- modules.TxPreEvent) event.Subscription {
	return pool.scope.Track(pool.txFeed.Subscribe(ch))
}

func (pool *TxPool) GetTxFee(tx *modules.Transaction) (*modules.AmountAsset, error) {
	return tx.GetTxFee(pool.GetUtxoEntry, time.Now().Unix())
}

func (pool *TxPool) limitNumberOrphans() error {
	// scan the orphan pool and remove any expired orphans when it's time.
	orphanTxs := pool.AllOrphanTxs()
	if now := time.Now(); now.After(pool.nextExpireScan) {
		originNum := len(orphanTxs)
		for _, tx := range orphanTxs {
			if now.After(tx.Expiration) {
				// remove
				pool.removeOrphan(tx, true)
			}
			ok, err := pool.ValidateOrphanTx(tx.Tx)
			if !ok && err == nil {
				pool.add(tx, !pool.config.NoLocals)
			}
		}
		// set next expireScan
		pool.nextExpireScan = time.Now().Add(pool.config.OrphanTTL)
		numOrphans := len(pool.AllOrphanTxs())

		if numExpied := originNum - numOrphans; numExpied > 0 {
			log.Debug(fmt.Sprintf("Expired %d %s (remaining: %d)", numExpied, pickNoun(numExpied,
				"orphan", "orphans"), numOrphans))
		}
	}
	// nothing to do if adding another orphan will not cause the pool to exceed the limit
	if len(pool.AllOrphanTxs())+1 <= pool.config.MaxOrphanTxs {
		return nil
	}

	// remove a random entry from the map.
	for _, tx := range orphanTxs {
		pool.removeOrphan(tx, false)
		break
	}
	return nil
}

// pickNoun returns the singular or plural form of a noun depending
// on the count n.
func pickNoun(n int, singular, plural string) string {
	if n == 1 {
		return singular
	}
	return plural
}

// maybeAddOrphan potentially adds an orphan to the orphan pool.
//
// This function MUST be called with the mempool lock held (for writes).
func (pool *TxPool) maybeAddOrphan(tx *modules.TxPoolTransaction, tag uint64) error {
	// orphan tx 不能超出交易池大小限制
	size := tx.Tx.SerializeSize()
	if size > pool.config.MaxOrphanTxSize {
		str := fmt.Sprintf("orphan transaction size of %d bytes is "+
			"larger than max allowed size of %d bytes",
			size, pool.config.MaxOrphanTxSize)
		return errors.New(str)
	}
	pool.addOrphan(tx, tag)
	return nil
}
func (pool *TxPool) addOrphan(otx *modules.TxPoolTransaction, tag uint64) {
	if pool.config.MaxOrphanTxs <= 0 {
		return
	}

	//pool.limitNumberOrphans()

	otx.Expiration = otx.CreationDate.Add(pool.config.OrphanTTL)
	otx.Tag = tag
	otx.IsOrphan = true
	pool.orphans.Store(otx.Tx.Hash(), otx)

	for i, msg := range otx.Tx.Messages() {
		if msg.App == modules.APP_PAYMENT {
			payment, ok := msg.Payload.(*modules.PaymentPayload)
			if ok {
				// add utxo in outputs
				preout := modules.OutPoint{TxHash: otx.Tx.Hash()}
				for j, out := range payment.Outputs {
					preout.MessageIndex = uint32(i)
					preout.OutIndex = uint32(j)
					utxo := &modules.Utxo{Amount: out.Value, Asset: &modules.Asset{out.Asset.AssetId, out.Asset.UniqueId},
						PkScript: out.PkScript[:]}
					pool.outputs.Store(preout, utxo)
					/*	pool.outputs[preout] = utxo*/
				}
				log.Debugf("Stored orphan tx's hash:[%s] (total: %d)", otx.Tx.Hash().String(), len(pool.AllOrphanTxs()))
			}
		}
	}
}

func (pool *TxPool) removeOrphan(tx *modules.TxPoolTransaction, reRedeemers bool) {
	hash := tx.Tx.Hash()
	orphanTxs := pool.AllOrphanTxs()
	otx, has := orphanTxs[hash]
	if !has {
		return
	}

	for _, msg := range otx.Tx.Messages() {
		if msg.App == modules.APP_PAYMENT {
			payment, ok := msg.Payload.(*modules.PaymentPayload)
			if ok {
				for _, in := range payment.Inputs {
					if _, ok := pool.outputs.Load(*in.PreviousOutPoint); ok {
						pool.deleteOrphanTxOutputs(*in.PreviousOutPoint)
					}
				}
			}
		}
	}
	// remove any orphans that redeem outputs from this one if requested.
	if reRedeemers {
		prevOut := modules.OutPoint{TxHash: hash}
		for i, msg := range tx.Tx.Messages() {
			if msg.App == modules.APP_PAYMENT {
				payment, ok := msg.Payload.(*modules.PaymentPayload)
				if ok {
					for j := range payment.Outputs {
						prevOut.MessageIndex = uint32(i)
						prevOut.OutIndex = uint32(j)

						pool.outputs.Delete(prevOut)
					}
				}
			}
		}
	}
	// remove the transaction from the orphan pool.
	pool.orphans.Delete(hash)
}

// This function is safe for concurrent access.
func (pool *TxPool) RemoveOrphan(tx *modules.TxPoolTransaction) {
	pool.mu.Lock()
	pool.removeOrphan(tx, false)
	pool.mu.Unlock()
}

// isOrphanInPool returns whether or not the passed transaction already exists
// in the orphan pool.
//
// This function MUST be called with the mempool lock held (for reads).
func (pool *TxPool) isOrphanInPool(hash common.Hash) bool {
	if _, exists := pool.orphans.Load(hash); exists {
		return true
	}
	return false
}

func (pool *TxPool) IsOrphanInPool(hash common.Hash) bool {
	// Protect concurrent access.
	return pool.isOrphanInPool(hash)

}

// validate tx is an orphanTx or not.
func (pool *TxPool) ValidateOrphanTx(tx *modules.Transaction) (bool, error) {
	// 交易的校验，inputs校验 ,先验证该交易的所有输入utxo是否有效。
	if len(tx.Messages()) <= 0 {
		return false, errors.New("this tx's message is null.")
	}
	var isOrphan bool
	var str string
	var err error
	hash := tx.Hash()
	for _, msg := range tx.Messages() {
		if msg.App == modules.APP_PAYMENT {
			payment, ok := msg.Payload.(*modules.PaymentPayload)
			if ok {
				for _, in := range payment.Inputs {
					if in.PreviousOutPoint != nil {
						utxo, err := pool.GetUtxoEntry(in.PreviousOutPoint)
						if err != nil && err == errors.ErrUtxoNotFound {
							// validate utxo in pool
							_, has := pool.outputs.Load(*in.PreviousOutPoint)
							if !has {
								isOrphan = true
								break
							}

						} else if err != nil && err != errors.ErrUtxoNotFound {
							str = err.Error()
							log.Info("get utxo failed.", "error", str)
							break
						}
						if utxo != nil {
							if utxo.IsModified() {
								str = fmt.Sprintf("the tx: (%s) input utxo:<key:(%s)> is invalide。",
									hash.String(), in.PreviousOutPoint.String())
								log.Info(str)
								break
							} else if utxo.IsSpent() {
								str = fmt.Sprintf("the tx: (%s) input utxo:<key:(%s)> is spent。",
									hash.String(), in.PreviousOutPoint.String())
								log.Info(str)
								break
							}
						}
					}
				}
			}
		}
	}
	if str != "" {
		err = errors.New(str)
		return isOrphan == true, err
	}
	return isOrphan == true, nil
}

func (pool *TxPool) deleteOrphanTxOutputs(outpoint modules.OutPoint) {
	pool.outputs.Delete(outpoint)
}
