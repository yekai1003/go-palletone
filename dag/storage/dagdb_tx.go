/*
 *
 *    This file is part of go-palletone.
 *    go-palletone is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *    go-palletone is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *    You should have received a copy of the GNU General Public License
 *    along with go-palletone.  If not, see <http://www.gnu.org/licenses/>.
 * /
 *
 *  * @author PalletOne core developer <dev@pallet.one>
 *  * @date 2018-2019
 *
 */

package storage

import (
	"errors"

	"github.com/palletone/go-palletone/common"
	"github.com/palletone/go-palletone/common/log"

	"github.com/palletone/go-palletone/dag/constants"
	"github.com/palletone/go-palletone/dag/modules"
)

/**
key: [TRANSACTION_PREFIX][tx hash]
value: transaction struct rlp encoding bytes
*/
func (dagdb *DagDb) SaveTransaction(tx *modules.Transaction) error {
	// save transaction
	txHash := tx.Hash()
	log.Debugf("Try to save tx[%s]", txHash.String())
	//bytes, err := json.Marshal(tx)
	//if err != nil {
	//	return err
	//}

	//str := *(*string)(unsafe.Pointer(&bytes))
	//Save tx to db
	key := append(constants.TRANSACTION_PREFIX, txHash.Bytes()...)
	err := StoreBytes(dagdb.db, key, tx)
	if err != nil {
		log.Errorf("Save tx[%s] error:%s", txHash.Str(), err.Error())
		return err
	}
	//Save reqid
	if tx.IsContractTx() {
		if err := dagdb.saveReqIdByTx(tx); err != nil {
			log.Error("SaveReqIdByTx is failed,", "error", err)
		}
	}
	//Save Address to tx

	//key0 := string(constants.TRANSACTION_PREFIX) + txHash.String()
	//if err := StoreString(dagdb.db, key0, str); err != nil {
	//	return err
	//}
	//key1 := string(constants.Transaction_Index) + txHash.String()
	//if err := StoreString(dagdb.db, key1, str); err != nil {
	//	return err
	//}
	//dagdb.updateAddrTransactions(tx, txHash)
	//// store output by addr
	//for i, msg := range tx.TxMessages {
	//	if msg.App >= modules.APP_CONTRACT_TPL_REQUEST && msg.App <= modules.APP_CONTRACT_STOP_REQUEST {
	//		if err := dagdb.saveReqIdByTx(tx); err != nil {
	//			log.Error("SaveReqIdByTx is failed,", "error", err)
	//		}
	//		continue
	//	}
	//	payload, ok := msg.Payload.(*modules.PaymentPayload)
	//	if ok {
	//		for _, output := range payload.Outputs {
	//			//  pkscript to addr
	//			addr, err := tokenengine.GetAddressFromScript(output.PkScript[:])
	//			if err != nil {
	//				log.Error("GetAddressFromScript is failed,", "error", err)
	//			}
	//			dagdb.saveOutputByAddr(addr.String(), txHash, i, output)
	//		}
	//	}
	//}
	return nil
}
func (dagdb *DagDb) saveReqIdByTx(tx *modules.Transaction) error {
	txhash := tx.Hash()
	reqid := tx.RequestHash()
	log.Debugf("Save RequestId[%s] map to TxId[%s]", reqid.String(), txhash.String())
	key := append(constants.ReqIdPrefix, reqid.Bytes()...)
	return dagdb.db.Put(key, txhash.Bytes())
}

//
//func (dagdb *DagDb) saveOutputByAddr(addr string, hash common.Hash, msgindex int, output *modules.Output) error {
//	if hash == (common.Hash{}) {
//		return errors.New("empty tx hash.")
//	}
//	key := append(constants.AddrOutput_Prefix, []byte(addr)...)
//	key = append(key, []byte(hash.String())...)
//	err := StoreBytes(dagdb.db, append(key, new(big.Int).SetInt64(int64(msgindex)).Bytes()...), output)
//	return err
//}
//
//func (dagdb *DagDb) updateAddrTransactions(tx *modules.Transaction, hash common.Hash) error {
//
//	if hash == (common.Hash{}) {
//		return errors.New("empty tx hash.")
//	}
//	froms, err := dagdb.GetTxFromAddress(tx)
//	if err != nil {
//		return err
//	}
//	// 1. save from_address
//	for _, addr := range froms {
//		go dagdb.saveAddrTxHashByKey(constants.AddrTx_From_Prefix, addr, hash)
//	}
//	// 2. to_address 已经在上层接口处理了。
//	// for _, addr := range tos { // constants.AddrTx_To_Prefix
//	// 	go dagdb.saveAddrTxHashByKey(constants.AddrTx_To_Prefix, addr, hash)
//	// }
//	return nil
//}
//func (dagdb *DagDb) saveAddrTxHashByKey(key []byte, addr string, hash common.Hash) error {
//
//	hashs := make([]common.Hash, 0)
//	data, err := dagdb.db.Get(append(key, []byte(addr)...))
//	if err != nil {
//		if err.Error() != "leveldb: not found" {
//			return err
//		} else { // first store the addr
//			hashs = append(hashs, hash)
//			if err := StoreBytes(dagdb.db, append(key, []byte(addr)...), hashs); err != nil {
//				return err
//			}
//			return nil
//		}
//	}
//	if err := rlp.DecodeBytes(data, &hashs); err != nil {
//		return err
//	}
//	hashs = append(hashs, hash)
//	if err := StoreBytes(dagdb.db, append(key, []byte(addr)...), hashs); err != nil {
//		return err
//	}
//	return nil
//}
//
//// Get income transactions
//func (dagdb *DagDb) GetAddrOutput(addr string) ([]modules.Output, error) {
//
//	data := dagdb.GetPrefix(append(constants.AddrOutput_Prefix, []byte(addr)...))
//	outputs := make([]modules.Output, 0)
//	var err error
//	for _, b := range data {
//		out := new(modules.Output)
//		if err := rlp.DecodeBytes(b, out); err == nil {
//			outputs = append(outputs, *out)
//		} else {
//			err = err
//		}
//	}
//	return outputs, err
//}
//
//func (dagdb *DagDb) GetTxFromAddress(tx *modules.Transaction) ([]string, error) {
//
//	froms := make([]string, 0)
//	if tx == nil {
//		return froms, errors.New("tx is nil, not exist address.")
//	}
//	outpoints, _ := tx.GetAddressInfo()
//	for _, op := range outpoints {
//		addr, err := dagdb.getOutpointAddr(op)
//		if err == nil {
//			froms = append(froms, addr)
//		} else {
//			log.Info("get out address is failed.", "error", err)
//		}
//	}
//
//	return froms, nil
//}
//func (dagdb *DagDb) getOutpointAddr(outpoint *modules.OutPoint) (string, error) {
//	if outpoint == nil {
//		return "", fmt.Errorf("outpoint_key is nil ")
//	}
//	out_key := append(constants.OutPointAddr_Prefix, outpoint.ToKey()...)
//	data, err := dagdb.db.Get(out_key[:])
//	if len(data) <= 0 {
//		return "", fmt.Errorf("address is null. outpoint_key(%s)", outpoint.ToKey())
//	}
//	if err != nil {
//		return "", err
//	}
//	var str string
//	err0 := rlp.DecodeBytes(data, &str)
//	return str, err0
//}

// GetTransaction retrieves a specific transaction from the database , along with its added positional metadata
// p2p 同步区块 分为同步header 和body。 GetBody可以省掉节点包装交易块的过程。
func (dagdb *DagDb) GetTransaction(hash common.Hash) (*modules.Transaction, common.Hash, uint64, uint64) {
	unitHash, unitNumber, txIndex, err1 := dagdb.GetTxLookupEntry(hash)
	if err1 != nil {
		log.Error("dag db GetTransaction", "GetTxLookupEntry err:", err1, "hash:", hash)
		return nil, unitHash, unitNumber, txIndex
	}
	// if unitHash != (common.Hash{}) {
	// 	body, _ := dagdb.GetBody(unitHash)
	// 	if body == nil || len(body) <= int(txIndex) {
	// 		return nil, common.Hash{}, 0, 0
	// 	}
	// 	tx, err := dagdb.gettrasaction(body[txIndex])
	// 	if err == nil {
	// 		return tx, unitHash, unitNumber, txIndex
	// 	}
	// }
	tx, err := dagdb.gettrasaction(hash)
	if err != nil {
		log.Error("gettrasaction error:", err.Error())
		return nil, unitHash, unitNumber, txIndex
	}

	return tx, unitHash, unitNumber, txIndex
}

// gettrasaction can get a transaction by hash.
func (dagdb *DagDb) gettrasaction(hash common.Hash) (*modules.Transaction, error) {
	if hash == (common.Hash{}) {
		return nil, errors.New("hash is not exist.")
	}
	tx := new(modules.Transaction)
	key := append(constants.TRANSACTION_PREFIX, hash.Bytes()...)
	err := retrieve(dagdb.db, key, tx)
	//data, err := getString(dagdb.db, []byte(key))
	if err != nil {
		log.Error("get transaction failed......", "error", err)
		return nil, err
	}
	return tx, nil
	//if err := json.Unmarshal([]byte(data), &tx); err != nil {
	//	log.Error("tx Unmarshal failed......", "error", err, "data:", data)
	//	return nil, err
	//}
	// TODO ---- 将不同msg‘s app 反序列化后赋值给payload interface{}.
	//log.Debug("================== transaction_info======================", "error", err, "transaction_info", tx)
	//msgs, err1 := ConvertMsg(tx)
	//if err1 != nil {
	//	log.Error("tx comvertmsg failed......", "err:", err1, "tx:", tx)
	//	return nil, err1
	//}
	//
	//tx.TxMessages = msgs
	//return tx, err
}

//func (dagdb *DagDb) GetReqIdByTxHash(hash common.Hash) (common.Hash, error) {
//	key := fmt.Sprintf("%s_%s", string(constants.TxHash2ReqPrefix), hash.String())
//	str, err := GetString(dagdb.db, key)
//	return common.HexToHash(str), err
//}

func (dagdb *DagDb) GetTxHashByReqId(reqid common.Hash) (common.Hash, error) {
	key := append(constants.ReqIdPrefix, reqid.Bytes()...)
	txid := common.Hash{}
	val, err := dagdb.db.Get(key)
	if err != nil {
		return txid, err
	}
	txid.SetBytes(val)

	return txid, err
}