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

package constants

// prefix info
var (
	UNIT_PREFIX             = []byte("ut")  // unit_prefix + mci + hash
	HEADER_PREFIX           = []byte("uh")  // prefix + hash
	HEADER_HEIGTH_PREFIX    = []byte("uht") // prefix + height:hash
	HeaderCanon_Prefix      = []byte("ch")  // Canon Header Prefix
	UNIT_HASH_NUMBER_Prefix = []byte("hn")
	//UNIT_NUMBER_PREFIX          = []byte("nh") // number 和unit hash 的对应关系
	BODY_PREFIX                 = []byte("ub")
	TRANSACTION_PREFIX          = []byte("tx")
	Transaction_Index           = []byte("ti")
	TRANSACTIONS_PREFIX         = []byte("ts")
	AddrTransactionsHash_Prefix = []byte("at")  // to addr  transactions hash prefix
	AddrTx_From_Prefix          = []byte("fat") // from addr transactions hash prefix
	AddrOutput_Prefix           = []byte("ao")  // addr output tx's hash + msg index.
	AddrOutPoint_Prefix         = []byte("ap")  // addr outpoint
	OutPointAddr_Prefix         = []byte("pa")  // outpoint addr
	CONTRACT_STATE_PREFIX       = []byte("cs")
	CONTRACT_TPL                = []byte("ct")
	CONTRACT_TPL_REQ            = []byte("ctq")
	CONTRACT_DEPLOY             = []byte("cdy")
	CONTRACT_DEPLOY_REQ         = []byte("cdr")
	CONTRACT_STOP_REQ           = []byte("csq")
	CONTRACT_INVOKE_REQ         = []byte("ciq")
	CONTRACT_SIgNATURE          = []byte("csn")

	MESSAGES_PREFIX               = []byte("me")
	POLL_PREFIX                   = []byte("po")
	CREATE_VOTE_PREFIX            = []byte("vo")
	ATTESTATION_PREFIX            = []byte("at")
	ASSET_PREFIX                  = []byte("as")
	ASSET_ATTESTORS               = []byte("ae")
	MEDIATOR_INFO_PREFIX          = []byte("mi")
	GLOBALPROPERTY_PREFIX         = []byte("gp")
	DYNAMIC_GLOBALPROPERTY_PREFIX = []byte("dp")
	MEDIATOR_SCHEME_PREFIX        = []byte("ms")
	ACCOUNT_INFO_PREFIX           = []byte("ai")
	CONF_PREFIX                   = []byte("cf")
	// lookup
	LookupPrefix = []byte("l")

	LastStableUnitHash   = []byte("stbu")
	LastUnstableUnitHash = []byte("ustbu")
	HeadUnitHash         = []byte("HeadUnitHash")
	HeadHeaderKey        = []byte("LastHeader")
	HeadFastKey          = []byte("LastFast")
	TrieSyncKey          = []byte("TrieSync")
	GenesisUnitHash      = []byte("GenesisUnitHash")
	// contract
	CONTRACT_PREFIX = []byte("cs")

	// other prefix
	EAENED_HEADERS_COMMISSION = "earned_headers_commossion"
	ALL_UNITS                 = "array_units"
	UTXOSNAPSHOT_PREFIX       = "us"

	// utxo && state storage
	CONTRACT_ATTRI    = []byte("contract") // like contract_[contract address]_[key]
	UTXO_PREFIX       = []byte("uo")
	UTXO_INDEX_PREFIX = []byte("ui")
	ASSET_INFO_PREFIX = []byte("pi") // ACCOUNT_INFO_PREFIX is also "ai"  asset=property

	// token info
	TOKENTYPE  = []byte("tp") // tp[types]
	TOKENINFOS = []byte("tokeninfos")
	// state current chain index
	CURRENTCHAININDEX_PREFIX = "ccix"

	STATE_VOTER_LIST = []byte("vl")

	// ReqId && TxHash maping
	ReqIdPrefix      = []byte("req")
	TxHash2ReqPrefix = []byte("tx2req")

	//filehash
	IDX_FileHash_Txid = []byte("mda")
)

// suffix
var (
	NumberSuffix = []byte("n")
)
