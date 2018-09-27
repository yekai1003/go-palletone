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
 *  * @author PalletOne core developer  <dev@pallet.one>
 *  * @date 2018
 *
 */

package storage

import (
	"errors"
	"fmt"
	"github.com/palletone/go-palletone/common"
	"github.com/palletone/go-palletone/common/hexutil"
	"github.com/palletone/go-palletone/common/ptndb"
	"github.com/palletone/go-palletone/common/rlp"
	"github.com/palletone/go-palletone/dag/modules"
	"log"
	"sort"
	"strings"
)

//保存了对合约写集、Config、Asset信息
type StateDatabase struct {
	db ptndb.Database
}

func NewStateDatabase(db ptndb.Database) *StateDatabase {
	return &StateDatabase{db: db}
}

type StateDb interface {
	GetConfig(name []byte) []byte
	GetPrefix(prefix []byte) map[string][]byte
	SaveConfig(confs []modules.PayloadMapStruct, stateVersion *modules.StateVersion) error
	SaveAssetInfo(assetInfo *modules.AssetInfo) error
	GetAssetInfo(assetId *modules.Asset) (*modules.AssetInfo, error)
	SaveContractState(id []byte, name string, value interface{}, version *modules.StateVersion) error
	SaveContractTemplate(templateId []byte, bytecode []byte, version []byte) error
	SaveContractTemplateState(id []byte, name string, value interface{}, version *modules.StateVersion) error
	DeleteState(key []byte) error
	GetContractTpl(templateID []byte) (version *modules.StateVersion, bytecode []byte, name string, path string)
	GetContractState(id string, field string) (*modules.StateVersion, []byte)
	GetTplAllState(id []byte) map[modules.ContractReadSet][]byte
	GetContractAllState(id []byte) map[modules.ContractReadSet][]byte
	GetTplState(id []byte, field string) (*modules.StateVersion, []byte)
	GetContract(id common.Hash) (*modules.Contract, error)
	SaveVote(id []byte, voteData interface{}) error
	SaveMediatorsList(Candidates MediatorCandidates) error
	GetMediatorsList() (MediatorCandidates, error)
	GetActiveMediators(n int) common.Addresses
	GetGlobalProperty() (globalProperty, error)
	SaveGlobalProperty(globalProperty globalProperty) error
	GetDynamicGlobalProperty() (modules.DynamicGlobalProperty, error)
	SaveDynamicGlobalProperty(DynamicGlobalProperty modules.DynamicGlobalProperty) error
	GetMediatorSchedule() (mediatorSchedule, error)
	SaveMediatorSchedule(MediatorSchedule mediatorSchedule) error
}

// ######################### SAVE IMPL START ###########################

func (statedb *StateDatabase) SaveAssetInfo(assetInfo *modules.AssetInfo) error {
	key := assetInfo.Tokey()
	return StoreBytes(statedb.db, key, assetInfo)
}

func (statedb *StateDatabase) SaveContractTemplateState(id []byte, name string, value interface{}, version *modules.StateVersion) error {
	return SaveContractState(statedb.db, CONTRACT_TPL, id, name, value, version)
}
func (statedb *StateDatabase) SaveContractState(id []byte, name string, value interface{}, version *modules.StateVersion) error {
	return SaveContractState(statedb.db, CONTRACT_STATE_PREFIX, id, name, value, version)
}
func (statedb *StateDatabase) DeleteState(key []byte) error {
	return statedb.db.Delete(key)
}

func (statedb *StateDatabase) SaveContractTemplate(templateId []byte, bytecode []byte, version []byte) error {
	key := append(CONTRACT_TPL, templateId...)
	key = append(key, []byte(modules.FIELD_SPLIT_STR)...)
	key = append(key, []byte(modules.FIELD_TPL_BYTECODE)...)
	key = append(key, []byte(modules.FIELD_SPLIT_STR)...)
	key = append(key, version...)
	if err := StoreBytes(statedb.db, key, bytecode); err != nil {
		return err
	}
	return nil
}

/**
保存合约属性信息
To save contract
*/
func SaveContractState(db ptndb.Database, prefix []byte, id []byte, field string, value interface{}, version *modules.StateVersion) error {
	key := []byte{}
	key = append(prefix, id...)
	key = append(key, []byte(modules.FIELD_SPLIT_STR)...)
	key = append(key, []byte(field)...)
	key = append(key, []byte(modules.FIELD_SPLIT_STR)...)
	key = append(key, version.Bytes()...)

	if err := StoreBytes(db, key, value); err != nil {
		log.Println("Save contract template", "error", err.Error())
		return err
	}
	return nil
}

// ######################### SAVE IMPL END ###########################

// ######################### GET IMPL START ###########################

/**
获取模板所有属性
To get contract or contract template all fields and return
*/
func (statedb *StateDatabase) GetTplAllState(id []byte) map[modules.ContractReadSet][]byte {
	// key format: [PREFIX][ID]_[field]_[version]
	key := append(CONTRACT_TPL, id...)
	key = append(key, []byte(modules.FIELD_SPLIT_STR)...)
	data := getprefix(statedb.db, []byte(key))
	if data == nil || len(data) <= 0 {
		return nil
	}
	allState := map[modules.ContractReadSet][]byte{}
	for k, v := range data {
		sKey := strings.Split(k, "^*^")
		if len(sKey) != 3 {
			continue
		}
		var version modules.StateVersion
		if !version.ParseStringKey(k) {
			continue
		}
		rdSet := modules.ContractReadSet{
			Key:   sKey[1],
			Value: &version,
		}
		allState[rdSet] = v
	}
	return allState
}

/**
获取合约（或模板）所有属性
To get contract or contract template all fields and return
*/
func (statedb *StateDatabase) GetContractAllState(id []byte) map[modules.ContractReadSet][]byte {
	// key format: [PREFIX][ID]_[field]_[version]
	key := fmt.Sprintf("%s%s^*^", CONTRACT_STATE_PREFIX, hexutil.Encode(id))
	data := getprefix(statedb.db, []byte(key))
	if data == nil || len(data) <= 0 {
		return nil
	}
	allState := map[modules.ContractReadSet][]byte{}
	for k, v := range data {
		sKey := strings.Split(k, "^*^")
		if len(sKey) != 3 {
			continue
		}
		var version modules.StateVersion
		if !version.ParseStringKey(key) {
			continue
		}
		rdSet := modules.ContractReadSet{
			Key:   sKey[1],
			Value: &version,
		}
		allState[rdSet] = v
	}
	return allState
}

/**
获取合约（或模板）某一个属性
To get contract or contract template one field
*/
func (statedb *StateDatabase) GetTplState(id []byte, field string) (*modules.StateVersion, []byte) {
	//key := fmt.Sprintf("%s%s^*^%s^*^", CONTRACT_TPL, hexutil.Encode(id[:]), field)
	key := append(CONTRACT_TPL, id...)
	key = append(key, []byte(modules.FIELD_SPLIT_STR)...)
	key = append(key, []byte(field)...)
	data := getprefix(statedb.db, []byte(key))
	if data == nil || len(data) != 1 {
		return nil, nil
	}
	for k, v := range data {
		var version modules.StateVersion
		if !version.ParseStringKey(k) {
			return nil, nil
		}
		return &version, v
	}
	return nil, nil
}

/**
获取合约（或模板）某一个属性
To get contract or contract template one field
*/
func (statedb *StateDatabase) GetContractState(id string, field string) (*modules.StateVersion, []byte) {
	key := fmt.Sprintf("%s%s^*^%s^*^", CONTRACT_STATE_PREFIX, id, field)
	data := getprefix(statedb.db, []byte(key))
	if data == nil || len(data) != 1 {
		return nil, nil
	}
	for k, v := range data {
		var version modules.StateVersion
		if !version.ParseStringKey(k) {
			return nil, nil
		}
		return &version, v
	}
	log.Println("11111111")
	return nil, nil
}
func (statedb *StateDatabase) GetAssetInfo(assetId *modules.Asset) (*modules.AssetInfo, error) {
	key := append(modules.ASSET_INFO_PREFIX, assetId.AssetId.String()...)
	data, err := statedb.db.Get(key)
	if err != nil {
		return nil, err
	}

	var assetInfo modules.AssetInfo
	err = rlp.DecodeBytes(data, &assetInfo)

	if err != nil {
		return nil, err
	}
	return &assetInfo, nil
}

// get prefix: return maps
func (db *StateDatabase) GetPrefix(prefix []byte) map[string][]byte {
	return getprefix(db.db, prefix)
}

// GetContract can get a Contract by the contract hash
func (statedb *StateDatabase) GetContract(id common.Hash) (*modules.Contract, error) {
	if common.EmptyHash(id) {
		return nil, errors.New("the filed not defined")
	}
	con_bytes, err := statedb.db.Get(append(CONTRACT_PTEFIX, id[:]...))
	if err != nil {
		log.Println("err:", err)
		return nil, err
	}
	contract := new(modules.Contract)
	err = rlp.DecodeBytes(con_bytes, contract)
	if err != nil {
		log.Println("err:", err)
		return nil, err
	}
	return contract, nil
}

// <<<<< Fengyiran
//get mediatorCandidates ==> sort ==> RETURN specified number of Addresses
func (statedb *StateDatabase) GetActiveMediators(n int) common.Addresses {
	Candidates, err := statedb.GetMediatorsList()
	if err != nil {
		return nil
	}
	return Candidates.GetHeadAddress(n)
}

func (statedb *StateDatabase) GetMediatorsList() (MediatorCandidates, error) {
	Candidates, err := GetDecodedComplexData(statedb.db, MEDIATOR_CANDIDATE_PREFIX, MediatorCandidates{})
	return Candidates.(MediatorCandidates), err
}
func (statedb *StateDatabase) SaveMediatorsList(Candidates MediatorCandidates) error {
	key := MEDIATOR_CANDIDATE_PREFIX
	value := Candidates
	return ErrorLogHandler(StoreBytes(statedb.db, key, value), "SaveMediatorsList")
}

func (statedb *StateDatabase) GetMediatorSchedule() (mediatorSchedule, error) {
	MediatorSchedule, err := GetDecodedComplexData(statedb.db, MEDIATOR_SCHEME_PREFIX, mediatorSchedule{})
	return MediatorSchedule.(mediatorSchedule), err
}
func (statedb *StateDatabase) SaveMediatorSchedule(MediatorSchedule mediatorSchedule) error {
	key := MEDIATOR_SCHEME_PREFIX
	value := MediatorSchedule
	return ErrorLogHandler(StoreBytes(statedb.db, key, value), "SaveMediatorsList")
}

func (statedb *StateDatabase) GetGlobalProperty() (globalProperty, error) {
	gp, err := GetDecodedComplexData(statedb.db, GLOBALPROPERTY_PREFIX, globalProperty{})
	return gp.(globalProperty), err
}
func (statedb *StateDatabase) SaveGlobalProperty(globalProperty globalProperty) error {
	key := GLOBALPROPERTY_PREFIX
	value := globalProperty
	return ErrorLogHandler(StoreBytes(statedb.db, key, value), "SaveGlobalProperty")
}

func (statedb *StateDatabase) GetDynamicGlobalProperty() (modules.DynamicGlobalProperty, error) {
	dgp, err := GetDecodedComplexData(statedb.db, DYNAMIC_GLOBALPROPERTY_PREFIX, modules.DynamicGlobalProperty{})
	return dgp.(modules.DynamicGlobalProperty), err
}
func (statedb *StateDatabase) SaveDynamicGlobalProperty(DynamicGlobalProperty modules.DynamicGlobalProperty) error {
	key := DYNAMIC_GLOBALPROPERTY_PREFIX
	value := DynamicGlobalProperty
	return ErrorLogHandler(StoreBytes(statedb.db, key, value), "SaveDynamicGlobalProperty")
}

func (statedb *StateDatabase) SaveVote(id []byte, vote interface{}) error {
	key := KeyConnector(VOTE_PREFIX, id)
	value := vote
	return ErrorLogHandler(StoreBytes(statedb.db, key, value), "SaveVote")
}

func GetDecodedComplexData(db ptndb.Database, key []byte, dataType interface{}) (interface{}, error) {
	valByte, err := db.Get(key)
	if err != nil {
		return nil, err
	}
	return rlp.GetDecodedFromBytes(valByte, dataType)
}
func ErrorLogHandler(err error, errType string) error {
	if err != nil {
		log.Println(errType, "error", err.Error())
		return err
	}
	return nil
}
func KeyConnector(keys ...[]byte) []byte {
	var res []byte
	for _, key := range keys {
		res = append(res, key...)
	}
	return res
}

type MediatorCandidates []MediatorCandidate
type MediatorCandidate struct {
	Address    common.Address
	VoteNumber VoteNumber
}
type VoteNumber uint64
type StateDBConfig [] StateConfig
type StateConfig struct {
	Prefix []byte
	suffix []byte
}

func (sc StateConfig) HasSuffix() bool {
	return sc.suffix != nil
}
func (ms MediatorCandidates) Swap(i, j int)      { ms[i], ms[j] = ms[j], ms[i] }
func (ms MediatorCandidates) Len() int           { return len(ms) }
func (ms MediatorCandidates) Less(i, j int) bool { return ms[i].VoteNumber > ms[j].VoteNumber }
func (ms MediatorCandidates) GetHeadAddress(n int) common.Addresses {
	if n < 21 {
		log.Println("less mediator number", "error", )
		return nil
	}
	var res common.Addresses
	sort.Sort(ms)
	for i := 0; i < n; i++ {
		res = append(res, ms[i].Address)
	}
	return res
}

// Fengyiran >>>>>

/**
获取合约模板
To get contract template
*/
func (statedb *StateDatabase) GetContractTpl(templateID []byte) (version *modules.StateVersion, bytecode []byte, name string, path string) {
	key := append(CONTRACT_TPL, templateID...)
	key = append(key, []byte(modules.FIELD_SPLIT_STR)...)
	key = append(key, []byte(modules.FIELD_TPL_BYTECODE)...)
	data := statedb.GetPrefix(key)

	if len(data) == 1 {
		for _, v := range data {
			if err := rlp.DecodeBytes(v, &bytecode); err != nil {
				fmt.Println("GetContractTpl when get bytecode", "error", err.Error(), "codeing:", v, "val:", bytecode)
				return
			}
		}
	}

	version, nameByte := statedb.GetTplState(templateID, modules.FIELD_TPL_NAME)
	if nameByte == nil {
		return
	}
	if err := rlp.DecodeBytes(nameByte, &name); err != nil {
		log.Println("GetContractTpl when get name", "error", err.Error())
		return
	}

	_, pathByte := statedb.GetTplState(templateID, modules.FIELD_TPL_PATH)
	if err := rlp.DecodeBytes(pathByte, &path); err != nil {
		log.Println("GetContractTpl when get path", "error", err.Error())
		return
	}
	return
}

// ######################### GET IMPL END ###########################
