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
 * @author PalletOne core developer Albert·Gou <dev@pallet.one>
 * @date 2018
 */

package storage

import (
	"encoding/json"
	"fmt"

	"github.com/palletone/go-palletone/common"
	"github.com/palletone/go-palletone/common/log"
	"github.com/palletone/go-palletone/contracts/syscontract"
	"github.com/palletone/go-palletone/core"
	"github.com/palletone/go-palletone/dag/constants"
	"github.com/palletone/go-palletone/dag/modules"
)

func mediatorKey(address common.Address) []byte {
	//key := append(constants.CONTRACT_STATE_PREFIX, syscontract.DepositContractAddress.Bytes()...)
	//key = append(key, string(constants.MEDIATOR_INFO_PREFIX)+string(address.Bytes())...)
	key := append(constants.MEDIATOR_INFO_PREFIX, address.Bytes()...)

	//log.Debugf("mediatorKey %v", string(key))

	return key
}

func (statedb *StateDb) StoreMediator(med *core.Mediator) error {
	mi := modules.MediatorToInfo(med)
	return statedb.StoreMediatorInfo(med.Address, mi)
}

func (statedb *StateDb) StoreMediatorInfo(add common.Address, mi *modules.MediatorInfo) error {
	//log.Debugf("Store Mediator Info %v", mi.AddStr)

	err := StoreToRlpBytes(statedb.db, mediatorKey(add), mi)
	if err != nil {
		log.Debugf("Store mediator error:%v", err.Error())
		return err
	}

	return nil
}

func (statedb *StateDb) RetrieveMediatorInfo(address common.Address) (*modules.MediatorInfo, error) {
	//data, err := statedb.db.Get(mediatorKey(address))
	//if err != nil {
	//	log.Debugf("Retrieve mediator error: %v", err.Error())
	//	return nil, err
	//}
	//
	//mi := modules.NewMediatorInfo()
	//err = json.Unmarshal(data, mi)
	//if err == nil {
	//	return mi, nil
	//}
	//
	//data, _, err = splitValueAndVersion(data)
	//if err != nil {
	//	log.Debugf("Retrieve mediator splitValueAndVersion error: %v", err.Error())
	//	return nil, err
	//}
	//
	//err = json.Unmarshal(data, mi)
	//if err != nil {
	//	log.Debugf("Retrieve mediator Unmarshal error: %v", err.Error())
	//	return nil, err
	//}

	mi := modules.NewMediatorInfo()
	err := RetrieveFromRlpBytes(statedb.db, mediatorKey(address), mi)
	if err != nil {
		log.Debugf("Retrieve mediator error: %v", err.Error())
		return nil, err
	}

	return mi, nil
}

func (statedb *StateDb) RetrieveMediator(address common.Address) (*core.Mediator, error) {
	mi, err := statedb.RetrieveMediatorInfo(address)
	if err != nil {
		log.Debugf(err.Error())
		return nil, err
	}

	med := mi.InfoToMediator()
	//med.Address = address

	return med, nil
}

func (statedb *StateDb) IsMediator(address common.Address) bool {
	list, err := statedb.getCandidateMediatorList()
	if err != nil {
		return false
	}

	return list[address.String()]
}

func (statedb *StateDb) GetMediators() map[common.Address]bool {
	list, err := statedb.getCandidateMediatorList()
	if err != nil {
		return nil
	}

	res := make(map[common.Address]bool, len(list))
	for addStr, _ := range list {
		add, err := common.StringToAddress(addStr)
		if err != nil {
			log.Debugf(err.Error())
			continue
		}

		res[add] = true
	}

	return res
}

func (statedb *StateDb) LookupMediatorInfo() []*modules.MediatorInfo {
	list, err := statedb.getCandidateMediatorList()
	if err != nil {
		return nil
	}

	result := make([]*modules.MediatorInfo, 0, len(list))
	for addStr, _ := range list {
		add, err := common.StringToAddress(addStr)
		if err != nil {
			log.Debugf(err.Error())
			continue
		}

		med, err := statedb.RetrieveMediatorInfo(add)
		if err != nil {
			continue
		}

		result = append(result, med)
	}

	return result
}

//xiaozhi
func (statedb *StateDb) getCandidateMediatorList() (map[string]bool, error) {
	depositeContractAddress := syscontract.DepositContractAddress
	val, _, err := statedb.GetContractState(depositeContractAddress.Bytes(), modules.MediatorList)
	if err != nil {
		return nil, fmt.Errorf("mediator candidate list is nil")
	}

	candidateList := make(map[string]bool)
	err = json.Unmarshal(val, &candidateList)
	if err != nil {
		return nil, err
	}

	return candidateList, nil
}
