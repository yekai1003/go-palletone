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
 *
 */

package modules

import (
	"fmt"
	"sort"

	"github.com/dedis/kyber"
	"github.com/palletone/go-palletone/common"
	"github.com/palletone/go-palletone/common/log"
	"github.com/palletone/go-palletone/core"
)

// 全局属性的结构体定义
type GlobalProperty struct {
	ChainParameters core.ChainParameters // 区块链网络参数

	ActiveMediators map[common.Address]bool // 当前活跃mediator集合；每个维护间隔更新一次

	GroupPubKey kyber.Point // 群公钥，用于验证群签名；每个维护间隔更新一次
}

// 动态全局属性的结构体定义
type DynamicGlobalProperty struct {
	HeadUnitNum uint64 // 最近的验证单元编号(数量)

	HeadUnitHash common.Hash // 最近的验证单元hash

	// LastVerifiedUnit *v.VerifiedUnit	// 最近生产的验证单元

	HeadUnitTime int64 // 最近的验证单元时间

	// CurrentMediator *common.Address // 当前生产验证单元的mediator, 用于判断是否连续同一个mediator生产验证单元

	// NextMaintenanceTime time.Time // 下一次系统维护时间

	// 当前的绝对时间槽数量，== 从创世开始所有的时间槽数量 == verifiedUnitNum + 丢失的槽数量
	CurrentASlot uint64

	/**
	在过去的128个见证单元生产slots中miss的数量。
	The count of verifiedUnit production slots that were missed in the past 128 verifiedUnits
	用于计算mediator的参与率。used to compute mediator participation.
	*/
	// RecentSlotsFilled float32

	LastIrreversibleUnitNum uint32
}

const TERMINTERVAL = 50 //DEBUG:50, DEPLOY:15000

func (gp *GlobalProperty) GetActiveMediatorCount() int {
	return len(gp.ActiveMediators)
}

func (gp *GlobalProperty) GetCurThreshold() int {
	aSize := gp.GetActiveMediatorCount()
	offset := (core.PalletOne100Percent - core.PalletOneIrreversibleThreshold) * aSize /
		core.PalletOne100Percent

	return aSize - offset
}

func (gp *GlobalProperty) IsActiveMediator(add common.Address) bool {
	return gp.ActiveMediators[add]
}

func (gp *GlobalProperty) GetActiveMediatorAddr(index int) common.Address {
	if index < 0 || index > gp.GetActiveMediatorCount()-1 {
		log.Error(fmt.Sprintf("%v is out of the bounds of active mediator list!", index))
	}

	meds := gp.GetActiveMediators()

	return meds[index]
}

// GetActiveMediators, return the list of active mediators, and the order of the list from small to large
func (gp *GlobalProperty) GetActiveMediators() []common.Address {
	mediators := make([]common.Address, 0, gp.GetActiveMediatorCount())

	for medAdd, _ := range gp.ActiveMediators {
		mediators = append(mediators, medAdd)
	}

	sortAddress(mediators)

	return mediators
}

func sortAddress(adds []common.Address) {
	aSize := len(adds)
	addStrs := make([]string, aSize, aSize)
	for i, add := range adds {
		addStrs[i] = add.Str()
	}

	sort.Strings(addStrs)

	for i, addStr := range addStrs {
		adds[i], _ = common.StringToAddress(addStr)
	}
}

func NewGlobalProp() *GlobalProperty {
	return &GlobalProperty{
		ChainParameters: core.NewChainParams(),
		ActiveMediators: make(map[common.Address]bool, 0),
		GroupPubKey:     core.Suite.Point().Null(),
	}
}

func NewDynGlobalProp() *DynamicGlobalProperty {
	return &DynamicGlobalProperty{
		HeadUnitNum:             0,
		HeadUnitHash:            common.Hash{},
		CurrentASlot:            0,
		LastIrreversibleUnitNum: 0,
	}
}

func InitGlobalProp(genesis *core.Genesis) *GlobalProperty {
	log.Debug("initialize global property...")

	// Create global properties
	gp := NewGlobalProp()

	log.Debug("initialize chain parameters...")
	gp.ChainParameters = genesis.InitialParameters

	log.Debug("Set active mediators...")
	// Set active mediators
	for i := uint16(0); i < genesis.InitialActiveMediators; i++ {
		initMed := genesis.InitialMediatorCandidates[i]
		gp.ActiveMediators[core.StrToMedAdd(initMed.AddStr)] = true
	}

	return gp
}

func InitDynGlobalProp(genesis *core.Genesis, genesisUnitHash common.Hash) *DynamicGlobalProperty {
	log.Debug("initialize dynamic global property...")

	// Create dynamic global properties
	dgp := NewDynGlobalProp()
	dgp.HeadUnitTime = genesis.InitialTimestamp
	dgp.HeadUnitHash = genesisUnitHash

	return dgp
}
