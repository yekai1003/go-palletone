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
 * Copyright IBM Corp. All Rights Reserved.
 * @author PalletOne core developers <dev@pallet.one>
 * @date 2018
 */

//Package deposit implements some functions for deposit contract.
package deposit

import (
	"encoding/json"
	"github.com/palletone/go-palletone/common"
	"github.com/palletone/go-palletone/contracts/shim"
)

//判断要成为 Jury 还是 Mediator 还是 Developer
func addList(role string, invokeaddr common.Address, stub shim.ChaincodeStubInterface) {
	switch {
	case role == "Mediator":
		//加入 Mediator 列表
		addMediatorList(invokeaddr, stub)
		//加入 Jury 列表
	case role == "Jury":
		addJuryList(invokeaddr, stub)
	case role == "Developer":
		//加入 Developer 列表
		addDeveloperList(invokeaddr, stub)
	}
}

//加入 Developer 列表
func addDeveloperList(invokeAddr common.Address, stub shim.ChaincodeStubInterface) {
	//先获取状态数据库中的 Developer 列表
	developerListBytes, _ := stub.GetState("DeveloperList")
	developerList := []common.Address{}
	_ = json.Unmarshal(developerListBytes, &developerList)
	//fmt.Printf("developerList = %#v\n", developerList)
	developerList = append(developerList, invokeAddr)
	developerListBytes, _ = json.Marshal(developerList)
	stub.PutState("DeveloperList", developerListBytes)
}

//加入 Mediator 列表
func addMediatorList(invokeAddr common.Address, stub shim.ChaincodeStubInterface) {
	//先获取状态数据库中的 Mediator 列表
	mediatorListBytes, _ := stub.GetState("MediatorList")
	mediatorList := []common.Address{}
	_ = json.Unmarshal(mediatorListBytes, &mediatorList)
	//fmt.Printf("MediatorList = %#v\n", mediatorList)
	mediatorList = append(mediatorList, invokeAddr)
	mediatorListBytes, _ = json.Marshal(mediatorList)
	stub.PutState("MediatorList", mediatorListBytes)
}

//加入 Jury 列表
func addJuryList(invokeAddr common.Address, stub shim.ChaincodeStubInterface) {
	//先获取状态数据库中的 Jury 列表
	juryListBytes, _ := stub.GetState("JuryList")
	juryList := []common.Address{}
	_ = json.Unmarshal(juryListBytes, &juryList)
	//fmt.Printf("JuryList = %#v\n", juryList)
	juryList = append(juryList, invokeAddr)
	juryListBytes, _ = json.Marshal(juryList)
	stub.PutState("JuryList", juryListBytes)
}

//无论是退款还是罚款，作相应处理
func handleMember(who string, invokeFromAddr common.Address, stub shim.ChaincodeStubInterface) {
	switch {
	case who == "Mediator":
		listBytes, _ := stub.GetState(who)
		mediatorList := []common.Address{}
		_ = json.Unmarshal(listBytes, &mediatorList)
		move(who, mediatorList, invokeFromAddr, stub)
	case who == "Jury":
		listBytes, _ := stub.GetState(who)
		juryList := []common.Address{}
		_ = json.Unmarshal(listBytes, &juryList)
		move(who, juryList, invokeFromAddr, stub)
	case who == "Developer":
		listBytes, _ := stub.GetState(who)
		developerList := []common.Address{}
		_ = json.Unmarshal(listBytes, &developerList)
		move(who, developerList, invokeFromAddr, stub)
	}
}

//从列表中移除
func move(who string, list []common.Address, invokeAddr common.Address, stub shim.ChaincodeStubInterface) {
	for i := 0; i < len(list); i++ {
		if list[i] == invokeAddr {
			list = append(list[:i], list[i+1:]...)
			break
		}
	}
	listBytes, _ := json.Marshal(list)
	stub.PutState(who, listBytes)
}