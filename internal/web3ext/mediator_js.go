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

package web3ext

const Mediator_JS = `
web3._extend({
	property: 'mediator',
	methods: [
		new web3._extend.Method({
			name: 'listAll',
			call: 'mediator_getList',
			params: 0,
		}),
		new web3._extend.Method({
			name: 'getVoted',
			call: 'mediator_getVoted',
			params: 1,
		}),
		new web3._extend.Method({
			name: 'dumpInitDKS',
			call: 'mediator_dumpInitDKS',
			params: 0,
		}),
		new web3._extend.Method({
			name: 'apply',
			call: 'mediator_apply',
			params: 1,
		}),
		new web3._extend.Method({
			name: 'isApproved',
			call: 'mediator_isApproved',
			params: 1,
		}),
		new web3._extend.Method({
			name: 'payDeposit',
			call: 'mediator_deposit',
			params: 2,
		}),
		new web3._extend.Method({
			name: 'checkDeposit',
			call: 'mediator_getDeposit',
			params: 1,
		}),
		new web3._extend.Method({
			name: 'isInList',
			call: 'mediator_isInList',
			params: 1,
		}),
		new web3._extend.Method({
			name: 'vote',
			call: 'mediator_vote',
			params: 2,
		}),
		new web3._extend.Method({
			name: 'getNextUpdateTime',
			call: 'mediator_getNextUpdateTime',
			params: 0,
		}),
		new web3._extend.Method({
			name: 'getInfo',
			call: 'mediator_getInfo',
			params: 1,
		}),
		new web3._extend.Method({
			name: 'startProduce',
			call: 'mediator_startProduce',
			params: 0,
		}),
		new web3._extend.Method({
			name: 'stopProduce',
			call: 'mediator_stopProduce',
			params: 0,
		}),	
		new web3._extend.Method({
			name: 'listVoteResults',
			call: 'mediator_listVoteResults',
			params: 0,
		}),
		new web3._extend.Method({
			name: 'lookupMediatorInfo',
			call: 'mediator_lookupMediatorInfo',
			params: 0,
		}),

	],
	properties: [
		new web3._extend.Property({
			name: 'listActives',
			getter: 'mediator_getActives'
		}),
	]
});
`
