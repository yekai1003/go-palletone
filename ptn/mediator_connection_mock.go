// Code generated by MockGen. DO NOT EDIT.
// Source: ./ptn/mediator_connection.go

// Package ptn is a generated GoMock package.
package ptn

import (
	gomock "github.com/golang/mock/gomock"
	common "github.com/palletone/go-palletone/common"
	event "github.com/palletone/go-palletone/common/event"
	mediatorplugin "github.com/palletone/go-palletone/consensus/mediatorplugin"
	modules "github.com/palletone/go-palletone/dag/modules"
	reflect "reflect"
)

// Mockproducer is a mock of producer interface
type Mockproducer struct {
	ctrl     *gomock.Controller
	recorder *MockproducerMockRecorder
}

// MockproducerMockRecorder is the mock recorder for Mockproducer
type MockproducerMockRecorder struct {
	mock *Mockproducer
}

// NewMockproducer creates a new mock instance
func NewMockproducer(ctrl *gomock.Controller) *Mockproducer {
	mock := &Mockproducer{ctrl: ctrl}
	mock.recorder = &MockproducerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *Mockproducer) EXPECT() *MockproducerMockRecorder {
	return m.recorder
}

// SubscribeNewProducedUnitEvent mocks base method
func (m *Mockproducer) SubscribeNewProducedUnitEvent(ch chan<- mediatorplugin.NewProducedUnitEvent) event.Subscription {
	ret := m.ctrl.Call(m, "SubscribeNewProducedUnitEvent", ch)
	ret0, _ := ret[0].(event.Subscription)
	return ret0
}

// SubscribeNewProducedUnitEvent indicates an expected call of SubscribeNewProducedUnitEvent
func (mr *MockproducerMockRecorder) SubscribeNewProducedUnitEvent(ch interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SubscribeNewProducedUnitEvent", reflect.TypeOf((*Mockproducer)(nil).SubscribeNewProducedUnitEvent), ch)
}

// AddToTBLSSignBufs mocks base method
func (m *Mockproducer) AddToTBLSSignBufs(newUnit *modules.Unit) {
	m.ctrl.Call(m, "AddToTBLSSignBufs", newUnit)
}

// AddToTBLSSignBufs indicates an expected call of AddToTBLSSignBufs
func (mr *MockproducerMockRecorder) AddToTBLSSignBufs(newUnit interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddToTBLSSignBufs", reflect.TypeOf((*Mockproducer)(nil).AddToTBLSSignBufs), newUnit)
}

// SubscribeSigShareEvent mocks base method
func (m *Mockproducer) SubscribeSigShareEvent(ch chan<- mediatorplugin.SigShareEvent) event.Subscription {
	ret := m.ctrl.Call(m, "SubscribeSigShareEvent", ch)
	ret0, _ := ret[0].(event.Subscription)
	return ret0
}

// SubscribeSigShareEvent indicates an expected call of SubscribeSigShareEvent
func (mr *MockproducerMockRecorder) SubscribeSigShareEvent(ch interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SubscribeSigShareEvent", reflect.TypeOf((*Mockproducer)(nil).SubscribeSigShareEvent), ch)
}

// AddToTBLSRecoverBuf mocks base method
func (m *Mockproducer) AddToTBLSRecoverBuf(newUnitHash common.Hash, sigShare []byte) error {
	ret := m.ctrl.Call(m, "AddToTBLSRecoverBuf", newUnitHash, sigShare)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddToTBLSRecoverBuf indicates an expected call of AddToTBLSRecoverBuf
func (mr *MockproducerMockRecorder) AddToTBLSRecoverBuf(newUnitHash, sigShare interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddToTBLSRecoverBuf", reflect.TypeOf((*Mockproducer)(nil).AddToTBLSRecoverBuf), newUnitHash, sigShare)
}

// SubscribeVSSDealEvent mocks base method
func (m *Mockproducer) SubscribeVSSDealEvent(ch chan<- mediatorplugin.VSSDealEvent) event.Subscription {
	ret := m.ctrl.Call(m, "SubscribeVSSDealEvent", ch)
	ret0, _ := ret[0].(event.Subscription)
	return ret0
}

// SubscribeVSSDealEvent indicates an expected call of SubscribeVSSDealEvent
func (mr *MockproducerMockRecorder) SubscribeVSSDealEvent(ch interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SubscribeVSSDealEvent", reflect.TypeOf((*Mockproducer)(nil).SubscribeVSSDealEvent), ch)
}

// ProcessVSSDeal mocks base method
func (m *Mockproducer) ProcessVSSDeal(deal *mediatorplugin.VSSDealEvent) error {
	ret := m.ctrl.Call(m, "ProcessVSSDeal", deal)
	ret0, _ := ret[0].(error)
	return ret0
}

// ProcessVSSDeal indicates an expected call of ProcessVSSDeal
func (mr *MockproducerMockRecorder) ProcessVSSDeal(deal interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ProcessVSSDeal", reflect.TypeOf((*Mockproducer)(nil).ProcessVSSDeal), deal)
}

// SubscribeVSSResponseEvent mocks base method
func (m *Mockproducer) SubscribeVSSResponseEvent(ch chan<- mediatorplugin.VSSResponseEvent) event.Subscription {
	ret := m.ctrl.Call(m, "SubscribeVSSResponseEvent", ch)
	ret0, _ := ret[0].(event.Subscription)
	return ret0
}

// SubscribeVSSResponseEvent indicates an expected call of SubscribeVSSResponseEvent
func (mr *MockproducerMockRecorder) SubscribeVSSResponseEvent(ch interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SubscribeVSSResponseEvent", reflect.TypeOf((*Mockproducer)(nil).SubscribeVSSResponseEvent), ch)
}

// AddToResponseBuf mocks base method
func (m *Mockproducer) AddToResponseBuf(resp *mediatorplugin.VSSResponseEvent) {
	m.ctrl.Call(m, "AddToResponseBuf", resp)
}

// AddToResponseBuf indicates an expected call of AddToResponseBuf
func (mr *MockproducerMockRecorder) AddToResponseBuf(resp interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddToResponseBuf", reflect.TypeOf((*Mockproducer)(nil).AddToResponseBuf), resp)
}

// LocalHaveActiveMediator mocks base method
func (m *Mockproducer) LocalHaveActiveMediator() bool {
	ret := m.ctrl.Call(m, "LocalHaveActiveMediator")
	ret0, _ := ret[0].(bool)
	return ret0
}

// LocalHaveActiveMediator indicates an expected call of LocalHaveActiveMediator
func (mr *MockproducerMockRecorder) LocalHaveActiveMediator() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LocalHaveActiveMediator", reflect.TypeOf((*Mockproducer)(nil).LocalHaveActiveMediator))
}

// LocalHavePrecedingMediator mocks base method
func (m *Mockproducer) LocalHavePrecedingMediator() bool {
	ret := m.ctrl.Call(m, "LocalHavePrecedingMediator")
	ret0, _ := ret[0].(bool)
	return ret0
}

// LocalHavePrecedingMediator indicates an expected call of LocalHavePrecedingMediator
func (mr *MockproducerMockRecorder) LocalHavePrecedingMediator() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LocalHavePrecedingMediator", reflect.TypeOf((*Mockproducer)(nil).LocalHavePrecedingMediator))
}

// SubscribeGroupSigEvent mocks base method
func (m *Mockproducer) SubscribeGroupSigEvent(ch chan<- mediatorplugin.GroupSigEvent) event.Subscription {
	ret := m.ctrl.Call(m, "SubscribeGroupSigEvent", ch)
	ret0, _ := ret[0].(event.Subscription)
	return ret0
}

// SubscribeGroupSigEvent indicates an expected call of SubscribeGroupSigEvent
func (mr *MockproducerMockRecorder) SubscribeGroupSigEvent(ch interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SubscribeGroupSigEvent", reflect.TypeOf((*Mockproducer)(nil).SubscribeGroupSigEvent), ch)
}

// UpdateMediatorsDKG mocks base method
func (m *Mockproducer) UpdateMediatorsDKG(isRenew bool) {
	m.ctrl.Call(m, "UpdateMediatorsDKG", isRenew)
}

// UpdateMediatorsDKG indicates an expected call of UpdateMediatorsDKG
func (mr *MockproducerMockRecorder) UpdateMediatorsDKG(isRenew interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "UpdateMediatorsDKG", reflect.TypeOf((*Mockproducer)(nil).UpdateMediatorsDKG), isRenew)
}

// IsEnabledGroupSign mocks base method
func (m *Mockproducer) IsEnabledGroupSign() bool {
	ret := m.ctrl.Call(m, "IsEnabledGroupSign")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsEnabledGroupSign indicates an expected call of IsEnabledGroupSign
func (mr *MockproducerMockRecorder) IsEnabledGroupSign() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsEnabledGroupSign", reflect.TypeOf((*Mockproducer)(nil).IsEnabledGroupSign))
}
