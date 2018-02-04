// Code generated by MockGen. DO NOT EDIT.
// Source: pkg/cloudprovider/cloud.go

// Package fake is a generated GoMock package.
package fake

import (
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// Fake is a mock of Interface interface
type Fake struct {
	ctrl     *gomock.Controller
	recorder *FakeMockRecorder
}

// FakeMockRecorder is the mock recorder for Fake
type FakeMockRecorder struct {
	mock *Fake
}

// NewFake creates a new mock instance
func NewFake(ctrl *gomock.Controller) *Fake {
	mock := &Fake{ctrl: ctrl}
	mock.recorder = &FakeMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *Fake) EXPECT() *FakeMockRecorder {
	return m.recorder
}

// GetInstanceIDByNodeName mocks base method
func (m *Fake) GetInstanceIDByNodeName(arg0 string) (string, error) {
	ret := m.ctrl.Call(m, "GetInstanceIDByNodeName", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInstanceIDByNodeName indicates an expected call of GetInstanceIDByNodeName
func (mr *FakeMockRecorder) GetInstanceIDByNodeName(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInstanceIDByNodeName", reflect.TypeOf((*Fake)(nil).GetInstanceIDByNodeName), arg0)
}

// GetInstanceGroupByNodeName mocks base method
func (m *Fake) GetInstanceGroupByNodeName(arg0 string) (string, error) {
	ret := m.ctrl.Call(m, "GetInstanceGroupByNodeName", arg0)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetInstanceGroupByNodeName indicates an expected call of GetInstanceGroupByNodeName
func (mr *FakeMockRecorder) GetInstanceGroupByNodeName(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetInstanceGroupByNodeName", reflect.TypeOf((*Fake)(nil).GetInstanceGroupByNodeName), arg0)
}
