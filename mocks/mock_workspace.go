// Code generated by MockGen. DO NOT EDIT.
// Source: ./internal/pkg/archer/workspace.go

// Package mocks is a generated GoMock package.
package mocks

import (
	archer "github.com/aws/amazon-ecs-cli-v2/internal/pkg/archer"
	gomock "github.com/golang/mock/gomock"
	reflect "reflect"
)

// MockWorkspace is a mock of Workspace interface
type MockWorkspace struct {
	ctrl     *gomock.Controller
	recorder *MockWorkspaceMockRecorder
}

// MockWorkspaceMockRecorder is the mock recorder for MockWorkspace
type MockWorkspaceMockRecorder struct {
	mock *MockWorkspace
}

// NewMockWorkspace creates a new mock instance
func NewMockWorkspace(ctrl *gomock.Controller) *MockWorkspace {
	mock := &MockWorkspace{ctrl: ctrl}
	mock.recorder = &MockWorkspaceMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockWorkspace) EXPECT() *MockWorkspaceMockRecorder {
	return m.recorder
}

// WriteManifest mocks base method
func (m *MockWorkspace) WriteManifest(manifestBlob []byte, applicationName string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WriteManifest", manifestBlob, applicationName)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WriteManifest indicates an expected call of WriteManifest
func (mr *MockWorkspaceMockRecorder) WriteManifest(manifestBlob, applicationName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteManifest", reflect.TypeOf((*MockWorkspace)(nil).WriteManifest), manifestBlob, applicationName)
}

// ReadManifestFile mocks base method
func (m *MockWorkspace) ReadManifestFile(manifestFileName string) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadManifestFile", manifestFileName)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReadManifestFile indicates an expected call of ReadManifestFile
func (mr *MockWorkspaceMockRecorder) ReadManifestFile(manifestFileName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadManifestFile", reflect.TypeOf((*MockWorkspace)(nil).ReadManifestFile), manifestFileName)
}

// ListManifestFiles mocks base method
func (m *MockWorkspace) ListManifestFiles() ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListManifestFiles")
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListManifestFiles indicates an expected call of ListManifestFiles
func (mr *MockWorkspaceMockRecorder) ListManifestFiles() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListManifestFiles", reflect.TypeOf((*MockWorkspace)(nil).ListManifestFiles))
}

// Create mocks base method
func (m *MockWorkspace) Create(projectName string) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Create", projectName)
	ret0, _ := ret[0].(error)
	return ret0
}

// Create indicates an expected call of Create
func (mr *MockWorkspaceMockRecorder) Create(projectName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Create", reflect.TypeOf((*MockWorkspace)(nil).Create), projectName)
}

// Summary mocks base method
func (m *MockWorkspace) Summary() (*archer.WorkspaceSummary, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Summary")
	ret0, _ := ret[0].(*archer.WorkspaceSummary)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Summary indicates an expected call of Summary
func (mr *MockWorkspaceMockRecorder) Summary() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Summary", reflect.TypeOf((*MockWorkspace)(nil).Summary))
}

// AppNames mocks base method
func (m *MockWorkspace) AppNames() ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AppNames")
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AppNames indicates an expected call of AppNames
func (mr *MockWorkspaceMockRecorder) AppNames() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AppNames", reflect.TypeOf((*MockWorkspace)(nil).AppNames))
}

// MockManifestIO is a mock of ManifestIO interface
type MockManifestIO struct {
	ctrl     *gomock.Controller
	recorder *MockManifestIOMockRecorder
}

// MockManifestIOMockRecorder is the mock recorder for MockManifestIO
type MockManifestIOMockRecorder struct {
	mock *MockManifestIO
}

// NewMockManifestIO creates a new mock instance
func NewMockManifestIO(ctrl *gomock.Controller) *MockManifestIO {
	mock := &MockManifestIO{ctrl: ctrl}
	mock.recorder = &MockManifestIOMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockManifestIO) EXPECT() *MockManifestIOMockRecorder {
	return m.recorder
}

// WriteManifest mocks base method
func (m *MockManifestIO) WriteManifest(manifestBlob []byte, applicationName string) (string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "WriteManifest", manifestBlob, applicationName)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// WriteManifest indicates an expected call of WriteManifest
func (mr *MockManifestIOMockRecorder) WriteManifest(manifestBlob, applicationName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteManifest", reflect.TypeOf((*MockManifestIO)(nil).WriteManifest), manifestBlob, applicationName)
}

// ReadManifestFile mocks base method
func (m *MockManifestIO) ReadManifestFile(manifestFileName string) ([]byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ReadManifestFile", manifestFileName)
	ret0, _ := ret[0].([]byte)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ReadManifestFile indicates an expected call of ReadManifestFile
func (mr *MockManifestIOMockRecorder) ReadManifestFile(manifestFileName interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ReadManifestFile", reflect.TypeOf((*MockManifestIO)(nil).ReadManifestFile), manifestFileName)
}

// ListManifestFiles mocks base method
func (m *MockManifestIO) ListManifestFiles() ([]string, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ListManifestFiles")
	ret0, _ := ret[0].([]string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ListManifestFiles indicates an expected call of ListManifestFiles
func (mr *MockManifestIOMockRecorder) ListManifestFiles() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ListManifestFiles", reflect.TypeOf((*MockManifestIO)(nil).ListManifestFiles))
}
