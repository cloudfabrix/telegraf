// Go API over pdh syscalls
//go:build windows

package win_perf_counters

import (
	"errors"
	"syscall"
	"time"
	"unsafe"
)

// Initial buffer size for return buffers
const initialBufferSize = uint32(1024) // 1kB

var errBufferLimitReached = errors.New("buffer limit reached")

// CounterValue is abstraction for PdhFmtCountervalueItemDouble
type CounterValue struct {
	InstanceName string
	Value        interface{}
}

// PerformanceQuery provides wrappers around Windows performance counters API for easy usage in GO
//
//nolint:interfacebloat // conditionally allow to contain more methods
type PerformanceQuery interface {
	Open() error
	Close() error
	AddCounterToQuery(counterPath string) (pdhCounterHandle, error)
	AddEnglishCounterToQuery(counterPath string) (pdhCounterHandle, error)
	GetCounterPath(counterHandle pdhCounterHandle) (string, error)
	ExpandWildCardPath(counterPath string) ([]string, error)
	GetFormattedCounterValueDouble(hCounter pdhCounterHandle) (float64, error)
	GetRawCounterValue(hCounter pdhCounterHandle) (int64, error)
	GetFormattedCounterArrayDouble(hCounter pdhCounterHandle) ([]CounterValue, error)
	GetRawCounterArray(hCounter pdhCounterHandle) ([]CounterValue, error)
	CollectData() error
	CollectDataWithTime() (time.Time, error)
	IsVistaOrNewer() bool
}

type PerformanceQueryCreator interface {
	NewPerformanceQuery(string, uint32) PerformanceQuery
}

// PdhError represents error returned from Performance Counters API
type PdhError struct {
	ErrorCode uint32
	errorText string
}

func (m *PdhError) Error() string {
	return m.errorText
}

func NewPdhError(code uint32) error {
	return &PdhError{
		ErrorCode: code,
		errorText: PdhFormatError(code),
	}
}

// PerformanceQueryImpl is implementation of PerformanceQuery interface, which calls phd.dll functions
type PerformanceQueryImpl struct {
	maxBufferSize uint32
	query         pdhQueryHandle
}

type PerformanceQueryCreatorImpl struct{}

func (m PerformanceQueryCreatorImpl) NewPerformanceQuery(_ string, maxBufferSize uint32) PerformanceQuery {
	return &PerformanceQueryImpl{maxBufferSize: maxBufferSize}
}

// Open creates a new counterPath that is used to manage the collection of performance data.
// It returns counterPath handle used for subsequent calls for adding counters and querying data
func (m *PerformanceQueryImpl) Open() error {
	if m.query != 0 {
		err := m.Close()
		if err != nil {
			return err
		}
	}
	var handle pdhQueryHandle

	if ret := PdhOpenQuery(0, 0, &handle); ret != ErrorSuccess {
		return NewPdhError(ret)
	}
	m.query = handle
	return nil
}

// Close closes the counterPath, releases associated counter handles and frees resources
func (m *PerformanceQueryImpl) Close() error {
	if m.query == 0 {
		return errors.New("uninitialized query")
	}

	if ret := PdhCloseQuery(m.query); ret != ErrorSuccess {
		return NewPdhError(ret)
	}
	m.query = 0
	return nil
}

func (m *PerformanceQueryImpl) AddCounterToQuery(counterPath string) (pdhCounterHandle, error) {
	var counterHandle pdhCounterHandle
	if m.query == 0 {
		return 0, errors.New("uninitialized query")
	}

	if ret := PdhAddCounter(m.query, counterPath, 0, &counterHandle); ret != ErrorSuccess {
		return 0, NewPdhError(ret)
	}
	return counterHandle, nil
}

func (m *PerformanceQueryImpl) AddEnglishCounterToQuery(counterPath string) (pdhCounterHandle, error) {
	var counterHandle pdhCounterHandle
	if m.query == 0 {
		return 0, errors.New("uninitialized query")
	}
	if ret := PdhAddEnglishCounter(m.query, counterPath, 0, &counterHandle); ret != ErrorSuccess {
		return 0, NewPdhError(ret)
	}
	return counterHandle, nil
}

// GetCounterPath return counter information for given handle
func (m *PerformanceQueryImpl) GetCounterPath(counterHandle pdhCounterHandle) (string, error) {
	for buflen := initialBufferSize; buflen <= m.maxBufferSize; buflen *= 2 {
		buf := make([]byte, buflen)

		// Get the info with the current buffer size
		size := buflen
		ret := PdhGetCounterInfo(counterHandle, 0, &size, &buf[0])
		if ret == ErrorSuccess {
			ci := (*PdhCounterInfo)(unsafe.Pointer(&buf[0])) //nolint:gosec // G103: Valid use of unsafe call to create PDH_COUNTER_INFO
			return UTF16PtrToString(ci.SzFullPath), nil
		}

		// Use the size as a hint if it exceeds the current buffer size
		if size > buflen {
			buflen = size
		}

		// We got a non-recoverable error so exit here
		if ret != PdhMoreData {
			return "", NewPdhError(ret)
		}
	}

	return "", errBufferLimitReached
}

// ExpandWildCardPath  examines local computer and returns those counter paths that match the given counter path which contains wildcard characters.
func (m *PerformanceQueryImpl) ExpandWildCardPath(counterPath string) ([]string, error) {
	for buflen := initialBufferSize; buflen <= m.maxBufferSize; buflen *= 2 {
		buf := make([]uint16, buflen)

		// Get the info with the current buffer size
		size := buflen
		ret := PdhExpandWildCardPath(counterPath, &buf[0], &size)
		if ret == ErrorSuccess {
			return UTF16ToStringArray(buf), nil
		}

		// Use the size as a hint if it exceeds the current buffer size
		if size > buflen {
			buflen = size
		}

		// We got a non-recoverable error so exit here
		if ret != PdhMoreData {
			return nil, NewPdhError(ret)
		}
	}

	return nil, errBufferLimitReached
}

// GetFormattedCounterValueDouble computes a displayable value for the specified counter
func (m *PerformanceQueryImpl) GetFormattedCounterValueDouble(hCounter pdhCounterHandle) (float64, error) {
	var counterType uint32
	var value PdhFmtCountervalueDouble

	if ret := PdhGetFormattedCounterValueDouble(hCounter, &counterType, &value); ret != ErrorSuccess {
		return 0, NewPdhError(ret)
	}
	if value.CStatus == PdhCstatusValidData || value.CStatus == PdhCstatusNewData {
		return value.DoubleValue, nil
	}
	return 0, NewPdhError(value.CStatus)
}

func (m *PerformanceQueryImpl) GetFormattedCounterArrayDouble(hCounter pdhCounterHandle) ([]CounterValue, error) {
	for buflen := initialBufferSize; buflen <= m.maxBufferSize; buflen *= 2 {
		buf := make([]byte, buflen)

		// Get the info with the current buffer size
		var itemCount uint32
		size := buflen
		ret := PdhGetFormattedCounterArrayDouble(hCounter, &size, &itemCount, &buf[0])
		if ret == ErrorSuccess {
			//nolint:gosec // G103: Valid use of unsafe call to create PDH_FMT_COUNTERVALUE_ITEM_DOUBLE
			items := (*[1 << 20]PdhFmtCountervalueItemDouble)(unsafe.Pointer(&buf[0]))[:itemCount]
			values := make([]CounterValue, 0, itemCount)
			for _, item := range items {
				if item.FmtValue.CStatus == PdhCstatusValidData || item.FmtValue.CStatus == PdhCstatusNewData {
					val := CounterValue{UTF16PtrToString(item.SzName), item.FmtValue.DoubleValue}
					values = append(values, val)
				}
			}
			return values, nil
		}

		// Use the size as a hint if it exceeds the current buffer size
		if size > buflen {
			buflen = size
		}

		// We got a non-recoverable error so exit here
		if ret != PdhMoreData {
			return nil, NewPdhError(ret)
		}
	}

	return nil, errBufferLimitReached
}

func (m *PerformanceQueryImpl) GetRawCounterArray(hCounter pdhCounterHandle) ([]CounterValue, error) {
	for buflen := initialBufferSize; buflen <= m.maxBufferSize; buflen *= 2 {
		buf := make([]byte, buflen)

		// Get the info with the current buffer size
		var itemCount uint32
		size := buflen
		ret := PdhGetRawCounterArray(hCounter, &size, &itemCount, &buf[0])
		if ret == ErrorSuccess {
			//nolint:gosec // G103: Valid use of unsafe call to create PDH_RAW_COUNTER_ITEM
			items := (*[1 << 20]PdhRawCounterItem)(unsafe.Pointer(&buf[0]))[:itemCount]
			values := make([]CounterValue, 0, itemCount)
			for _, item := range items {
				if item.RawValue.CStatus == PdhCstatusValidData || item.RawValue.CStatus == PdhCstatusNewData {
					val := CounterValue{UTF16PtrToString(item.SzName), item.RawValue.FirstValue}
					values = append(values, val)
				}
			}
			return values, nil
		}

		// Use the size as a hint if it exceeds the current buffer size
		if size > buflen {
			buflen = size
		}

		// We got a non-recoverable error so exit here
		if ret != PdhMoreData {
			return nil, NewPdhError(ret)
		}
	}

	return nil, errBufferLimitReached
}

func (m *PerformanceQueryImpl) CollectData() error {
	var ret uint32
	if m.query == 0 {
		return errors.New("uninitialized query")
	}

	if ret = PdhCollectQueryData(m.query); ret != ErrorSuccess {
		return NewPdhError(ret)
	}
	return nil
}

func (m *PerformanceQueryImpl) CollectDataWithTime() (time.Time, error) {
	if m.query == 0 {
		return time.Now(), errors.New("uninitialized query")
	}
	ret, mtime := PdhCollectQueryDataWithTime(m.query)
	if ret != ErrorSuccess {
		return time.Now(), NewPdhError(ret)
	}
	return mtime, nil
}

func (m *PerformanceQueryImpl) IsVistaOrNewer() bool {
	return PdhAddEnglishCounterSupported()
}

func (m *PerformanceQueryImpl) GetRawCounterValue(hCounter pdhCounterHandle) (int64, error) {
	if m.query == 0 {
		return 0, errors.New("uninitialised query")
	}

	var counterType uint32
	var value PdhRawCounter
	var ret uint32

	if ret = PdhGetRawCounterValue(hCounter, &counterType, &value); ret == ErrorSuccess {
		if value.CStatus == PdhCstatusValidData || value.CStatus == PdhCstatusNewData {
			return value.FirstValue, nil
		}
		return 0, NewPdhError(value.CStatus)
	}
	return 0, NewPdhError(ret)
}

// UTF16PtrToString converts Windows API LPTSTR (pointer to string) to go string
func UTF16PtrToString(s *uint16) string {
	if s == nil {
		return ""
	}
	//nolint:gosec // G103: Valid use of unsafe call to create string from Windows API LPTSTR (pointer to string)
	return syscall.UTF16ToString((*[1 << 29]uint16)(unsafe.Pointer(s))[0:])
}

// UTF16ToStringArray converts list of Windows API NULL terminated strings  to go string array
func UTF16ToStringArray(buf []uint16) []string {
	var strings []string
	nextLineStart := 0
	stringLine := UTF16PtrToString(&buf[0])
	for stringLine != "" {
		strings = append(strings, stringLine)
		nextLineStart += len([]rune(stringLine)) + 1
		remainingBuf := buf[nextLineStart:]
		stringLine = UTF16PtrToString(&remainingBuf[0])
	}
	return strings
}
