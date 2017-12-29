package session

import (
	"sync"
	"time"
)

type object struct {
	sync.RWMutex
	Fsync     sync.RWMutex
	param     Param
	data      map[string]Data
	writeTime time.Time
}

// Data - Объект сессии
type Data struct {
	ID   int
	Time time.Time
}

// Param - параметры инициализации
type Param struct {
	Path         string
	InactiveTime int64
	WriteTime    time.Duration
	Secret       string
}
