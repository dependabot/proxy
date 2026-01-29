package threadsafe

import "sync"

type Map[K comparable, V any] struct {
	sync.RWMutex
	unsafe map[K]V
}

func NewMap[K comparable, V any]() *Map[K, V] {
	return &Map[K, V]{
		unsafe: make(map[K]V),
	}
}

func (m *Map[K, V]) Set(key K, value V) {
	m.Lock()
	defer m.Unlock()

	m.unsafe[key] = value
}

func (m *Map[K, V]) Get(key K) (V, bool) {
	m.RLock()
	defer m.RUnlock()

	value, found := m.unsafe[key]
	return value, found
}
