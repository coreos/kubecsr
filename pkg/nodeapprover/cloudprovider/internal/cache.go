package internal

import (
	"sync"
	"time"

	"k8s.io/client-go/tools/cache"
)

type timedcacheEntry struct {
	key  string
	data interface{}
}

type TimedCache struct {
	store cache.Store
	lock  sync.Mutex
}

// ttl time.Duration
func NewTimedCache(ttl time.Duration) TimedCache {
	return TimedCache{
		store: cache.NewTTLStore(cacheKeyFunc, ttl),
	}
}

func cacheKeyFunc(obj interface{}) (string, error) {
	return obj.(*timedcacheEntry).key, nil
}

func (t *TimedCache) GetOrCreate(key string, createFunc func() interface{}) (interface{}, error) {
	entry, exists, err := t.store.GetByKey(key)
	if err != nil {
		return nil, err
	}
	if exists {
		return (entry.(*timedcacheEntry)).data, nil
	}

	t.lock.Lock()
	defer t.lock.Unlock()
	entry, exists, err = t.store.GetByKey(key)
	if err != nil {
		return nil, err
	}
	if exists {
		return (entry.(*timedcacheEntry)).data, nil
	}

	if createFunc == nil {
		return nil, nil
	}
	created := createFunc()
	t.store.Add(&timedcacheEntry{
		key:  key,
		data: created,
	})
	return created, nil
}

func (t *TimedCache) Delete(key string) {
	_ = t.store.Delete(&timedcacheEntry{
		key: key,
	})
}
