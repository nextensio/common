package common

import (
	"fmt"
	"sync"
	"sync/atomic"
)

// Golang syncpools are "best effort" pools: ie unlike traditional buffer
// pools where we think of "fixed size" pools, there is no fixed size here.
// The element in the pool can be reclaimed by the Go garbage collector anytime
// and if the pool is short of elements, then Go will call New() to alloc
// a new pool member. Also an element taken from the pool need not go back to
// the pool, it can be collected by Go garbage collector and go back to the
// common memory pool
//
// Our buffer pool philosophy is simple: optimize for the most common code path
// So in the most common code path, we will allocate (GetBuf) somewhere and it
// will go through a series of functions/goroutines and finally get "done", ie
// it will be transmitted - and at that point we do a PutBuf where the buffer
// will go back to the sync pool
//
// For the not-common code path like errors where we do a GetBuf and then run
// into some error, we dont do a PutBuf, so it just goes back to the garbage
// collector. So if there are too many errors, the buffer cache wont be big
// enough, maybe there are some cases where its not really an "error" but a
// common code path where we return without transmitting/doing anything, at
// that point we will have to identify it and call a PutBuf - so the goal is
// that PutBufs should be few in number, so every coder does not have to worry
// about doing a PutBuf.
//
// The pool examples on internet talk about a "defer PutBuf()" which looks like it
// takes care of the error case also, since it will call the deferred putbuf
// on error - but then there is the problem that we should not do PutBuf twice,
// if there is no error, we need to somehow "cancel" the deferred putbuf, and
// there is no easy way to do that, then we need reference counts and a series
// of complex logic to do a hold and release of the reference count etc.. - which
// very quickly gets out of control and no one will ever know where to hold and
// where to release the refcount etc.. So its ok, lets live with the 90% good cases
// where things will be in cache, if its not, then it will end up doing an alloc
// again.
//
// The refcount here is not meant for anything complex, its just meant to catch
// someone who does a putbuf on the same buffer two (or more) times - someone will
// do that some day for sure, and we just want to catch that. But again, even this
// count wont really catch it because the sequence can be put1 (0), get(1), put2(0)
// where put1 and put2 (double puts) still end up with a good refcount (0) because
// of the intermediate get, so its just a "best effort" catch mechanism

type NxtPool struct {
	p    *sync.Pool
	Size uint
}

func NewPool(size uint) NxtPool {
	bufPool := sync.Pool{
		New: func() interface{} {
			buf := make([]byte, size)
			return &NxtBuf{
				refcount: 0,
				Buf:      buf,
				pool:     nil,
			}
		},
	}
	return NxtPool{p: &bufPool, Size: size}
}

func GetBuf(pool NxtPool) *NxtBuf {
	buf := pool.p.Get().(*NxtBuf)
	buf.pool = pool.p
	new := atomic.AddInt32(&buf.refcount, 1)
	if new != 1 {
		panic(fmt.Sprintf("Bad get refcount %d", new))
	}
	return buf
}

func PutBuf(buf *NxtBuf) {
	if buf == nil {
		return
	}
	new := atomic.AddInt32(&buf.refcount, -1)
	if new != 0 {
		panic(fmt.Sprintf("Bad put refcount %d", new))
	}
	buf.pool.Put(buf)
}

func PutBufs(bufs []*NxtBuf) {
	for _, b := range bufs {
		PutBuf(b)
	}
}
