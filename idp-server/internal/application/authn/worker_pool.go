package authn

import (
	"context"
	"fmt"
	"runtime"
)

type poolJob struct {
	ctx  context.Context
	fn   func(context.Context) (any, error)
	done chan poolResult
}

type poolResult struct {
	value any
	err   error
}

type workerPool struct {
	queue chan poolJob
}

func newIOPool() *workerPool {
	workers := max(8, runtime.GOMAXPROCS(0)*4)
	return newWorkerPool(workers, workers*8)
}

func newCPUPool() *workerPool {
	workers := max(1, runtime.GOMAXPROCS(0))
	return newWorkerPool(workers, workers*8)
}

func newWorkerPool(workers, queue int) *workerPool {
	if workers <= 0 {
		workers = 1
	}
	if queue < workers {
		queue = workers
	}
	pool := &workerPool{
		queue: make(chan poolJob, queue),
	}
	for i := 0; i < workers; i++ {
		go pool.runWorker()
	}
	return pool
}

func (p *workerPool) runWorker() {
	for job := range p.queue {
		if err := job.ctx.Err(); err != nil {
			job.done <- poolResult{err: err}
			continue
		}
		value, err := job.fn(job.ctx)
		job.done <- poolResult{value: value, err: err}
	}
}

func runWithPool[T any](ctx context.Context, pool *workerPool, fn func(context.Context) (T, error)) (T, error) {
	var zero T
	if pool == nil {
		return fn(ctx)
	}
	done := make(chan poolResult, 1)
	job := poolJob{
		ctx: ctx,
		fn: func(execCtx context.Context) (any, error) {
			value, err := fn(execCtx)
			if err != nil {
				return nil, err
			}
			return value, nil
		},
		done: done,
	}
	select {
	case pool.queue <- job:
	case <-ctx.Done():
		return zero, ctx.Err()
	}

	select {
	case result := <-done:
		if result.err != nil {
			return zero, result.err
		}
		value, ok := result.value.(T)
		if !ok {
			return zero, fmt.Errorf("worker pool type mismatch")
		}
		return value, nil
	case <-ctx.Done():
		return zero, ctx.Err()
	}
}
