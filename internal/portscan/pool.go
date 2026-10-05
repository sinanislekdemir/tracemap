package portscan

import (
	"context"
	"errors"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// Pool is a reusable, fixed-size worker pool for port probes. Instead of
// spawning one goroutine per port, a Pool keeps a set of worker goroutines that
// drain a shared job queue, so a scan never creates more goroutines than the
// pool is sized for. A single pool can be shared by every host in an operation
// (for example all hosts in a CIDR block), and its size bounds the total number
// of probes in flight across all of those hosts.
//
// A Pool is safe for concurrent use. Call Close once every Scan has returned.
type Pool struct {
	scanner *Scanner
	jobs    chan probeJob
	done    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
}

// probeJob is one port probe plus the sink that reports its outcome.
type probeJob struct {
	ctx      context.Context
	ip       string
	host     string
	port     int
	protocol string
	timeout  time.Duration
	probe    bool
	jitter   time.Duration

	// report is called once the probe has run, with found=false when the port
	// is closed (or the probe was skipped).
	report func(result Result, found bool)
	// finish always runs when the job completes, releasing its slot.
	finish func()
}

// errPoolClosed is returned by Scan once the pool has been closed.
var errPoolClosed = errors.New("port scan pool is closed")

// NewPool starts a pool of workers bound to scanner. A workers value <= 0 uses
// DefaultConcurrency; a nil scanner uses a fresh one.
func NewPool(scanner *Scanner, workers int) *Pool {
	if scanner == nil {
		scanner = NewScanner()
	}
	if workers <= 0 {
		workers = DefaultConcurrency
	}
	p := &Pool{
		scanner: scanner,
		jobs:    make(chan probeJob),
		done:    make(chan struct{}),
	}
	p.wg.Add(workers)
	for i := 0; i < workers; i++ {
		go p.worker()
	}
	return p
}

func (p *Pool) worker() {
	defer p.wg.Done()
	for {
		select {
		case job := <-p.jobs:
			job.run(p.scanner)
		case <-p.done:
			return
		}
	}
}

// Close stops the pool's workers and waits for them to exit. It is safe to call
// more than once. No Scan may be started after Close.
func (p *Pool) Close() {
	p.once.Do(func() { close(p.done) })
	p.wg.Wait()
}

// Scan probes opts.Ports on host using the pool's workers and returns the open
// ones, sorted by port. It has the same contract as Scanner.Scan, but concurrent
// calls share one concurrency budget instead of each starting its own workers.
func (p *Pool) Scan(ctx context.Context, host string, opts Options, obs Observer) ([]Result, error) {
	select {
	case <-p.done:
		return nil, errPoolClosed
	default:
	}
	plan, err := p.scanner.plan(ctx, host, opts)
	if err != nil {
		return nil, err
	}
	return p.run(ctx, plan, obs)
}

// run submits a plan's ports to the pool and collects the open ones. It returns
// once every submitted probe has finished or the context is cancelled.
func (p *Pool) run(ctx context.Context, plan scanPlan, obs Observer) ([]Result, error) {
	total := len(plan.ports)

	var (
		mu      sync.Mutex
		results []Result
		open    int64
		done    int64
	)
	var inflight sync.WaitGroup

	report := func(result Result, found bool) {
		if found {
			atomic.AddInt64(&open, 1)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
			if obs.OnOpen != nil {
				obs.OnOpen(result)
			}
		}
		n := atomic.AddInt64(&done, 1)
		if obs.OnProgress != nil && (n%progressEvery == 0 || int(n) == total) {
			obs.OnProgress(int(n), total, int(atomic.LoadInt64(&open)))
		}
	}

submit:
	for _, port := range plan.ports {
		inflight.Add(1)
		job := probeJob{
			ctx:      ctx,
			ip:       plan.ip,
			host:     plan.host,
			port:     port,
			protocol: plan.protocol,
			timeout:  plan.timeout,
			probe:    plan.probe,
			jitter:   plan.jitter,
			report:   report,
			finish:   inflight.Done,
		}
		select {
		case p.jobs <- job:
		case <-p.done:
			inflight.Done()
			break submit
		case <-ctx.Done():
			inflight.Done()
			break submit
		}
	}
	inflight.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].Port != results[j].Port {
			return results[i].Port < results[j].Port
		}
		return results[i].Protocol < results[j].Protocol
	})
	if err := ctx.Err(); err != nil {
		return results, err
	}
	return results, nil
}

// run probes one port and reports its outcome.
func (j probeJob) run(s *Scanner) {
	defer j.finish()
	if j.ctx.Err() != nil {
		return
	}
	if j.jitter > 0 && !sleepJitter(j.ctx, j.jitter) {
		return
	}
	result, found := s.scanPort(j.ctx, j.ip, j.host, j.port, j.protocol, j.timeout, j.probe)
	j.report(result, found)
}
