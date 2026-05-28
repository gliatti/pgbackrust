//! Parallel job dispatcher (port of src/protocol/parallel.c).
//!
//! Distributes a queue of `Job`s across a fixed pool of workers and collects
//! `JobResult`s. This slice runs workers as in-process threads invoking a
//! user-supplied worker function; the per-worker protocol loop and
//! local/remote process transport layer build on top of this later.
//!
//! In the C implementation (`protocolParallel*`) the main process keeps a
//! queue of `ProtocolParallelJob`s and a fixed array of `ProtocolClient`
//! workers; on each `protocolParallelProcess()` pass it hands a queued job to
//! every idle worker and reaps any that have completed. Here we replace the
//! event loop and the inter-process protocol with `std::thread` workers that
//! pull from a shared queue and call a Rust closure directly. The externally
//! observable contract is the same: every job yields exactly one result, and
//! a single failing job never sinks the whole run.

use std::collections::VecDeque;
use std::panic::AssertUnwindSafe;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;

use crate::message::{Request, Response};

/// A unit of work: a protocol [`Request`] plus an opaque key the caller uses
/// to correlate the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Job {
    /// Caller-chosen correlation key, echoed back on the matching
    /// [`JobResult`]. Keys need not be unique, but the caller is responsible
    /// for telling results apart if they are not.
    pub key: String,
    /// The request handed to the worker function.
    pub request: Request,
}

/// Outcome of a single [`Job`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobResult {
    /// The originating job's [`Job::key`].
    pub key: String,
    /// `Ok` with the worker's [`Response`], or `Err` with a message if the
    /// worker function returned an error or panicked.
    pub result: Result<Response, String>,
}

/// Runs jobs across a fixed pool of worker threads.
///
/// Each thread pulls jobs from a shared queue until it is drained, runs the
/// caller-supplied worker function, and reports the outcome. Results are
/// returned in completion order, which is non-deterministic across runs with
/// more than one worker; callers that need a stable order should sort by
/// [`JobResult::key`].
#[derive(Debug, Clone, Copy)]
pub struct ParallelExecutor {
    worker_count: usize,
}

impl ParallelExecutor {
    /// Create an executor that will spread work across up to `worker_count`
    /// threads. A `worker_count` of zero is clamped to one so the queue is
    /// always drained.
    #[must_use]
    pub const fn new(worker_count: usize) -> Self {
        Self { worker_count }
    }

    /// Enqueue all `jobs`, run them across the pool, and return every result.
    ///
    /// Exactly one [`JobResult`] is produced per input [`Job`]. A worker
    /// function that returns `Err` becomes an `Err` result; a worker function
    /// that *panics* is caught (via [`std::panic::catch_unwind`]) and likewise
    /// turned into an `Err` result, so one bad job never aborts the run.
    ///
    /// The number of threads spawned is `min(worker_count, jobs.len())` (at
    /// least one when there is work, none when `jobs` is empty), matching the
    /// C dispatcher which never starts more workers than there are jobs.
    pub fn run<F>(self, jobs: Vec<Job>, worker: F) -> Vec<JobResult>
    where
        F: Fn(&Request) -> Result<Response, String> + Send + Sync + 'static,
    {
        if jobs.is_empty() {
            return Vec::new();
        }

        let job_count = jobs.len();
        let thread_count = self.worker_count.max(1).min(job_count);

        let queue: Arc<Mutex<VecDeque<Job>>> = Arc::new(Mutex::new(jobs.into()));
        let worker = Arc::new(worker);
        let (tx, rx) = mpsc::channel::<JobResult>();

        let mut handles = Vec::with_capacity(thread_count);
        for _ in 0..thread_count {
            let queue = Arc::clone(&queue);
            let worker = Arc::clone(&worker);
            let tx = tx.clone();
            handles.push(thread::spawn(move || {
                loop {
                    // Pop one job under the lock, then release it before
                    // running the (potentially slow) worker function so the
                    // other threads can make progress concurrently.
                    let job = {
                        let mut q = queue.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        match q.pop_front() {
                            Some(job) => job,
                            None => break,
                        }
                    };

                    let result = run_one(worker.as_ref(), &job.request);
                    // The receiver is only dropped after all senders (and thus
                    // all threads) are gone, so a send here cannot fail; if it
                    // somehow did there is nothing useful to do but stop.
                    if tx.send(JobResult { key: job.key, result }).is_err() {
                        break;
                    }
                }
            }));
        }

        // Drop our own sender so the channel closes once every worker exits.
        drop(tx);

        // Collect before joining: receiving until the channel closes drains
        // all results, and the threads finish on their own once the queue is
        // empty. Joining afterwards surfaces nothing actionable (panics are
        // already caught per-job) but keeps the pool tidy.
        let mut results = Vec::with_capacity(job_count);
        for result in rx {
            results.push(result);
        }
        for handle in handles {
            // A thread can only panic outside catch_unwind via a poisoned
            // mutex or a channel-send bug, neither of which should abort the
            // caller; ignore the join outcome.
            let _ = handle.join();
        }

        results
    }
}

/// Run the worker on one request, converting an `Err` return or a panic into
/// an `Err(String)` so a single job can never take down the pool.
fn run_one<F>(worker: &F, request: &Request) -> Result<Response, String>
where
    F: Fn(&Request) -> Result<Response, String>,
{
    match std::panic::catch_unwind(AssertUnwindSafe(|| worker(request))) {
        Ok(result) => result,
        Err(payload) => Err(format!("worker panicked: {}", panic_message(payload.as_ref()))),
    }
}

/// Best-effort extraction of a human-readable message from a panic payload.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    payload.downcast_ref::<&str>().map_or_else(
        || {
            payload
                .downcast_ref::<String>()
                .map_or_else(|| "unknown panic".to_owned(), Clone::clone)
        },
        |s| (*s).to_owned(),
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::message::{OkResponse, Response};
    use serde_json::json;
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Build a job whose request `cmd` carries the key so a worker can branch
    /// on it, and whose key is the same string for easy correlation.
    fn job(key: &str) -> Job {
        Job {
            key: key.to_owned(),
            request: Request {
                cmd: key.to_owned(),
                param: Vec::new(),
            },
        }
    }

    /// Build a response echoing the request's `cmd` back. Worker closures
    /// wrap this in `Ok(...)` to satisfy the `Fn(&Request) -> Result<..>`
    /// signature; keeping it `Result`-free avoids the `unnecessary_wraps`
    /// lint that a plain always-`Ok` worker fn would trip.
    fn echo_response(request: &Request) -> Response {
        Response::Ok(OkResponse {
            out: Some(json!(request.cmd)),
        })
    }

    #[test]
    fn runs_all_jobs_single_worker() {
        let jobs: Vec<Job> = (0..5).map(|n| job(&format!("k{n}"))).collect();
        let results = ParallelExecutor::new(1).run(jobs, |r| Ok(echo_response(r)));

        assert_eq!(results.len(), 5);
        let keys: HashSet<String> = results.iter().map(|r| r.key.clone()).collect();
        let expected: HashSet<String> = (0..5).map(|n| format!("k{n}")).collect();
        assert_eq!(keys, expected);
        assert!(results.iter().all(|r| r.result.is_ok()));
    }

    #[test]
    fn distributes_across_workers() {
        // Each job records the thread that ran it; with 4 workers and a brief
        // stall per job, more than one worker must be observed.
        static THREADS_SEEN: AtomicUsize = AtomicUsize::new(0);
        let seen: Arc<Mutex<HashSet<thread::ThreadId>>> = Arc::new(Mutex::new(HashSet::new()));
        let seen_worker = Arc::clone(&seen);

        let jobs: Vec<Job> = (0..20).map(|n| job(&format!("k{n}"))).collect();
        let results = ParallelExecutor::new(4).run(jobs, move |request| {
            let mut s = seen_worker.lock().unwrap();
            if s.insert(thread::current().id()) {
                THREADS_SEEN.fetch_add(1, Ordering::SeqCst);
            }
            drop(s);
            // Hold each job briefly so work overlaps across threads.
            thread::sleep(std::time::Duration::from_millis(5));
            Ok(echo_response(request))
        });

        assert_eq!(results.len(), 20);
        let keys: HashSet<String> = results.iter().map(|r| r.key.clone()).collect();
        assert_eq!(keys.len(), 20);
        assert!(results.iter().all(|r| r.result.is_ok()));
        // Prove the pool actually used more than one worker.
        assert!(
            seen.lock().unwrap().len() > 1,
            "expected work to spread across multiple threads"
        );
    }

    #[test]
    fn worker_error_becomes_err_result() {
        let jobs = vec![job("ok-a"), job("boom"), job("ok-b")];
        let results = ParallelExecutor::new(3).run(jobs, |request| {
            if request.cmd == "boom" {
                Err("kaboom".to_owned())
            } else {
                Ok(echo_response(request))
            }
        });

        assert_eq!(results.len(), 3);
        for r in &results {
            if r.key == "boom" {
                assert_eq!(r.result, Err("kaboom".to_owned()));
            } else {
                assert!(r.result.is_ok(), "{} should be Ok", r.key);
            }
        }
    }

    #[test]
    fn worker_panic_is_isolated() {
        let jobs = vec![job("ok-a"), job("panic"), job("ok-b")];
        let results = ParallelExecutor::new(3).run(jobs, |request| {
            assert!(request.cmd != "panic", "intentional test panic");
            Ok(echo_response(request))
        });

        assert_eq!(results.len(), 3);
        for r in &results {
            if r.key == "panic" {
                match &r.result {
                    Err(msg) => assert!(
                        msg.contains("worker panicked"),
                        "panic message should be surfaced, got: {msg}"
                    ),
                    Ok(_) => panic!("panicking job should yield an Err result"),
                }
            } else {
                assert!(r.result.is_ok(), "{} should be Ok", r.key);
            }
        }
    }

    #[test]
    fn empty_job_list_returns_empty() {
        let results = ParallelExecutor::new(4).run(Vec::new(), |r| Ok(echo_response(r)));
        assert!(results.is_empty());
    }

    #[test]
    fn more_workers_than_jobs_is_fine() {
        let jobs = vec![job("k0"), job("k1")];
        let results = ParallelExecutor::new(8).run(jobs, |r| Ok(echo_response(r)));

        assert_eq!(results.len(), 2);
        let keys: HashSet<String> = results.iter().map(|r| r.key.clone()).collect();
        assert_eq!(keys, HashSet::from(["k0".to_owned(), "k1".to_owned()]));
        assert!(results.iter().all(|r| r.result.is_ok()));
    }
}
