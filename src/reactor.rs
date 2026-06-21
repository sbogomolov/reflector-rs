//! Single-threaded reactor: a registration arena dispatched against I/O readiness.
//!
//! Built on a generational-index [`arena`]. Registrations are addressed by a
//! `Copy` [`Key`], never a pointer or reference — which is what lets a handler
//! reach back into the reactor (to register or unregister others, or arm write
//! interest) without aliasing the storage it lives in. A freed slot bumps its
//! generation, so a stale key fails safe (resolves to nothing) instead of
//! dangling.
//!
//! The reactor owns a [`poll::Poller`] and drives the kernel (epoll/kqueue) as
//! registrations come and go; [`Reactor::poll_once`] waits for readiness and
//! dispatches it. It also owns each registered fd, so unregistering removes the
//! kernel interest and closes the fd together — no stale-interest window.
//!
//! Dispatch **takes the handler out of its slot** for the duration of its call,
//! so `&mut Reactor` is free to hand to the handler. The handler can therefore
//! mutate the reactor freely — including registering new fds, which in the C++
//! original risked invalidating the iterator mid-loop and needed a re-resolve;
//! here nothing borrows the arena during the call, so it just works.

mod arena;
mod poll;

pub(crate) use self::arena::Key;

use std::io;
use std::num::NonZeroUsize;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::Duration;

use self::arena::Arena;
use self::poll::Poller;

/// How many ready fds one [`wait`](poll::Poller::wait) reports. The reflector
/// watches only a handful of fds, so this is ample headroom; level-triggering
/// re-reports any overflow on the next wait, so a small buffer never loses events.
const EVENT_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).unwrap();

/// Callbacks for a registered file descriptor.
///
/// `on_readable` is required; `on_writable` defaults to a no-op and only fires
/// while write interest is armed (see [`Reactor::set_write_interest`]). Each is
/// handed the fd and `&mut Reactor`, so a handler can register or unregister
/// others, arm/disarm its own write interest, etc.
pub(crate) trait Handler {
    /// The registered fd is readable.
    fn on_readable(&mut self, fd: RawFd, reactor: &mut Reactor);

    /// The registered fd is writable and write interest is armed.
    fn on_writable(&mut self, _fd: RawFd, _reactor: &mut Reactor) {}
}

/// What a registration is ready for in a given dispatch — the event a poll loop
/// (or a test) feeds the reactor.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Readiness {
    /// The fd is readable.
    pub(crate) readable: bool,
    /// The fd is writable.
    pub(crate) writable: bool,
}

/// One registered fd: the reactor owns the fd, tracks write interest, and holds
/// the handler (taken out only transiently during dispatch).
struct Registration {
    fd: OwnedFd,
    write_interest: bool,
    handler: Option<Box<dyn Handler>>,
}

/// The single-threaded reactor: owns the registrations and the poller, and
/// dispatches readiness to handlers.
pub(crate) struct Reactor {
    registrations: Arena<Registration>,
    poll: Poller,
}

impl Reactor {
    /// A new reactor with an empty registration set and a fresh poller.
    ///
    /// # Errors
    /// Returns an error if the poller's backing fd (epoll/kqueue) cannot be created.
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            registrations: Arena::new(),
            poll: Poller::new(EVENT_CAPACITY)?,
        })
    }

    /// Register `handler` for `fd`, returning the key that addresses it. The
    /// reactor takes ownership of `fd`; write interest starts disarmed. The key is
    /// the only way to unregister or re-target the registration later.
    ///
    /// # Errors
    /// Returns an error if the kernel registration fails; the arena insert is
    /// rolled back so no partial registration remains.
    pub(crate) fn register(&mut self, fd: OwnedFd, handler: Box<dyn Handler>) -> io::Result<Key> {
        let raw = fd.as_raw_fd();
        let key = self.registrations.insert(Registration {
            fd,
            write_interest: false,
            handler: Some(handler),
        });
        if let Err(e) = self.poll.add(raw, key) {
            // Undo the insert so a failed registration leaves nothing behind.
            self.registrations.remove(key);
            return Err(e);
        }
        log::debug!("registered fd {raw}");
        Ok(key)
    }

    /// Drop the registration `key` addresses: remove its kernel interest and close
    /// the fd. Returns whether it was still live.
    ///
    /// # Errors
    /// Returns an error if removing the kernel interest fails.
    pub(crate) fn unregister(&mut self, key: Key) -> io::Result<bool> {
        let Some(reg) = self.registrations.remove(key) else {
            log::trace!("unregister: {key:?} already gone");
            return Ok(false);
        };
        let raw = reg.fd.as_raw_fd();
        // Remove kernel interest before `reg` drops and closes the fd.
        self.poll.remove(raw)?;
        log::debug!("unregistered fd {raw}");
        Ok(true)
    }

    /// Arm or disarm delivery of write readiness for the registration `key`
    /// addresses. Returns whether the key was live.
    ///
    /// # Errors
    /// Returns an error if updating the kernel's write interest fails.
    pub(crate) fn set_write_interest(&mut self, key: Key, enabled: bool) -> io::Result<bool> {
        let Some(reg) = self.registrations.get_mut(key) else {
            log::trace!("set_write_interest: {key:?} already gone");
            return Ok(false);
        };
        let raw = reg.fd.as_raw_fd();
        // Program the kernel first; flip the in-memory flag only on success, so the
        // arena and the kernel never disagree about write interest. (`self.poll` and
        // `self.registrations` are disjoint fields, so the `reg` borrow can stay live
        // across the syscall.)
        self.poll.set_write(raw, key, enabled)?;
        reg.write_interest = enabled;
        log::trace!(
            "fd {raw}: write interest {}",
            if enabled { "armed" } else { "disarmed" }
        );
        Ok(true)
    }

    /// Whether `key` still addresses a live registration.
    #[must_use]
    pub(crate) fn is_registered(&self, key: Key) -> bool {
        self.registrations.contains(key)
    }

    /// Wait for readiness (until `timeout`, or block if `None`) and dispatch each
    /// ready fd. The single step a run loop repeats.
    ///
    /// # Errors
    /// Returns an error if the underlying wait fails. An interrupted wait reports
    /// no events rather than erroring.
    pub(crate) fn poll_once(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        let ready = self.poll.wait(timeout)?;
        for i in 0..ready {
            // Copy the event out (it is `Copy`) so the `self.poll` borrow ends
            // before `dispatch` needs `&mut self`.
            let event = self.poll.event(i);
            self.dispatch(event.key, event.readiness);
        }
        Ok(())
    }

    /// Deliver `readiness` to the registration `key` addresses — the seam
    /// [`poll_once`](Self::poll_once) drives the reactor through. A stale key is a
    /// safe no-op.
    fn dispatch(&mut self, key: Key, readiness: Readiness) {
        // Take the handler out so `self` is free to be borrowed for the call. The
        // slot stays put, so `key` stays valid and the handler can be returned.
        let Some(reg) = self.registrations.get_mut(key) else {
            // stale key — the registration is gone
            log::trace!("dispatch: {key:?} is stale, ignored");
            return;
        };
        let fd = reg.fd.as_raw_fd();
        let Some(mut handler) = reg.handler.take() else {
            // reentrant dispatch of a slot already in flight
            log::trace!("dispatch: fd {fd} already in flight, ignored");
            return;
        };

        log::trace!(
            "dispatch fd {fd}: readable={} writable={}",
            readiness.readable,
            readiness.writable
        );

        if readiness.readable {
            handler.on_readable(fd, self);
        }
        // Write is re-gated after the read phase: the read handler may have
        // unregistered the fd or disarmed write interest in between.
        if readiness.writable {
            if self
                .registrations
                .get(key)
                .is_some_and(|reg| reg.write_interest)
            {
                handler.on_writable(fd, self);
            } else {
                log::trace!("dispatch fd {fd}: write suppressed after read phase");
            }
        }

        // Return the handler — unless the registration was removed during the
        // call, in which case the slot is gone and the handler is dropped.
        if let Some(reg) = self.registrations.get_mut(key) {
            reg.handler = Some(handler);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::rc::Rc;

    const READABLE: Readiness = Readiness {
        readable: true,
        writable: false,
    };
    const WRITABLE: Readiness = Readiness {
        readable: false,
        writable: true,
    };
    const BOTH: Readiness = Readiness {
        readable: true,
        writable: true,
    };

    fn short() -> Duration {
        Duration::from_millis(50)
    }

    /// A connected socketpair: the owned end (to register) plus its peer (kept
    /// alive; write to it to make the registered end readable).
    fn pair() -> (OwnedFd, UnixStream) {
        let (a, b) = UnixStream::pair().unwrap();
        (OwnedFd::from(a), b)
    }

    /// A handler whose behavior is supplied as closures, so each test wires up
    /// only what it needs.
    type Action = Box<dyn FnMut(RawFd, &mut Reactor)>;

    struct TestHandler {
        on_read: Action,
        on_write: Option<Action>,
    }

    impl TestHandler {
        fn read(action: impl FnMut(RawFd, &mut Reactor) + 'static) -> Box<dyn Handler> {
            Box::new(Self {
                on_read: Box::new(action),
                on_write: None,
            })
        }

        fn read_write(
            read: impl FnMut(RawFd, &mut Reactor) + 'static,
            write: impl FnMut(RawFd, &mut Reactor) + 'static,
        ) -> Box<dyn Handler> {
            Box::new(Self {
                on_read: Box::new(read),
                on_write: Some(Box::new(write)),
            })
        }
    }

    impl Handler for TestHandler {
        fn on_readable(&mut self, fd: RawFd, reactor: &mut Reactor) {
            (self.on_read)(fd, reactor);
        }

        fn on_writable(&mut self, fd: RawFd, reactor: &mut Reactor) {
            if let Some(write) = &mut self.on_write {
                write(fd, reactor);
            }
        }
    }

    #[test]
    fn dispatch_calls_on_readable_with_the_fd() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let fd = a.as_raw_fd();
        let seen = Rc::new(Cell::new(0));
        let key = reactor
            .register(a, {
                let seen = seen.clone();
                TestHandler::read(move |f, _| seen.set(f))
            })
            .unwrap();
        reactor.dispatch(key, READABLE);
        assert_eq!(seen.get(), fd);
    }

    #[test]
    fn handler_can_unregister_itself() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let hits = Rc::new(Cell::new(0u32));
        let self_key = Rc::new(Cell::new(None));
        let key = reactor
            .register(a, {
                let hits = hits.clone();
                let self_key = self_key.clone();
                TestHandler::read(move |_, reactor| {
                    hits.set(hits.get() + 1);
                    if let Some(k) = self_key.get() {
                        reactor.unregister(k).unwrap();
                    }
                })
            })
            .unwrap();
        self_key.set(Some(key));

        reactor.dispatch(key, READABLE);
        assert_eq!(hits.get(), 1);
        assert!(!reactor.is_registered(key));

        // The now-stale key dispatches to nothing.
        reactor.dispatch(key, READABLE);
        assert_eq!(hits.get(), 1);
    }

    #[test]
    fn handler_can_register_during_dispatch() {
        // The C++ rehash hazard: registering a new fd mid-dispatch. Here nothing
        // borrows the arena during the call, so it is simply allowed.
        let mut reactor = Reactor::new().unwrap();
        let (a, _pa) = pair();
        let (c, _pc) = pair();
        let added = Rc::new(Cell::new(None));
        // The handler takes ownership of `c` out of this slot when it fires.
        let to_add = Rc::new(RefCell::new(Some(c)));
        let key = reactor
            .register(a, {
                let added = added.clone();
                let to_add = to_add.clone();
                TestHandler::read(move |_, reactor| {
                    let c = to_add.borrow_mut().take().unwrap();
                    let new_key = reactor.register(c, TestHandler::read(|_, _| {})).unwrap();
                    added.set(Some(new_key));
                })
            })
            .unwrap();
        reactor.dispatch(key, READABLE);
        assert!(reactor.is_registered(added.get().unwrap()));
        assert!(reactor.is_registered(key));
    }

    #[test]
    fn handler_can_unregister_another() {
        let mut reactor = Reactor::new().unwrap();
        let (victim_fd, _pv) = pair();
        let (actor_fd, _pa) = pair();
        let victim_hits = Rc::new(Cell::new(0u32));
        let victim = reactor
            .register(victim_fd, {
                let victim_hits = victim_hits.clone();
                TestHandler::read(move |_, _| victim_hits.set(victim_hits.get() + 1))
            })
            .unwrap();
        let victim_cell = Rc::new(Cell::new(Some(victim)));
        let actor = reactor
            .register(actor_fd, {
                let victim_cell = victim_cell.clone();
                TestHandler::read(move |_, reactor| {
                    if let Some(v) = victim_cell.get() {
                        reactor.unregister(v).unwrap();
                    }
                })
            })
            .unwrap();

        reactor.dispatch(actor, READABLE);
        assert!(!reactor.is_registered(victim));

        // Dispatching the stale victim key is a safe no-op.
        reactor.dispatch(victim, READABLE);
        assert_eq!(victim_hits.get(), 0);
    }

    #[test]
    fn write_interest_gates_on_writable() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let writes = Rc::new(Cell::new(0u32));
        let key = reactor
            .register(
                a,
                TestHandler::read_write(|_, _| {}, {
                    let writes = writes.clone();
                    move |_, _| writes.set(writes.get() + 1)
                }),
            )
            .unwrap();

        // Disarmed: writable readiness does nothing.
        reactor.dispatch(key, WRITABLE);
        assert_eq!(writes.get(), 0);

        assert!(reactor.set_write_interest(key, true).unwrap());
        reactor.dispatch(key, WRITABLE);
        assert_eq!(writes.get(), 1);
    }

    #[test]
    fn read_handler_disarming_write_skips_the_write_phase() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let writes = Rc::new(Cell::new(0u32));
        let self_key = Rc::new(Cell::new(None));
        let key = reactor
            .register(
                a,
                TestHandler::read_write(
                    {
                        let self_key = self_key.clone();
                        move |_, reactor| {
                            if let Some(k) = self_key.get() {
                                reactor.set_write_interest(k, false).unwrap();
                            }
                        }
                    },
                    {
                        let writes = writes.clone();
                        move |_, _| writes.set(writes.get() + 1)
                    },
                ),
            )
            .unwrap();
        self_key.set(Some(key));
        reactor.set_write_interest(key, true).unwrap();

        // Both ready, but the read handler disarms write before the write phase.
        reactor.dispatch(key, BOTH);
        assert_eq!(writes.get(), 0);
    }

    #[test]
    fn read_handler_unregistering_itself_skips_the_write_phase() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let writes = Rc::new(Cell::new(0u32));
        let self_key = Rc::new(Cell::new(None));
        let key = reactor
            .register(
                a,
                TestHandler::read_write(
                    {
                        let self_key = self_key.clone();
                        move |_, reactor| {
                            if let Some(k) = self_key.get() {
                                reactor.unregister(k).unwrap();
                            }
                        }
                    },
                    {
                        let writes = writes.clone();
                        move |_, _| writes.set(writes.get() + 1)
                    },
                ),
            )
            .unwrap();
        self_key.set(Some(key));
        reactor.set_write_interest(key, true).unwrap();

        reactor.dispatch(key, BOTH);
        assert_eq!(writes.get(), 0); // fd gone after read, write skipped
        assert!(!reactor.is_registered(key));
    }

    #[test]
    fn dispatching_a_stale_key_is_a_noop() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let key = reactor
            .register(a, TestHandler::read(|_, _| panic!("must not fire")))
            .unwrap();
        assert!(reactor.unregister(key).unwrap());
        reactor.dispatch(key, READABLE); // no panic, no effect
    }

    #[test]
    fn poll_once_dispatches_a_ready_fd() {
        let mut reactor = Reactor::new().unwrap();
        let (a, peer) = pair();
        let fired = Rc::new(Cell::new(false));
        reactor
            .register(a, {
                let fired = fired.clone();
                TestHandler::read(move |_, _| fired.set(true))
            })
            .unwrap();

        // Nothing ready yet: poll_once dispatches nothing.
        reactor.poll_once(Some(short())).unwrap();
        assert!(!fired.get());

        // Make the registered fd readable, then poll: the handler fires.
        (&peer).write_all(b"x").unwrap();
        reactor.poll_once(Some(short())).unwrap();
        assert!(fired.get());
    }
}
