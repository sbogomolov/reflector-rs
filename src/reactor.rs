//! Single-threaded reactor: a registration arena dispatched against I/O readiness.
//!
//! Built on a generational-index [`arena`]. Registrations are addressed by a
//! `Copy` [`Key`], never a pointer or reference — which is what lets a handler
//! reach back into the reactor (to register or unregister others, or arm write
//! interest) without aliasing the storage it lives in. A freed slot bumps its
//! generation, so a stale key fails safe (resolves to nothing) instead of
//! dangling.
//!
//! The reactor owns a [`poll::Poller`] and drives the kernel (epoll/kqueue) as handlers
//! and their watched fds come and go; [`Reactor::poll_once`] waits for readiness and
//! dispatches it. A [`Handler`] is registered once and **owns** the fds it
//! [`watch`](Reactor::watch)es; each fd is watched under its own [`RegKey`], so an event
//! names the exact fd and the reactor dispatches the owning handler with the `reg_key`/`fd`
//! that fired. Unwatching (or unregistering) removes the kernel interest *first*, then
//! the handler drops and closes the fds — so interest is always gone before a fd closes:
//! no stale-interest window, and no fd the reactor double-owns (a capture socket the
//! handler also needs for I/O stays owned by the handler).
//!
//! Dispatch **takes the handler out of its slot** for the duration of its call, so
//! `&mut Reactor` is free to hand to the handler. The handler can therefore mutate the
//! reactor freely — watch/unwatch fds, register or unregister others — which a loop
//! holding an iterator into the storage would risk invalidating mid-iteration; here
//! nothing borrows the arenas during the call, so it just works.

mod arena;
mod poll;
mod signal;

pub(crate) use self::arena::{Arena, Key};

use std::io;
use std::num::NonZeroUsize;
use std::os::fd::RawFd;
use std::time::Duration;

use self::poll::Poller;

/// How many ready fds one [`wait`](poll::Poller::wait) reports. The reflector
/// watches only a handful of fds, so this is ample headroom; level-triggering
/// re-reports any overflow on the next wait, so a small buffer never loses events.
const EVENT_CAPACITY: NonZeroUsize = NonZeroUsize::new(64).unwrap();

/// A `Copy` handle to a registered handler — what [`register`](Reactor::register)
/// returns and [`unregister`](Reactor::unregister) takes. A newtype over the arena
/// [`Key`] so it can't be confused with a [`RegKey`] (a different arena).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct HandlerKey(Key);

/// A `Copy` handle to one watched fd of a handler — what [`watch`](Reactor::watch)
/// returns. It names a single fd, so it is the handle for [`set_write_interest`] and
/// [`unwatch`], and the reactor hands it back to dispatch so a handler learns *which* of
/// its fds fired.
///
/// [`set_write_interest`]: Reactor::set_write_interest
/// [`unwatch`]: Reactor::unwatch
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(crate) struct RegKey(Key);

/// Callbacks for a registered handler. The handler **owns** the fds it watches and keeps
/// them open while watched; the reactor only watches them. Each fd is watched under its
/// own [`RegKey`], so readiness on any one dispatches the handler with the `reg_key`/`fd`
/// that fired.
///
/// `on_readable` is required; `on_writable` defaults to a no-op and only fires while
/// write interest is armed for that fd (see [`Reactor::set_write_interest`]). Each is
/// handed `&mut Reactor`, so a handler can watch/unwatch fds, register or unregister
/// others, arm/disarm its own write interest, etc.
pub(crate) trait Handler {
    /// The fd that `event.reg_key` addresses is readable.
    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor);

    /// The fd that `event.reg_key` addresses is writable and its write interest is armed.
    fn on_writable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}
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

/// What fired, handed to [`Handler::on_readable`] / [`Handler::on_writable`]: the
/// registration key (for [`set_write_interest`]/[`unwatch`]), the fd, and the opaque
/// `user_data` the handler attached at [`watch`]. The reactor never interprets
/// `user_data` — a handler can pack a key, an index, or anything into it.
///
/// [`set_write_interest`]: Reactor::set_write_interest
/// [`unwatch`]: Reactor::unwatch
/// [`watch`]: Reactor::watch
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReadyEvent {
    /// The registration whose fd is ready.
    pub(crate) reg_key: RegKey,
    /// The fd that is ready.
    pub(crate) fd: RawFd,
    /// The opaque value the handler passed to [`watch`](Reactor::watch).
    pub(crate) user_data: u64,
}

/// A registered handler plus the keys of the fd-registrations that dispatch to it (so
/// [`unregister`](Reactor::unregister) can tear them all down). The handler is taken out
/// of `handler` only transiently, while it is mid-dispatch.
struct HandlerEntry {
    handler: Option<Box<dyn Handler>>,
    regs: Vec<RegKey>,
}

/// One watched fd: the fd, the handler it dispatches to, and whether its write interest
/// is armed. The poll layer tags the fd with this registration's [`RegKey`], so an event
/// names the exact fd.
struct Registration {
    fd: RawFd,
    handler_key: HandlerKey,
    write_interest: bool,
    user_data: u64,
}

/// The single-threaded reactor: owns the handlers and their per-fd registrations plus
/// the poller, and dispatches readiness to handlers.
pub(crate) struct Reactor {
    handlers: Arena<HandlerEntry>,
    registrations: Arena<Registration>,
    poll: Poller,
    shutdown: bool,
}

impl Reactor {
    /// A new reactor with no handlers and a fresh poller.
    ///
    /// # Errors
    /// Returns an error if the poller's backing fd (epoll/kqueue) cannot be created.
    pub(crate) fn new() -> io::Result<Self> {
        Ok(Self {
            handlers: Arena::new(),
            registrations: Arena::new(),
            poll: Poller::new(EVENT_CAPACITY)?,
            shutdown: false,
        })
    }

    /// Register `handler`, returning its key. It watches no fds yet — attach them with
    /// [`watch`](Self::watch), or use [`register_with_fds`](Self::register_with_fds) for
    /// a handler whose fds are known up front.
    pub(crate) fn register(&mut self, handler: Box<dyn Handler>) -> HandlerKey {
        HandlerKey(self.handlers.insert(HandlerEntry {
            handler: Some(handler),
            regs: Vec::new(),
        }))
    }

    /// Register `handler` and [`watch`](Self::watch) each `(fd, user_data)` under it in one
    /// step. On a failure the handler and any fds already attached are rolled back, so
    /// nothing is left behind.
    ///
    /// # Errors
    /// Returns an error if watching any fd fails.
    pub(crate) fn register_with_fds(
        &mut self,
        handler: Box<dyn Handler>,
        fds: &[(RawFd, u64)],
    ) -> io::Result<HandlerKey> {
        let handler_key = self.register(handler);
        for &(fd, user_data) in fds {
            if let Err(e) = self.watch(handler_key, fd, user_data) {
                self.unregister(handler_key).ok();
                return Err(e);
            }
        }
        Ok(handler_key)
    }

    /// Watch `fd` for readability on behalf of the handler `handler_key` addresses,
    /// returning the registration key — the handle to [`unwatch`](Self::unwatch) it or arm
    /// its write interest. `user_data` is opaque: the reactor stores it and hands it back
    /// in the [`ReadyEvent`] (a handler typically packs its own key there). The handler
    /// keeps owning the fd; the reactor only watches it.
    ///
    /// # Errors
    /// Returns an error if `handler_key` is not a live handler, or if the kernel
    /// registration fails (the arena insert is rolled back so no partial watch remains).
    pub(crate) fn watch(
        &mut self,
        handler_key: HandlerKey,
        fd: RawFd,
        user_data: u64,
    ) -> io::Result<RegKey> {
        // Borrow the handler once, up front — its `regs` get the new reg key at the end.
        // `handlers`, `registrations`, and `poll` are disjoint fields, so this borrow
        // stays live across the insert and the poll syscall.
        let Some(handler_entry) = self.handlers.get_mut(handler_key.0) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "watch: no such handler",
            ));
        };
        let reg_key = RegKey(self.registrations.insert(Registration {
            fd,
            handler_key,
            write_interest: false,
            user_data,
        }));
        if let Err(e) = self.poll.add(fd, reg_key.0) {
            self.registrations.remove(reg_key.0);
            return Err(e);
        }
        // Record it on the handler so `unregister` can find every fd to tear down.
        handler_entry.regs.push(reg_key);
        log::debug!("watch fd {fd} for {handler_key:?} as {reg_key:?}");
        Ok(reg_key)
    }

    /// Stop watching the fd that `reg_key` addresses, removing its kernel interest. The fd
    /// is *not* closed (the handler still owns it). Returns whether it was still live.
    ///
    /// # Errors
    /// Returns an error if removing the kernel interest fails.
    pub(crate) fn unwatch(&mut self, reg_key: RegKey) -> io::Result<bool> {
        let Some(registration) = self.registrations.remove(reg_key.0) else {
            log::trace!("unwatch: {reg_key:?} already gone");
            return Ok(false);
        };
        // Unlink it from its handler's list, then drop the kernel interest.
        if let Some(handler_entry) = self.handlers.get_mut(registration.handler_key.0) {
            handler_entry.regs.retain(|&r| r != reg_key);
        }
        self.poll.remove(registration.fd)?;
        log::debug!("unwatch fd {} ({reg_key:?})", registration.fd);
        Ok(true)
    }

    /// Drop the handler `handler_key` addresses and stop watching every fd registered to
    /// it, removing each fd's kernel interest *first* — before the handler drops and closes
    /// them. Returns whether it was still live.
    ///
    /// # Errors
    /// Returns the first error from removing a kernel interest; the rest are still
    /// removed (best-effort) so no fd is left watched.
    pub(crate) fn unregister(&mut self, handler_key: HandlerKey) -> io::Result<bool> {
        let Some(handler_entry) = self.handlers.remove(handler_key.0) else {
            log::trace!("unregister: {handler_key:?} already gone");
            return Ok(false);
        };
        // `handler_entry` keeps the handler (and its fds) alive until this returns. Tear
        // down each fd registration — kernel interest then arena slot — before it drops.
        let mut first_err = None;
        for reg_key in handler_entry.regs {
            if let Some(registration) = self.registrations.remove(reg_key.0)
                && let Err(e) = self.poll.remove(registration.fd)
            {
                first_err.get_or_insert(e);
            }
        }
        log::debug!("unregistered {handler_key:?}");
        match first_err {
            Some(e) => Err(e),
            None => Ok(true),
        }
    }

    /// Arm or disarm delivery of write readiness for the fd that `reg_key` addresses.
    /// Returns whether the registration was live.
    ///
    /// # Errors
    /// Returns an error if updating the kernel's write interest fails.
    pub(crate) fn set_write_interest(
        &mut self,
        reg_key: RegKey,
        enabled: bool,
    ) -> io::Result<bool> {
        let Some(registration) = self.registrations.get_mut(reg_key.0) else {
            log::trace!("set_write_interest: {reg_key:?} already gone");
            return Ok(false);
        };
        // Program the kernel first; flip the in-memory flag only on success, so the arena
        // and the kernel never disagree about write interest. (`self.poll` and
        // `self.registrations` are disjoint fields, so the `registration` borrow can stay
        // live across the syscall.)
        self.poll.set_write(registration.fd, reg_key.0, enabled)?;
        registration.write_interest = enabled;
        log::trace!(
            "fd {}: write interest {}",
            registration.fd,
            if enabled { "armed" } else { "disarmed" }
        );
        Ok(true)
    }

    /// Whether `handler_key` still addresses a live handler.
    #[must_use]
    pub(crate) fn is_registered(&self, handler_key: HandlerKey) -> bool {
        self.handlers.contains(handler_key.0)
    }

    /// Wait for readiness (until `timeout`, or block if `None`) and dispatch each
    /// ready fd. The single step a run loop repeats.
    ///
    /// # Errors
    /// Returns an error if the underlying wait fails. An interrupted wait reports
    /// no events rather than erroring.
    pub(crate) fn poll_once(&mut self, timeout: Option<Duration>) -> io::Result<()> {
        self.poll.wait(timeout)?;
        // `next_event` returns an owned (`Copy`) event, so the `self.poll` borrow
        // ends before `dispatch` needs `&mut self`.
        while let Some(event) = self.poll.next_event() {
            self.dispatch(RegKey(event.key), event.readiness);
        }
        Ok(())
    }

    /// Run until a shutdown signal (SIGINT/SIGTERM) arrives, dispatching readiness
    /// in between. A self-pipe shutdown handler is installed for the duration and
    /// the previous signal dispositions are restored before returning.
    ///
    /// # Errors
    /// Returns an error if the shutdown handler cannot be installed or a wait fails.
    pub(crate) fn run(&mut self) -> io::Result<()> {
        let (shutdown, pipe) = signal::ShutdownPipe::install()?;
        let fd = pipe.read_fd();
        // The signal pipe is read-only with no per-fd token, so `user_data` is unused (0).
        let handler_key = self.register_with_fds(Box::new(pipe), &[(fd, 0)])?;
        self.shutdown = false;
        let result = self.run_loop();
        // Restore the signal handlers and unpublish the write fd *before* closing
        // the read end, so a late signal can't write to a reader-less pipe.
        drop(shutdown);
        self.unregister(handler_key).ok();
        result
    }

    /// Dispatch readiness until [`request_shutdown`](Self::request_shutdown) is
    /// called. Blocks in each wait, so it idles at zero cost between events.
    fn run_loop(&mut self) -> io::Result<()> {
        while !self.shutdown {
            self.poll_once(None)?;
        }
        Ok(())
    }

    /// Ask the run loop to stop once the current dispatch returns. Handlers call
    /// this (the self-pipe handler does, on a shutdown signal); calling it outside
    /// a run loop just arms the next one to exit immediately.
    pub(crate) fn request_shutdown(&mut self) {
        self.shutdown = true;
    }

    /// Deliver `readiness` to the fd that `reg_key` addresses — the seam
    /// [`poll_once`](Self::poll_once) drives the reactor through. A stale `reg_key` (its fd
    /// was unwatched) is a safe no-op.
    fn dispatch(&mut self, reg_key: RegKey, readiness: Readiness) {
        // Resolve which fd fired and which handler owns it.
        let Some(registration) = self.registrations.get(reg_key.0) else {
            // stale reg_key — the fd was unwatched
            log::trace!("dispatch: {reg_key:?} is stale, ignored");
            return;
        };
        let handler_key = registration.handler_key;
        let event = ReadyEvent {
            reg_key,
            fd: registration.fd,
            user_data: registration.user_data,
        };
        // Take the handler out so `self` is free to pass to it. The slot stays put, so
        // `handler_key` stays valid and the handler is returned after the call.
        let Some(handler_entry) = self.handlers.get_mut(handler_key.0) else {
            log::trace!("dispatch: {reg_key:?} -> {handler_key:?} gone, ignored");
            return;
        };
        let Some(mut handler) = handler_entry.handler.take() else {
            // reentrant dispatch of a handler already in flight
            log::trace!("dispatch: {handler_key:?} already in flight, ignored");
            return;
        };

        log::trace!(
            "dispatch {reg_key:?} (fd {}): readable={} writable={}",
            event.fd,
            readiness.readable,
            readiness.writable
        );

        if readiness.readable {
            handler.on_readable(event, self);
        }
        // Write is re-gated after the read phase: the read handler may have unwatched the
        // fd or disarmed its write interest in between.
        if readiness.writable {
            if self
                .registrations
                .get(reg_key.0)
                .is_some_and(|r| r.write_interest)
            {
                handler.on_writable(event, self);
            } else {
                log::trace!("dispatch {reg_key:?}: write suppressed after read phase");
            }
        }

        // Return the handler — unless it was removed during the call, in which case the
        // handler_entry is gone and the handler is dropped.
        if let Some(handler_entry) = self.handlers.get_mut(handler_key.0) {
            handler_entry.handler = Some(handler);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::io::Write;
    use std::os::fd::{AsRawFd, OwnedFd};
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

    /// A handler whose behavior is supplied as closures, so each test wires up only what
    /// it needs. Like any real handler, it owns its fd. Each closure gets the [`ReadyEvent`]
    /// that fired plus the reactor.
    type Action = Box<dyn FnMut(ReadyEvent, &mut Reactor)>;

    struct TestHandler {
        fd: OwnedFd,
        on_read: Action,
        on_write: Option<Action>,
    }

    impl TestHandler {
        fn read(
            fd: OwnedFd,
            action: impl FnMut(ReadyEvent, &mut Reactor) + 'static,
        ) -> Box<dyn Handler> {
            Box::new(Self {
                fd,
                on_read: Box::new(action),
                on_write: None,
            })
        }

        fn read_write(
            fd: OwnedFd,
            read: impl FnMut(ReadyEvent, &mut Reactor) + 'static,
            write: impl FnMut(ReadyEvent, &mut Reactor) + 'static,
        ) -> Box<dyn Handler> {
            Box::new(Self {
                fd,
                on_read: Box::new(read),
                on_write: Some(Box::new(write)),
            })
        }
    }

    impl Handler for TestHandler {
        fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
            (self.on_read)(event, reactor);
        }

        fn on_writable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
            if let Some(write) = &mut self.on_write {
                write(event, reactor);
            }
        }
    }

    /// Register a single-fd handler and watch its fd (no user data); return both keys —
    /// the handler key (for `is_registered`/`unregister`) and the reg key (for
    /// `dispatch`/write interest).
    fn watch1(reactor: &mut Reactor, handler: Box<dyn Handler>, fd: RawFd) -> (HandlerKey, RegKey) {
        let hk = reactor.register(handler);
        let rk = reactor.watch(hk, fd, 0).unwrap();
        (hk, rk)
    }

    #[test]
    fn dispatch_calls_on_readable() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let seen = Rc::new(Cell::new(false));
        let handler = {
            let seen = seen.clone();
            TestHandler::read(a, move |_event, _reactor| seen.set(true))
        };
        let (_hk, rk) = watch1(&mut reactor, handler, raw);
        reactor.dispatch(rk, READABLE);
        assert!(seen.get());
    }

    #[test]
    fn handler_can_unregister_itself() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let hits = Rc::new(Cell::new(0u32));
        let self_key: Rc<Cell<Option<HandlerKey>>> = Rc::new(Cell::new(None));
        let handler = {
            let hits = hits.clone();
            let self_key = self_key.clone();
            TestHandler::read(a, move |_event, reactor| {
                hits.set(hits.get() + 1);
                if let Some(k) = self_key.get() {
                    reactor.unregister(k).unwrap();
                }
            })
        };
        let (hk, rk) = watch1(&mut reactor, handler, raw);
        self_key.set(Some(hk));

        reactor.dispatch(rk, READABLE);
        assert_eq!(hits.get(), 1);
        assert!(!reactor.is_registered(hk));

        // The now-stale reg dispatches to nothing.
        reactor.dispatch(rk, READABLE);
        assert_eq!(hits.get(), 1);
    }

    #[test]
    fn handler_can_register_during_dispatch() {
        // The classic mid-dispatch hazard: registering a new handler while dispatching.
        // Nothing borrows the arenas during the call, so it is simply allowed.
        let mut reactor = Reactor::new().unwrap();
        let (a, _pa) = pair();
        let raw = a.as_raw_fd();
        let (c, _pc) = pair();
        let added: Rc<Cell<Option<HandlerKey>>> = Rc::new(Cell::new(None));
        // The handler takes ownership of `c` out of this slot when it fires.
        let to_add = Rc::new(RefCell::new(Some(c)));
        let handler = {
            let added = added.clone();
            let to_add = to_add.clone();
            TestHandler::read(a, move |_event, reactor| {
                let c = to_add.borrow_mut().take().unwrap();
                let c_raw = c.as_raw_fd();
                let new_key = reactor
                    .register_with_fds(TestHandler::read(c, |_, _| {}), &[(c_raw, 0)])
                    .unwrap();
                added.set(Some(new_key));
            })
        };
        let (hk, rk) = watch1(&mut reactor, handler, raw);
        reactor.dispatch(rk, READABLE);
        assert!(reactor.is_registered(added.get().unwrap()));
        assert!(reactor.is_registered(hk));
    }

    #[test]
    fn handler_can_unregister_another() {
        let mut reactor = Reactor::new().unwrap();
        let (victim_fd, _pv) = pair();
        let victim_raw = victim_fd.as_raw_fd();
        let (actor_fd, _pa) = pair();
        let actor_raw = actor_fd.as_raw_fd();
        let victim_hits = Rc::new(Cell::new(0u32));
        let victim_handler = {
            let victim_hits = victim_hits.clone();
            TestHandler::read(victim_fd, move |_event, _reactor| {
                victim_hits.set(victim_hits.get() + 1);
            })
        };
        let (victim, victim_rk) = watch1(&mut reactor, victim_handler, victim_raw);
        let victim_cell = Rc::new(Cell::new(Some(victim)));
        let actor_handler = {
            let victim_cell = victim_cell.clone();
            TestHandler::read(actor_fd, move |_event, reactor| {
                if let Some(v) = victim_cell.get() {
                    reactor.unregister(v).unwrap();
                }
            })
        };
        let (_actor, actor_rk) = watch1(&mut reactor, actor_handler, actor_raw);

        reactor.dispatch(actor_rk, READABLE);
        assert!(!reactor.is_registered(victim));

        // Dispatching the stale victim reg is a safe no-op.
        reactor.dispatch(victim_rk, READABLE);
        assert_eq!(victim_hits.get(), 0);
    }

    #[test]
    fn write_interest_gates_on_writable() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let writes = Rc::new(Cell::new(0u32));
        let handler = TestHandler::read_write(a, |_, _| {}, {
            let writes = writes.clone();
            move |_event, _reactor| writes.set(writes.get() + 1)
        });
        let (_hk, rk) = watch1(&mut reactor, handler, raw);

        // Disarmed: writable readiness does nothing.
        reactor.dispatch(rk, WRITABLE);
        assert_eq!(writes.get(), 0);

        assert!(reactor.set_write_interest(rk, true).unwrap());
        reactor.dispatch(rk, WRITABLE);
        assert_eq!(writes.get(), 1);
    }

    #[test]
    fn read_handler_disarming_write_skips_the_write_phase() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let writes = Rc::new(Cell::new(0u32));
        // The read phase disarms write interest on its own reg before the write phase.
        let handler = TestHandler::read_write(
            a,
            |event, reactor| {
                reactor.set_write_interest(event.reg_key, false).unwrap();
            },
            {
                let writes = writes.clone();
                move |_event, _reactor| writes.set(writes.get() + 1)
            },
        );
        let (_hk, rk) = watch1(&mut reactor, handler, raw);
        reactor.set_write_interest(rk, true).unwrap();

        // Both ready, but the read handler disarms write before the write phase.
        reactor.dispatch(rk, BOTH);
        assert_eq!(writes.get(), 0);
    }

    #[test]
    fn read_handler_unregistering_itself_skips_the_write_phase() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let writes = Rc::new(Cell::new(0u32));
        let self_key: Rc<Cell<Option<HandlerKey>>> = Rc::new(Cell::new(None));
        let handler = TestHandler::read_write(
            a,
            {
                let self_key = self_key.clone();
                move |_event, reactor| {
                    if let Some(k) = self_key.get() {
                        reactor.unregister(k).unwrap();
                    }
                }
            },
            {
                let writes = writes.clone();
                move |_event, _reactor| writes.set(writes.get() + 1)
            },
        );
        let (hk, rk) = watch1(&mut reactor, handler, raw);
        self_key.set(Some(hk));
        reactor.set_write_interest(rk, true).unwrap();

        reactor.dispatch(rk, BOTH);
        assert_eq!(writes.get(), 0); // handler gone after read, write skipped
        assert!(!reactor.is_registered(hk));
    }

    #[test]
    fn dispatching_a_stale_reg_is_a_noop() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let handler = TestHandler::read(a, |_, _| panic!("must not fire"));
        let (hk, rk) = watch1(&mut reactor, handler, raw);
        assert!(reactor.unregister(hk).unwrap());
        reactor.dispatch(rk, READABLE); // no panic, no effect
    }

    #[test]
    fn poll_once_dispatches_a_ready_fd() {
        let mut reactor = Reactor::new().unwrap();
        let (a, peer) = pair();
        let raw = a.as_raw_fd();
        let fired = Rc::new(Cell::new(false));
        let handler = {
            let fired = fired.clone();
            TestHandler::read(a, move |_event, _reactor| fired.set(true))
        };
        watch1(&mut reactor, handler, raw);

        // Nothing ready yet: poll_once dispatches nothing.
        reactor.poll_once(Some(short())).unwrap();
        assert!(!fired.get());

        // Make the registered fd readable, then poll: the handler fires.
        (&peer).write_all(b"x").unwrap();
        reactor.poll_once(Some(short())).unwrap();
        assert!(fired.get());
    }

    #[test]
    fn run_loop_stops_when_a_handler_requests_shutdown() {
        let mut reactor = Reactor::new().unwrap();
        let (a, peer) = pair();
        let raw = a.as_raw_fd();
        let handler = TestHandler::read(a, |_event, reactor| reactor.request_shutdown());
        watch1(&mut reactor, handler, raw);
        // Readable before looping, so the first (blocking) wait returns at once.
        (&peer).write_all(b"x").unwrap();
        reactor.run_loop().unwrap();
        assert!(reactor.shutdown);
    }

    #[test]
    fn unwatch_removes_one_fd_and_leaves_the_handler() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _pa) = pair();
        let a_raw = a.as_raw_fd();
        let (b, _pb) = pair();
        let b_raw = b.as_raw_fd();
        let hits = Rc::new(Cell::new(0u32));
        // One handler watching two fds (it owns `a`; the test keeps `b` alive).
        let handler = {
            let hits = hits.clone();
            TestHandler::read(a, move |_event, _reactor| hits.set(hits.get() + 1))
        };
        let hk = reactor.register(handler);
        let reg_a = reactor.watch(hk, a_raw, 0).unwrap();
        let reg_b = reactor.watch(hk, b_raw, 0).unwrap();

        reactor.dispatch(reg_a, READABLE);
        reactor.dispatch(reg_b, READABLE);
        assert_eq!(hits.get(), 2);

        // Unwatch one fd: it goes stale, but the handler and its other fd stay live.
        assert!(reactor.unwatch(reg_a).unwrap());
        reactor.dispatch(reg_a, READABLE); // stale, no-op
        reactor.dispatch(reg_b, READABLE);
        assert_eq!(hits.get(), 3);
        assert!(reactor.is_registered(hk));

        // Unwatching an already-gone reg is a benign false.
        assert!(!reactor.unwatch(reg_a).unwrap());
    }

    #[test]
    fn watch_hands_back_the_ready_event() {
        let mut reactor = Reactor::new().unwrap();
        let (a, _peer) = pair();
        let raw = a.as_raw_fd();
        let seen: Rc<Cell<Option<ReadyEvent>>> = Rc::new(Cell::new(None));
        let handler = {
            let seen = seen.clone();
            TestHandler::read(a, move |event, _reactor| seen.set(Some(event)))
        };
        let hk = reactor.register(handler);
        let rk = reactor.watch(hk, raw, 0xdead_beef).unwrap();

        reactor.dispatch(rk, READABLE);
        let event = seen.get().expect("handler fired");
        assert_eq!(event.user_data, 0xdead_beef); // the token round-trips
        assert_eq!(event.fd, raw);
        assert_eq!(event.reg_key, rk);
    }
}
