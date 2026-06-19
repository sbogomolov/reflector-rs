//! Single-threaded reactor: a registration arena dispatched against I/O readiness.
//!
//! Built on a generational-index [`arena`]. Registrations are addressed by a
//! `Copy` [`Key`], never a pointer or reference — which is what lets a handler
//! reach back into the reactor (to register or unregister others, or arm write
//! interest) without aliasing the storage it lives in. A freed slot bumps its
//! generation, so a stale key fails safe (resolves to nothing) instead of
//! dangling.
//!
//! Dispatch **takes the handler out of its slot** for the duration of its call,
//! so `&mut Reactor` is free to hand to the handler. The handler can therefore
//! mutate the reactor freely — including registering new fds, which in the C++
//! original risked invalidating the iterator mid-loop and needed a re-resolve;
//! here nothing borrows the arena during the call, so it just works.

mod arena;

pub use arena::Key;

use std::os::fd::RawFd;

use arena::Arena;

/// Callbacks for a registered file descriptor.
///
/// `on_readable` is required; `on_writable` defaults to a no-op and only fires
/// while write interest is armed (see [`Reactor::set_write_interest`]). Each is
/// handed the fd and `&mut Reactor`, so a handler can register or unregister
/// others, arm/disarm its own write interest, etc.
pub trait Handler {
    /// The registered fd is readable.
    fn on_readable(&mut self, fd: RawFd, reactor: &mut Reactor);

    /// The registered fd is writable and write interest is armed.
    fn on_writable(&mut self, _fd: RawFd, _reactor: &mut Reactor) {}
}

/// What a registration is ready for in a given dispatch — the event a poll loop
/// (or a test) feeds the reactor.
#[derive(Debug, Clone, Copy)]
pub struct Readiness {
    /// The fd is readable.
    pub readable: bool,
    /// The fd is writable.
    pub writable: bool,
}

/// One registered fd: its handler (taken out only transiently during dispatch)
/// and whether write readiness should be delivered.
struct Registration {
    fd: RawFd,
    write_interest: bool,
    handler: Option<Box<dyn Handler>>,
}

/// The single-threaded reactor: owns the registrations, dispatches readiness.
pub struct Reactor {
    registrations: Arena<Registration>,
}

impl Reactor {
    /// An empty reactor.
    #[must_use]
    pub fn new() -> Self {
        Self {
            registrations: Arena::new(),
        }
    }

    /// Register `handler` for `fd`, returning the key that addresses it. Write
    /// interest starts disarmed. The key is the only way to unregister or
    /// re-target the registration later.
    pub fn register(&mut self, fd: RawFd, handler: Box<dyn Handler>) -> Key {
        self.registrations.insert(Registration {
            fd,
            write_interest: false,
            handler: Some(handler),
        })
    }

    /// Drop the registration `key` addresses. Returns whether it was still live.
    pub fn unregister(&mut self, key: Key) -> bool {
        self.registrations.remove(key).is_some()
    }

    /// Arm or disarm delivery of write readiness for the registration `key`
    /// addresses. Returns whether the key was live.
    pub fn set_write_interest(&mut self, key: Key, enabled: bool) -> bool {
        if let Some(reg) = self.registrations.get_mut(key) {
            reg.write_interest = enabled;
            true
        } else {
            false
        }
    }

    /// Whether `key` still addresses a live registration.
    #[must_use]
    pub fn is_registered(&self, key: Key) -> bool {
        self.registrations.contains(key)
    }

    /// Deliver `readiness` to the registration `key` addresses — the seam a poll
    /// loop drives the reactor through. A stale key is a safe no-op.
    pub fn dispatch(&mut self, key: Key, readiness: Readiness) {
        // Take the handler out so `self` is free to be borrowed for the call. The
        // slot stays put, so `key` stays valid and the handler can be returned.
        let (fd, mut handler) = match self.registrations.get_mut(key) {
            Some(reg) => {
                let fd = reg.fd;
                match reg.handler.take() {
                    Some(handler) => (fd, handler),
                    None => return, // reentrant dispatch of a slot already in flight
                }
            }
            None => return, // stale key — the registration is gone
        };

        if readiness.readable {
            handler.on_readable(fd, self);
        }
        // The read handler may have unregistered this fd or disarmed its write.
        if readiness.writable
            && self
                .registrations
                .get(key)
                .is_some_and(|reg| reg.write_interest)
        {
            handler.on_writable(fd, self);
        }

        // Return the handler — unless the registration was removed during the
        // call, in which case the slot is gone and the handler is dropped.
        if let Some(reg) = self.registrations.get_mut(key) {
            reg.handler = Some(handler);
        }
    }
}

impl Default for Reactor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
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
        let mut reactor = Reactor::new();
        let seen = Rc::new(Cell::new(0));
        let key = reactor.register(3, {
            let seen = seen.clone();
            TestHandler::read(move |fd, _| seen.set(fd))
        });
        reactor.dispatch(key, READABLE);
        assert_eq!(seen.get(), 3);
    }

    #[test]
    fn handler_can_unregister_itself() {
        let mut reactor = Reactor::new();
        let hits = Rc::new(Cell::new(0u32));
        let self_key = Rc::new(Cell::new(None));
        let key = reactor.register(3, {
            let hits = hits.clone();
            let self_key = self_key.clone();
            TestHandler::read(move |_, reactor| {
                hits.set(hits.get() + 1);
                if let Some(k) = self_key.get() {
                    reactor.unregister(k);
                }
            })
        });
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
        let mut reactor = Reactor::new();
        let added = Rc::new(Cell::new(None));
        let key = reactor.register(3, {
            let added = added.clone();
            TestHandler::read(move |_, reactor| {
                let new_key = reactor.register(4, TestHandler::read(|_, _| {}));
                added.set(Some(new_key));
            })
        });
        reactor.dispatch(key, READABLE);
        assert!(reactor.is_registered(added.get().unwrap()));
        assert!(reactor.is_registered(key));
    }

    #[test]
    fn handler_can_unregister_another() {
        let mut reactor = Reactor::new();
        let victim_hits = Rc::new(Cell::new(0u32));
        let victim = reactor.register(4, {
            let victim_hits = victim_hits.clone();
            TestHandler::read(move |_, _| victim_hits.set(victim_hits.get() + 1))
        });
        let victim_cell = Rc::new(Cell::new(Some(victim)));
        let actor = reactor.register(3, {
            let victim_cell = victim_cell.clone();
            TestHandler::read(move |_, reactor| {
                if let Some(v) = victim_cell.get() {
                    reactor.unregister(v);
                }
            })
        });

        reactor.dispatch(actor, READABLE);
        assert!(!reactor.is_registered(victim));

        // Dispatching the stale victim key is a safe no-op.
        reactor.dispatch(victim, READABLE);
        assert_eq!(victim_hits.get(), 0);
    }

    #[test]
    fn write_interest_gates_on_writable() {
        let mut reactor = Reactor::new();
        let writes = Rc::new(Cell::new(0u32));
        let key = reactor.register(
            3,
            TestHandler::read_write(|_, _| {}, {
                let writes = writes.clone();
                move |_, _| writes.set(writes.get() + 1)
            }),
        );

        // Disarmed: writable readiness does nothing.
        reactor.dispatch(key, WRITABLE);
        assert_eq!(writes.get(), 0);

        assert!(reactor.set_write_interest(key, true));
        reactor.dispatch(key, WRITABLE);
        assert_eq!(writes.get(), 1);
    }

    #[test]
    fn read_handler_disarming_write_skips_the_write_phase() {
        let mut reactor = Reactor::new();
        let writes = Rc::new(Cell::new(0u32));
        let self_key = Rc::new(Cell::new(None));
        let key = reactor.register(
            3,
            TestHandler::read_write(
                {
                    let self_key = self_key.clone();
                    move |_, reactor| {
                        if let Some(k) = self_key.get() {
                            reactor.set_write_interest(k, false);
                        }
                    }
                },
                {
                    let writes = writes.clone();
                    move |_, _| writes.set(writes.get() + 1)
                },
            ),
        );
        self_key.set(Some(key));
        reactor.set_write_interest(key, true);

        // Both ready, but the read handler disarms write before the write phase.
        reactor.dispatch(key, BOTH);
        assert_eq!(writes.get(), 0);
    }

    #[test]
    fn read_handler_unregistering_itself_skips_the_write_phase() {
        let mut reactor = Reactor::new();
        let writes = Rc::new(Cell::new(0u32));
        let self_key = Rc::new(Cell::new(None));
        let key = reactor.register(
            3,
            TestHandler::read_write(
                {
                    let self_key = self_key.clone();
                    move |_, reactor| {
                        if let Some(k) = self_key.get() {
                            reactor.unregister(k);
                        }
                    }
                },
                {
                    let writes = writes.clone();
                    move |_, _| writes.set(writes.get() + 1)
                },
            ),
        );
        self_key.set(Some(key));
        reactor.set_write_interest(key, true);

        reactor.dispatch(key, BOTH);
        assert_eq!(writes.get(), 0); // fd gone after read, write skipped
        assert!(!reactor.is_registered(key));
    }

    #[test]
    fn dispatching_a_stale_key_is_a_noop() {
        let mut reactor = Reactor::new();
        let key = reactor.register(3, TestHandler::read(|_, _| panic!("must not fire")));
        assert!(reactor.unregister(key));
        reactor.dispatch(key, READABLE); // no panic, no effect
    }
}
