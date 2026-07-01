//! A fixed-capacity byte buffer for one direction of a proxied TCP stream: appended at the back (from
//! a recv, possibly after a header rewrite), consumed from the front as a send drains them. Backed by a
//! `Box<[MaybeUninit<u8>]>` allocated on first use — most send-side buffers never backpressure, so they
//! never allocate — and never zero-filled, since only the written `storage[consumed..filled]` region is
//! ever read. Capacity is fixed: an append past it returns [`Overflow`] and the proxy drops-and-closes
//! rather than let a stuck peer pin unbounded memory. Two cursors bound the live bytes:
//! `storage[consumed..filled]`.

use std::mem::MaybeUninit;
use std::{ptr, slice};

/// From [`StreamBuffer::append`] when the data won't fit even after reclaiming the consumed prefix —
/// the caller drops and closes the connection.
#[derive(Debug)]
pub(crate) struct Overflow;

/// A bounded FIFO byte buffer: append at `filled`, consume from `consumed`, unsent bytes in between.
/// The backing box is allocated (uninitialized) on first use, sized to `capacity`, and never reallocates.
pub(crate) struct StreamBuffer {
    /// The backing store, `None` until the first append or `free_tail_mut`; `capacity` bytes once set.
    storage: Option<Box<[MaybeUninit<u8>]>>,
    capacity: usize,
    /// Bytes written; the initialized region is `storage[..filled]`.
    filled: usize,
    /// Bytes drained from the front; the live (unsent) region is `storage[consumed..filled]`.
    consumed: usize,
}

impl StreamBuffer {
    /// Holds at most `cap` live bytes. The backing store is allocated — uninitialized, never zero-filled —
    /// on the first `append`/`free_tail_mut`, so an idle buffer costs nothing.
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self {
            storage: None,
            capacity: cap,
            filled: 0,
            consumed: 0,
        }
    }

    /// The unsent bytes, for one `send`.
    pub(crate) fn pending(&self) -> &[u8] {
        match &self.storage {
            // SAFETY: bytes enter `[..filled]` only via `append` (which writes them) or `commit` (whose
            // contract is that `free_tail_mut`'s region was written), so `[consumed..filled]` is
            // initialized. `MaybeUninit<u8>` and `u8` share layout.
            Some(storage) => unsafe {
                let live = &storage[self.consumed..self.filled];
                slice::from_raw_parts(live.as_ptr().cast::<u8>(), live.len())
            },
            None => &[],
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.filled - self.consumed
    }

    /// Nothing waiting to be sent — the cue to disarm write interest.
    pub(crate) fn is_empty(&self) -> bool {
        self.filled == self.consumed
    }

    /// Append `data`, reclaiming the consumed prefix first if the tail can't hold it. `Err` (buffer
    /// unchanged) if the live bytes plus `data` would exceed capacity — the caller drops-and-closes.
    pub(crate) fn append(&mut self, data: &[u8]) -> Result<(), Overflow> {
        if self.len() + data.len() > self.capacity {
            return Err(Overflow);
        }
        if data.is_empty() {
            return Ok(()); // nothing to write — and no reason to force the lazy allocation
        }
        // Fits, but maybe not in the tail — slide the live bytes down to reclaim the consumed gap.
        if self.filled + data.len() > self.capacity {
            self.compact();
        }
        let filled = self.filled;
        let storage = self.ensure_alloc();
        // SAFETY: `filled + data.len() <= capacity` (checked above, and `compact` reclaimed the consumed
        // prefix if the tail was short), so the destination stays in bounds. Source and destination can't
        // overlap: `data` is a shared borrow, `storage` lives behind `&mut self`, so `data` aliasing it
        // would be a shared+exclusive borrow of the same bytes — which the borrow checker rejects.
        // `MaybeUninit<u8>` and `u8` share layout.
        unsafe {
            ptr::copy_nonoverlapping(
                data.as_ptr(),
                storage.as_mut_ptr().add(filled).cast::<u8>(),
                data.len(),
            );
        }
        self.filled = filled + data.len();
        Ok(())
    }

    /// The free space at the back, to receive into in place. Reclaims the consumed prefix first when
    /// the tail is exhausted, so the whole spare capacity is offered as one slice; pair with
    /// [`commit`](Self::commit) to mark how many bytes landed. Empty only when full of live bytes — the
    /// caller then holds an unframable, over-long message and drops-and-closes. The bytes are
    /// uninitialized: write, don't read, until they are committed.
    pub(crate) fn free_tail_mut(&mut self) -> &mut [MaybeUninit<u8>] {
        if self.filled == self.capacity && self.consumed > 0 {
            self.compact();
        }
        let filled = self.filled;
        &mut self.ensure_alloc()[filled..]
    }

    /// Mark `n` bytes received into [`free_tail_mut`](Self::free_tail_mut) as filled.
    pub(crate) fn commit(&mut self, n: usize) {
        debug_assert!(self.filled + n <= self.capacity, "commit past the capacity");
        self.filled += n;
    }

    /// Drop the first `n` bytes after a send wrote them. Resets both cursors to the front once the
    /// buffer empties, so a fully-drained buffer offers its whole capacity again.
    pub(crate) fn consume(&mut self, n: usize) {
        debug_assert!(
            self.consumed + n <= self.filled,
            "consume past the filled bytes"
        );
        self.consumed += n;
        // `>=`, not `==`: the assert is compiled out in release, so an over-consume must still reset
        // cleanly rather than leave `consumed > filled` — which would underflow `len` and panic
        // `pending`'s slice next call.
        if self.consumed >= self.filled {
            self.consumed = 0;
            self.filled = 0;
        }
    }

    /// The backing store, allocating it (uninitialized) on first call.
    fn ensure_alloc(&mut self) -> &mut [MaybeUninit<u8>] {
        let capacity = self.capacity;
        &mut self
            .storage
            .get_or_insert_with(|| Box::new_uninit_slice(capacity))[..]
    }

    /// Slide the live bytes to the front, dropping the consumed prefix.
    fn compact(&mut self) {
        if let Some(storage) = &mut self.storage {
            storage.copy_within(self.consumed..self.filled, 0);
        }
        self.filled -= self.consumed;
        self.consumed = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Write `data` into the front of an uninitialized tail slice, for tests.
    fn fill(tail: &mut [MaybeUninit<u8>], data: &[u8]) {
        for (slot, &byte) in tail.iter_mut().zip(data) {
            slot.write(byte);
        }
    }

    #[test]
    fn new_buffer_is_empty() {
        let b = StreamBuffer::with_capacity(8);
        assert!(b.is_empty());
        assert_eq!(b.len(), 0);
        assert_eq!(b.pending(), b"");
    }

    #[test]
    fn append_then_pending_returns_the_bytes() {
        let mut b = StreamBuffer::with_capacity(8);
        b.append(b"abc").unwrap();
        assert_eq!(b.pending(), b"abc");
        assert_eq!(b.len(), 3);
        assert!(!b.is_empty());
    }

    #[test]
    fn consume_advances_the_front() {
        let mut b = StreamBuffer::with_capacity(8);
        b.append(b"abcd").unwrap();
        b.consume(2);
        assert_eq!(b.pending(), b"cd");
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn consuming_everything_empties_and_offers_full_capacity_again() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"abcd").unwrap();
        b.consume(4);
        assert!(b.is_empty());
        // The cursors reset, so the whole capacity is available — not just the tail.
        b.append(b"wxyz").unwrap();
        assert_eq!(b.pending(), b"wxyz");
    }

    #[test]
    fn append_compacts_to_reclaim_consumed_space() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"ab").unwrap();
        b.consume(2); // consumed=2, filled=2: the tail has only 2 free bytes
        // 3 bytes don't fit the tail but do fit after reclaiming the consumed prefix.
        b.append(b"xyz").unwrap();
        assert_eq!(b.pending(), b"xyz");
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn fills_to_exactly_capacity() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"abcd").unwrap();
        assert_eq!(b.len(), 4);
        assert!(b.append(b"e").is_err()); // one more overflows
    }

    #[test]
    fn append_past_capacity_overflows_and_leaves_the_buffer_intact() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"abc").unwrap();
        assert!(b.append(b"de").is_err()); // 3 + 2 > 4
        // The failed append didn't disturb the live bytes.
        assert_eq!(b.pending(), b"abc");
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn free_tail_mut_offers_the_spare_capacity_and_commit_fills_it() {
        let mut b = StreamBuffer::with_capacity(8);
        b.append(b"ab").unwrap();
        let tail = b.free_tail_mut();
        assert_eq!(tail.len(), 6);
        fill(tail, b"xyz");
        b.commit(3);
        assert_eq!(b.pending(), b"abxyz");
    }

    #[test]
    fn free_tail_mut_compacts_when_the_tail_is_exhausted() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"abcd").unwrap(); // tail full
        b.consume(2); // live "cd"; tail exhausted but 2 bytes reclaimable
        let tail = b.free_tail_mut(); // compacts: "cd" slides to the front
        assert_eq!(tail.len(), 2);
        fill(tail, b"ef");
        b.commit(2);
        assert_eq!(b.pending(), b"cdef");
    }

    #[test]
    fn free_tail_mut_is_empty_when_full_of_live_bytes() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"abcd").unwrap();
        assert!(b.free_tail_mut().is_empty()); // no consumed prefix to reclaim
    }

    #[test]
    #[cfg_attr(
        not(debug_assertions),
        ignore = "consume's guard is a debug_assert!, compiled out in release"
    )]
    #[should_panic(expected = "consume past the filled bytes")]
    fn consuming_past_the_filled_bytes_panics() {
        let mut b = StreamBuffer::with_capacity(4);
        b.append(b"ab").unwrap();
        b.consume(3); // only 2 are filled
    }
}
