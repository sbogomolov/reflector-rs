//! A fixed-capacity byte buffer for one direction of a proxied TCP stream: bytes are appended at the
//! back (from a recv, possibly after a header rewrite) and consumed from the front as a send drains
//! them. Backed by a `Box<[u8]>` sized once at construction — it never grows, so an append that would
//! exceed the capacity returns [`Overflow`] and the proxy drops-and-closes rather than letting a stuck
//! peer pin unbounded memory. Two cursors bound the live bytes: `storage[consumed..filled]`.

/// Returned by [`StreamBuffer::append`] when the data would not fit even after reclaiming the consumed
/// prefix — the caller responds by dropping and closing the connection.
#[derive(Debug)]
pub(crate) struct Overflow;

/// A bounded FIFO byte buffer: append at `filled`, consume from `consumed`, the unsent bytes in
/// between. Fixed capacity (the `Box<[u8]>` length); never reallocates.
pub(crate) struct StreamBuffer {
    storage: Box<[u8]>,
    /// Bytes written; the valid region is `storage[..filled]`.
    filled: usize,
    /// Bytes already drained from the front; the live (unsent) region is `storage[consumed..filled]`.
    consumed: usize,
}

impl StreamBuffer {
    /// A buffer holding at most `cap` live bytes, zero-filled up front (no later allocation).
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self {
            storage: vec![0u8; cap].into_boxed_slice(),
            filled: 0,
            consumed: 0,
        }
    }

    /// The unsent bytes, for one `send`.
    pub(crate) fn pending(&self) -> &[u8] {
        &self.storage[self.consumed..self.filled]
    }

    /// The number of unsent bytes.
    pub(crate) fn len(&self) -> usize {
        self.filled - self.consumed
    }

    /// Whether nothing is waiting to be sent — the cue to disarm write interest.
    pub(crate) fn is_empty(&self) -> bool {
        self.filled == self.consumed
    }

    /// Append `data`, reclaiming the consumed prefix first if the tail can't hold it. `Err` if the
    /// live bytes plus `data` would exceed the capacity — the caller drops-and-closes. On `Err` the
    /// buffer is unchanged. Never reallocates: the capacity bounds it.
    pub(crate) fn append(&mut self, data: &[u8]) -> Result<(), Overflow> {
        if self.len() + data.len() > self.storage.len() {
            return Err(Overflow);
        }
        // It fits, but maybe not in the tail — slide the live bytes down to reclaim the consumed gap.
        if self.filled + data.len() > self.storage.len() {
            self.compact();
        }
        let end = self.filled + data.len();
        self.storage[self.filled..end].copy_from_slice(data);
        self.filled = end;
        Ok(())
    }

    /// The free space at the back, to receive into in place. Reclaims the consumed prefix first when
    /// the tail is exhausted, so the whole spare capacity is offered as one slice; pair with
    /// [`commit`](Self::commit) to mark how many bytes landed. Empty only when the buffer is full of
    /// live bytes — the caller then holds an unframable, over-long message and drops-and-closes.
    pub(crate) fn free_tail_mut(&mut self) -> &mut [u8] {
        if self.filled == self.storage.len() && self.consumed > 0 {
            self.compact();
        }
        &mut self.storage[self.filled..]
    }

    /// Mark `n` bytes — received into [`free_tail_mut`](Self::free_tail_mut) — as filled.
    pub(crate) fn commit(&mut self, n: usize) {
        debug_assert!(
            self.filled + n <= self.storage.len(),
            "commit past the capacity"
        );
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
        // `>=`, not `==`: a release build compiles the assert out, so an over-consume must still reset
        // cleanly here rather than leave `consumed > filled` — which would underflow `len` and panic
        // `pending`'s slice on the next call.
        if self.consumed >= self.filled {
            self.consumed = 0;
            self.filled = 0;
        }
    }

    /// Slide the live bytes to the front, dropping the consumed prefix.
    fn compact(&mut self) {
        self.storage.copy_within(self.consumed..self.filled, 0);
        self.filled -= self.consumed;
        self.consumed = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        tail[..3].copy_from_slice(b"xyz");
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
        tail.copy_from_slice(b"ef");
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
