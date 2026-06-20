//! A generational-index arena.
//!
//! [`insert`](Arena::insert) stores a value and returns a `Copy` [`Key`]. The key
//! carries the slot's `index` and its `generation`; [`remove`](Arena::remove)
//! bumps that generation, so any key referring to the old occupant no longer
//! matches and resolves to `None`. Reusing a slot for a new value therefore can't
//! be mistaken for the old one — a stale key is detected, not dangling.
//!
//! This is the foundation the reactor uses to hand out cheap, copyable handles to
//! registrations instead of pointers, sidestepping the aliasing that storing
//! cross-references would otherwise create.

/// A `Copy` handle into an [`Arena`].
///
/// Valid only for the value it was returned for; once that value is removed the
/// key is stale and every lookup with it returns `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    index: u32,
    generation: u32,
}

impl Key {
    /// Pack the key into a `u64`, recoverable losslessly via
    /// [`from_u64`](Key::from_u64). The two `u32` halves fit exactly, which lets
    /// the key ride in an opaque 64-bit slot (such as a kernel readiness token).
    #[must_use]
    pub fn to_u64(self) -> u64 {
        (u64::from(self.index) << 32) | u64::from(self.generation)
    }

    /// Reconstruct a key packed by [`to_u64`](Key::to_u64).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub fn from_u64(packed: u64) -> Self {
        Self {
            index: (packed >> 32) as u32,
            generation: packed as u32,
        }
    }
}

/// One arena slot: occupied (`Some`) or free (`None`), plus the generation that
/// keys must match to address the current occupant.
struct Slot<T> {
    generation: u32,
    value: Option<T>,
}

/// A slab of slots addressed by generational [`Key`]s, with a free list so freed
/// slots are reused without invalidating live keys to other slots.
pub struct Arena<T> {
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
}

impl<T> Arena<T> {
    /// An empty arena.
    #[must_use]
    pub fn new() -> Self {
        Self {
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    /// Store `value`, returning a key that addresses it.
    ///
    /// # Panics
    /// Panics if more than `u32::MAX` slots have ever been allocated (the index
    /// space is exhausted) — unreachable for the reactor's handful of descriptors.
    pub fn insert(&mut self, value: T) -> Key {
        if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index as usize];
            slot.value = Some(value);
            Key {
                index,
                generation: slot.generation,
            }
        } else {
            let index = u32::try_from(self.slots.len()).expect("arena index space exhausted");
            self.slots.push(Slot {
                generation: 0,
                value: Some(value),
            });
            Key {
                index,
                generation: 0,
            }
        }
    }

    /// A shared reference to the value `key` addresses, or `None` if stale.
    #[must_use]
    pub fn get(&self, key: Key) -> Option<&T> {
        self.slot(key)?.value.as_ref()
    }

    /// A mutable reference to the value `key` addresses, or `None` if stale.
    pub fn get_mut(&mut self, key: Key) -> Option<&mut T> {
        self.slot_mut(key)?.value.as_mut()
    }

    /// Remove and return the value `key` addresses, freeing the slot. A stale key
    /// removes nothing and returns `None`.
    pub fn remove(&mut self, key: Key) -> Option<T> {
        let slot = self.slot_mut(key)?;
        let value = slot.value.take()?;
        // Bumping the generation strands every existing key to this slot; wrapping
        // keeps it panic-free (a collision would need 2^32 reuses of one slot).
        slot.generation = slot.generation.wrapping_add(1);
        self.free.push(key.index);
        Some(value)
    }

    /// Whether `key` still addresses a live value.
    #[must_use]
    pub fn contains(&self, key: Key) -> bool {
        self.get(key).is_some()
    }

    /// The slot `key` names, only if its generation still matches.
    fn slot(&self, key: Key) -> Option<&Slot<T>> {
        self.slots
            .get(key.index as usize)
            .filter(|slot| slot.generation == key.generation)
    }

    fn slot_mut(&mut self, key: Key) -> Option<&mut Slot<T>> {
        self.slots
            .get_mut(key.index as usize)
            .filter(|slot| slot.generation == key.generation)
    }
}

impl<T> Default for Arena<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_then_get_returns_value() {
        let mut arena = Arena::new();
        let key = arena.insert("hello");
        assert_eq!(arena.get(key), Some(&"hello"));
        assert!(arena.contains(key));
    }

    #[test]
    fn get_mut_allows_mutation() {
        let mut arena = Arena::new();
        let key = arena.insert(1);
        *arena.get_mut(key).unwrap() += 41;
        assert_eq!(arena.get(key), Some(&42));
    }

    #[test]
    fn remove_returns_value_and_strands_the_key() {
        let mut arena = Arena::new();
        let key = arena.insert("v");
        assert_eq!(arena.remove(key), Some("v"));
        assert_eq!(arena.get(key), None);
        assert!(!arena.contains(key));
        // Removing an already-stale key is a no-op.
        assert_eq!(arena.remove(key), None);
    }

    #[test]
    fn reused_slot_gets_a_fresh_generation() {
        let mut arena = Arena::new();
        let first = arena.insert("first");
        arena.remove(first);
        let second = arena.insert("second");
        // The free list reuses the slot, so the index matches but the generation
        // differs — the old key stays stale, the new key is live.
        assert_eq!(first.index, second.index);
        assert_ne!(first.generation, second.generation);
        assert_eq!(arena.get(first), None);
        assert_eq!(arena.get(second), Some(&"second"));
    }

    #[test]
    fn wrong_generation_key_does_not_resolve() {
        let mut arena = Arena::new();
        let key = arena.insert("v");
        let forged = Key {
            index: key.index,
            generation: key.generation.wrapping_add(1),
        };
        assert_eq!(arena.get(forged), None);
    }

    #[test]
    fn out_of_range_key_does_not_resolve() {
        let arena: Arena<i32> = Arena::new();
        let bogus = Key {
            index: 999,
            generation: 0,
        };
        assert_eq!(arena.get(bogus), None);
    }

    #[test]
    fn distinct_keys_are_independent() {
        let mut arena = Arena::new();
        let a = arena.insert("a");
        let b = arena.insert("b");
        assert_ne!(a, b);
        arena.remove(a);
        // Removing one leaves the other untouched.
        assert_eq!(arena.get(a), None);
        assert_eq!(arena.get(b), Some(&"b"));
    }

    #[test]
    fn copied_key_addresses_the_same_slot() {
        let mut arena = Arena::new();
        let key = arena.insert("shared");
        // `Key: Copy`, so this duplicates the handle; `key` stays usable afterward
        // (a move would forbid the uses below) — copyable handles, not pointers.
        let copy = key;
        assert_eq!(key, copy);
        assert_eq!(arena.get(key), Some(&"shared"));
        assert_eq!(arena.get(copy), Some(&"shared"));
        // Both name the same slot: a mutation through one is seen through the other.
        *arena.get_mut(copy).unwrap() = "updated";
        assert_eq!(arena.get(key), Some(&"updated"));
    }

    #[test]
    fn key_u64_round_trips() {
        for key in [
            Key {
                index: 0,
                generation: 0,
            },
            Key {
                index: 1,
                generation: 2,
            },
            Key {
                index: u32::MAX,
                generation: 0,
            },
            Key {
                index: 0,
                generation: u32::MAX,
            },
            Key {
                index: u32::MAX,
                generation: u32::MAX,
            },
        ] {
            assert_eq!(Key::from_u64(key.to_u64()), key);
        }
    }
}
