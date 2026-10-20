//! Synchronization primitives: [`Mutex`] abstraction supporting both `std` and `parking_lot`.
//!
//! This module provides a [`Mutex`] type that is either a wrapper around [`std::sync::Mutex`]
//! (with poison disabled) or a re-export of [`parking_lot::Mutex`], depending on whether the
//! `parking_lot` feature is enabled.
//!
//! - With the `parking_lot` feature enabled, [`parking_lot::Mutex`] is used directly.
//! - Without the feature, a poison-free wrapper around [`std::sync::Mutex`] is used.
//!
//! This abstraction allows high-availability systems to avoid poisoning and to seamlessly
//! switch between standard and high-performance synchronization primitives.

#[cfg(feature = "parking_lot")]
pub use parking_lot::Mutex;
#[cfg(not(feature = "parking_lot"))]
pub use std_mutex::Mutex;

#[cfg(not(feature = "parking_lot"))]
mod std_mutex {
    use std::{
        fmt,
        ops::{Deref, DerefMut},
        sync,
    };

    /// A `Mutex` that never poisons and has the same interface as [`std::sync::Mutex`].
    pub struct Mutex<T: ?Sized>(sync::Mutex<T>);

    impl<T: ?Sized + fmt::Debug> fmt::Debug for Mutex<T> {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt::Debug::fmt(&self.0, fmt)
        }
    }

    impl<T> Mutex<T> {
        /// Like [`std::sync::Mutex::new`].
        #[inline]
        pub fn new(t: T) -> Mutex<T> {
            Mutex(sync::Mutex::new(t))
        }
    }

    impl<T: ?Sized> Mutex<T> {
        /// Like [`std::sync::Mutex::lock`].
        #[inline]
        pub fn lock(&self) -> MutexGuard<'_, T> {
            MutexGuard(self.0.lock().unwrap_or_else(|e| e.into_inner()))
        }

        /// Like [`std::sync::Mutex::try_lock`].
        #[inline]
        pub fn try_lock<'a>(&'a self) -> TryLockResult<MutexGuard<'a, T>> {
            match self.0.try_lock() {
                Ok(t) => Ok(MutexGuard(t)),
                Err(sync::TryLockError::Poisoned(e)) => Ok(MutexGuard(e.into_inner())),
                Err(sync::TryLockError::WouldBlock) => Err(TryLockError(())),
            }
        }
    }

    /// Like [`std::sync::MutexGuard`].
    #[must_use]
    pub struct MutexGuard<'a, T: ?Sized + 'a>(sync::MutexGuard<'a, T>);

    impl<T: ?Sized> Deref for MutexGuard<'_, T> {
        type Target = T;

        #[inline]
        fn deref(&self) -> &T {
            self.0.deref()
        }
    }

    impl<T: ?Sized> DerefMut for MutexGuard<'_, T> {
        #[inline]
        fn deref_mut(&mut self) -> &mut T {
            self.0.deref_mut()
        }
    }

    /// Like [`std::sync::TryLockResult`].
    pub type TryLockResult<T> = Result<T, TryLockError>;

    /// Like [`std::sync::TryLockError`].
    #[derive(Debug)]
    pub struct TryLockError(());

    impl fmt::Display for TryLockError {
        fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
            fmt.write_str("Mutex is already locked")
        }
    }
}
