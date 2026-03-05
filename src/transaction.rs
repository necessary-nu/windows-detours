use std::ffi::c_void;
use std::sync::{Mutex, MutexGuard};

use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::System::Threading::GetCurrentThread;

use crate::error::{DetourError, DetourResult};
use crate::ffi;
use crate::hook::{RawDetourHook, StaticDetourSlot};

/// Detours only permits one active transaction per process at a time.
/// This mutex serializes all `Transaction` lifetimes.
static TXN_MUTEX: Mutex<()> = Mutex::new(());

/// An active Detours transaction.
///
/// Hooks are queued then committed atomically. Auto-aborts on drop if not committed.
/// Only one transaction may be active per process; creating a second will block until
/// the first is finished.
pub struct Transaction {
    committed: bool,
    _guard: MutexGuard<'static, ()>,
}

impl Transaction {
    /// Begins a new Detours transaction.
    ///
    /// Blocks if another transaction is already active in this process.
    pub fn new() -> DetourResult<Self> {
        let guard = TXN_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        DetourError::from_long(unsafe { ffi::DetourTransactionBegin() })?;
        Ok(Self {
            committed: false,
            _guard: guard,
        })
    }

    /// Enlists a thread so its instruction pointer is updated during commit.
    ///
    /// # Safety
    /// `thread` must be a valid thread handle.
    pub unsafe fn update_thread(&mut self, thread: HANDLE) -> DetourResult {
        DetourError::from_long(unsafe { ffi::DetourUpdateThread(thread) })
    }

    /// Enlists the current thread for instruction-pointer update during commit.
    pub fn update_current_thread(&mut self) -> DetourResult {
        unsafe { self.update_thread(GetCurrentThread()) }
    }

    /// Queues a hook attach for a typed static slot.
    ///
    /// # Safety
    /// The slot must have been initialized with valid function pointers.
    pub unsafe fn attach<F>(&mut self, slot: &StaticDetourSlot<F>) -> DetourResult {
        let raw = slot.as_raw();
        unsafe { self.attach_raw(&raw) }
    }

    /// Queues a hook detach for a typed static slot.
    ///
    /// # Safety
    /// The slot must have been previously attached.
    pub unsafe fn detach<F>(&mut self, slot: &StaticDetourSlot<F>) -> DetourResult {
        let raw = slot.as_raw();
        unsafe { self.detach_raw(&raw) }
    }

    /// Queues a hook attach using raw pointers.
    ///
    /// # Safety
    /// The hook's pointers must be valid for the attach operation.
    pub unsafe fn attach_raw(&mut self, hook: &RawDetourHook) -> DetourResult {
        DetourError::from_long(unsafe { ffi::DetourAttach(hook.pp_pointer, hook.p_detour) })
    }

    /// Queues a hook detach using raw pointers.
    ///
    /// # Safety
    /// The hook must have been previously attached.
    pub unsafe fn detach_raw(&mut self, hook: &RawDetourHook) -> DetourResult {
        DetourError::from_long(unsafe { ffi::DetourDetach(hook.pp_pointer, hook.p_detour) })
    }

    /// Commits all queued operations atomically.
    pub fn commit(mut self) -> DetourResult {
        self.committed = true;
        DetourError::from_long(unsafe { ffi::DetourTransactionCommit() })
    }

    /// Commits all queued operations, returning the failed pointer on error.
    pub fn commit_ex(mut self) -> DetourResult<Option<*mut *mut c_void>> {
        self.committed = true;
        let mut failed: *mut *mut c_void = std::ptr::null_mut();
        let result = unsafe { ffi::DetourTransactionCommitEx(&mut failed) };
        DetourError::from_long(result)?;
        if failed.is_null() {
            Ok(None)
        } else {
            Ok(Some(failed))
        }
    }

    /// Explicitly aborts the transaction, discarding all queued operations.
    pub fn abort(mut self) -> DetourResult {
        self.committed = true;
        DetourError::from_long(unsafe { ffi::DetourTransactionAbort() })
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                ffi::DetourTransactionAbort();
            }
        }
    }
}
