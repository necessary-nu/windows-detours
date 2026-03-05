use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::sync::OnceLock;

/// Raw pointer pair for a target function and its detour.
pub struct RawDetourHook {
    pub(crate) pp_pointer: *mut *mut c_void,
    pub(crate) p_detour: *mut c_void,
}

impl RawDetourHook {
    /// Creates a new raw hook from a pointer-to-pointer and a detour pointer.
    ///
    /// # Safety
    /// `pp_pointer` must point to a valid function pointer that Detours can modify.
    /// `p_detour` must point to a valid detour function.
    pub unsafe fn new(pp_pointer: *mut *mut c_void, p_detour: *mut c_void) -> Self {
        Self {
            pp_pointer,
            p_detour,
        }
    }
}

/// Thread-safe slot storing original and detour function pointers.
///
/// Created via the `static_detour!` macro. Initialization is one-shot (subsequent calls
/// to [`initialize`](Self::initialize) are no-ops).
pub struct StaticDetourSlot<F> {
    original: UnsafeCell<*mut c_void>,
    detour: UnsafeCell<*mut c_void>,
    init: OnceLock<()>,
    _marker: std::marker::PhantomData<F>,
}

unsafe impl<F> Send for StaticDetourSlot<F> {}
unsafe impl<F> Sync for StaticDetourSlot<F> {}

impl<F> Default for StaticDetourSlot<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F> StaticDetourSlot<F> {
    /// Creates a new uninitialized slot.
    pub const fn new() -> Self {
        Self {
            original: UnsafeCell::new(std::ptr::null_mut()),
            detour: UnsafeCell::new(std::ptr::null_mut()),
            init: OnceLock::new(),
            _marker: std::marker::PhantomData,
        }
    }

    /// Stores the original and detour function pointers. No-op if already initialized.
    ///
    /// # Safety
    /// `original` and `detour` must be valid function pointers with the signature `F`.
    pub unsafe fn initialize(&self, original: *mut c_void, detour: *mut c_void) {
        self.init.get_or_init(|| unsafe {
            *self.original.get() = original;
            *self.detour.get() = detour;
        });
    }

    /// Returns the (possibly trampolined) original function pointer.
    ///
    /// # Safety
    /// The slot must have been initialized. The returned pointer is only valid as
    /// a function pointer of type `F`.
    pub unsafe fn get_original(&self) -> *mut c_void {
        unsafe { *self.original.get() }
    }

    /// Returns a [`RawDetourHook`] referencing this slot's pointers.
    pub fn as_raw(&self) -> RawDetourHook {
        RawDetourHook {
            pp_pointer: self.original.get(),
            p_detour: unsafe { *self.detour.get() },
        }
    }

    /// Returns `true` if the slot has been initialized.
    pub fn is_initialized(&self) -> bool {
        self.init.get().is_some()
    }
}

/// Declares one or more static [`StaticDetourSlot`]s.
///
/// # Example
///
/// ```no_run
/// use windows_detours::static_detour;
///
/// static_detour! {
///     static MY_HOOK: unsafe extern "system" fn(u32) -> u32;
/// }
/// ```
#[macro_export]
macro_rules! static_detour {
    ($($(#[$meta:meta])* $vis:vis static $name:ident : $ty:ty ;)*) => {
        $(
            $(#[$meta])*
            $vis static $name: $crate::StaticDetourSlot<$ty> = $crate::StaticDetourSlot::new();
        )*
    };
}
