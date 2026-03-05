//! Safe Rust bindings to Microsoft [Detours](https://github.com/microsoft/Detours).
//!
//! Detours intercepts Win32 functions by rewriting target function images. It uses
//! a transaction model: begin a transaction, queue one or more attach/detach operations,
//! then commit atomically. If the transaction is dropped without committing it is
//! automatically aborted.
//!
//! Additional features include module/export/import enumeration, PE binary payload
//! editing, and DLL injection into child processes.
//!
//! # Quick start
//!
//! ```no_run
//! use std::ffi::c_void;
//! use windows_detours::{Transaction, static_detour};
//!
//! static_detour! {
//!     static HOOK: unsafe extern "system" fn(u32) -> u32;
//! }
//!
//! unsafe extern "system" fn my_detour(x: u32) -> u32 {
//!     let orig: unsafe extern "system" fn(u32) -> u32 =
//!         unsafe { std::mem::transmute(HOOK.get_original()) };
//!     (unsafe { orig(x) }) + 1
//! }
//!
//! fn attach(target: unsafe extern "system" fn(u32) -> u32) {
//!     unsafe { HOOK.initialize(target as *mut c_void, my_detour as *mut c_void) };
//!     let mut txn = Transaction::new().unwrap();
//!     txn.update_current_thread().unwrap();
//!     unsafe { txn.attach(&HOOK).unwrap() };
//!     txn.commit().unwrap();
//! }
//! ```

#![cfg(windows)]

#[allow(non_snake_case)]
/// Raw FFI bindings to the Detours C library.
pub mod ffi;

/// Error types for Detours operations.
pub mod error;

/// Transaction-based hook management.
pub mod transaction;

/// Static hook slots and the `static_detour!` macro.
pub mod hook;

/// Module, export, and import enumeration.
pub mod module;

/// Utility functions: function lookup, code pointers, payloads, and configuration.
pub mod util;

/// Process creation with DLL injection.
pub mod process;

/// PE binary payload and import-table editing.
pub mod binary;

pub use binary::BinaryEditor;
pub use error::{DetourError, DetourResult};
pub use hook::{RawDetourHook, StaticDetourSlot};
pub use module::{
    Export, ImportFile, ImportFunc, ModuleIter, enumerate_exports, enumerate_imports,
    get_containing_module, get_entry_point, get_module_size,
};
pub use process::{
    copy_payload_to_process, find_remote_payload, is_helper_process, restore_after_with,
    update_process_with_dll,
};
pub use transaction::Transaction;
pub use util::{
    code_from_pointer, find_function, find_payload, find_payload_ex, set_ignore_too_small,
    set_retain_regions,
};
