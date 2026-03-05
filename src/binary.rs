use std::ffi::c_void;

use windows_sys::Win32::Foundation::HANDLE;

use crate::error::{DetourError, DetourResult};
use crate::ffi;
use crate::ffi::GUID;

/// Reads and modifies a PE binary's payloads and import table. Closed on drop.
pub struct BinaryEditor {
    handle: *mut c_void,
}

impl BinaryEditor {
    /// Opens a PE binary for editing.
    ///
    /// # Safety
    /// `file` must be a valid file handle opened for reading.
    pub unsafe fn open(file: HANDLE) -> DetourResult<Self> {
        let handle = unsafe { ffi::DetourBinaryOpen(file) };
        if handle.is_null() {
            Err(DetourError::new(unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            }))
        } else {
            Ok(Self { handle })
        }
    }

    /// Sets (or replaces) a payload identified by GUID.
    pub fn set_payload(&mut self, guid: &GUID, data: &[u8]) -> DetourResult<*mut c_void> {
        let result = unsafe {
            ffi::DetourBinarySetPayload(
                self.handle,
                guid,
                data.as_ptr() as *const c_void,
                data.len() as u32,
            )
        };
        if result.is_null() {
            Err(DetourError::new(unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            }))
        } else {
            Ok(result)
        }
    }

    /// Finds a payload by GUID, returning its contents.
    pub fn find_payload(&self, guid: &GUID) -> Option<&[u8]> {
        let mut size: u32 = 0;
        let ptr = unsafe { ffi::DetourBinaryFindPayload(self.handle, guid, &mut size) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(ptr as *const u8, size as usize) })
        }
    }

    /// Deletes the payload identified by GUID.
    pub fn delete_payload(&mut self, guid: &GUID) -> DetourResult {
        DetourError::from_bool(unsafe { ffi::DetourBinaryDeletePayload(self.handle, guid) })
    }

    /// Removes all payloads from the binary.
    pub fn purge_payloads(&mut self) -> DetourResult {
        DetourError::from_bool(unsafe { ffi::DetourBinaryPurgePayloads(self.handle) })
    }

    /// Resets the import table to its original state.
    pub fn reset_imports(&mut self) -> DetourResult {
        DetourError::from_bool(unsafe { ffi::DetourBinaryResetImports(self.handle) })
    }

    /// Edits the import table using the provided callbacks.
    ///
    /// # Safety
    /// `context` must be valid for use by the callback functions, or null.
    pub unsafe fn edit_imports(
        &mut self,
        context: *mut c_void,
        byway: ffi::PfDetourBinaryBywayCallback,
        file: ffi::PfDetourBinaryFileCallback,
        symbol: ffi::PfDetourBinarySymbolCallback,
        commit: ffi::PfDetourBinaryCommitCallback,
    ) -> DetourResult {
        DetourError::from_bool(unsafe {
            ffi::DetourBinaryEditImports(self.handle, context, byway, file, symbol, commit)
        })
    }

    /// Writes the modified binary to a file.
    ///
    /// # Safety
    /// `file` must be a valid file handle opened for writing.
    pub unsafe fn write(&mut self, file: HANDLE) -> DetourResult {
        DetourError::from_bool(unsafe { ffi::DetourBinaryWrite(self.handle, file) })
    }
}

impl Drop for BinaryEditor {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                ffi::DetourBinaryClose(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}
