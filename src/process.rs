use std::ffi::c_void;

use windows_sys::Win32::Foundation::HANDLE;

use crate::error::{DetourError, DetourResult};
use crate::ffi;
use crate::ffi::GUID;

/// Updates a suspended process to load the given DLLs when it resumes.
///
/// # Safety
/// `process` must be a valid process handle with appropriate access rights.
pub unsafe fn update_process_with_dll(process: HANDLE, dlls: &[&std::ffi::CStr]) -> DetourResult {
    let ptrs: Vec<*const u8> = dlls.iter().map(|d| d.as_ptr() as *const u8).collect();
    DetourError::from_bool(unsafe {
        ffi::DetourUpdateProcessWithDll(process, ptrs.as_ptr(), ptrs.len() as u32)
    })
}

/// Copies a payload into the address space of a remote process.
///
/// # Safety
/// `process` must be a valid process handle with appropriate access rights.
pub unsafe fn copy_payload_to_process(process: HANDLE, guid: &GUID, data: &[u8]) -> DetourResult {
    DetourError::from_bool(unsafe {
        ffi::DetourCopyPayloadToProcess(
            process,
            guid,
            data.as_ptr() as *const c_void,
            data.len() as u32,
        )
    })
}

/// Finds a payload in a remote process by GUID.
///
/// # Safety
/// `process` must be a valid process handle with appropriate access rights.
pub unsafe fn find_remote_payload(process: HANDLE, guid: &GUID) -> Option<*mut c_void> {
    let mut size: u32 = 0;
    let ptr = unsafe { ffi::DetourFindRemotePayload(process, guid, &mut size) };
    if ptr.is_null() { None } else { Some(ptr) }
}

/// Returns `true` if the current process is a Detours helper process.
pub fn is_helper_process() -> bool {
    unsafe { ffi::DetourIsHelperProcess() != 0 }
}

/// Restores the import table after the process was created with `DetourCreateProcessWithDll`.
pub fn restore_after_with() -> DetourResult {
    DetourError::from_bool(unsafe { ffi::DetourRestoreAfterWith() })
}
