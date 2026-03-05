use std::ffi::{CString, c_void};

use windows_sys::Win32::Foundation::HMODULE;

use crate::ffi;
use crate::ffi::GUID;

/// Finds a function by module and name, searching both exports and debug symbols.
pub fn find_function(module: &str, function: &str) -> Option<*mut c_void> {
    let module = CString::new(module).ok()?;
    let function = CString::new(function).ok()?;
    let result = unsafe {
        ffi::DetourFindFunction(module.as_ptr() as *const u8, function.as_ptr() as *const u8)
    };
    if result.is_null() { None } else { Some(result) }
}

/// Resolves a function pointer to its actual code address, skipping jump stubs.
///
/// # Safety
/// `ptr` must be a valid code pointer.
pub unsafe fn code_from_pointer(ptr: *mut c_void) -> *mut c_void {
    unsafe { ffi::DetourCodeFromPointer(ptr, std::ptr::null_mut()) }
}

/// Configures whether Detours silently ignores target functions too small to hook.
pub fn set_ignore_too_small(ignore: bool) {
    unsafe {
        ffi::DetourSetIgnoreTooSmall(ignore as i32);
    }
}

/// Configures whether Detours retains trampoline regions after detaching.
pub fn set_retain_regions(retain: bool) {
    unsafe {
        ffi::DetourSetRetainRegions(retain as i32);
    }
}

/// Finds a payload embedded in a specific module by GUID.
///
/// # Safety
/// `module` must be a valid module handle.
pub unsafe fn find_payload(module: HMODULE, guid: &GUID) -> Option<&[u8]> {
    let mut size: u32 = 0;
    let ptr = unsafe { ffi::DetourFindPayload(module, guid, &mut size) };
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(ptr as *const u8, size as usize) })
    }
}

/// Finds a payload embedded in any loaded module by GUID.
pub fn find_payload_ex(guid: &GUID) -> Option<&'static [u8]> {
    let mut size: u32 = 0;
    let ptr = unsafe { ffi::DetourFindPayloadEx(guid, &mut size) };
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { std::slice::from_raw_parts(ptr as *const u8, size as usize) })
    }
}
