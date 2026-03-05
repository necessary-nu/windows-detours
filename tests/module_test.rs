use std::ffi::c_void;
use windows_detours::{
    ModuleIter, enumerate_exports, enumerate_imports, get_containing_module, get_entry_point,
    get_module_size,
};

fn get_module(name: Option<&str>) -> windows_sys::Win32::Foundation::HMODULE {
    match name {
        Some(n) => {
            let wide: Vec<u16> = n.encode_utf16().chain(std::iter::once(0)).collect();
            unsafe { windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(wide.as_ptr()) }
        }
        None => unsafe {
            windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(std::ptr::null())
        },
    }
}

#[test]
fn test_module_iter_yields_modules() {
    let modules: Vec<_> = ModuleIter::new().collect();
    assert!(
        modules.len() >= 2,
        "Expected at least 2 modules, got {}",
        modules.len()
    );
}

#[test]
fn test_module_iter_default() {
    let modules: Vec<_> = ModuleIter::default().collect();
    assert!(!modules.is_empty());
}

#[test]
fn test_enumerate_exports_kernel32() {
    let kernel32 = get_module(Some("kernel32.dll"));
    assert!(!kernel32.is_null());
    let exports = unsafe { enumerate_exports(kernel32) };
    let has_get_proc = exports
        .iter()
        .any(|e| e.name.as_deref() == Some("GetProcAddress"));
    assert!(has_get_proc, "kernel32 should export GetProcAddress");
}

#[test]
fn test_enumerate_imports_self() {
    let exe = get_module(None);
    assert!(!exe.is_null());
    let imports = unsafe { enumerate_imports(exe) };
    assert!(
        !imports.is_empty(),
        "test exe should import at least one DLL"
    );
}

#[test]
fn test_get_containing_module() {
    let kernel32 = get_module(Some("kernel32.dll"));
    assert!(!kernel32.is_null());
    // Use the kernel32 base address itself as a known address inside kernel32
    let module = unsafe { get_containing_module(kernel32 as *const c_void) };
    assert!(
        module.is_some(),
        "should find module for kernel32 base address"
    );
}

#[test]
fn test_get_entry_point() {
    let exe = get_module(None);
    assert!(!exe.is_null());
    let ep = unsafe { get_entry_point(exe) };
    assert!(ep.is_some(), "exe should have an entry point");
}

#[test]
fn test_get_module_size() {
    let exe = get_module(None);
    assert!(!exe.is_null());
    let size = unsafe { get_module_size(exe) };
    assert!(size > 0, "module size should be > 0");
}
