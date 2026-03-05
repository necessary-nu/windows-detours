use std::ffi::c_void;

use windows_sys::Win32::Foundation::{HMODULE, TRUE};
use windows_sys::core::BOOL;

use crate::ffi;

/// Iterator over loaded modules in the current process.
pub struct ModuleIter {
    last: HMODULE,
    done: bool,
}

impl ModuleIter {
    /// Creates a new iterator starting from the first module.
    pub fn new() -> Self {
        Self {
            last: std::ptr::null_mut(),
            done: false,
        }
    }
}

impl Iterator for ModuleIter {
    type Item = HMODULE;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let next = unsafe { ffi::DetourEnumerateModules(self.last) };
        if next.is_null() {
            self.done = true;
            None
        } else {
            self.last = next;
            Some(next)
        }
    }
}

impl Default for ModuleIter {
    fn default() -> Self {
        Self::new()
    }
}

/// A single exported function from a module.
#[derive(Debug, Clone)]
pub struct Export {
    /// The export ordinal number.
    pub ordinal: u32,
    /// The export name, if present.
    pub name: Option<String>,
    /// Pointer to the exported code.
    pub code: *mut c_void,
}

/// Enumerates all exports of a loaded module.
///
/// # Safety
/// `module` must be a valid module handle.
pub unsafe fn enumerate_exports(module: HMODULE) -> Vec<Export> {
    struct Context {
        exports: Vec<Export>,
    }
    let mut ctx = Context {
        exports: Vec::new(),
    };

    unsafe extern "system" fn callback(
        context: *mut c_void,
        ordinal: u32,
        name: *const u8,
        code: *mut c_void,
    ) -> BOOL {
        let ctx = unsafe { &mut *(context as *mut Context) };
        let name_str = if name.is_null() {
            None
        } else {
            Some(
                unsafe { std::ffi::CStr::from_ptr(name as *const i8) }
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        ctx.exports.push(Export {
            ordinal,
            name: name_str,
            code,
        });
        TRUE
    }

    unsafe {
        ffi::DetourEnumerateExports(
            module,
            &mut ctx as *mut Context as *mut c_void,
            Some(callback),
        );
    }

    ctx.exports
}

/// An imported function within an import file entry.
#[derive(Debug, Clone)]
pub struct ImportFunc {
    /// The import ordinal number.
    pub ordinal: u32,
    /// The imported function name, if present.
    pub name: Option<String>,
    /// Pointer to the imported function.
    pub func: *mut c_void,
}

/// An import table entry representing a DLL and its imported functions.
#[derive(Debug, Clone)]
pub struct ImportFile {
    /// The module handle of the imported DLL.
    pub module: HMODULE,
    /// The DLL file name, if present.
    pub name: Option<String>,
    /// Functions imported from this DLL.
    pub functions: Vec<ImportFunc>,
}

/// Enumerates all imports of a loaded module.
///
/// # Safety
/// `module` must be a valid module handle.
pub unsafe fn enumerate_imports(module: HMODULE) -> Vec<ImportFile> {
    struct Context {
        files: Vec<ImportFile>,
    }

    let mut ctx = Context { files: Vec::new() };

    unsafe extern "system" fn file_callback(
        context: *mut c_void,
        module: HMODULE,
        file: *const u8,
    ) -> BOOL {
        let ctx = unsafe { &mut *(context as *mut Context) };
        let name = if file.is_null() {
            None
        } else {
            Some(
                unsafe { std::ffi::CStr::from_ptr(file as *const i8) }
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        ctx.files.push(ImportFile {
            module,
            name,
            functions: Vec::new(),
        });
        TRUE
    }

    unsafe extern "system" fn func_callback(
        context: *mut c_void,
        ordinal: u32,
        func_name: *const u8,
        func_ptr: *mut c_void,
    ) -> BOOL {
        let ctx = unsafe { &mut *(context as *mut Context) };
        let name = if func_name.is_null() {
            None
        } else {
            Some(
                unsafe { std::ffi::CStr::from_ptr(func_name as *const i8) }
                    .to_string_lossy()
                    .into_owned(),
            )
        };
        if let Some(last) = ctx.files.last_mut() {
            last.functions.push(ImportFunc {
                ordinal,
                name,
                func: func_ptr,
            });
        }
        TRUE
    }

    unsafe {
        ffi::DetourEnumerateImports(
            module,
            &mut ctx as *mut Context as *mut c_void,
            Some(file_callback),
            Some(func_callback),
        );
    }

    ctx.files
}

/// Returns the module that contains the given address.
///
/// # Safety
/// `addr` must point to valid memory within a loaded module.
pub unsafe fn get_containing_module(addr: *const c_void) -> Option<HMODULE> {
    let result = unsafe { ffi::DetourGetContainingModule(addr as *mut c_void) };
    if result.is_null() { None } else { Some(result) }
}

/// Returns the entry point of the given module.
///
/// # Safety
/// `module` must be a valid module handle.
pub unsafe fn get_entry_point(module: HMODULE) -> Option<*mut c_void> {
    let result = unsafe { ffi::DetourGetEntryPoint(module) };
    if result.is_null() { None } else { Some(result) }
}

/// Returns the size (in bytes) of the given module's image.
///
/// # Safety
/// `module` must be a valid module handle.
pub unsafe fn get_module_size(module: HMODULE) -> u32 {
    unsafe { ffi::DetourGetModuleSize(module) }
}
