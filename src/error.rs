use std::fmt;

/// A Windows error code returned by a Detours operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetourError {
    code: u32,
}

impl DetourError {
    /// Creates a `DetourError` from a raw Windows error code.
    pub fn new(code: u32) -> Self {
        Self { code }
    }

    /// Returns the underlying Windows error code.
    pub fn code(&self) -> u32 {
        self.code
    }

    pub(crate) fn from_long(code: i32) -> Result<(), DetourError> {
        if code == 0 {
            Ok(())
        } else {
            Err(DetourError { code: code as u32 })
        }
    }

    pub(crate) fn from_bool(ok: i32) -> Result<(), DetourError> {
        if ok != 0 {
            Ok(())
        } else {
            Err(DetourError {
                code: unsafe { windows_sys::Win32::Foundation::GetLastError() },
            })
        }
    }
}

impl fmt::Display for DetourError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self.code {
            1 => "ERROR_INVALID_FUNCTION",
            6 => "ERROR_INVALID_HANDLE",
            87 => "ERROR_INVALID_PARAMETER",
            1314 => "ERROR_PRIVILEGE_NOT_HELD",
            // ERROR_INVALID_OPERATION
            4317 => "ERROR_INVALID_OPERATION",
            // ERROR_INVALID_BLOCK
            9 => "ERROR_INVALID_BLOCK",
            _ => "",
        };
        if msg.is_empty() {
            write!(f, "Detour error (code {:#x})", self.code)
        } else {
            write!(f, "Detour error: {} (code {:#x})", msg, self.code)
        }
    }
}

impl std::error::Error for DetourError {}

/// Type alias for `Result<T, DetourError>`.
pub type DetourResult<T = ()> = Result<T, DetourError>;
