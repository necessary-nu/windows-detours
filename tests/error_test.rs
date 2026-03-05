use windows_detours::{DetourError, DetourResult};

#[test]
fn test_error_new_and_code() {
    let err = DetourError::new(42);
    assert_eq!(err.code(), 42);
}

#[test]
fn test_error_display_known() {
    let err = DetourError::new(87);
    let msg = format!("{err}");
    assert!(msg.contains("ERROR_INVALID_PARAMETER"), "got: {msg}");
}

#[test]
fn test_error_display_unknown() {
    let err = DetourError::new(9999);
    let msg = format!("{err}");
    assert!(msg.contains("0x"), "expected hex in: {msg}");
}

#[test]
fn test_error_equality() {
    assert_eq!(DetourError::new(1), DetourError::new(1));
    assert_ne!(DetourError::new(1), DetourError::new(2));
}

#[test]
fn test_error_is_std_error() {
    let err = DetourError::new(1);
    let _dyn_err: &dyn std::error::Error = &err;
}

#[test]
fn test_result_type_alias() {
    let ok: DetourResult<u32> = Ok(42);
    assert_eq!(ok.unwrap(), 42);

    let err: DetourResult<u32> = Err(DetourError::new(1));
    assert!(err.is_err());
}
