use windows_detours::{is_helper_process, restore_after_with};

#[test]
fn test_is_helper_process() {
    assert!(
        !is_helper_process(),
        "normal process should not be a helper"
    );
}

#[test]
fn test_restore_after_with() {
    // Not injected, so this should return an error — but must not panic
    let result = restore_after_with();
    assert!(
        result.is_err(),
        "should fail when not launched via DetourCreateProcessWithDll"
    );
}
