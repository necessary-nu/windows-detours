use windows_detours::{
    code_from_pointer, find_function, find_payload_ex, set_ignore_too_small, set_retain_regions,
};

#[test]
fn test_find_function_known() {
    let ptr = find_function("kernel32.dll", "GetProcAddress");
    assert!(ptr.is_some(), "should find GetProcAddress in kernel32.dll");
}

#[test]
fn test_find_function_unknown() {
    let ptr = find_function("kernel32.dll", "NonExistentFunction_XYZ_12345");
    assert!(ptr.is_none());
}

#[test]
fn test_find_function_bad_module() {
    let ptr = find_function("nonexistent_module_xyz.dll", "SomeFunc");
    assert!(ptr.is_none());
}

#[test]
fn test_set_ignore_too_small() {
    set_ignore_too_small(true);
    set_ignore_too_small(false);
}

#[test]
fn test_set_retain_regions() {
    set_retain_regions(true);
    set_retain_regions(false);
}

#[test]
fn test_find_payload_ex_not_found() {
    let guid = windows_sys::core::GUID {
        data1: 0xDEADBEEF,
        data2: 0x1234,
        data3: 0x5678,
        data4: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
    };
    let result = find_payload_ex(&guid);
    assert!(result.is_none());
}

#[test]
fn test_code_from_pointer() {
    let ptr = find_function("kernel32.dll", "GetProcAddress");
    assert!(ptr.is_some());
    let code = unsafe { code_from_pointer(ptr.unwrap()) };
    assert!(
        !code.is_null(),
        "code_from_pointer should return non-null for a valid function"
    );
}
