use std::os::windows::io::AsRawHandle;
use windows_detours::BinaryEditor;

fn open_self() -> BinaryEditor {
    let path = std::env::current_exe().expect("current_exe");
    let file = std::fs::File::open(&path).expect("open exe");
    let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
    // Keep file alive — leak it so handle stays valid through the test
    let file = Box::leak(Box::new(file));
    let _ = file;
    unsafe { BinaryEditor::open(handle).expect("BinaryEditor::open") }
}

fn test_guid(byte: u8) -> windows_sys::core::GUID {
    windows_sys::core::GUID {
        data1: 0xAAAA_0000 | byte as u32,
        data2: 0xBBBB,
        data3: 0xCCCC,
        data4: [byte; 8],
    }
}

#[test]
fn test_binary_open_and_drop() {
    let _editor = open_self();
    // Just let it drop — should not crash
}

#[test]
fn test_binary_find_payload_not_found() {
    let editor = open_self();
    let guid = test_guid(0x01);
    assert!(editor.find_payload(&guid).is_none());
}

#[test]
fn test_binary_set_and_find_payload() {
    let mut editor = open_self();
    let guid = test_guid(0x02);
    let data = b"hello detours";
    editor.set_payload(&guid, data).expect("set_payload");
    let found = editor
        .find_payload(&guid)
        .expect("find_payload should succeed");
    assert!(
        found.starts_with(data),
        "payload should start with the set data"
    );
}

#[test]
fn test_binary_delete_payload() {
    let mut editor = open_self();
    let guid = test_guid(0x03);
    editor.set_payload(&guid, b"temp").expect("set_payload");
    editor.delete_payload(&guid).expect("delete_payload");
    assert!(editor.find_payload(&guid).is_none());
}

#[test]
fn test_binary_purge_payloads() {
    let mut editor = open_self();
    let guid1 = test_guid(0x04);
    let guid2 = test_guid(0x05);
    editor.set_payload(&guid1, b"one").expect("set 1");
    editor.set_payload(&guid2, b"two").expect("set 2");
    editor.purge_payloads().expect("purge");
    assert!(editor.find_payload(&guid1).is_none());
    assert!(editor.find_payload(&guid2).is_none());
}

#[test]
fn test_binary_reset_imports() {
    let mut editor = open_self();
    editor
        .reset_imports()
        .expect("reset_imports should not fail");
}
