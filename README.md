# windows-detours

Safe Rust bindings to [Microsoft Detours](https://github.com/microsoft/Detours) — a library for intercepting Win32 API functions by rewriting target function images at runtime.

## Features

- **Transaction-based hooking** — begin, queue attach/detach operations, then commit atomically. Auto-aborts on drop.
- **Module enumeration** — iterate loaded modules, enumerate exports and imports.
- **PE binary editing** — read and modify payloads and import tables in on-disk PE binaries.
- **Process injection** — create processes with injected DLLs and copy payloads to remote processes.
- **Utility functions** — find functions by name across exports and debug symbols, resolve code pointers, manage embedded payloads.

## Requirements

- **Windows** (the crate is `#[cfg(windows)]`)
- **MSVC toolchain** — the `cc` build dependency compiles the Detours C++ sources, which require MSVC

## Quick start

```rust
use std::ffi::c_void;
use windows_detours::{Transaction, static_detour};

static_detour! {
    static HOOK: unsafe extern "system" fn(u32) -> u32;
}

unsafe extern "system" fn my_detour(x: u32) -> u32 {
    let orig: unsafe extern "system" fn(u32) -> u32 =
        unsafe { std::mem::transmute(HOOK.get_original()) };
    (unsafe { orig(x) }) + 1
}

fn attach(target: unsafe extern "system" fn(u32) -> u32) {
    unsafe { HOOK.initialize(target as *mut c_void, my_detour as *mut c_void) };
    let mut txn = Transaction::new().unwrap();
    txn.update_current_thread().unwrap();
    unsafe { txn.attach(&HOOK).unwrap() };
    txn.commit().unwrap();
}
```

## API overview

| Module | Description |
|--------|-------------|
| `transaction` | Transaction lifecycle: begin, attach/detach, commit/abort |
| `hook` | `StaticDetourSlot`, `RawDetourHook`, and the `static_detour!` macro |
| `module` | `ModuleIter`, `enumerate_exports`, `enumerate_imports`, module queries |
| `util` | `find_function`, `code_from_pointer`, payload search, configuration |
| `process` | `update_process_with_dll`, `copy_payload_to_process`, helper process APIs |
| `binary` | `BinaryEditor` for reading/modifying PE binary payloads and imports |
| `ffi` | Raw FFI bindings (prefer the safe wrappers above) |
| `error` | `DetourError` and `DetourResult` |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
