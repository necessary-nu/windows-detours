use std::ffi::c_void;
use windows_detours::{StaticDetourSlot, Transaction, static_detour};

// A simple function we'll hook
unsafe extern "system" fn add_numbers(a: u32, b: u32) -> u32 {
    a + b
}

// Our detour function
unsafe extern "system" fn hooked_add(a: u32, b: u32) -> u32 {
    // Call original but multiply result by 10
    let original: unsafe extern "system" fn(u32, u32) -> u32 =
        unsafe { std::mem::transmute(ADD_HOOK.get_original()) };
    unsafe { original(a, b) * 10 }
}

static_detour! {
    static ADD_HOOK: unsafe extern "system" fn(u32, u32) -> u32;
}

#[test]
fn test_hook_and_unhook() {
    // Verify original behavior
    let result = unsafe { add_numbers(3, 4) };
    assert_eq!(result, 7);

    // Initialize the hook slot
    unsafe {
        ADD_HOOK.initialize(add_numbers as *mut c_void, hooked_add as *mut c_void);
    }

    // Attach the hook
    {
        let mut txn = Transaction::new().expect("begin transaction");
        txn.update_current_thread().expect("update thread");
        unsafe { txn.attach(&ADD_HOOK).expect("attach hook") };
        txn.commit().expect("commit transaction");
    }

    // Verify hooked behavior
    let result = unsafe { add_numbers(3, 4) };
    assert_eq!(result, 70); // (3+4) * 10

    // Detach the hook
    {
        let mut txn = Transaction::new().expect("begin transaction");
        txn.update_current_thread().expect("update thread");
        unsafe { txn.detach(&ADD_HOOK).expect("detach hook") };
        txn.commit().expect("commit transaction");
    }

    // Verify original behavior restored
    let result = unsafe { add_numbers(3, 4) };
    assert_eq!(result, 7);
}

#[test]
fn test_transaction_abort_on_drop() {
    // Start a transaction and let it drop without committing — should abort gracefully
    {
        let _txn = Transaction::new().expect("begin transaction");
        // Drop without commit — Drop impl should call abort
    }

    // Should be able to start a new transaction after the abort
    let txn = Transaction::new().expect("begin new transaction after abort");
    txn.abort().expect("explicit abort");
}

#[test]
fn test_module_iteration() {
    use windows_detours::ModuleIter;

    let modules: Vec<_> = ModuleIter::new().collect();
    // There should be at least the exe and ntdll
    assert!(
        modules.len() >= 2,
        "Expected at least 2 modules, got {}",
        modules.len()
    );
}

#[test]
fn test_transaction_new_and_commit() {
    let txn = Transaction::new().expect("begin transaction");
    txn.commit().expect("commit with no ops");
}

#[test]
fn test_commit_ex_no_failure() {
    let txn = Transaction::new().expect("begin transaction");
    let result = txn.commit_ex().expect("commit_ex");
    assert!(result.is_none(), "no failed pointer expected");
}

#[test]
fn test_slot_uninitialized() {
    let slot = StaticDetourSlot::<unsafe extern "system" fn()>::new();
    assert!(!slot.is_initialized());
}

#[test]
fn test_slot_initialize_once() {
    static SLOT: StaticDetourSlot<unsafe extern "system" fn()> = StaticDetourSlot::new();

    unsafe extern "system" fn dummy() {}
    unsafe extern "system" fn dummy2() {}

    unsafe {
        SLOT.initialize(dummy as *mut c_void, dummy2 as *mut c_void);
    }
    assert!(SLOT.is_initialized());

    // Second initialize is a no-op — original pointer should remain the same
    unsafe extern "system" fn other() {}
    unsafe {
        SLOT.initialize(other as *mut c_void, other as *mut c_void);
    }
    let orig = unsafe { SLOT.get_original() };
    assert_eq!(
        orig, dummy as *mut c_void,
        "second initialize should be a no-op"
    );
}

#[test]
fn test_hook_multiple_functions() {
    unsafe extern "system" fn mul(a: u32, b: u32) -> u32 {
        a * b
    }
    unsafe extern "system" fn sub(a: u32, b: u32) -> u32 {
        a - b
    }

    unsafe extern "system" fn hooked_mul(a: u32, b: u32) -> u32 {
        let orig: unsafe extern "system" fn(u32, u32) -> u32 =
            unsafe { std::mem::transmute(MUL_HOOK.get_original()) };
        unsafe { orig(a, b) + 1 }
    }
    unsafe extern "system" fn hooked_sub(a: u32, b: u32) -> u32 {
        let orig: unsafe extern "system" fn(u32, u32) -> u32 =
            unsafe { std::mem::transmute(SUB_HOOK.get_original()) };
        unsafe { orig(a, b) + 100 }
    }

    static_detour! {
        static MUL_HOOK: unsafe extern "system" fn(u32, u32) -> u32;
        static SUB_HOOK: unsafe extern "system" fn(u32, u32) -> u32;
    }

    unsafe {
        MUL_HOOK.initialize(mul as *mut c_void, hooked_mul as *mut c_void);
        SUB_HOOK.initialize(sub as *mut c_void, hooked_sub as *mut c_void);
    }

    // Attach both in one transaction
    {
        let mut txn = Transaction::new().expect("begin");
        txn.update_current_thread().expect("update thread");
        unsafe {
            txn.attach(&MUL_HOOK).expect("attach mul");
            txn.attach(&SUB_HOOK).expect("attach sub");
        }
        txn.commit().expect("commit");
    }

    assert_eq!(unsafe { mul(3, 4) }, 13); // 12 + 1
    assert_eq!(unsafe { sub(10, 3) }, 107); // 7 + 100

    // Detach both
    {
        let mut txn = Transaction::new().expect("begin");
        txn.update_current_thread().expect("update thread");
        unsafe {
            txn.detach(&MUL_HOOK).expect("detach mul");
            txn.detach(&SUB_HOOK).expect("detach sub");
        }
        txn.commit().expect("commit");
    }

    assert_eq!(unsafe { mul(3, 4) }, 12);
    assert_eq!(unsafe { sub(10, 3) }, 7);
}
