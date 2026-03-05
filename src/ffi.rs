//! Raw FFI bindings to the Detours C library. Prefer the safe wrappers in the parent module.

use std::ffi::c_void;

use windows_sys::Win32::Foundation::{HANDLE, HMODULE};
use windows_sys::core::BOOL;

/// Windows GUID type.
pub type GUID = windows_sys::core::GUID;
/// 32-bit signed integer (Win32 `LONG`).
pub type LONG = i32;
/// 32-bit unsigned integer (Win32 `ULONG`).
pub type ULONG = u32;
/// 32-bit unsigned integer (Win32 `DWORD`).
pub type DWORD = u32;
/// Pointer to a mutable byte (Win32 `PBYTE`).
pub type PBYTE = *mut u8;

/// Callback for export enumeration.
pub type PfDetourEnumerateExportCallback = Option<
    unsafe extern "system" fn(
        pContext: *mut c_void,
        nOrdinal: ULONG,
        pszName: *const u8,
        pCode: *mut c_void,
    ) -> BOOL,
>;

/// Callback for import file enumeration.
pub type PfDetourImportFileCallback = Option<
    unsafe extern "system" fn(pContext: *mut c_void, hModule: HMODULE, pszFile: *const u8) -> BOOL,
>;

/// Callback for import function enumeration.
pub type PfDetourImportFuncCallback = Option<
    unsafe extern "system" fn(
        pContext: *mut c_void,
        nOrdinal: DWORD,
        pszFunc: *const u8,
        pvFunc: *mut c_void,
    ) -> BOOL,
>;

/// Extended callback for import function enumeration.
pub type PfDetourImportFuncCallbackEx = Option<
    unsafe extern "system" fn(
        pContext: *mut c_void,
        nOrdinal: DWORD,
        pszFunc: *const u8,
        ppvFunc: *mut *mut c_void,
    ) -> BOOL,
>;

/// Callback for binary byway (added DLL) enumeration.
pub type PfDetourBinaryBywayCallback = Option<
    unsafe extern "system" fn(
        pContext: *mut c_void,
        pszFile: *const u8,
        ppszOutFile: *mut *const u8,
    ) -> BOOL,
>;

/// Callback for binary file (import DLL) enumeration.
pub type PfDetourBinaryFileCallback = Option<
    unsafe extern "system" fn(
        pContext: *mut c_void,
        pszOrigFile: *const u8,
        pszFile: *const u8,
        ppszOutFile: *mut *const u8,
    ) -> BOOL,
>;

/// Callback for binary symbol (import function) enumeration.
pub type PfDetourBinarySymbolCallback = Option<
    unsafe extern "system" fn(
        pContext: *mut c_void,
        nOrigOrdinal: ULONG,
        nOrdinal: ULONG,
        pnOutOrdinal: *mut ULONG,
        pszOrigSymbol: *const u8,
        pszSymbol: *const u8,
        ppszOutSymbol: *mut *const u8,
    ) -> BOOL,
>;

/// Callback invoked when binary import edits are committed.
pub type PfDetourBinaryCommitCallback =
    Option<unsafe extern "system" fn(pContext: *mut c_void) -> BOOL>;

/// ANSI process-creation routine for DLL injection.
pub type PdetourCreateProcessRoutineA = Option<
    unsafe extern "system" fn(
        lpApplicationName: *const u8,
        lpCommandLine: *mut u8,
        lpProcessAttributes: *mut c_void,
        lpThreadAttributes: *mut c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: *mut c_void,
        lpCurrentDirectory: *const u8,
        lpStartupInfo: *mut c_void,
        lpProcessInformation: *mut c_void,
    ) -> BOOL,
>;

/// Wide process-creation routine for DLL injection.
pub type PdetourCreateProcessRoutineW = Option<
    unsafe extern "system" fn(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *mut c_void,
        lpThreadAttributes: *mut c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: *mut c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *mut c_void,
        lpProcessInformation: *mut c_void,
    ) -> BOOL,
>;

unsafe extern "system" {
    // ==================== Transaction APIs ====================
    pub fn DetourTransactionBegin() -> LONG;
    pub fn DetourTransactionAbort() -> LONG;
    pub fn DetourTransactionCommit() -> LONG;
    pub fn DetourTransactionCommitEx(pppFailedPointer: *mut *mut *mut c_void) -> LONG;

    // ==================== Thread APIs ====================
    pub fn DetourUpdateThread(hThread: HANDLE) -> LONG;

    // ==================== Attach/Detach APIs ====================
    pub fn DetourAttach(ppPointer: *mut *mut c_void, pDetour: *mut c_void) -> LONG;
    pub fn DetourAttachEx(
        ppPointer: *mut *mut c_void,
        pDetour: *mut c_void,
        ppRealTrampoline: *mut *mut c_void,
        ppRealTarget: *mut *mut c_void,
        ppRealDetour: *mut *mut c_void,
    ) -> LONG;
    pub fn DetourDetach(ppPointer: *mut *mut c_void, pDetour: *mut c_void) -> LONG;

    // ==================== Config APIs ====================
    pub fn DetourSetIgnoreTooSmall(fIgnore: BOOL) -> BOOL;
    pub fn DetourSetRetainRegions(fRetain: BOOL) -> BOOL;
    pub fn DetourSetSystemRegionLowerBound(pSystemRegionLowerBound: *mut c_void) -> *mut c_void;
    pub fn DetourSetSystemRegionUpperBound(pSystemRegionUpperBound: *mut c_void) -> *mut c_void;

    // ==================== Code Functions ====================
    pub fn DetourFindFunction(pszModule: *const u8, pszFunction: *const u8) -> *mut c_void;
    pub fn DetourCodeFromPointer(pPointer: *mut c_void, ppGlobals: *mut *mut c_void)
    -> *mut c_void;
    pub fn DetourCopyInstruction(
        pDst: *mut c_void,
        ppDstPool: *mut *mut c_void,
        pSrc: *mut c_void,
        ppTarget: *mut *mut c_void,
        plExtra: *mut LONG,
    ) -> *mut c_void;
    pub fn DetourSetCodeModule(hModule: HMODULE, fLimitReferencesToModule: BOOL) -> BOOL;
    pub fn DetourAllocateRegionWithinJumpBounds(
        pbTarget: *const c_void,
        pcbAllocatedSize: *mut DWORD,
    ) -> *mut c_void;
    pub fn DetourIsFunctionImported(pbCode: PBYTE, pbAddress: PBYTE) -> BOOL;

    // ==================== Module Functions ====================
    pub fn DetourGetContainingModule(pvAddr: *mut c_void) -> HMODULE;
    pub fn DetourEnumerateModules(hModuleLast: HMODULE) -> HMODULE;
    pub fn DetourGetEntryPoint(hModule: HMODULE) -> *mut c_void;
    pub fn DetourGetModuleSize(hModule: HMODULE) -> ULONG;
    pub fn DetourEnumerateExports(
        hModule: HMODULE,
        pContext: *mut c_void,
        pfExport: PfDetourEnumerateExportCallback,
    ) -> BOOL;
    pub fn DetourEnumerateImports(
        hModule: HMODULE,
        pContext: *mut c_void,
        pfImportFile: PfDetourImportFileCallback,
        pfImportFunc: PfDetourImportFuncCallback,
    ) -> BOOL;
    pub fn DetourEnumerateImportsEx(
        hModule: HMODULE,
        pContext: *mut c_void,
        pfImportFile: PfDetourImportFileCallback,
        pfImportFuncEx: PfDetourImportFuncCallbackEx,
    ) -> BOOL;

    // ==================== Payload Functions ====================
    pub fn DetourFindPayload(
        hModule: HMODULE,
        rguid: *const GUID,
        pcbData: *mut DWORD,
    ) -> *mut c_void;
    pub fn DetourFindPayloadEx(rguid: *const GUID, pcbData: *mut DWORD) -> *mut c_void;
    pub fn DetourGetSizeOfPayloads(hModule: HMODULE) -> DWORD;
    pub fn DetourFreePayload(pvData: *mut c_void) -> BOOL;

    // ==================== Memory Functions ====================
    pub fn DetourVirtualProtectSameExecute(
        pAddress: *mut c_void,
        cbSize: usize,
        dwNewProtect: DWORD,
        pdwOldProtect: *mut DWORD,
    ) -> BOOL;
    pub fn DetourVirtualProtectSameExecuteEx(
        hProcess: HANDLE,
        pAddress: *mut c_void,
        cbSize: usize,
        dwNewProtect: DWORD,
        pdwOldProtect: *mut DWORD,
    ) -> BOOL;
    pub fn DetourAreSameGuid(left: *const GUID, right: *const GUID) -> BOOL;
}

// ==================== Binary Functions ====================
unsafe extern "system" {
    pub fn DetourBinaryOpen(hFile: HANDLE) -> *mut c_void;
    pub fn DetourBinaryEnumeratePayloads(
        pBinary: *mut c_void,
        pGuid: *mut GUID,
        pcbData: *mut DWORD,
        pnIterator: *mut DWORD,
    ) -> *mut c_void;
    pub fn DetourBinaryFindPayload(
        pBinary: *mut c_void,
        rguid: *const GUID,
        pcbData: *mut DWORD,
    ) -> *mut c_void;
    pub fn DetourBinarySetPayload(
        pBinary: *mut c_void,
        rguid: *const GUID,
        pData: *const c_void,
        cbData: DWORD,
    ) -> *mut c_void;
    pub fn DetourBinaryDeletePayload(pBinary: *mut c_void, rguid: *const GUID) -> BOOL;
    pub fn DetourBinaryPurgePayloads(pBinary: *mut c_void) -> BOOL;
    pub fn DetourBinaryResetImports(pBinary: *mut c_void) -> BOOL;
    pub fn DetourBinaryEditImports(
        pBinary: *mut c_void,
        pContext: *mut c_void,
        pfByway: PfDetourBinaryBywayCallback,
        pfFile: PfDetourBinaryFileCallback,
        pfSymbol: PfDetourBinarySymbolCallback,
        pfCommit: PfDetourBinaryCommitCallback,
    ) -> BOOL;
    pub fn DetourBinaryWrite(pBinary: *mut c_void, hFile: HANDLE) -> BOOL;
    pub fn DetourBinaryClose(pBinary: *mut c_void) -> BOOL;
}

// ==================== Process Functions ====================
unsafe extern "system" {
    pub fn DetourCreateProcessWithDllExA(
        lpApplicationName: *const u8,
        lpCommandLine: *mut u8,
        lpProcessAttributes: *mut c_void,
        lpThreadAttributes: *mut c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: *mut c_void,
        lpCurrentDirectory: *const u8,
        lpStartupInfo: *mut c_void,
        lpProcessInformation: *mut c_void,
        lpDllName: *const u8,
        pfCreateProcessA: PdetourCreateProcessRoutineA,
    ) -> BOOL;

    pub fn DetourCreateProcessWithDllExW(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *mut c_void,
        lpThreadAttributes: *mut c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: *mut c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *mut c_void,
        lpProcessInformation: *mut c_void,
        lpDllName: *const u8,
        pfCreateProcessW: PdetourCreateProcessRoutineW,
    ) -> BOOL;

    pub fn DetourCreateProcessWithDllsA(
        lpApplicationName: *const u8,
        lpCommandLine: *mut u8,
        lpProcessAttributes: *mut c_void,
        lpThreadAttributes: *mut c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: *mut c_void,
        lpCurrentDirectory: *const u8,
        lpStartupInfo: *mut c_void,
        lpProcessInformation: *mut c_void,
        nDlls: DWORD,
        rlpDlls: *const *const u8,
        pfCreateProcessA: PdetourCreateProcessRoutineA,
    ) -> BOOL;

    pub fn DetourCreateProcessWithDllsW(
        lpApplicationName: *const u16,
        lpCommandLine: *mut u16,
        lpProcessAttributes: *mut c_void,
        lpThreadAttributes: *mut c_void,
        bInheritHandles: BOOL,
        dwCreationFlags: DWORD,
        lpEnvironment: *mut c_void,
        lpCurrentDirectory: *const u16,
        lpStartupInfo: *mut c_void,
        lpProcessInformation: *mut c_void,
        nDlls: DWORD,
        rlpDlls: *const *const u8,
        pfCreateProcessW: PdetourCreateProcessRoutineW,
    ) -> BOOL;

    pub fn DetourProcessViaHelperA(
        dwTargetPid: DWORD,
        lpDllName: *const u8,
        pfCreateProcessA: PdetourCreateProcessRoutineA,
    ) -> BOOL;

    pub fn DetourProcessViaHelperW(
        dwTargetPid: DWORD,
        lpDllName: *const u8,
        pfCreateProcessW: PdetourCreateProcessRoutineW,
    ) -> BOOL;

    pub fn DetourProcessViaHelperDllsA(
        dwTargetPid: DWORD,
        nDlls: DWORD,
        rlpDlls: *const *const u8,
        pfCreateProcessA: PdetourCreateProcessRoutineA,
    ) -> BOOL;

    pub fn DetourProcessViaHelperDllsW(
        dwTargetPid: DWORD,
        nDlls: DWORD,
        rlpDlls: *const *const u8,
        pfCreateProcessW: PdetourCreateProcessRoutineW,
    ) -> BOOL;

    pub fn DetourUpdateProcessWithDll(
        hProcess: HANDLE,
        rlpDlls: *const *const u8,
        nDlls: DWORD,
    ) -> BOOL;

    pub fn DetourUpdateProcessWithDllEx(
        hProcess: HANDLE,
        hImage: HMODULE,
        bIs32Bit: BOOL,
        rlpDlls: *const *const u8,
        nDlls: DWORD,
    ) -> BOOL;

    pub fn DetourCopyPayloadToProcess(
        hProcess: HANDLE,
        rguid: *const GUID,
        pvData: *const c_void,
        cbData: DWORD,
    ) -> BOOL;

    pub fn DetourCopyPayloadToProcessEx(
        hProcess: HANDLE,
        rguid: *const GUID,
        pvData: *const c_void,
        cbData: DWORD,
    ) -> *mut c_void;

    pub fn DetourFindRemotePayload(
        hProcess: HANDLE,
        rguid: *const GUID,
        pcbData: *mut DWORD,
    ) -> *mut c_void;

    pub fn DetourRestoreAfterWith() -> BOOL;
    pub fn DetourRestoreAfterWithEx(pvData: *mut c_void, cbData: DWORD) -> BOOL;
    pub fn DetourIsHelperProcess() -> BOOL;
}
