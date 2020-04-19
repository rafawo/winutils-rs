// Copyright (c) 2019 Rafael Alcaraz Mercado. All rights reserved.
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
// THE SOURCE CODE IS AVAILABLE UNDER THE ABOVE CHOSEN LICENSE "AS IS", WITH NO WARRANTIES.

//! Collection of random Windows API utilities for ease of use in more Rust idiomatic ways

use crate::errorcodes::{error_code_to_winresult_code, WinResult, WinResultCode};
use crate::windefs::*;

/// Closes a handle using windows CloseHandle API.
/// This function panics on failure.
pub fn close_handle(handle: &mut Handle) {
    if *handle == std::ptr::null_mut() {
        return;
    }

    #[allow(unused_assignments)]
    let mut result: Bool = 0;

    unsafe {
        result = winapi::um::handleapi::CloseHandle(*handle);
    }

    match result {
        0 => {
            panic!("Closing handle failed with error code {}", unsafe {
                winapi::um::errhandlingapi::GetLastError()
            });
        }
        _ => {}
    }
}

/// Rust wrapper of windows CreateFile API.
pub fn create_file(
    path: &str,
    access_mask: DWord,
    share_mode: DWord,
    security_descriptor: Option<&mut winapi::um::minwinbase::SECURITY_ATTRIBUTES>,
    creation_disposition: DWord,
    flags_and_attributes: DWord,
    template_file: Option<Handle>,
) -> WinResult<Handle> {
    let security_descriptor_ptr = match security_descriptor {
        Some(security_descriptor) => security_descriptor,
        None => std::ptr::null_mut(),
    };

    let template_file_handle = match template_file {
        Some(template_file) => template_file,
        None => std::ptr::null_mut(),
    };

    unsafe {
        let handle = winapi::um::fileapi::CreateFileW(
            widestring::WideCString::from_str(path).unwrap().as_ptr(),
            access_mask,
            share_mode,
            security_descriptor_ptr,
            creation_disposition,
            flags_and_attributes,
            template_file_handle,
        );

        match handle {
            handle if handle != std::ptr::null_mut() => Ok(handle),
            _handle => Err(WinResultCode::ErrorFileNotFound),
        }
    }
}

/// Returns whether two Guids are equal.
pub fn guid_are_equal(left: &Guid, right: &Guid) -> bool {
    left.Data1 == right.Data1
        && left.Data2 == right.Data2
        && left.Data3 == right.Data3
        && left.Data4 == right.Data4
}

#[link(name = "cfgmgr32")]
extern "C" {
    fn CM_Register_Notification(
        pFilter: winapi::um::cfgmgr32::PCM_NOTIFY_FILTER,
        pContext: PVoid,
        pCallback: winapi::um::cfgmgr32::PCM_NOTIFY_CALLBACK,
        pNotifyContex: winapi::um::cfgmgr32::PHCMNOTIFICATION,
    ) -> winapi::um::cfgmgr32::CONFIGRET;

    fn CM_Unregister_Notification(
        NotifyContext: winapi::um::cfgmgr32::HCMNOTIFICATION,
    ) -> winapi::um::cfgmgr32::CONFIGRET;

    fn CM_MapCrToWin32Err(
        CmReturnCode: winapi::um::cfgmgr32::CONFIGRET,
        DefaultErr: DWord,
    ) -> DWord;
}

/// Rust abstraction of a CMNOTIFICATION.
/// On drop, it automatically unregisters the notification (panics on error).
pub struct CmNotification {
    handle: winapi::um::cfgmgr32::HCMNOTIFICATION,
}

impl std::ops::Drop for CmNotification {
    fn drop(&mut self) {
        unsafe {
            match CM_Unregister_Notification(self.handle) {
                error if error != winapi::um::cfgmgr32::CR_SUCCESS => {
                    let error_code =
                        CM_MapCrToWin32Err(error, winapi::shared::winerror::ERROR_GEN_FAILURE);
                    panic!(
                        "Failed to unregister CM Notification with error code {}",
                        error_code
                    );
                }
                _ => {}
            }
        }
    }
}

impl CmNotification {
    /// Register a new CMNOTIFICATION.
    pub fn register(
        filter: winapi::um::cfgmgr32::PCM_NOTIFY_FILTER,
        context: PVoid,
        callback: winapi::um::cfgmgr32::PCM_NOTIFY_CALLBACK,
    ) -> WinResult<CmNotification> {
        unsafe {
            let mut handle = std::mem::zeroed::<winapi::um::cfgmgr32::HCMNOTIFICATION>();

            match CM_Register_Notification(filter, context, callback, &mut handle) {
                error if error != winapi::um::cfgmgr32::CR_SUCCESS => {
                    Err(error_code_to_winresult_code(CM_MapCrToWin32Err(
                        error,
                        winapi::shared::winerror::ERROR_GEN_FAILURE,
                    )))
                }
                _ => Ok(CmNotification { handle }),
            }
        }
    }
}

/// Common possible results from waiting on a single event.
#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum WinEventResult {
    WaitObject0,
    WaitTimeout,
    WaitFailed(WinResultCode),
}

/// Thin Rust abstraction of a Windows EVENT.
/// On drop, closes the underlying handle.
pub struct WinEvent {
    handle: Handle,
}

impl std::ops::Drop for WinEvent {
    fn drop(&mut self) {
        close_handle(&mut self.handle);
    }
}

impl WinEvent {
    /// Returns the wrapped handle.
    pub fn get_handle(&self) -> Handle {
        self.handle.clone()
    }

    /// Creates a new windows EVENT, which can be configured to be named,
    /// manual reset, initial state and attributes as desired.
    pub fn create(
        manual_reset: bool,
        initial_state: bool,
        name: Option<&str>,
        event_attributes: Option<winapi::um::minwinbase::SECURITY_ATTRIBUTES>,
    ) -> WinResult<WinEvent> {
        let event_attributes_ptr = match event_attributes {
            Some(mut event_attributes) => &mut event_attributes,
            None => std::ptr::null_mut(),
        };

        let name_wstr = match name {
            Some(name) => widestring::WideCString::from_str(name).unwrap(),
            None => widestring::WideCString::from_str("").unwrap(),
        };

        let name_ptr = match name {
            Some(_) => name_wstr.as_ptr(),
            None => std::ptr::null(),
        };

        let manual_reset: Bool = match manual_reset {
            true => 1,
            false => 0,
        };

        let initial_state: Bool = match initial_state {
            true => 1,
            false => 0,
        };

        unsafe {
            match winapi::um::synchapi::CreateEventW(
                event_attributes_ptr,
                manual_reset,
                initial_state,
                name_ptr,
            ) {
                handle if handle != std::ptr::null_mut() => Ok(WinEvent { handle }),
                _ => {
                    return Err(error_code_to_winresult_code(
                        winapi::um::errhandlingapi::GetLastError(),
                    ))
                }
            }
        }
    }

    /// Opens a named windows EVENT.
    pub fn open(name: &str, desired_access: DWord, inherit_handle: bool) -> WinResult<WinEvent> {
        let inherit_handle: Bool = match inherit_handle {
            true => 1,
            false => 0,
        };

        unsafe {
            match winapi::um::synchapi::OpenEventW(
                desired_access,
                inherit_handle,
                widestring::WideCString::from_str(name).unwrap().as_ptr(),
            ) {
                handle if handle != std::ptr::null_mut() => Ok(WinEvent { handle }),
                _ => {
                    return Err(error_code_to_winresult_code(
                        winapi::um::errhandlingapi::GetLastError(),
                    ))
                }
            }
        }
    }

    /// Sets a Windows EVENT.
    pub fn set(&self) -> WinResult<()> {
        unsafe {
            match winapi::um::synchapi::SetEvent(self.handle) {
                0 => {
                    return Err(error_code_to_winresult_code(
                        winapi::um::errhandlingapi::GetLastError(),
                    ))
                }
                _ => Ok(()),
            }
        }
    }

    /// Resets a Windows EVENT.
    pub fn reset(&self) -> WinResult<()> {
        unsafe {
            match winapi::um::synchapi::ResetEvent(self.handle) {
                0 => {
                    return Err(error_code_to_winresult_code(
                        winapi::um::errhandlingapi::GetLastError(),
                    ))
                }
                _ => Ok(()),
            }
        }
    }

    /// Pulses a Windows EVENT.
    pub fn pulse(&self) -> WinResult<()> {
        unsafe {
            match winapi::um::winbase::PulseEvent(self.handle) {
                0 => {
                    return Err(error_code_to_winresult_code(
                        winapi::um::errhandlingapi::GetLastError(),
                    ))
                }
                _ => Ok(()),
            }
        }
    }

    /// Waits for a period of time for a Windows EVENT to be signalled.
    pub fn wait(&self, milliseconds: DWord) -> WinEventResult {
        unsafe {
            match winapi::um::synchapi::WaitForSingleObject(self.handle, milliseconds) {
                winapi::um::winbase::WAIT_OBJECT_0 => WinEventResult::WaitObject0,
                winapi::shared::winerror::WAIT_TIMEOUT => WinEventResult::WaitTimeout,
                winapi::um::winbase::WAIT_FAILED => WinEventResult::WaitFailed(
                    error_code_to_winresult_code(winapi::um::errhandlingapi::GetLastError()),
                ),
                _ => WinEventResult::WaitFailed(error_code_to_winresult_code(
                    winapi::um::errhandlingapi::GetLastError(),
                )),
            }
        }
    }
}

/// Thin Rust wrapper of a Windows HMODULE.
/// On drop frees the library, panics on failure.
pub struct WinLibrary {
    handle: winapi::shared::minwindef::HMODULE,
}

impl std::ops::Drop for WinLibrary {
    fn drop(&mut self) {
        unsafe {
            match winapi::um::libloaderapi::FreeLibrary(self.handle) {
                0 => {
                    panic!(
                        "Failed to free library with error code {}",
                        winapi::um::errhandlingapi::GetLastError(),
                    );
                }
                _ => {}
            }
        }
    }
}

impl WinLibrary {
    /// Loads a library by name with the supplied flags.
    pub fn load(lib_file_name: &str, flags: DWord) -> WinResult<WinLibrary> {
        unsafe {
            match winapi::um::libloaderapi::LoadLibraryExW(
                widestring::WideCString::from_str(lib_file_name)
                    .unwrap()
                    .as_ptr(),
                std::ptr::null_mut(),
                flags,
            ) {
                handle if handle != std::ptr::null_mut() => Ok(WinLibrary { handle }),
                _ => Err(error_code_to_winresult_code(
                    winapi::um::errhandlingapi::GetLastError(),
                )),
            }
        }
    }

    /// Returns the process address by name on the loaded library.
    pub fn proc_address(&self, proc_name: &str) -> WinResult<winapi::shared::minwindef::FARPROC> {
        unsafe {
            match winapi::um::libloaderapi::GetProcAddress(
                self.handle,
                std::ffi::CString::new(proc_name).unwrap().as_ptr(),
            ) {
                farproc if farproc != std::ptr::null_mut() => Ok(farproc),
                _ => Err(error_code_to_winresult_code(
                    winapi::um::errhandlingapi::GetLastError(),
                )),
            }
        }
    }
}

#[link(name = "RpcRT4")]
extern "C" {
    fn UuidCreate(guid: *mut Guid) -> winapi::shared::rpc::RPC_STATUS;

    fn UuidFromStringW(
        guid_string: winapi::shared::rpcdce::RPC_WSTR,
        guid: *mut Guid,
    ) -> winapi::shared::rpc::RPC_STATUS;
}

/// Creates a new GUID.
pub fn create_guid() -> WinResult<Guid> {
    let mut guid: Guid = GUID_NULL;
    unsafe {
        match UuidCreate(&mut guid) {
            0 => Ok(guid),
            error_code => Err(error_code_to_winresult_code(error_code as u32)),
        }
    }
}

/// Parses the given string to a GUID.
pub fn parse_guid(guid_string: &str) -> WinResult<Guid> {
    let mut guid: Guid = GUID_NULL;
    unsafe {
        match UuidFromStringW(
            widestring::WideCString::from_str(guid_string)
                .unwrap()
                .into_vec_with_nul()
                .as_mut_ptr(),
            &mut guid,
        ) {
            0 => Ok(guid),
            error_code => Err(error_code_to_winresult_code(error_code as u32)),
        }
    }
}

/// Enables a privilege in the current thread.
pub fn enable_privilege(
    token_handle: Handle,
    id: &winapi::um::winnt::LUID,
    enable: bool,
) -> WinResult<bool> {
    use winapi::um::{securitybaseapi, winnt};

    unsafe {
        let mut new_value = std::mem::zeroed::<winnt::TOKEN_PRIVILEGES>();
        let mut prev_value = std::mem::zeroed::<winnt::TOKEN_PRIVILEGES>();
        let mut prev_length: DWord = std::mem::size_of::<winnt::TOKEN_PRIVILEGES>() as DWord;

        new_value.PrivilegeCount = 1;
        new_value.Privileges[0].Luid = *id;
        new_value.Privileges[0].Attributes = match enable {
            true => winnt::SE_PRIVILEGE_ENABLED,
            false => 0,
        };

        if securitybaseapi::AdjustTokenPrivileges(
            token_handle,
            0,
            &mut new_value,
            std::mem::size_of::<winnt::TOKEN_PRIVILEGES>() as DWord,
            &mut prev_value,
            &mut prev_length,
        ) == 0
        {
            return Err(error_code_to_winresult_code(
                winapi::um::errhandlingapi::GetLastError(),
            ));
        }

        Ok(0 == prev_value.PrivilegeCount
            || 0 != (prev_value.Privileges[0].Attributes & winnt::SE_PRIVILEGE_ENABLED))
    }
}

/// Thin Rust wrapper of a "temporary" privilege, which is reverted back to the original
/// thread's token on drop. Panics on failure.
pub struct TemporaryPrivilege {
    privilege: winapi::um::winnt::LUID,
    token_handle: Handle,
    had_privilege_already: bool,
    impersonating_self: bool,
}

impl std::ops::Drop for TemporaryPrivilege {
    fn drop(&mut self) {
        if self.had_privilege_already {
            if enable_privilege(self.token_handle, &self.privilege, false).is_err() {
                panic!("It's not safe to leave privileges enabled on failure.");
            }
        }

        if self.impersonating_self {
            if unsafe { winapi::um::securitybaseapi::RevertToSelf() } == 0 {
                panic!("Failed to revert impersonation to self!");
            }
        }

        close_handle(&mut self.token_handle);
    }
}

impl TemporaryPrivilege {
    /// Creates a new "temporary" privilege.
    pub fn new(privilege_name: &str) -> WinResult<TemporaryPrivilege> {
        use winapi::um::{errhandlingapi, processthreadsapi, securitybaseapi, winbase, winnt};

        unsafe {
            let mut privilege = std::mem::zeroed::<winnt::LUID>();

            if winbase::LookupPrivilegeValueW(
                std::ptr::null(),
                widestring::WideCString::from_str(privilege_name)
                    .unwrap()
                    .as_ptr(),
                &mut privilege,
            ) == 0
            {
                return Err(error_code_to_winresult_code(errhandlingapi::GetLastError()));
            }

            let mut token_handle: Handle = std::ptr::null_mut();
            let mut impersonating_self = false;

            if processthreadsapi::OpenThreadToken(
                processthreadsapi::GetCurrentThread(),
                winnt::TOKEN_ADJUST_PRIVILEGES | winnt::TOKEN_QUERY,
                0,
                &mut token_handle,
            ) == 0
            {
                let error = errhandlingapi::GetLastError();

                if error != winapi::shared::winerror::ERROR_NO_TOKEN {
                    return Err(error_code_to_winresult_code(error));
                }

                if securitybaseapi::ImpersonateSelf(winnt::SecurityImpersonation) == 0 {
                    return Err(error_code_to_winresult_code(errhandlingapi::GetLastError()));
                }

                if processthreadsapi::OpenThreadToken(
                    processthreadsapi::GetCurrentThread(),
                    winnt::TOKEN_ADJUST_PRIVILEGES | winnt::TOKEN_QUERY,
                    0,
                    &mut token_handle,
                ) == 0
                {
                    let error = errhandlingapi::GetLastError();

                    if securitybaseapi::RevertToSelf() == 0 {
                        panic!("Failed to revert impersonation to self!");
                    }

                    return Err(error_code_to_winresult_code(error));
                }

                impersonating_self = true;
            }

            let had_privilege_already = enable_privilege(token_handle, &privilege, true)?;

            Ok(TemporaryPrivilege {
                privilege,
                token_handle,
                had_privilege_already,
                impersonating_self,
            })
        }
    }
}

#[link(name = "Pathcch")]
extern "C" {
    pub fn PathCchCombine(
        pszPathOut: PWStr,
        cchPathOut: usize,
        pszPathIn: PCWStr,
        pszMore: PCWStr,
    ) -> winapi::shared::ntdef::HRESULT;
}

/// Thin Rust wrapper of a WSTR pointer that can be used to
/// receive return parameters from windows API that use CoTaskMemAlloc under the covers.
/// On drop, frees the memory using CoTaskMemFree.
pub struct CoTaskMemWString {
    ptr: PWStr,
}

impl std::ops::Drop for CoTaskMemWString {
    fn drop(&mut self) {
        unsafe {
            winapi::um::combaseapi::CoTaskMemFree(self.ptr as LPVoid);
        }
    }
}

impl CoTaskMemWString {
    /// Creates a new empty CoTaskMemWString, with its pointer initialized to null.
    pub fn new() -> CoTaskMemWString {
        CoTaskMemWString {
            ptr: std::ptr::null_mut(),
        }
    }

    /// Returns a mutable pointer to the wrapped wide string pointer, useful
    /// for passing to win32 APIs that return CoTaskMemAlloc string.
    pub fn ptr_mut(&mut self) -> *mut PWStr {
        &mut self.ptr
    }

    /// This function creates a String representation of the underlying WSTR.
    pub fn to_string(&mut self) -> String {
        match self.ptr {
            ptr if ptr != std::ptr::null_mut() => unsafe {
                widestring::WideCString::from_ptr_str(self.ptr).to_string_lossy()
            },
            _ => String::from(""),
        }
    }
}

/// Wrapper struct that holds a raw pointer to a `LocalAlloc`'d memory.
pub struct LocalMemory {
    ptr: winapi::um::winnt::PVOID,
}

impl std::ops::Drop for LocalMemory {
    fn drop(&mut self) {
        self.force_free();
    }
}

impl LocalMemory {
    /// Creates a new `LocalMemory` instance by calling `LocalAlloc` and wrapping
    /// the resulting memory allocation on a raw pointer.
    pub fn new(
        flags: winapi::shared::minwindef::UINT,
        bytes: winapi::shared::basetsd::SIZE_T,
    ) -> WinResult<Self> {
        let ptr = unsafe { winapi::um::winbase::LocalAlloc(flags, bytes) };
        lasterror_if(ptr == std::ptr::null_mut())?;
        Ok(LocalMemory { ptr })
    }

    /// Returns a new `LocalMemory` instance that has not allocated memory
    /// and wraps a null raw pointer.
    pub fn new_empty() -> Self {
        Self::from_raw(std::ptr::null_mut())
    }

    /// Creates a new `LocalMemory` instance by wrapping the supplied raw pointer.
    pub fn from_raw(ptr: winapi::um::winnt::PVOID) -> Self {
        LocalMemory { ptr }
    }

    /// Returns whether if the underlying wrapped raw pointer is valid (not null).
    pub fn valid_ptr(&self) -> bool {
        self.ptr != std::ptr::null_mut()
    }

    /// Releases the underlying raw pointer, so that when this `LocalMemory` instance
    /// drops it won't call `LocalFree`.
    pub unsafe fn release(&mut self) -> winapi::um::winnt::PVOID {
        let ptr = self.ptr;
        self.ptr = std::ptr::null_mut();
        ptr
    }

    /// Frees the currently wrapped raw pointer and then wraps the supplied raw pointer.
    pub fn reset(&mut self, ptr: winapi::um::winnt::PVOID) {
        self.force_free();
        self.ptr = ptr;
    }

    /// Frees the wrapped raw pointer using `LocalFree`, if valid.
    pub fn force_free(&mut self) {
        if self.valid_ptr() {
            unsafe {
                winapi::um::winbase::LocalFree(self.ptr);
            }
            self.ptr = std::ptr::null_mut();
        }
    }

    /// Returns the underlying allocated memory's raw pointer.
    pub unsafe fn ptr<T>(&self) -> *const T {
        self.ptr as *const T
    }

    /// Returns the underlying allocated memory's raw pointer.
    pub unsafe fn ptr_mut<T>(&mut self) -> *mut T {
        self.ptr as *mut T
    }
}

/// Thin Rust wrapper of a WSTR pointer that can be used to
/// receive return parameters from windows API that use LocalAlloc under the covers.
/// On drop, frees the memory using LocalFree.
pub struct LocalWString {
    ptr: PWStr,
}

impl std::ops::Drop for LocalWString {
    fn drop(&mut self) {
        unsafe {
            winapi::um::winbase::LocalFree(self.ptr as LPVoid);
        }
    }
}

impl LocalWString {
    /// Creates a new empty LocalWString, with its pointer initialized to null.
    pub fn new() -> LocalWString {
        LocalWString {
            ptr: std::ptr::null_mut(),
        }
    }

    /// Returns a mutable pointer to the wrapped wide string pointer, useful
    /// for passing to win32 APIs that return LocalAlloc string.
    pub fn ptr_mut(&mut self) -> *mut PWStr {
        &mut self.ptr
    }

    /// This function creates a String representation of the underlying WSTR.
    pub fn to_string(&self) -> String {
        match self.ptr {
            ptr if ptr != std::ptr::null_mut() => unsafe {
                widestring::WideCString::from_ptr_str(self.ptr).to_string_lossy()
            },
            _ => String::from(""),
        }
    }
}

/// Returns a descriptive error message for a given HRESULT, for frendlier error reporting.
pub fn hresult_message(hresult: winapi::shared::winerror::HRESULT) -> String {
    use winapi::um::winbase::{
        FormatMessageW, FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM,
        FORMAT_MESSAGE_IGNORE_INSERTS,
    };

    let mut wstr = LocalWString::new();
    unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM
                | FORMAT_MESSAGE_ALLOCATE_BUFFER
                | FORMAT_MESSAGE_IGNORE_INSERTS,
            std::ptr::null(),
            hresult as u32,
            0,
            wstr.ptr_mut() as winapi::shared::ntdef::LPWSTR,
            0,
            std::ptr::null_mut(),
        );
    }
    wstr.to_string()
}

/// Returns a win error if the supplied condition resolves to `false`.
pub fn lasterror_if(condition: bool) -> WinResult<()> {
    if condition {
        let last_error = unsafe { winapi::um::errhandlingapi::GetLastError() };
        if last_error != winapi::shared::winerror::ERROR_SUCCESS {
            return Err(error_code_to_winresult_code(last_error));
        }
    }

    Ok(())
}

/// Returns an Err if the supplied parameter is FALSE.
pub fn lasterror_if_win32_bool_false(result: Bool) -> WinResult<()> {
    lasterror_if(result == winapi::shared::minwindef::FALSE)
}

/// Simple wrapper of a DACL with an underlying LocalMemory.
/// Instances of this struct can only be safely obtained through `LocalSecurityDescriptor::get_dacl`.
pub struct LocalDAcl {
    local_mem: LocalMemory,
}

impl LocalDAcl {
    /// Get the underlying local memory as an ACL immutable reference.
    pub fn get(&self) -> &winapi::um::winnt::ACL {
        unsafe { &*(self.local_mem.ptr as *const winapi::um::winnt::ACL) }
    }

    /// Get the underlying local memory as an ACL mutable reference.
    pub fn get_mut(&mut self) -> &mut winapi::um::winnt::ACL {
        unsafe { &mut *(self.local_mem.ptr_mut() as *mut winapi::um::winnt::ACL) }
    }
}

impl Default for LocalDAcl {
    fn default() -> Self {
        LocalDAcl {
            local_mem: LocalMemory::new_empty(),
        }
    }
}

/// Thin Rust wrapper of a `SECURITY_DESCRIPTOR` pointer that can be used to
/// receive return parameters from windows API that use LocalAlloc under the covers.
/// On drop, frees the memory using LocalFree.
pub struct LocalSecurityDescriptor {
    ptr: winapi::um::winnt::PSECURITY_DESCRIPTOR,
}

impl std::ops::Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        self.force_free();
    }
}

impl LocalSecurityDescriptor {
    /// Creates a new empty `LocalSecurityDescriptor`, with its pointer initialized to null.
    pub fn new() -> Self {
        LocalSecurityDescriptor {
            ptr: std::ptr::null_mut(),
        }
    }

    /// Creates a new `LocalSecurityDescriptor` that wraps the given raw pointer.
    pub fn from_raw(ptr: winapi::um::winnt::PSECURITY_DESCRIPTOR) -> Self {
        LocalSecurityDescriptor { ptr }
    }

    /// Returns a mutable pointer to the wrapped security descriptor pointer, useful
    /// for passing to win32 APIs that return LocalAlloc security descriptor.
    pub fn ptr_mut(&mut self) -> *mut winapi::um::winnt::PSECURITY_DESCRIPTOR {
        &mut self.ptr
    }

    /// Returns the pointer to the security descriptor.
    pub fn get(&self) -> winapi::um::winnt::PSECURITY_DESCRIPTOR {
        self.ptr
    }

    /// Returns whether the underlying pointer is valid or not.
    pub fn valid_ptr(&self) -> bool {
        self.ptr != std::ptr::null_mut()
    }

    /// Releases the wrapped pointer, invalidating it internally.
    pub unsafe fn release(&mut self) -> winapi::um::winnt::PSECURITY_DESCRIPTOR {
        let ptr = self.ptr;
        self.ptr = std::ptr::null_mut();
        ptr
    }

    /// Frees the underlying ptr, if any, and changes the wrapped pointer to the supplied one.
    pub fn reset(&mut self, ptr: winapi::um::winnt::PSECURITY_DESCRIPTOR) {
        self.force_free();
        self.ptr = ptr;
    }

    /// Forces a LocalFree of the underlying pointer.
    pub fn force_free(&mut self) {
        if self.valid_ptr() {
            unsafe { winapi::um::winbase::LocalFree(self.ptr as LPVoid) };
            self.ptr = std::ptr::null_mut();
        }
    }

    /// Returns whether the security descriptor is absolute or not.
    pub fn is_absolute(&self) -> WinResult<bool> {
        let mut control: winapi::um::winnt::SECURITY_DESCRIPTOR_CONTROL = 0;
        let mut revision: DWord = 0;
        lasterror_if_win32_bool_false(unsafe {
            winapi::um::securitybaseapi::GetSecurityDescriptorControl(
                self.get(),
                &mut control,
                &mut revision,
            )
        })?;
        Ok((control & winapi::um::winnt::SE_SELF_RELATIVE) == 0)
    }

    /// If the underlying security descriptor is not absolute yet, it is made to be.
    pub fn make_absolute(&mut self) -> WinResult<()> {
        if self.is_absolute()? {
            return Ok(());
        }

        unsafe {
            let mut header_size: DWord = 0;
            let mut dacl_size: DWord = 0;
            let mut sacl_size: DWord = 0;
            let mut owner_size: DWord = 0;
            let mut group_size: DWord = 0;

            let result = winapi::um::securitybaseapi::MakeAbsoluteSD(
                self.get(),
                std::ptr::null_mut(),
                &mut header_size,
                std::ptr::null_mut(),
                &mut dacl_size,
                std::ptr::null_mut(),
                &mut sacl_size,
                std::ptr::null_mut(),
                &mut owner_size,
                std::ptr::null_mut(),
                &mut group_size,
            );

            let last_error = winapi::um::errhandlingapi::GetLastError();
            if (result == winapi::shared::minwindef::FALSE)
                && (last_error != winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER)
            {
                return Err(error_code_to_winresult_code(
                    winapi::um::errhandlingapi::GetLastError(),
                ));
            }

            let total_size = header_size + dacl_size + sacl_size + owner_size + group_size;
            let mut absolute = LocalSecurityDescriptor::from_raw(winapi::um::winbase::LocalAlloc(
                winapi::um::minwinbase::LMEM_FIXED,
                total_size as usize,
            ));
            lasterror_if(!absolute.valid_ptr())?;

            let position: *mut Byte = absolute.get() as *mut _ as *mut Byte;

            let position = position.offset(header_size as isize);
            let dacl = position as *mut _ as winapi::um::winnt::PACL;

            let position = position.offset(dacl_size as isize);
            let sacl = position as *mut _ as winapi::um::winnt::PACL;

            let position = position.offset(sacl_size as isize);
            let owner = position as *mut _ as winapi::um::winnt::PSID;

            let position = position.offset(owner_size as isize);
            let group = position as *mut _ as winapi::um::winnt::PSID;

            lasterror_if_win32_bool_false(winapi::um::securitybaseapi::MakeAbsoluteSD(
                self.get(),
                absolute.get(),
                &mut header_size,
                dacl,
                &mut dacl_size,
                sacl,
                &mut sacl_size,
                owner,
                &mut owner_size,
                group,
                &mut group_size,
            ))?;

            self.force_free();
            self.ptr = absolute.release();
        }

        Ok(())
    }

    /// Returns a newly allocated DACL that corresponds to the security descriptor.
    pub fn get_dacl(&self) -> WinResult<Option<LocalDAcl>> {
        let mut present: Bool = 0;
        let mut defaulted: Bool = 0;
        let mut pdacl: winapi::um::winnt::PACL = std::ptr::null_mut();

        lasterror_if_win32_bool_false(unsafe {
            winapi::um::securitybaseapi::GetSecurityDescriptorDacl(
                self.get(),
                &mut present,
                &mut pdacl,
                &mut defaulted,
            )
        })?;

        if present == winapi::shared::minwindef::FALSE {
            Ok(None)
        } else {
            unsafe {
                let mut dacl = LocalDAcl {
                    local_mem: LocalMemory::new(0, (*pdacl).AclSize as usize)?,
                };

                winapi::um::winnt::RtlCopyMemory(
                    dacl.local_mem.ptr_mut(),
                    pdacl as *const _,
                    (*pdacl).AclSize as usize,
                );

                Ok(Some(dacl))
            }
        }
    }

    /// Returns a DACL for the security descriptor with the additional user SID.
    pub fn add_user_dacl(&self, psid: winapi::um::winnt::PSID) -> WinResult<Option<LocalDAcl>> {
        match self.get_dacl()? {
            None => Ok(None),
            Some(mut dacl) => {
                let mut ea = winapi::um::accctrl::EXPLICIT_ACCESSW {
                    grfAccessPermissions: winapi::um::combaseapi::COM_RIGHTS_EXECUTE
                        | winapi::um::combaseapi::COM_RIGHTS_EXECUTE_LOCAL,
                    grfAccessMode: winapi::um::accctrl::GRANT_ACCESS,
                    grfInheritance: winapi::um::accctrl::NO_INHERITANCE,
                    Trustee: winapi::um::accctrl::TRUSTEE_W {
                        pMultipleTrustee: std::ptr::null_mut(),
                        MultipleTrusteeOperation: winapi::um::accctrl::NO_MULTIPLE_TRUSTEE,
                        TrusteeForm: winapi::um::accctrl::TRUSTEE_IS_SID,
                        TrusteeType: winapi::um::accctrl::TRUSTEE_IS_UNKNOWN,
                        ptstrName: psid as winapi::um::winnt::LPWCH,
                    },
                };

                let mut pdacl: winapi::um::winnt::PACL = std::ptr::null_mut();
                match unsafe {
                    winapi::um::aclapi::SetEntriesInAclW(1, &mut ea, dacl.get_mut(), &mut pdacl)
                } {
                    error if error != winapi::shared::winerror::ERROR_SUCCESS => {
                        Err(error_code_to_winresult_code(error))
                    }
                    _ => {
                        dacl.local_mem.reset(pdacl as *mut _);
                        Ok(Some(dacl))
                    }
                }
            }
        }
    }
}

/// Convenient wrapper of a Token information, that stores an internal buffer to
/// hold enough memory to return the requested information class type.
pub struct TokenInformation {
    buffer: Vec<u8>,
}

impl TokenInformation {
    /// Creates a new `TokenInformation` instance, where by the given info class and token
    /// handle it allocates enough memory on an internal buffer, with enough size
    /// to hold the token's requested information.
    pub fn new(
        info_class: winapi::um::winnt::TOKEN_INFORMATION_CLASS,
        token: winapi::um::winnt::HANDLE,
    ) -> WinResult<Self> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut token = token;
        if token == std::ptr::null_mut() {
            token = (-6) as isize as winapi::um::winnt::HANDLE;
        }
        let token = token;

        let mut info_size: DWord = 0;
        let result = unsafe {
            winapi::um::securitybaseapi::GetTokenInformation(
                token,
                info_class,
                std::ptr::null_mut(),
                0,
                &mut info_size,
            )
        };

        let last_error = unsafe { winapi::um::errhandlingapi::GetLastError() };
        lasterror_if(
            result == winapi::shared::minwindef::FALSE
                && last_error != winapi::shared::winerror::ERROR_INSUFFICIENT_BUFFER,
        )?;

        buffer.resize(info_size as usize, 0);

        lasterror_if_win32_bool_false(unsafe {
            winapi::um::securitybaseapi::GetTokenInformation(
                token,
                info_class,
                buffer.as_mut_ptr() as *mut _,
                info_size,
                &mut info_size,
            )
        })?;

        Ok(TokenInformation { buffer })
    }

    /// Returns the underlying allocated buffer as the specified type.
    /// Marked as `unsafe` due to the missing guarantees of the caller
    /// using it as the intended allocated type.
    pub unsafe fn info<T>(&self) -> &T {
        &*(self.buffer.as_ptr() as *const T)
    }

    /// Returns the underlying allocated buffer as the specified type.
    /// Marked as `unsafe` due to the missing guarantees of the caller
    /// using it as the intended allocated type.
    pub unsafe fn info_mut<T>(&mut self) -> &mut T {
        &mut *(self.buffer.as_mut_ptr() as *mut T)
    }
}

/// Wrapper of the COM library initialization.
/// When dropped, `CoUninitialize` is called if this instance hasn't been released.
pub struct ComLibraryRuntime {
    should_uninit: bool,
}

impl std::ops::Drop for ComLibraryRuntime {
    fn drop(&mut self) {
        if self.should_uninit {
            unsafe {
                winapi::um::combaseapi::CoUninitialize();
            }
        }
    }
}

impl ComLibraryRuntime {
    /// Creates a new `ComLibraryRuntime` by calling `CoInitializeEx` with
    /// the supplied init flags.
    pub fn new(co_init: DWord) -> WinResult<Self> {
        match unsafe { winapi::um::combaseapi::CoInitializeEx(std::ptr::null_mut(), co_init) } {
            winapi::shared::winerror::S_OK => Ok(ComLibraryRuntime {
                should_uninit: true,
            }),
            hresult => Err(error_code_to_winresult_code(hresult as u32)),
        }
    }

    /// Releases this wrapper so that when dropped, it doesn't uninitialize
    /// the COM library runtime.
    pub unsafe fn release(&mut self) {
        self.should_uninit = false;
    }

    /// Sets up COM security with the specified security string descriptor.
    pub fn setup_security(sec_str_desc: &str) -> WinResult<()> {
        let mut sec_desc = LocalSecurityDescriptor::new();
        lasterror_if_win32_bool_false(unsafe {
            winapi::shared::sddl::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                widestring::WideCString::from_str(sec_str_desc)
                    .unwrap()
                    .as_ptr(),
                winapi::shared::sddl::SDDL_REVISION_1.into(),
                sec_desc.ptr_mut(),
                std::ptr::null_mut(),
            )
        })?;

        sec_desc.make_absolute()?;
        let token_user = TokenInformation::new(winapi::um::winnt::TokenUser, std::ptr::null_mut())?;
        lasterror_if_win32_bool_false(unsafe {
            winapi::um::securitybaseapi::SetSecurityDescriptorOwner(
                sec_desc.get(),
                token_user.info::<winapi::um::winnt::TOKEN_USER>().User.Sid,
                winapi::shared::minwindef::FALSE,
            )
        })?;

        sec_desc.make_absolute()?;
        let token_primary_group =
            TokenInformation::new(winapi::um::winnt::TokenPrimaryGroup, std::ptr::null_mut())?;
        lasterror_if_win32_bool_false(unsafe {
            winapi::um::securitybaseapi::SetSecurityDescriptorGroup(
                sec_desc.get(),
                token_primary_group
                    .info::<winapi::um::winnt::TOKEN_PRIMARY_GROUP>()
                    .PrimaryGroup,
                winapi::shared::minwindef::FALSE,
            )
        })?;

        sec_desc.make_absolute()?;
        let dacl = sec_desc.add_user_dacl(unsafe {
            token_user.info::<winapi::um::winnt::TOKEN_USER>().User.Sid
        })?;

        sec_desc.make_absolute()?;
        lasterror_if_win32_bool_false(unsafe {
            winapi::um::securitybaseapi::SetSecurityDescriptorDacl(
                sec_desc.get(),
                winapi::shared::minwindef::TRUE,
                dacl.unwrap_or_default().get_mut(),
                winapi::shared::minwindef::FALSE,
            )
        })?;

        sec_desc.make_absolute()?;

        let result = match unsafe {
            winapi::um::combaseapi::CoInitializeSecurity(
                sec_desc.get(),
                -1,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                winapi::shared::rpcdce::RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                winapi::shared::rpcdce::RPC_C_IMP_LEVEL_IDENTIFY,
                std::ptr::null_mut(),
                winapi::um::objidl::EOAC_DYNAMIC_CLOAKING | winapi::um::objidlbase::EOAC_RESERVED1,
                std::ptr::null_mut(),
            )
        } {
            hresult if hresult != winapi::shared::winerror::S_OK => {
                Err(error_code_to_winresult_code(hresult as u32))
            }
            _ => Ok(()),
        };

        // Ensure variables stay in scope when calling CoInitializeSecurity
        drop(dacl);
        drop(token_primary_group);
        drop(token_user);

        result
    }
}
