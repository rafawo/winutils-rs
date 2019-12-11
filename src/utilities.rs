// Copyright © rafawo (rafawo1@hotmail.com). All rights reserved.
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
/// receive return parameters from windows API that use CoTaskMemAlloc
/// under the covers.
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

/// Thin Rust wrapper of a WSTR pointer that can be used to
/// receive return parameters from windows API that use LocalAlloc
/// under the covers.
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
