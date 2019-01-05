// Copyright © rafawo (rafawo1@hotmail.com). All rights reserved.
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
// THE SOURCE CODE IS AVAILABLE UNDER THE ABOVE CHOSEN LICENSE "AS IS", WITH NO WARRANTIES.

//! This project is a collection of Rust abstractions of random Windows API and definitions.
//! This crate will slowly grow as time goes by.
//! The main reason this crate exists is to have a common crate that
//! [virtdisk-rs](https://github.com/rafawo/virtdisk-rs) and [hcs-rs](https://github.com/rafawo/hcs-rs)
//! crates can use to share windows utilities and definitions.

pub mod diskformat;
pub mod errorcodes;
pub mod utilities;

pub mod windefs {
    //! Defines type aliases for Windows Definitions to use Rust naming conventions
    //! throughout the crate.

    pub type Bool = winapi::shared::minwindef::BOOL;
    pub type Boolean = winapi::shared::ntdef::BOOLEAN;
    pub type Byte = winapi::shared::minwindef::BYTE;
    pub type ULong = winapi::shared::minwindef::ULONG;
    pub type UShort = winapi::shared::minwindef::USHORT;
    pub type UInt = winapi::shared::minwindef::UINT;
    pub type ULongPtr = winapi::shared::basetsd::ULONG_PTR;
    pub type DWord = winapi::shared::minwindef::DWORD;
    pub type DWordLong = winapi::shared::ntdef::DWORDLONG;
    pub type LongLong = winapi::shared::ntdef::LONGLONG;
    pub type LargeInteger = winapi::shared::ntdef::LARGE_INTEGER;
    pub type Handle = winapi::shared::ntdef::HANDLE;
    pub type PCWStr = winapi::shared::ntdef::PCWSTR;
    pub type LPCWStr = winapi::shared::ntdef::LPCWSTR;
    pub type PWStr = winapi::shared::ntdef::PWSTR;
    pub type LPWStr = winapi::shared::ntdef::LPWSTR;
    pub type UChar = winapi::shared::ntdef::UCHAR;
    pub type Void = winapi::shared::ntdef::VOID;
    pub type PVoid = winapi::shared::ntdef::PVOID;
    pub type LPVoid = winapi::shared::minwindef::LPVOID;
    pub type WChar = winapi::shared::ntdef::WCHAR;
    pub type Word = winapi::shared::minwindef::WORD;
    pub type HResult = winapi::shared::ntdef::HRESULT;

    pub type Guid = winapi::shared::guiddef::GUID;
    pub type Acl = winapi::um::winnt::ACL;
    pub type SecurityDescriptor = winapi::um::winnt::SECURITY_DESCRIPTOR;
    pub type Overlapped = winapi::um::minwinbase::OVERLAPPED;

    pub const GUID_NULL: Guid = Guid {
        Data1: 0x00000000,
        Data2: 0x0000,
        Data3: 0x0000,
        Data4: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
    };
}
