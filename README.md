# winutils-rs
Rust abstractions of random Windows API and definitions

## Overview

This project is a collection of Rust abstractions of random Windows API and definitions. This crate will slowly grow as time goes by.

The main reason this crate exists is to have a common crate that [virtdisk-rs](https://github.com/rafawo/virtdisk-rs) and [hcs-rs](https://github.com/rafawo/hcs-rs) crates can use to share windows utilities and definitions.

## Crates.io version notes

This section briefly describes all published crates.io [versions](https://crates.io/crates/winutils-rs/versions) of this project, ordered from latest to oldest.

- [**0.2.0 Mar 15, 2019**](https://crates.io/crates/winutils-rs/0.2.0)
  - Cleaned up and fixed documentation
  - Renamed error codes enumeration from `ResultCode` to `WinResultCode`
  - Fixes [issue 1](https://github.com/rafawo/winutils-rs/issues/1) by preferring a raw pointer cast instead of using a transmute with unnecessary bit copies
- [**0.1.6 Mar 15, 2019**](https://crates.io/crates/winutils-rs/0.1.6)
  - Contains the oldest stable set of windows utilities
  - Error code definitions added from winerror.h in the Windows 10 SDK, ***no HRESULT definitions***
- [**0.1.5 Jan 8, 2019**](https://crates.io/crates/winutils-rs/0.1.5)
  - **YANKED, DO NOT USE**
- [**0.1.4 Jan 8, 2019**](https://crates.io/crates/winutils-rs/0.1.4)
  - **YANKED, DO NOT USE**
- [**0.1.3 Jan 8, 2019**](https://crates.io/crates/winutils-rs/0.1.3)
  - **YANKED, DO NOT USE**
- [**0.1.2 Jan 4, 2019**](https://crates.io/crates/winutils-rs/0.1.2)
  - **YANKED, DO NOT USE**
- [**0.1.1 Jan 3, 2019**](https://crates.io/crates/winutils-rs/0.1.1)
  - **YANKED, DO NOT USE**
- [**0.1.0 Jan 3, 2019**](https://crates.io/crates/winutils-rs/0.1.0)
  - **YANKED, DO NOT USE**
