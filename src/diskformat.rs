// Copyright © rafawo (rafawo1@hotmail.com). All rights reserved.
// Licensed under the Apache License, Version 2.0
// <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// All files in the project carrying such notice may not be copied, modified, or distributed
// except according to those terms.
// THE SOURCE CODE IS AVAILABLE UNDER THE ABOVE CHOSEN LICENSE "AS IS", WITH NO WARRANTIES.

//! Module that contains defintions to undocumented APIs for disk formatting

use crate::errorcodes::{error_code_to_winresult_code, WinResultCode};
use crate::utilities::WinEvent;
use crate::windefs::*;

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
#[allow(non_snake_case, non_camel_case_types)]
pub enum FmIfsMediaType {
    FmMediaUnknown,
    FmMediaF5_160_512,   // 5.25", 160KB,  512 bytes/sector
    FmMediaF5_180_512,   // 5.25", 180KB,  512 bytes/sector
    FmMediaF5_320_512,   // 5.25", 320KB,  512 bytes/sector
    FmMediaF5_320_1024,  // 5.25", 320KB,  1024 bytes/sector
    FmMediaF5_360_512,   // 5.25", 360KB,  512 bytes/sector
    FmMediaF3_720_512,   // 3.5",  720KB,  512 bytes/sector
    FmMediaF5_1Pt2_512,  // 5.25", 1.2MB,  512 bytes/sector
    FmMediaF3_1Pt44_512, // 3.5",  1.44MB, 512 bytes/sector
    FmMediaF3_2Pt88_512, // 3.5",  2.88MB, 512 bytes/sector
    FmMediaF3_20Pt8_512, // 3.5",  20.8MB, 512 bytes/sector
    FmMediaRemovable,    // Removable media other than floppy
    FmMediaFixed,
    FmMediaF3_120M_512, // 3.5", 120M Floppy
    // FMR Sep.8.1994 SFT YAM
    // FMR Jul.14.1994 SFT KMR
    FmMediaF3_640_512, // 3.5" ,  640KB,  512 bytes/sector
    FmMediaF5_640_512, // 5.25",  640KB,  512 bytes/sector
    FmMediaF5_720_512, // 5.25",  720KB,  512 bytes/sector
    // FMR Sep.8.1994 SFT YAM
    // FMR Jul.14.1994 SFT KMR
    FmMediaF3_1Pt2_512, // 3.5" , 1.2Mb,   512 bytes/sector
    // FMR Sep.8.1994 SFT YAM
    // FMR Jul.14.1994 SFT KMR
    FmMediaF3_1Pt23_1024, // 3.5" , 1.23Mb, 1024 bytes/sector
    FmMediaF5_1Pt23_1024, // 5.25", 1.23MB, 1024 bytes/sector
    FmMediaF3_128Mb_512,  // 3.5" , 128MB,  512 bytes/sector  3.5"MO
    FmMediaF3_230Mb_512,  // 3.5" , 230MB,  512 bytes/sector  3.5"MO
    FmMediaF3_200Mb_512,  // 3.5" , 200MB,  512 bytes/sector  HiFD (200MB Floppy)
    FmMediaF3_240Mb_512,  // 3.5" , 240MB,  512 bytes/sector  HiFD (240MB Floppy)
    FmMediaEndOfData,     // Total data count.
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum FmIfsPacketType {
    FmIfsPercentCompleted = 0,
    FmIfsFormatReport = 1,
    FmIfsInsertDisk = 2,
    FmIfsIncompatibleFileSystem = 3,
    FmIfsFormattingDestination = 4,
    FmIfsIncompatibleMedia = 5,
    FmIfsAccessDenied = 6,
    FmIfsMediaWriteProtected = 7,
    FmIfsCantLock = 8,
    FmIfsCantQuickFormat = 9,
    FmIfsIoError = 10,
    FmIfsFinished = 11,
    FmIfsBadLabel = 12,
    FmIfsCheckOnReboot = 13,
    FmIfsTextMessage = 14,
    FmIfsHiddenStatus = 15,
    FmIfsClusterSizeTooSmall = 16,
    FmIfsClusterSizeTooBig = 17,
    FmIfsVolumeTooSmall = 18,
    FmIfsVolumeTooBig = 19,
    FmIfsNoMediaInDevice = 20,
    FmIfsClustersCountBeyond32bits = 21,
    FmIfsCantChkMultiVolumeOfSameFS = 22,
    FmIfsFormatFatUsing64KCluster = 23,
    FmIfsDeviceOffLine = 24,
    FmIfsChkdskProgress = 25,
    FmIfsBadSectorInfo = 26,
    FmIfsBadUdfRevision = 27,
    FmIfsCantInvalidateFve = 28,
    FmIfsFveInvalidated = 29,
    FmIfsLowLevelLongTimeFormat = 30,
    FmIfsFormatHardwareFailure = 31,
    FmIfsCantContinueInReadOnly = 32,
    FmIfsCheckOnDismount = 33,
    FmIfsScanAlreadyRunning = 34,
    FmIfsClusterSizeIllegal = 35,
    FmIfsClusterSizeSectorSizeMismatch = 36,
    FmIfsPartitionNotClusterAligned = 37,
}

/// The structure below defines information to be passed into FormatEx2.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FmIfsFormatEx2Param {
    // These are fields supported in version 1.0
    pub major: UChar, // initial version is 1.0
    pub minor: UChar,
    pub flags: ULong,
    pub label_string: PWStr, // supplies the volume's label
    pub cluster_size: ULong, // supplies the cluster size for the volume

    // These are fields added in version 2.0
    pub version: UShort,   // supplies the UDF version
    pub context: ULongPtr, // context supplied on call-backs
    pub passes: UInt,      // number of passes of random data to make during format

    // There are fields added in version 2.1
    pub log_file_size: ULong, // supplies the initial size for $LogFile in bytes
}

pub type FmIfsCallback = extern "C" fn(
    packet_type: FmIfsPacketType,
    packet_length: ULong,
    packet_data: PVoid,
) -> Boolean;

pub type FormatEx2Routine = extern "C" fn(
    drive_name: PWStr,
    media_type: FmIfsMediaType,
    file_system_name: PWStr,
    param: *mut FmIfsFormatEx2Param,
    callback: FmIfsCallback,
);

pub const FMIFS_FORMAT_QUICK: u32 = 0x00000001;
pub const FMIFS_FORMAT_TXF_DISABLE: u32 = 0x00002000;
pub const FMIFS_FORMAT_SHORT_NAMES_DISABLE: u32 = 0x00000040;
pub const FMIFS_FORMAT_FORCE: u32 = 0x00000004;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FmIfsFinishedInformation {
    pub success: Boolean,
    pub final_result: ULong,
}

pub struct FormatContext {
    pub event: WinEvent,
    pub result: WinResultCode,
}

pub static mut FORMAT_CONTEXT_LOCK: Option<std::sync::Mutex<u32>> = None;
pub static mut FORMAT_CONTEXT: Option<FormatContext> = None;

pub extern "C" fn format_ex2_callback(
    packet_type: FmIfsPacketType,
    _packet_length: ULong,
    packet_data: PVoid,
) -> Boolean {
    match packet_type {
        FmIfsPacketType::FmIfsFinished => {
            let info: FmIfsFinishedInformation =
                unsafe { *(packet_data as *const FmIfsFinishedInformation) };

            unsafe {
                if let Some(ref mut context) = FORMAT_CONTEXT {
                    context.result = match info.success {
                        result if result != 0 => WinResultCode::ErrorSuccess,
                        _ => error_code_to_winresult_code(info.final_result),
                    };

                    if info.success == 0 && info.final_result == 0 {
                        // Format can fail without populating the FinalResult parameter, just assume general failure
                        context.result = WinResultCode::ErrorGenFailure;
                    }

                    match context.event.set() {
                        Err(_) => panic!("Failed to signal event for format context"),
                        Ok(_) => {}
                    }
                }
            }
        }
        _ => {}
    }

    1
}
