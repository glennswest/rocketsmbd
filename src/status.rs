//! NT status codes used on the wire, plus errno mapping.
#![allow(dead_code)]

pub const SUCCESS: u32 = 0x0000_0000;
pub const PENDING: u32 = 0x0000_0103;
pub const NOTIFY_CLEANUP: u32 = 0x0000_010B;
pub const NOTIFY_ENUM_DIR: u32 = 0x0000_010C;
pub const BUFFER_OVERFLOW: u32 = 0x8000_0005;
pub const NO_MORE_FILES: u32 = 0x8000_0006;
pub const UNSUCCESSFUL: u32 = 0xC000_0001;
pub const NOT_IMPLEMENTED: u32 = 0xC000_0002;
pub const INVALID_PARAMETER: u32 = 0xC000_000D;
pub const NO_SUCH_FILE: u32 = 0xC000_000F;
pub const INVALID_DEVICE_REQUEST: u32 = 0xC000_0010;
pub const END_OF_FILE: u32 = 0xC000_0011;
pub const MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
pub const ACCESS_DENIED: u32 = 0xC000_0022;
pub const BUFFER_TOO_SMALL: u32 = 0xC000_0023;
pub const OBJECT_NAME_INVALID: u32 = 0xC000_0033;
pub const OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
pub const OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
pub const SHARING_VIOLATION: u32 = 0xC000_0043;
pub const FILE_LOCK_CONFLICT: u32 = 0xC000_0054;
pub const LOCK_NOT_GRANTED: u32 = 0xC000_0055;
pub const LOGON_FAILURE: u32 = 0xC000_006D;
pub const DELETE_PENDING: u32 = 0xC000_0056;
pub const DISK_FULL: u32 = 0xC000_007F;
pub const INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const IO_DEVICE_ERROR: u32 = 0xC000_0185;
pub const FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
pub const NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const BAD_NETWORK_NAME: u32 = 0xC000_00CC;
pub const NETWORK_NAME_DELETED: u32 = 0xC000_00C9;
pub const DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
pub const NOT_A_DIRECTORY: u32 = 0xC000_0103;
pub const CANCELLED: u32 = 0xC000_0120;
pub const FILE_CLOSED: u32 = 0xC000_0128;
pub const USER_SESSION_DELETED: u32 = 0xC000_0203;

/// Map a Unix errno to the closest NT status.
pub fn from_errno(e: i32) -> u32 {
    match e {
        libc::ENOENT => OBJECT_NAME_NOT_FOUND,
        libc::ENOTDIR => OBJECT_PATH_NOT_FOUND,
        libc::EACCES | libc::EPERM | libc::EROFS | libc::EBADF => ACCESS_DENIED,
        libc::EEXIST => OBJECT_NAME_COLLISION,
        libc::EISDIR => FILE_IS_A_DIRECTORY,
        libc::ENOTEMPTY => DIRECTORY_NOT_EMPTY,
        libc::ENOSPC | libc::EDQUOT => DISK_FULL,
        libc::ENFILE | libc::EMFILE | libc::ENOMEM => INSUFFICIENT_RESOURCES,
        libc::EINVAL => INVALID_PARAMETER,
        libc::EBUSY => SHARING_VIOLATION,
        libc::EIO => IO_DEVICE_ERROR,
        _ => UNSUCCESSFUL,
    }
}
