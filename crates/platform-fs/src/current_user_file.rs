//! Current process user DACL is installed in the original CREATE, before bytes.
use super::{invalid, regular};
use std::{
    fs::File,
    io,
    mem::{offset_of, size_of},
    os::windows::io::{AsRawHandle, FromRawHandle},
    ptr,
};
use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_NO_TOKEN, HANDLE},
    Security::{
        AclSizeInformation,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_FILE_OBJECT,
        },
        EqualSid, GetAce, GetAclInformation, GetLengthSid, GetSecurityDescriptorControl,
        GetTokenInformation, IsValidAcl, IsValidSid, TokenUser, ACCESS_ALLOWED_ACE,
        ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
    },
    Storage::FileSystem::FILE_ALL_ACCESS,
    System::Threading::{GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken},
};

struct LocalAllocation(*mut core::ffi::c_void);
impl Drop for LocalAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: each allocation was returned by a documented LocalAlloc API.
            unsafe { LocalFree(self.0) };
        }
    }
}

struct ProcessUser {
    buffer: Vec<usize>,
}
impl ProcessUser {
    fn new() -> io::Result<Self> {
        let mut thread_token: HANDLE = ptr::null_mut();
        // SAFETY: current thread pseudo-handle is valid; token is writable output.
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut thread_token) } != 0 {
            // SAFETY: successful OpenThreadToken transferred this owned handle.
            drop(unsafe { File::from_raw_handle(thread_token) });
            return Err(invalid(
                "current process credential mapping refuses impersonation",
            ));
        }
        if io::Error::last_os_error().raw_os_error() != Some(ERROR_NO_TOKEN as i32) {
            return Err(io::Error::last_os_error());
        }
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: process pseudo-handle is valid; token is writable output.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful OpenProcessToken returned one owned handle.
        let token = unsafe { File::from_raw_handle(token) };
        let mut length = 0;
        // SAFETY: null buffer requests the required TOKEN_USER allocation size.
        unsafe {
            GetTokenInformation(
                token.as_raw_handle() as HANDLE,
                TokenUser,
                ptr::null_mut(),
                0,
                &mut length,
            )
        };
        if !(size_of::<TOKEN_USER>()..=65536).contains(&(length as usize)) {
            return Err(invalid("bounded current process user information required"));
        }
        let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
        let capacity = buffer.len() * size_of::<usize>();
        // SAFETY: usize storage is aligned for TOKEN_USER and capacity is bounded.
        if unsafe {
            GetTokenInformation(
                token.as_raw_handle() as HANDLE,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                capacity as u32,
                &mut length,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let result = Self { buffer };
        let sid = result.sid();
        let begin = result.buffer.as_ptr() as usize;
        let end = begin + capacity;
        if (sid as usize) < begin || (sid as usize) > end.saturating_sub(8) {
            return Err(invalid("current process user SID must be in owned buffer"));
        }
        // SAFETY: token SID pointer is within the live token-information buffer.
        let sid_length = unsafe { GetLengthSid(sid) } as usize;
        if (sid as usize).checked_add(sid_length).is_none_or(|last| last > end)
            // SAFETY: bounded token-information SID bytes remain alive.
            || unsafe { IsValidSid(sid) } == 0
        {
            return Err(invalid("valid bounded current process user SID required"));
        }
        Ok(result)
    }
    fn sid(&self) -> PSID {
        // SAFETY: buffer holds successful TOKEN_USER output and remains aligned.
        unsafe { (*self.buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid }
    }
}

pub(super) struct CurrentUserSecurity {
    descriptor: LocalAllocation,
}
impl CurrentUserSecurity {
    pub(super) fn new() -> io::Result<Self> {
        let user = ProcessUser::new()?;
        let mut sid_string = ptr::null_mut();
        // SAFETY: validated user SID is alive and output receives LocalAlloc data.
        if unsafe { ConvertSidToStringSidW(user.sid(), &mut sid_string) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let allocation = LocalAllocation(sid_string.cast());
        let mut length = 0;
        // SAFETY: successful conversion returns a terminated Windows SID string.
        while length < 256 && unsafe { *sid_string.add(length) } != 0 {
            length += 1;
        }
        if length == 256 {
            return Err(invalid("bounded process user SID string required"));
        }
        // SAFETY: the successful conversion owns length UTF-16 units.
        let sid = String::from_utf16(unsafe { std::slice::from_raw_parts(sid_string, length) })
            .map_err(|_| invalid("process user SID encoding"))?;
        drop(allocation);
        let sddl: Vec<u16> = format!("O:{sid}D:P(A;;FA;;;{sid})")
            .encode_utf16()
            .chain([0])
            .collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: terminated SDDL is alive; output receives a LocalAlloc descriptor.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            descriptor: LocalAllocation(descriptor),
        })
    }
    pub(super) fn pointer(&self) -> PSECURITY_DESCRIPTOR {
        self.descriptor.0
    }
}

/// Audit only the actual retained regular-file handle, never an ACL pathname.
pub fn verify_current_user_private_file(file: &File) -> io::Result<()> {
    verify_private_object(file, false, 0, true)
}

/// This is a retained directory prerequisite, never a regular-file relaxation.
pub(super) fn verify_current_user_private_directory(file: &File) -> io::Result<()> {
    verify_private_object(file, true, 0x03, true)
}

/// SQLite's child inherits the sole owner ACE from an already proven directory.
/// This separate check never grants the original explicit-file ACL contract.
pub(super) fn verify_current_user_private_inherited_file(file: &File) -> io::Result<()> {
    verify_private_object(file, false, 0x10, false)
}

fn verify_private_object(
    file: &File,
    directory: bool,
    ace_flags: u8,
    protected: bool,
) -> io::Result<()> {
    regular(file, directory)?;
    let user = ProcessUser::new()?;
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: live file handle; all requested descriptor outputs are writable.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _allocation = LocalAllocation(descriptor);
    let mut control = 0;
    let mut revision = 0;
    // SAFETY: descriptor, owner, and DACL point into the live successful output.
    if owner.is_null() || acl.is_null()
        // SAFETY: both owner and current user SID remain in live validated outputs.
        || unsafe { EqualSid(owner, user.sid()) } == 0
        // SAFETY: successful GetSecurityInfo returned this nonnull live DACL.
        || unsafe { IsValidAcl(acl) } == 0
        // SAFETY: owned native descriptor remains alive; outputs are sized.
        || unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
        || protected && control & SE_DACL_PROTECTED == 0
    {
        return Err(invalid(
            "current process user owner and protected DACL required",
        ));
    }
    let mut information = ACL_SIZE_INFORMATION::default();
    // SAFETY: validated ACL and sized aligned ACL_SIZE_INFORMATION output.
    if unsafe {
        GetAclInformation(
            acl,
            ptr::from_mut(&mut information).cast(),
            size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    } == 0
        || information.AceCount != 1
    {
        return Err(invalid("exact one current process user ACE required"));
    }
    let mut ace = ptr::null_mut();
    // SAFETY: validated one-entry ACL and writable ACE pointer output.
    if unsafe { GetAce(acl, 0, &mut ace) } == 0 || ace.is_null() {
        return Err(invalid("current process user ACE unavailable"));
    }
    // SAFETY: GetAce returned an aligned ACE header in the validated ACL.
    let header = unsafe { &*ace.cast::<windows_sys::Win32::Security::ACE_HEADER>() };
    if header.AceType != 0
        || header.AceFlags != ace_flags
        || (header.AceSize as usize) < size_of::<ACCESS_ALLOWED_ACE>()
    {
        return Err(invalid(
            "explicit noninherited current user allow ACE required",
        ));
    }
    // SAFETY: checked ACCESS_ALLOWED type and minimum size in valid ACL.
    let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
    // SAFETY: SidStart offset is within the checked minimum ACE allocation.
    let sid: PSID = unsafe {
        ace.cast::<u8>()
            .add(offset_of!(ACCESS_ALLOWED_ACE, SidStart))
            .cast()
    };
    // SAFETY: GetAce and IsValidAcl provide a valid allowed-ACE SID layout.
    let sid_length = unsafe { GetLengthSid(sid) } as usize;
    if allowed.Mask != FILE_ALL_ACCESS
        || offset_of!(ACCESS_ALLOWED_ACE, SidStart) + sid_length != header.AceSize as usize
        // SAFETY: bounded SID occupies the validated allowed ACE.
        || unsafe { EqualSid(sid, user.sid()) } == 0
    {
        return Err(invalid("exact current process user file rights required"));
    }
    Ok(())
}

/// Original handle-backed owner and DACL bytes, bounded and audited to the
/// nonimpersonated current process user. Application code exposes only digests.
pub fn capture_current_user_private_acl(file: &File) -> io::Result<(Vec<u8>, Vec<u8>)> {
    verify_current_user_private_file(file)?;
    let mut owner = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let mut descriptor = ptr::null_mut();
    // SAFETY: the retained file handle is valid; native outputs are writable.
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle() as HANDLE,
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(io::Error::from_raw_os_error(status as i32));
    }
    let _allocation = LocalAllocation(descriptor);
    let user = ProcessUser::new()?;
    // SAFETY: successful descriptor outputs stay alive until the owned allocation drops.
    if owner.is_null()
        || acl.is_null()
        || unsafe { IsValidSid(owner) } == 0
        || unsafe { IsValidAcl(acl) } == 0
        || unsafe { EqualSid(owner, user.sid()) } == 0
    {
        return Err(invalid(
            "original ACL owner must be the current process user",
        ));
    }
    // SAFETY: valid SID and ACL have their documented length fields.
    let owner_length = unsafe { GetLengthSid(owner) } as usize;
    let acl_length = unsafe { (*acl).AclSize } as usize;
    if !(8..=65536).contains(&owner_length) || !(8..=65536).contains(&acl_length) {
        return Err(invalid("original ACL snapshot bounds"));
    }
    // SAFETY: lengths were validated in the successful, live native allocation.
    let owner_bytes =
        unsafe { std::slice::from_raw_parts(owner.cast::<u8>(), owner_length) }.to_vec();
    // SAFETY: validated ACL length stays within the native descriptor allocation.
    let acl_bytes = unsafe { std::slice::from_raw_parts(acl.cast::<u8>(), acl_length) }.to_vec();
    verify_current_user_private_file(file)?;
    Ok((owner_bytes, acl_bytes))
}
