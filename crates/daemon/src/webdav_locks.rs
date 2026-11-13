//! Finite listener-local endpoint locks never claim filesystem exclusion.
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use sync_extend_core_model::{webdav::AuthorizedWebDavPath, EntryId};

struct Lock {
    account: String,
    export: String,
    path: String,
    recursive: bool,
    expires: Instant,
}

#[derive(Default)]
pub struct Locks {
    active: BTreeMap<String, Lock>,
}

impl Locks {
    fn expire(&mut self) {
        self.active.retain(|_, lock| lock.expires > Instant::now());
    }

    pub fn acquire(
        &mut self,
        account: &str,
        path: &AuthorizedWebDavPath,
        recursive: bool,
        seconds: u64,
    ) -> Option<String> {
        self.expire();
        if self.active.len() >= 1024
            || !(1..=3600).contains(&seconds)
            || !self.allowed(account, path, &[], recursive)
        {
            return None;
        }
        let id = EntryId::random().ok()?.to_string();
        let token = format!(
            "urn:uuid:{}-{}-{}-{}-{}",
            &id[..8],
            &id[8..12],
            &id[12..16],
            &id[16..20],
            &id[20..]
        );
        self.active.insert(
            token.clone(),
            Lock {
                account: account.into(),
                export: path.export_name.clone(),
                path: path
                    .path
                    .as_ref()
                    .map_or(String::new(), ToString::to_string),
                recursive,
                expires: Instant::now() + Duration::from_secs(seconds),
            },
        );
        Some(token)
    }

    pub fn token_matches(
        &mut self,
        account: &str,
        path: &AuthorizedWebDavPath,
        token: &str,
    ) -> bool {
        self.expire();
        self.active.get(token).is_some_and(|lock| {
            lock.account == account
                && lock.export == path.export_name
                && (lock.path == path.path.as_ref().map_or("", |path| path.as_str())
                    || lock.recursive
                        && (lock.path.is_empty()
                            || path.path.as_ref().is_some_and(|path| {
                                path.as_str().starts_with(&format!("{}/", lock.path))
                            })))
        })
    }

    pub fn refresh(
        &mut self,
        account: &str,
        path: &AuthorizedWebDavPath,
        token: &str,
        seconds: u64,
    ) -> bool {
        self.expire();
        let Some(lock) = self.active.get_mut(token) else {
            return false;
        };
        if lock.account != account
            || lock.export != path.export_name
            || path.path.as_ref().map_or("", |path| path.as_str()) != lock.path
            || !(1..=3600).contains(&seconds)
        {
            return false;
        }
        lock.expires = Instant::now() + Duration::from_secs(seconds);
        true
    }

    pub fn unlock(&mut self, account: &str, path: &AuthorizedWebDavPath, token: &str) -> bool {
        self.expire();
        if !self.active.get(token).is_some_and(|lock| {
            lock.account == account
                && lock.export == path.export_name
                && lock.path == path.path.as_ref().map_or("", |path| path.as_str())
        }) {
            return false;
        }
        self.active.remove(token);
        true
    }

    pub fn allowed(
        &mut self,
        account: &str,
        path: &AuthorizedWebDavPath,
        tokens: &[String],
        recursive: bool,
    ) -> bool {
        self.expire();
        let path_text = path.path.as_ref().map_or("", |path| path.as_str());
        self.active.iter().all(|(id, lock)| {
            let affected = lock.export == path.export_name
                && (lock.path == path_text
                    || lock.recursive
                        && (lock.path.is_empty()
                            || path_text.starts_with(&format!("{}/", lock.path)))
                    || recursive
                        && (path_text.is_empty()
                            || lock.path.starts_with(&format!("{path_text}/"))));
            !affected || lock.account == account && tokens.iter().any(|token| token == id)
        })
    }
}

pub fn valid_token(value: &str) -> bool {
    let Some(uuid) = value.strip_prefix("urn:uuid:") else {
        return false;
    };
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(index, byte)| {
            if [8, 13, 18, 23].contains(&index) {
                byte == b'-'
            } else {
                byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)
            }
        })
}
