use egzreader::EgzReader;
pub use err::TwrptarxError;
use err::*;
use roaes::RoaesSource;
use snafu::ResultExt;
use std::io::{BufRead, BufReader, Read};
use std::ops::{Deref, DerefMut};
use tar::{Archive, Entry};

mod err {
    use roaes::RoaesError;
    use snafu::Snafu;

    #[derive(Debug, Snafu)]
    #[snafu(visibility = "pub(crate)")]
    pub enum TwrptarxError {
        TIO {
            source: std::io::Error,
            desc: String,
        },
        TIOTar {
            index: usize,
            offset: u64,
            source: std::io::Error,
            desc: String,
        },
        TRoaes {
            source: RoaesError,
        },
        TMissingKey,
        TKeyForNonOAES,
        CallBackSignalError,
    }
}

pub struct TwrpTarFile<R: Read>(Archive<EgzReader<R>>);

pub enum TwrpTarKind<R>
where
    R: Read,
{
    Plain(TwrpTarFile<BufReader<R>>),
    Encrypted(TwrpTarFile<RoaesSource<BufReader<R>>>),
}

pub enum CallbackResult {
    Continue,
    Stop,
    Error,
}

impl From<()> for CallbackResult {
    fn from(_: ()) -> Self {
        CallbackResult::Continue
    }
}

impl Default for CallbackResult {
    fn default() -> Self {
        CallbackResult::Continue
    }
}

impl<R> TwrpTarFile<R>
where
    R: Read,
{
    pub fn iter_backup<CbEnt, CbEntR>(&mut self, mut cb_entry: CbEnt) -> Result<(), TwrptarxError>
    where
        CbEnt: FnMut(Entry<EgzReader<R>>) -> CbEntR,
        CbEntR: Into<CallbackResult>,
    {
        for (i, res_entry) in self
            .0
            .entries()
            .context(TIO {
                desc: "unable to start reading tar archive entries",
            })?
            .enumerate()
        {
            let entry = res_entry.context(TIOTar {
                index: i,
                offset: 999_999_999_999_999_999u64,
                desc: "unable to read tar archive entry",
            })?;
            match cb_entry(entry).into() {
                CallbackResult::Continue => {}
                CallbackResult::Stop => {
                    break;
                }
                CallbackResult::Error => {
                    // panic!("callback signalled error!");
                    return Err(TwrptarxError::CallBackSignalError);
                }
            }
        }
        Ok(())
    }
}

impl<R> Deref for TwrpTarFile<R>
where
    R: Read,
{
    type Target = Archive<EgzReader<R>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<R> DerefMut for TwrpTarFile<R>
where
    R: Read,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub fn try_iter_twrp_backup<R>(src: R, key: Option<&[u8]>) -> Result<TwrpTarKind<R>, TwrptarxError>
where
    R: Read,
{
    // test for OAES
    let mut buf = BufReader::with_capacity(4096 * 4, src);
    buf.fill_buf().context(TIO {
        desc: "unable to pre-fill reader buffer",
    })?;
    let magic_number = RoaesSource::has_magic_number(buf.buffer()).context(TRoaes)?;
    if magic_number {}
    match (magic_number, key) {
        (true, Some(key)) => {
            let foundation = RoaesSource::new(buf, key).context(TRoaes)?;
            let uncompressed = EgzReader::new(foundation);
            let archive = Archive::new(uncompressed);
            return Ok(TwrpTarKind::Encrypted(TwrpTarFile(archive)));
        }
        (false, None) => {
            let uncompressed = EgzReader::new(buf);
            let archive = Archive::new(uncompressed);
            return Ok(TwrpTarKind::Plain(TwrpTarFile(archive)));
        }
        (true, None) => return Err(TwrptarxError::TMissingKey),
        (false, Some(..)) => return Err(TwrptarxError::TKeyForNonOAES),
    }
}

#[cfg(test)]
mod tests {
    use crate::{try_iter_twrp_backup, TwrpTarKind};
    use std::fs::File;
    use std::path::Path;
    use tar::EntryType;

    #[test]
    fn test_magic() {
        let sample: &[u8] = &[
            0x4f, 0x41, 0x45, 0x53, 0x01, 0x02, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x90, 0xd2, 0x76, 0xc0, 0x09, 0xf8, 0xa1, 0xfd, 0x83, 0xf8, 0x99, 0x3c,
            0x7d, 0xb3, 0x1b, 0x35,
        ];

        let tk = try_iter_twrp_backup(sample, Some(b"asd")).unwrap();
        if let TwrpTarKind::Encrypted(_) = tk {
            //ok
        } else {
            panic!("expected to recognise encrypted archive");
        }
    }

    #[test]
    fn test_sample() {
        let path_sample = "sample/some-dir.tar.gz";

        let src = File::open(path_sample).unwrap();

        /*
        drwxr-xr-x test-user/test-group 0 2021-11-06 22:55 some-dir/
        drwxr-xr-x test-user/test-group 0 2021-11-06 22:55 some-dir/c/
        drwxr-xr-x test-user/test-group 0 2021-11-06 22:55 some-dir/c/00/
        drwxr-xr-x test-user/test-group 0 2021-11-06 22:55 some-dir/c/01/
        drwxr-xr-x test-user/test-group 0 2021-11-06 22:55 some-dir/a/
        drwxr-xr-x test-user/test-group 0 2021-11-12 23:02 some-dir/a/01/
        -rw-r--r-- test-user/test-group 498676 2021-11-07 19:56 some-dir/a/01/25622749924_d925c32564_o_resize.jpg
        drwxr-xr-x test-user/test-group      0 2021-11-06 22:55 some-dir/a/00/
        drwxr-xr-x test-user/test-group      0 2021-11-06 22:55 some-dir/b/
        drwxr-xr-x test-user/test-group      0 2021-11-12 23:03 some-dir/b/00/
        -rw-r--r-- test-user/test-group     25 2021-11-06 22:54 some-dir/b/00/whenever.txt
        drwxr-xr-x test-user/test-group      0 2021-11-06 22:55 some-dir/b/01/
        */

        let mut entries_golden = vec![
            ("some-dir/", EntryType::Directory, 0u64),
            ("some-dir/c/", EntryType::Directory, 0u64),
            ("some-dir/c/00", EntryType::Directory, 0u64),
            ("some-dir/c/01", EntryType::Directory, 0u64),
            ("some-dir/a/", EntryType::Directory, 0u64),
            ("some-dir/a/01", EntryType::Directory, 0u64),
            (
                "some-dir/a/01/25622749924_d925c32564_o_resize.jpg",
                EntryType::Regular,
                498676u64,
            ),
            ("some-dir/a/00", EntryType::Directory, 0u64),
            ("some-dir/b/", EntryType::Directory, 0u64),
            ("some-dir/b/00", EntryType::Directory, 0u64),
            ("some-dir/b/00/whenever.txt", EntryType::Regular, 25u64),
            ("some-dir/b/01/", EntryType::Directory, 0u64),
        ]
        .into_iter();

        let ttk = try_iter_twrp_backup(src, None).unwrap();
        if let TwrpTarKind::Plain(mut plain) = ttk {
            plain
                .iter_backup(|ent| {
                    let (name, kind, size) = entries_golden.next().unwrap();
                    assert_eq!(
                        <str as AsRef<Path>>::as_ref(name),
                        ent.path().unwrap().as_ref(),
                        "path did not match up"
                    );
                    assert_eq!(kind, ent.header().entry_type(), "type did not match up");
                    assert_eq!(size, ent.size(), "size did not match up");
                    // implicit:
                    // CallbackResult::Continue
                })
                .unwrap();
        } else {
            panic!("bad type");
        }
        assert!(
            entries_golden.next().is_none(),
            "iterator not exhausted, sample tar is missing items!"
        )
    }
}
