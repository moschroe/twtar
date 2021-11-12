use std::env::args_os;
use std::io::{stdin, stdout, Error as IOError, ErrorKind as IOErrorKind, Read, Write};
use std::process::exit;
use tar::{Builder, Entry, EntryType, Header};
use twtar::{try_iter_twrp_backup, CallbackResult, TwrpTarKind};

const USAGE: &str = r###"USAGE: twrp2tar [<key>] < backup_archive > converted archive

twrp2tar will (lossily!) convert a tar archive as created by the android recovery firmware TWRP
(Team Win Recovery Project, https://twrp.me/) to a GNU tar file. Gzip compression of the source
archive will be handled transparently. So will encryption with the TWRP-flavoured openaes
encryption, in which case the decryption key has to be specified as the sole parameter (take care
of quotes, if necessary!).

WARNING! THIS CONVERSION WILL OMIT A NUMBER OF CRUCIAL EXTENDED ATTRIBUTES OF THE ORIGINAL ARCHIVE!
ONLY ACCESS TO FILES WILL BE POSSIBLE, RESTORING THE CONVERTED BACKUP TO AN ANDROID DEVICE
WILL FAIL!
"###;

fn usage() -> ! {
    eprint!("{}", USAGE);
    exit(0)
}

fn main() {
    let opt_key_os = args_os().skip(1).nth(0);
    let opt_key = opt_key_os.as_ref().map(|oss| {
        if oss == "/?" || oss == "-?" || oss == "-h" || oss == "--help" || oss == "-help" {
            usage();
        }
        Vec::from({
            #[cfg(windows)]
            {
                use os_str_bytes::OsStrBytes;
                oss.to_raw_bytes()
            }
            #[cfg(not(windows))]
            {
                use std::os::unix::prelude::OsStrExt;
                oss.as_bytes()
            }
        })
    });

    let sin = stdin();
    let sin_locked = sin.lock();

    let sout = stdout();
    let sout_locked = sout.lock();

    let mut archive = Builder::new(sout_locked);

    let mut counter = 0u32;

    let mut warning_absolute = false;

    let twrp_tar_kind = try_iter_twrp_backup(sin_locked, opt_key.as_ref().map(|v| v.as_slice()))
        .expect("unable to parse STDIN");

    match twrp_tar_kind {
        TwrpTarKind::Plain(mut plain) => {
            plain
                .iter_backup(|entry: Entry<_>| {
                    if let Err(err) =
                        transfer_entry(entry, &mut archive, &mut warning_absolute, &mut counter)
                    {
                        eprintln!("error: {:?}", err);
                        return CallbackResult::Error;
                    }
                    CallbackResult::default()
                })
                .expect("unable to process backup");
            archive
                .finish()
                .expect("unable to finish writing tar archive");
            eprintln!("        \r{:07}", counter);
        }
        TwrpTarKind::Encrypted(mut encr) => {
            encr.iter_backup(|entry: Entry<_>| {
                if let Err(err) =
                    transfer_entry(entry, &mut archive, &mut warning_absolute, &mut counter)
                {
                    eprintln!("error: {:?}", err);
                    return CallbackResult::Error;
                }
                CallbackResult::default()
            })
            .expect("unable to process backup");
            archive
                .finish()
                .expect("unable to finish writing tar archive");
            eprintln!("        \r{:07}", counter);
        }
    }
}

fn transfer_entry<R: Read, W: Write>(
    ent: Entry<R>,
    archive: &mut Builder<W>,
    warning_absolute: &mut bool,
    counter: &mut u32,
) -> std::io::Result<()> {
    let mut hn = Header::new_gnu();
    let ho = ent.header();

    hn.set_entry_type(ho.entry_type());
    if let Some(name_link) = ho
        .link_name()
        .map_err(|err| IOError::new(IOErrorKind::Other, err))?
    {
        hn.set_link_name(name_link)?;
    }
    hn.set_mode(ho.mode()?);
    hn.set_uid(ho.uid()?);
    hn.set_gid(ho.gid()?);
    hn.set_mtime(ho.mtime()?);
    if let Some(name_usr) = ho
        .username()
        .map_err(|errutf| IOError::new(IOErrorKind::Other, errutf))?
    {
        hn.set_username(name_usr)?;
    }
    if let Some(name_grp) = ho
        .groupname()
        .map_err(|errutf| IOError::new(IOErrorKind::Other, errutf))?
    {
        hn.set_groupname(name_grp)?;
    }
    match ho.entry_type() {
        EntryType::Block => {
            if let Some(dev_major) = ho
                .device_major()
                .map_err(|err| IOError::new(IOErrorKind::Other, err))?
            {
                hn.set_device_major(dev_major)?;
            }
            if let Some(dev_minor) = ho
                .device_minor()
                .map_err(|err| IOError::new(IOErrorKind::Other, err))?
            {
                hn.set_device_minor(dev_minor)?;
            }
        }
        _ => {}
    }
    let path = ho.path()?;
    if path.is_absolute() {
        if !*warning_absolute {
            eprintln!(
                "\nEncountered absolute path! All absolute paths will \
                            be converted to relative ones!"
            );
            *warning_absolute = true;
        }
        let path_rel = path
            .strip_prefix("/")
            .map_err(|err| IOError::new(IOErrorKind::Other, err))?;
        hn.set_path(path_rel)?;
    } else {
        hn.set_path(path)?;
    }
    let ho_size = ho.size()?;
    hn.set_size(ho_size);

    hn.set_cksum();
    // if ho_size > 0 {
    //     dbg!(ho.entry_size()?);
    //     dbg!(&ho);
    //     dbg!(&hn);
    //     panic!();
    // }
    eprint!("        \r{:07}", counter);
    *counter += 1;
    archive.append(&hn, ent)?;
    Ok(())
}
