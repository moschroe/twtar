roaes
-----

_Disclaimer: Neither this project, nor the author, are in any way associated with Team Win or Team Win Recovery Project (TWRP). No infringement on or claim over the aforementioned terms is made or intended._

### Library

Allows iterating over entries TWRP ([Team Win Recovery Project (TWRP)][1]) backup tar files, even when they are
encrypted and/or gzip-compressed.

Uses roaes for handling the [TWRP][2] openaes format. Look there for a standalone decryption/encryption tool.

### Binary

The executable `twrp2tar` will (optionally) decrypt the openaes format, (optionally) undo gzip compression and then
process the tar data, creating a new tar file with the same contents as the original _apart from extended attributes
(see below!)._ It uses very simple command line parsing. Running the command with `-?` will print its usage information.

For binary releases, check on github at <https://github.com/moschroe/twtar>.

> #### Beware
> 
> **At the time of writing, the underlying tar library does not support creating extension headers. This means that the
> conversion from a TWRP backup file to a GNU tar file will be lossy! The resulting tar file will 
> _not be a working backup_ that can be restored onto an android device!**
> 
> The sole purpose is to provide access to backed-up files on a non-android system.

```text
USAGE: twrp2tar [<key>] < backup_archive > converted archive

twrp2tar will (lossily!) convert a tar archive as created by the android recovery firmware TWRP
(Team Win Recovery Project, https://twrp.me/) to a GNU tar file. Gzip compression of the source
archive will be handled transparently. So will encryption with the TWRP-flavoured openaes
encryption, in which case the decryption key has to be specified as the sole parameter (take care
of quotes, if necessary!).

WARNING! THIS CONVERSION WILL OMIT A NUMBER OF CRUCIAL EXTENDED ATTRIBUTES OF THE ORIGINAL ARCHIVE!
ONLY ACCESS TO FILES WILL BE POSSIBLE, RESTORING THE CONVERTED BACKUP TO AN ANDROID DEVICE
WILL FAIL!
```

Data is read from standard input and written to standard output. No file handles are opened at all. To process data, use appropriate shell mechanisms like `twrp2tar < twrp-backup.file > GNU-tar.file`.

[1]: <https://twrp.me/>
[2]: <https://crates.io/crates/roaes>