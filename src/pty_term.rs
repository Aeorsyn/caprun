use anyhow::{anyhow, Result};
use std::{
    ffi::CStr,
    fs::File,
    io::{Read, Write},
    os::unix::{
        io::FromRawFd,
        process::CommandExt,
    },
    process::{Child, Command},
};

pub struct PtySession {
    pub master_read: File,
    pub master_write: File,
    pub child: Child,
}

pub fn spawn_bash(cols: u16, rows: u16) -> Result<PtySession> {
    unsafe {
        let master = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        if master < 0 { return Err(anyhow!("posix_openpt failed")); }
        if libc::grantpt(master) != 0 || libc::unlockpt(master) != 0 {
            libc::close(master);
            return Err(anyhow!("grantpt/unlockpt failed"));
        }
        let name_ptr = libc::ptsname(master);
        if name_ptr.is_null() {
            libc::close(master);
            return Err(anyhow!("ptsname failed"));
        }
        let slave_name = CStr::from_ptr(name_ptr).to_owned();
        let slave = libc::open(slave_name.as_ptr(), libc::O_RDWR);
        if slave < 0 {
            libc::close(master);
            return Err(anyhow!("open slave pty failed"));
        }

        let ws = libc::winsize { ws_row: rows, ws_col: cols, ws_xpixel: 0, ws_ypixel: 0 };
        libc::ioctl(slave, libc::TIOCSWINSZ, &ws);

        let mut cmd = Command::new("/bin/bash");
        cmd.arg("-i")
            .env("TERM", "xterm-256color")
            .env("PS1", "\\[\\e[36m\\]caprun\\[\\e[0m\\]:\\[\\e[32m\\]\\W\\[\\e[0m\\]\\$ ");

        cmd.pre_exec(move || {
            libc::close(master);
            libc::setsid();
            libc::ioctl(slave, libc::TIOCSCTTY, 0);
            libc::dup2(slave, 0);
            libc::dup2(slave, 1);
            libc::dup2(slave, 2);
            if slave > 2 { libc::close(slave); }
            Ok(())
        });

        let child = cmd.spawn()?;
        libc::close(slave);

        let master_read = File::from_raw_fd(master);
        let master_write = master_read.try_clone()?;
        Ok(PtySession { master_read, master_write, child })
    }
}

pub fn read_loop(mut reader: File, tx: tokio::sync::mpsc::Sender<String>) {
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let txt = String::from_utf8_lossy(&buf[..n]).into_owned();
                if tx.blocking_send(txt).is_err() { break; }
            }
        }
    }
}

pub fn write_all(writer: &mut File, data: &[u8]) -> bool {
    writer.write_all(data).is_ok() && writer.flush().is_ok()
}
