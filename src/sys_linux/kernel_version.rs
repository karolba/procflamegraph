use nix::sys::utsname::uname;

pub(crate) fn kernel_major_minor() -> Option<(u32, u32)> {
    let uname = uname().ok()?;
    let release = uname.release().to_string_lossy();

    let major_length = release.find('.')?;
    let minor_length = release[major_length + 1..].find('.')?;

    let major = str::parse::<u32>(&release[0..major_length]).ok()?;
    let minor = str::parse::<u32>(&release[major_length + 1..major_length + 1 + minor_length]).ok()?;

    Some((major, minor))
}
