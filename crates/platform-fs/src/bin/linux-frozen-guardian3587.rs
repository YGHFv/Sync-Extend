//! Inherited-descriptor Linux watchdog; the owner separately binds durable intent.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn inherited(value: &std::ffi::OsStr) -> std::io::Result<std::fs::File> {
    let descriptor: u32 = value
        .to_str()
        .ok_or_else(|| std::io::Error::other("descriptor encoding"))?
        .parse()
        .map_err(|_| std::io::Error::other("descriptor number"))?;
    // SAFETY: this fresh helper receives each explicit descriptor exactly once
    // from its launcher and has no other File owner for these inherited values.
    unsafe { sync_extend_platform_fs::take_inherited_descriptor(descriptor) }
}

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::io::Write;
    use sync_extend_platform_fs::{
        OutsideGuardian, OutsidePreparationGate, OutsideSupervisor, ThawObservation,
    };
    let args: Vec<_> = std::env::args_os().take(12).collect();
    use std::os::unix::ffi::OsStrExt;
    if args.len() > 10
        || args
            .iter()
            .any(|value| value.as_os_str().as_bytes().len() > 4096)
    {
        return Err("bounded helper arguments required".into());
    }
    let mode = args
        .get(1)
        .and_then(|value| value.to_str())
        .ok_or("mode required")?;
    fn number(value: &std::ffi::OsStr) -> Result<u32, Box<dyn std::error::Error>> {
        Ok(value.to_str().ok_or("number encoding")?.parse()?)
    }
    fn report(event: &str, row: ThawObservation) {
        println!("{{\"event\":\"{}\",\"reason\":\"{}\",\"owner_exit_before_thaw\":{},\"guardian_exit_before_thaw\":{},\"exit_verified_ns\":{},\"guardian_exit_verified_ns\":{},\"thaw_finished_ns\":{},\"actual_Rust_guardian\":true}}",
            event,row.reason,row.owner_exit_before_thaw,row.guardian_exit_before_thaw,
            row.exit_verified_ns.map_or_else(|| "null".into(), |value| value.to_string()),
            row.guardian_exit_verified_ns.map_or_else(|| "null".into(), |value| value.to_string()),
            row.thaw_finished_ns);
    }
    match mode {
        "guardian" if args.len() == 7 => {
            let descriptors = args[2..5]
                .iter()
                .map(|value| number(value.as_os_str()))
                .collect::<Result<Vec<_>, _>>()?;
            if descriptors.iter().enumerate().any(|(index, value)| {
                descriptors
                    .iter()
                    .skip(index + 1)
                    .any(|other| other == value)
            }) {
                return Err("distinct inherited descriptors required".into());
            }
            let helper = OutsideGuardian::new(
                inherited(&args[2])?,
                inherited(&args[3])?,
                inherited(&args[4])?,
                number(&args[5])?,
                number(&args[6])?,
            )?;
            println!("{{\"event\":\"GUARD_READY\",\"actual_Rust_guardian\":true}}");
            std::io::stdout().flush()?;
            report("THAWED", helper.run()?);
        }
        "supervisor" if args.len() == 9 => {
            let descriptors = args[2..6]
                .iter()
                .map(|value| number(value.as_os_str()))
                .collect::<Result<Vec<_>, _>>()?;
            if descriptors.iter().enumerate().any(|(index, value)| {
                descriptors
                    .iter()
                    .skip(index + 1)
                    .any(|other| other == value)
            }) {
                return Err("distinct inherited descriptors required".into());
            }
            let helper = OutsideSupervisor::new(
                inherited(&args[2])?,
                inherited(&args[3])?,
                inherited(&args[4])?,
                inherited(&args[5])?,
                number(&args[6])?,
                number(&args[7])?,
                number(&args[8])?,
            )?;
            println!("{{\"event\":\"SUPERVISOR_READY\",\"actual_Rust_guardian\":true}}");
            std::io::stdout().flush()?;
            match helper.run()? {
                Some(row) => report("SUPERVISORY_THAWED", row),
                None => println!("{{\"event\":\"GUARDIAN_FINISHED\"}}"),
            }
        }

        "prepared-guardian" if args.len() == 8 => {
            let descriptors = args[2..6]
                .iter()
                .map(|value| number(value.as_os_str()))
                .collect::<Result<Vec<_>, _>>()?;
            if descriptors.iter().enumerate().any(|(index, value)| {
                descriptors
                    .iter()
                    .skip(index + 1)
                    .any(|other| other == value)
            }) {
                return Err("distinct inherited preparation descriptors required".into());
            }
            let helper = OutsideGuardian::new(
                inherited(&args[2])?,
                inherited(&args[3])?,
                inherited(&args[4])?,
                number(&args[6])?,
                number(&args[7])?,
            )?;
            let preparation = OutsidePreparationGate::new(inherited(&args[5])?)?;
            println!("{{\"event\":\"GUARD_PREPARED\",\"actual_Rust_guardian\":true}}");
            std::io::stdout().flush()?;
            if !preparation.wait_arm()? {
                println!("{{\"event\":\"PREPARATION_CANCELLED\",\"actual_Rust_guardian\":true}}");
                return Ok(());
            }
            println!("{{\"event\":\"GUARD_READY\",\"actual_Rust_guardian\":true}}");
            std::io::stdout().flush()?;
            report("THAWED", helper.run()?);
        }
        "prepared-supervisor" if args.len() == 10 => {
            let descriptors = args[2..7]
                .iter()
                .map(|value| number(value.as_os_str()))
                .collect::<Result<Vec<_>, _>>()?;
            if descriptors.iter().enumerate().any(|(index, value)| {
                descriptors
                    .iter()
                    .skip(index + 1)
                    .any(|other| other == value)
            }) {
                return Err("distinct inherited preparation descriptors required".into());
            }
            let helper = OutsideSupervisor::new(
                inherited(&args[2])?,
                inherited(&args[3])?,
                inherited(&args[4])?,
                inherited(&args[5])?,
                number(&args[7])?,
                number(&args[8])?,
                number(&args[9])?,
            )?;
            let preparation = OutsidePreparationGate::new(inherited(&args[6])?)?;
            println!("{{\"event\":\"SUPERVISOR_PREPARED\",\"actual_Rust_guardian\":true}}");
            std::io::stdout().flush()?;
            if !preparation.wait_arm()? {
                println!("{{\"event\":\"PREPARATION_CANCELLED\",\"actual_Rust_guardian\":true}}");
                return Ok(());
            }
            println!("{{\"event\":\"SUPERVISOR_READY\",\"actual_Rust_guardian\":true}}");
            std::io::stdout().flush()?;
            match helper.run_after_preparation()? {
                Some(row) => report("SUPERVISORY_THAWED", row),
                None => println!("{{\"event\":\"GUARDIAN_FINISHED\"}}"),
            }
        }
        _ => return Err("known bounded mode and inherited descriptors required".into()),
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("explicit Linux inherited-descriptor volume guardian required");
    std::process::exit(2);
}
