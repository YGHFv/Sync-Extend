//! XML request metadata is bounded independently of upload body limits.
use quick_xml::{events::Event, name::ResolveResult, reader::NsReader};

#[derive(Clone)]
pub enum Properties {
    All,
    Names,
    Selected(Vec<(String, String)>),
}

pub fn properties(bytes: &[u8]) -> Result<Properties, ()> {
    if bytes.is_empty() {
        return Ok(Properties::All);
    }
    let elements = elements(bytes, false)?;
    if elements.first() != Some(&(1, "DAV:".into(), "propfind".into())) {
        return Err(());
    }
    let modes: Vec<_> = elements
        .iter()
        .filter(|(depth, _, _)| *depth == 2)
        .collect();
    if modes.len() != 1 || modes[0].1 != "DAV:" {
        return Err(());
    }
    match modes[0].2.as_str() {
        "allprop" if elements.len() == 2 => Ok(Properties::All),
        "propname" if elements.len() == 2 => Ok(Properties::Names),
        "prop" => {
            if elements.iter().any(|(depth, _, _)| *depth > 3) {
                return Err(());
            }
            let properties = elements
                .into_iter()
                .skip(2)
                .map(|(_, namespace, name)| (namespace, name))
                .collect();
            Ok(Properties::Selected(properties))
        }
        _ => Err(()),
    }
}

pub fn exclusive_write_lock(bytes: &[u8]) -> Result<(), ()> {
    let elements = elements(bytes, true)?;
    if elements.first() != Some(&(1, "DAV:".into(), "lockinfo".into())) {
        return Err(());
    }
    let scope: Vec<_> = elements
        .iter()
        .filter(|(_, ns, name)| ns == "DAV:" && name == "lockscope")
        .collect();
    let kind: Vec<_> = elements
        .iter()
        .filter(|(_, ns, name)| ns == "DAV:" && name == "locktype")
        .collect();
    if scope.len() != 1
        || kind.len() != 1
        || !elements.contains(&(3, "DAV:".into(), "exclusive".into()))
        || !elements.contains(&(3, "DAV:".into(), "write".into()))
        || elements
            .iter()
            .any(|(_, ns, name)| ns == "DAV:" && name == "shared")
    {
        return Err(());
    }
    Ok(())
}

fn elements(bytes: &[u8], allow_text: bool) -> Result<Vec<(usize, String, String)>, ()> {
    if bytes.len() > 65536 {
        return Err(());
    }
    let mut reader = NsReader::from_reader(bytes);
    let mut depth = 0usize;
    let mut events = 0usize;
    let mut roots = 0usize;
    let mut output = Vec::new();
    loop {
        events += 1;
        if events > 4096 {
            return Err(());
        }
        let (namespace, event) = reader.read_resolved_event().map_err(|_| ())?;
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                if depth == 0 {
                    roots += 1;
                }
                let namespace = match namespace {
                    ResolveResult::Bound(namespace) => std::str::from_utf8(namespace.as_ref())
                        .map_err(|_| ())?
                        .to_owned(),
                    ResolveResult::Unbound => String::new(),
                    ResolveResult::Unknown(_) => return Err(()),
                };
                let local = std::str::from_utf8(start.local_name().as_ref())
                    .map_err(|_| ())?
                    .to_owned();
                output.push((depth + 1, namespace, local));
                // Empty has no corresponding End event.
                if !empty {
                    depth += 1;
                }
                if depth > 32 {
                    return Err(());
                }
            }
            Event::End(_) => {
                depth = depth.checked_sub(1).ok_or(())?;
            }
            Event::Text(text) => {
                let value = text.decode().map_err(|_| ())?;
                if (!allow_text || depth == 0) && !value.trim().is_empty() {
                    return Err(());
                }
            }
            Event::Comment(_) | Event::Decl(_) => {}
            Event::Eof => break,
            Event::DocType(_) | Event::PI(_) | Event::CData(_) | Event::GeneralRef(_) => {
                return Err(())
            }
        }
    }
    if roots != 1 || depth != 0 {
        return Err(());
    }
    Ok(output)
}
