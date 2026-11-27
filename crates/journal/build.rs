//! Deterministic bytes for trusted, packaged Journal SQL inputs only.
use std::{env, fs, path::PathBuf};
const SQL_INPUTS: &[&str] = &[
    "conflict_resolution_retirement_fences.sql",
    "migration-002.sql",
    "migration-003.sql",
    "migration-004.sql",
    "migration-005.sql",
    "migration-006.sql",
    "migration-007.sql",
    "migration-008.sql",
    "migration-009.sql",
    "migration-010.sql",
    "migration-011.sql",
    "migration-012.sql",
    "migration-013.sql",
    "migration-014.sql",
    "migration-015.sql",
    "migration-016.sql",
    "migration-017.sql",
    "migration-018.sql",
    "migration-019.sql",
    "migration-020.sql",
    "migration-021.sql",
    "migration-022.sql",
    "migration-023.sql",
    "migration-024.sql",
    "migration-025.sql",
    "migration-026.sql",
    "migration-027.sql",
    "migration-028.sql",
    "migration-029.sql",
    "migration-030.sql",
    "migration-031.sql",
    "migration-032.sql",
    "migration-033.sql",
    "migration-034.sql",
    "migration-035.sql",
    "migration-036.sql",
    "migration-037.sql",
    "migration-038.sql",
    "migration-039.sql",
    "migration-040.sql",
    "migration-041.sql",
    "migration-042.sql",
    "migration-043.sql",
    "migration-044.sql",
    "migration-045.sql",
    "migration-046.sql",
    "migration-047.sql",
    "migration-048.sql",
    "migration-049.sql",
    "migration-050.sql",
    "migration-051.sql",
    "migration-052.sql",
    "migration-053.sql",
    "migration-054.sql",
    "migration-055.sql",
    "migration-056.sql",
    "migration-057.sql",
    "migration-058.sql",
    "migration-059.sql",
    "migration-060.sql",
    "migration-061.sql",
    "migration-062.sql",
    "migration-063.sql",
    "migration-064.sql",
    "migration-065.sql",
    "migration-066.sql",
    "migration-067.sql",
    "migration-068.sql",
    "migration-069.sql",
    "migration-070.sql",
    "migration-071.sql",
    "migration-072.sql",
    "migration-073.sql",
    "migration-074.sql",
    "remote_replace_retirement_fences.sql",
    "schema.sql",
    "storage-pull-attempt-budget-schema.sql",
    "storage-traffic-schema.sql",
];
fn main() {
    let root = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let output = PathBuf::from(env::var_os("OUT_DIR").expect("output directory"));
    println!("cargo:rerun-if-changed=build.rs");
    let mut macros = String::from(
        "// Generated from fixed trusted Journal SQL source inputs.\nmacro_rules! journal_sql {\n",
    );
    for name in SQL_INPUTS {
        assert!(!name.contains('/') && name.ends_with(".sql"));
        println!("cargo:rerun-if-changed=src/{name}");
        let bytes = fs::read(root.join("src").join(name)).expect("read trusted SQL");
        let original = std::str::from_utf8(&bytes).expect("trusted SQL must be UTF-8");
        let canonical = original.replace("\r\n", "\n");
        assert!(!canonical.contains('\r'), "bare CR in trusted SQL {name}");
        fs::write(output.join(name), canonical).expect("write canonical SQL");
        macros.push_str(&format!(
            "    (\"{name}\") => {{ include_str!(concat!(env!(\"OUT_DIR\"), \"/{name}\")) }};\n"
        ));
    }
    macros.push_str("}\n");
    fs::write(output.join("journal_sql_macros.rs"), macros).expect("write SQL input mapping");
}
