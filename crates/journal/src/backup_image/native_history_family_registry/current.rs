//! Additive schema-70 inventory. Existing schema-69 rules and digests stay frozen.
use super::*;
use std::sync::OnceLock;
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CatalogDefinition {
    pub kind: String,
    pub name: String,
    pub table: String,
    pub sql: Option<String>,
}
const fn columns<const N: usize>(source: &[ColumnSpec]) -> [NativeHistoryColumnSpec; N] {
    assert!(
        source.len() == N,
        "native history exact additive column count"
    );
    let mut result = [NativeHistoryColumnSpec {
        name: "",
        kind: NativeHistoryColumnKind::NonnegativeInteger,
        primary_key: 0,
        not_null: false,
        default: None,
    }; N];
    let mut i = 0;
    while i < N {
        let c = &source[i];
        result[i] = NativeHistoryColumnSpec {
            name: c.name,
            kind: match c.kind {
                ColumnKind::Text(n) => NativeHistoryColumnKind::HexText(n),
                ColumnKind::Utf8 { min, max } => NativeHistoryColumnKind::Utf8 { min, max },
                ColumnKind::Integer => NativeHistoryColumnKind::NonnegativeInteger,
                ColumnKind::Blob { min, max } => NativeHistoryColumnKind::BoundedBlob { min, max },
            },
            primary_key: c.primary_key,
            not_null: c.not_null,
            default: c.default,
        };
        i += 1;
    }
    result
}
const C0: [NativeHistoryColumnSpec; 22] =
    columns(super::super::native_history_persistence::schema::TABLES[0].columns);
const C1: [NativeHistoryColumnSpec; 6] =
    columns(super::super::native_history_persistence::schema::TABLES[1].columns);
const C2: [NativeHistoryColumnSpec; 7] =
    columns(super::super::native_history_persistence::schema::TABLES[2].columns);
const C3: [NativeHistoryColumnSpec; 8] =
    columns(super::super::native_history_persistence::schema::TABLES[3].columns);
const C4: [NativeHistoryColumnSpec; 4] =
    columns(super::super::native_history_persistence::schema::TABLES[4].columns);
const C5: [NativeHistoryColumnSpec; 8] =
    columns(super::super::native_history_persistence::schema::TABLES[5].columns);
const C6: [NativeHistoryColumnSpec; 3] =
    columns(super::super::native_history_persistence::schema::TABLES[6].columns);
const C7: [NativeHistoryColumnSpec; 6] =
    columns(super::super::native_history_persistence::schema::TABLES[7].columns);
const C8: [NativeHistoryColumnSpec; 14] =
    columns(super::super::native_history_persistence::schema::TABLES[8].columns);
const C9: [NativeHistoryColumnSpec; 6] =
    columns(super::super::native_history_persistence::schema::TABLES[9].columns);
const EXTRA: &[NativeHistoryTableRule] = &[
    NativeHistoryTableRule {
        table: "native_history_sources",
        family: "retained_native_history",
        slice: 27,
        columns: &C0,
        clock_columns: &[],
        signature_columns: &[],
        native_identity_columns: &[],
        root_bound_columns: &[],
        owner: NativeHistoryOwnerRelation::Anchor,
        direct_reference: NativeHistoryDirectReference::None,
        audited_embedded_columns: &[],
        portable_state: false,
    },
    NativeHistoryTableRule {
        table: "native_history_source_tables",
        family: "retained_native_history",
        slice: 27,
        columns: &C1,
        clock_columns: &[],
        signature_columns: &[],
        native_identity_columns: &[],
        root_bound_columns: &[],
        owner: NativeHistoryOwnerRelation::Child {
            parent: "native_history_sources",
            columns: &[("source_digest", "source_digest")],
        },
        direct_reference: NativeHistoryDirectReference::None,
        audited_embedded_columns: &[],
        portable_state: false,
    },
    NativeHistoryTableRule {
        table: "native_history_source_rows",
        family: "retained_native_history",
        slice: 27,
        columns: &C2,
        clock_columns: &[],
        signature_columns: &[],
        native_identity_columns: &[],
        root_bound_columns: &[],
        owner: NativeHistoryOwnerRelation::Child {
            parent: "native_history_sources",
            columns: &[("source_digest", "source_digest")],
        },
        direct_reference: NativeHistoryDirectReference::None,
        audited_embedded_columns: &[],
        portable_state: false,
    },
    NativeHistoryTableRule {
        table: "native_history_holds",
        family: "retained_native_history",
        slice: 27,
        columns: &C3,
        clock_columns: &[],
        signature_columns: &[],
        native_identity_columns: &[],
        root_bound_columns: &[],
        owner: NativeHistoryOwnerRelation::Child {
            parent: "native_history_sources",
            columns: &[("source_digest", "source_digest")],
        },
        direct_reference: NativeHistoryDirectReference::None,
        audited_embedded_columns: &[],
        portable_state: false,
    },
    NativeHistoryTableRule {
        table: "native_history_hold_rows",
        family: "retained_native_history",
        slice: 27,
        columns: &C4,
        clock_columns: &[],
        signature_columns: &[],
        native_identity_columns: &[],
        root_bound_columns: &[],
        owner: NativeHistoryOwnerRelation::Child {
            parent: "native_history_holds",
            columns: &[
                ("source_digest", "source_digest"),
                ("hold_ordinal", "ordinal"),
            ],
        },
        direct_reference: NativeHistoryDirectReference::None,
        audited_embedded_columns: &[],
        portable_state: false,
    },
    NativeHistoryTableRule {
        table: "native_history_hold_objects",
        family: "retained_native_history",
        slice: 27,
        columns: &C5,
        clock_columns: &[],
        signature_columns: &[],
        native_identity_columns: &[],
        root_bound_columns: &[],
        owner: NativeHistoryOwnerRelation::Child {
            parent: "native_history_holds",
            columns: &[
                ("source_digest", "source_digest"),
                ("hold_ordinal", "ordinal"),
            ],
        },
        direct_reference: NativeHistoryDirectReference::None,
        audited_embedded_columns: &[],
        portable_state: false,
    },
    NativeHistoryTableRule {
        table: "native_history_projection_rows",
        family: "retained_native_history",
        slice: 27,
        columns: &C6,
        clock_columns: &[],
        signature_columns: &[],
        native_identity_columns: &[],
        root_bound_columns: &[],
        owner: NativeHistoryOwnerRelation::Child {
            parent: "native_history_sources",
            columns: &[("source_digest", "source_digest")],
        },
        direct_reference: NativeHistoryDirectReference::None,
        audited_embedded_columns: &[],
        portable_state: false,
    },
    NativeHistoryTableRule {
        table: "native_history_projection_root_columns",
        family: "retained_native_history",
        slice: 27,
        columns: &C7,
        clock_columns: &[],
        signature_columns: &[],
        native_identity_columns: &[],
        root_bound_columns: &[],
        owner: NativeHistoryOwnerRelation::Child {
            parent: "native_history_sources",
            columns: &[("source_digest", "source_digest")],
        },
        direct_reference: NativeHistoryDirectReference::None,
        audited_embedded_columns: &[],
        portable_state: false,
    },
    NativeHistoryTableRule {
        table: "native_history_fresh_writers",
        family: "retained_native_history",
        slice: 27,
        columns: &C8,
        clock_columns: &[],
        signature_columns: &[],
        native_identity_columns: &[],
        root_bound_columns: &[],
        owner: NativeHistoryOwnerRelation::Child {
            parent: "native_history_sources",
            columns: &[("source_digest", "source_digest")],
        },
        direct_reference: NativeHistoryDirectReference::None,
        audited_embedded_columns: &[],
        portable_state: false,
    },
    NativeHistoryTableRule {
        table: "native_history_fresh_writer_events",
        family: "retained_native_history",
        slice: 27,
        columns: &C9,
        clock_columns: &[],
        signature_columns: &[],
        native_identity_columns: &[],
        root_bound_columns: &[],
        owner: NativeHistoryOwnerRelation::Child {
            parent: "native_history_fresh_writers",
            columns: &[("writer_id", "writer_id")],
        },
        direct_reference: NativeHistoryDirectReference::None,
        audited_embedded_columns: &[],
        portable_state: false,
    },
];
pub(super) fn tables() -> &'static [NativeHistoryTableRule] {
    static VALUE: OnceLock<Vec<NativeHistoryTableRule>> = OnceLock::new();
    VALUE.get_or_init(|| [TABLE_RULES, EXTRA].concat())
}
pub(super) fn families() -> &'static [&'static str] {
    static VALUE: OnceLock<Vec<&'static str>> = OnceLock::new();
    VALUE.get_or_init(|| {
        let mut v = FAMILIES.to_vec();
        v.push("retained_native_history");
        v
    })
}
pub(super) fn slices() -> &'static [NativeHistorySliceSpec] {
    static VALUE: OnceLock<Vec<NativeHistorySliceSpec>> = OnceLock::new();
    VALUE.get_or_init(|| {
        let mut v = SLICES.to_vec();
        v.push(NativeHistorySliceSpec {
            source: "migration-070.sql",
            tables: &[
                "native_history_sources",
                "native_history_source_tables",
                "native_history_source_rows",
                "native_history_holds",
                "native_history_hold_rows",
                "native_history_hold_objects",
                "native_history_projection_rows",
                "native_history_projection_root_columns",
                "native_history_fresh_writers",
                "native_history_fresh_writer_events",
            ],
        });
        v
    })
}

pub(super) fn catalog(version: u32) -> Result<&'static [CatalogDefinition]> {
    static V70: OnceLock<Vec<CatalogDefinition>> = OnceLock::new();
    static V71: OnceLock<Vec<CatalogDefinition>> = OnceLock::new();
    static V72: OnceLock<Vec<CatalogDefinition>> = OnceLock::new();
    static V73: OnceLock<Vec<CatalogDefinition>> = OnceLock::new();
    let cell = match version {
        70 => &V70,
        71 => &V71,
        72 => &V72,
        73 => &V73,
        _ => {
            return Err(JournalError::Invariant(
                "native history current catalog version",
            ));
        }
    };
    if cell.get().is_none() {
        let compiled = super::super::schema_catalog::compiled_definitions(version)?
            .iter()
            .cloned()
            .map(|(kind, name, table, sql)| CatalogDefinition {
                kind,
                name,
                table,
                sql,
            })
            .collect();
        let _ = cell.set(compiled);
    }
    Ok(cell.get().ok_or(JournalError::Invariant(
        "native history compiled catalog cache",
    ))?)
}
