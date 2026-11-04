use anyhow::{Context, Result};
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;

use crate::config::inspectors::SystemFeaturesPolicy;

use super::plan::{find_capability_state, find_state_case_insensitive, FeatureAction};
use super::snapshot::SystemFeaturesSnapshot;

const REPORT_DIRECTORY: &str = "puente";

pub(super) fn write_before_reconciliation(
    snapshot: &SystemFeaturesSnapshot,
    policy: &SystemFeaturesPolicy,
    actions: &[FeatureAction],
    suppressed_actions: &[FeatureAction],
    note: &str,
) -> Result<()> {
    let mut current = format!(
        "Inventario observado antes de reconciliar\nGenerado (UTC): {}\n{note}\n",
        chrono::Utc::now().to_rfc3339()
    );
    append_active_items(&mut current, snapshot);
    write_report("system_features_01_current.txt", &current)?;

    let mut plan = format!(
        "Comparación de inventario y política Nickel\nGenerado (UTC): {}\n{note}\n",
        chrono::Utc::now().to_rfc3339()
    );
    plan.push_str(
        "\nNota: DISM no informa el modo de compatibilidad Internet Explorer por sitio de Microsoft Edge; este informe cubre solo características opcionales y capacidades de Windows.\n",
    );
    append_plan(&mut plan, snapshot, policy, actions, suppressed_actions);
    write_report("system_features_02_plan.txt", &plan)
}

pub(super) fn write_final_report(snapshot: &SystemFeaturesSnapshot, note: &str) -> Result<()> {
    let mut report = format!(
        "Último inventario observado después de reconciliar\nGenerado (UTC): {}\n{note}\n",
        chrono::Utc::now().to_rfc3339()
    );
    append_all_items(&mut report, snapshot);
    write_report("system_features_03_final.txt", &report)
}

pub(super) fn write_unavailable_reports(policy: &SystemFeaturesPolicy, error: &str) -> Result<()> {
    let note = format!("No se pudo obtener el inventario DISM: {error}");
    write_report(
        "system_features_01_current.txt",
        &format!(
            "Inventario actual no disponible\nGenerado (UTC): {}\n{note}\n",
            chrono::Utc::now().to_rfc3339()
        ),
    )?;

    let mut plan = format!(
        "No se puede calcular el plan sin un inventario DISM confiable\nGenerado (UTC): {}\n{note}\n",
        chrono::Utc::now().to_rfc3339()
    );
    plan.push_str(
        "\nNota: DISM no informa el modo de compatibilidad Internet Explorer por sitio de Microsoft Edge; este informe cubre solo características opcionales y capacidades de Windows.\n",
    );
    append_policy_entries(&mut plan, policy);
    write_report("system_features_02_plan.txt", &plan)?;
    write_report(
        "system_features_03_final.txt",
        &format!(
            "Estado final no disponible\nGenerado (UTC): {}\n{note}\n",
            chrono::Utc::now().to_rfc3339()
        ),
    )
}

fn write_report(name: &str, contents: &str) -> Result<()> {
    fs::create_dir_all(REPORT_DIRECTORY)
        .with_context(|| format!("no se pudo crear la carpeta de informes {REPORT_DIRECTORY}"))?;
    let path = Path::new(REPORT_DIRECTORY).join(name);
    fs::write(&path, contents).with_context(|| {
        format!(
            "no se pudo escribir el informe de depuración {}",
            path.display()
        )
    })
}

fn append_active_items(report: &mut String, snapshot: &SystemFeaturesSnapshot) {
    append_active_section(report, "Características opcionales", &snapshot.features);
    append_active_section(report, "Capacidades de Windows", &snapshot.capabilities);

    writeln!(report, "\nOperaciones DISM pendientes:").unwrap();
    let mut count = 0;
    for (kind, items) in [
        ("Característica", &snapshot.features),
        ("Capacidad", &snapshot.capabilities),
    ] {
        for (name, state) in items {
            if state.is_transition_pending() {
                writeln!(report, "- {kind}: {name} [{state:?}]").unwrap();
                count += 1;
            }
        }
    }
    if count == 0 {
        report.push_str("- Ninguna\n");
    }
}

fn append_active_section(
    report: &mut String,
    title: &str,
    items: &std::collections::BTreeMap<String, windows_features::FeatureState>,
) {
    let active: Vec<_> = items
        .iter()
        .filter(|(_, state)| state.is_enabled_or_pending())
        .collect();
    writeln!(report, "\n{title} activas ({}):", active.len()).unwrap();
    if active.is_empty() {
        report.push_str("- Ninguna\n");
    } else {
        for (name, state) in active {
            writeln!(report, "- {name} [{state:?}]").unwrap();
        }
    }
}

fn append_plan(
    report: &mut String,
    snapshot: &SystemFeaturesSnapshot,
    policy: &SystemFeaturesPolicy,
    actions: &[FeatureAction],
    suppressed_actions: &[FeatureAction],
) {
    for (title, matches) in [
        (
            "Activar / instalar",
            actions
                .iter()
                .filter(|action| {
                    matches!(
                        action,
                        FeatureAction::EnableFeature(_) | FeatureAction::AddCapability(_)
                    )
                })
                .collect::<Vec<_>>(),
        ),
        (
            "Desactivar / quitar",
            actions
                .iter()
                .filter(|action| {
                    matches!(
                        action,
                        FeatureAction::DisableFeature(_) | FeatureAction::RemoveCapability(_)
                    )
                })
                .collect::<Vec<_>>(),
        ),
    ] {
        writeln!(report, "\n{title} ({}):", matches.len()).unwrap();
        if matches.is_empty() {
            report.push_str("- Ninguna\n");
        } else {
            for action in matches {
                writeln!(report, "- {}", action_description(action)).unwrap();
            }
        }
    }

    writeln!(
        report,
        "\nAcciones pausadas tras fallo previo ({}):",
        suppressed_actions.len()
    )
    .unwrap();
    if suppressed_actions.is_empty() {
        report.push_str("- Ninguna\n");
    } else {
        for action in suppressed_actions {
            writeln!(report, "- {}", action_description(action)).unwrap();
        }
        report.push_str(
            "No se reintentan hasta que DISM informe un estado distinto para estos elementos o se reinicie el proceso.\n",
        );
    }

    report.push_str("\nEntradas de política no encontradas en el inventario DISM:\n");
    let mut missing = 0;
    for name in policy.optional_features.keys() {
        if find_state_case_insensitive(&snapshot.features, name).is_none() {
            writeln!(report, "- Característica: {name}").unwrap();
            missing += 1;
        }
    }
    for name in policy.capabilities.keys() {
        if find_capability_state(&snapshot.capabilities, name).is_none() {
            writeln!(report, "- Capacidad: {name}").unwrap();
            missing += 1;
        }
    }
    if missing == 0 {
        report.push_str("- Ninguna\n");
    }
}

fn append_policy_entries(report: &mut String, policy: &SystemFeaturesPolicy) {
    report.push_str("\nPolítica cargada (inventario actual desconocido):\n");
    for (name, desired) in &policy.optional_features {
        writeln!(report, "- Característica: {name} => {desired:?}").unwrap();
    }
    for (name, desired) in &policy.capabilities {
        writeln!(report, "- Capacidad: {name} => {desired:?}").unwrap();
    }
}

fn append_all_items(report: &mut String, snapshot: &SystemFeaturesSnapshot) {
    for (title, items) in [
        ("Características opcionales", &snapshot.features),
        ("Capacidades de Windows", &snapshot.capabilities),
    ] {
        writeln!(report, "\n{title} ({}):", items.len()).unwrap();
        if items.is_empty() {
            report.push_str("- Ninguna\n");
        } else {
            for (name, state) in items {
                writeln!(report, "- {name} [{state:?}]").unwrap();
            }
        }
    }
}

fn action_description(action: &FeatureAction) -> String {
    match action {
        FeatureAction::EnableFeature(name) => format!("Activar característica: {name}"),
        FeatureAction::DisableFeature(name) => format!("Desactivar característica: {name}"),
        FeatureAction::AddCapability(name) => format!("Instalar capacidad: {name}"),
        FeatureAction::RemoveCapability(name) => format!("Quitar capacidad: {name}"),
    }
}
