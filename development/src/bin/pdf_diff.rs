use anyhow::{Context, Result};
use std::{
    collections::HashSet,
    env,
    fmt::Write as _,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::process::Command;
use tracing::{info, trace};
use tracing_subscriber::{Layer, layer::SubscriberExt, util::SubscriberInitExt};
use typst_webservice::PdfContext;

const MODEL_FILE_PREFIX: &str = "model-";
const MODEL_H_TEMPLATE_PREFIX: &str = "model-h";
const MODEL_H_INPUT_PREFIX: &str = "model-h-";
const FRY_TEMPLATE_SUFFIX: &str = "fry.typ";
const NL_TEMPLATE_SUFFIX: &str = "nl.typ";
const EXAMPLE_INPUTS_DIR: &str = "example-inputs";
const DEFAULT_EXAMPLE_INPUT_FILE: &str = "example-1.json";
const DIFF_PDF_BINARY: &str = "diff-pdf";
const TMP_DIR_NAME: &str = "tmp";
const MODELS_DIR_NAME: &str = "models";
const CURRENT_MODELS_DIR_NAME: &str = "current-models";
const MAIN_MODELS_DIR_NAME: &str = "main-models";
const DIFFS_DIR_NAME: &str = "diffs";
const CURRENT_PDFS_DIR_NAME: &str = "current-pdfs";
const MAIN_PDFS_DIR_NAME: &str = "main-pdfs";
const GIT_MAIN_BRANCH: &str = "main";
const PDF_FILE_EXTENSION: &str = "pdf";
const RESULTS_FILE_NAME: &str = "results.md";
const TABLE_TEMPLATE_HEADER: &str = "Template";
const TABLE_STATUS_HEADER: &str = "Status";
const TABLE_DIFF_HEADER: &str = "Diff";
const STATUS_ADDED: &str = "added";
const STATUS_DELETED: &str = "deleted";
const STATUS_CHANGED: &str = "changed";
const STATUS_IDENTICAL: &str = "identical";

/// Return whether a binary name resolves to an executable file somewhere on `PATH`.
fn binary_in_path(name: &str) -> bool {
    if let Ok(paths) = env::var("PATH") {
        for dir in env::split_paths(&paths) {
            let full = dir.join(name);
            if full.is_file() {
                return true;
            }
        }
    }
    false
}

/// Collect all model Typst files below `root`, returning paths relative to that root.
fn collect_typst_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        tracing::debug!("Scanning directory {}", dir.display());

        for entry in std::fs::read_dir(&dir)
            .with_context(|| format!("Failed to read directory {}", dir.display()))?
        {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().and_then(|ext| ext.to_str()) == Some("typ")
                && path
                    .file_name()
                    .map(|name| name.to_string_lossy().starts_with(MODEL_FILE_PREFIX))
                    == Some(true)
            {
                files.push(
                    path.strip_prefix(root)
                        .with_context(|| format!("Failed to strip prefix {}", root.display()))?
                        .to_path_buf(),
                );
            }
        }
    }

    Ok(files)
}

/// Render a template with the provided JSON input and write the resulting PDF to `output`.
async fn render_pdf(
    context: Arc<PdfContext>,
    template: String,
    input: serde_json::Value,
    file: &Path,
    output: &Path,
) -> Result<()> {
    trace!(
        template = template,
        file = %file.display(),
        output = %output.display(),
        "Rendering typst file"
    );
    let bytes = tokio::task::spawn_blocking(move || PdfContext::render(context, template, input))
        .await
        .context("Typst render task panicked")?
        .with_context(|| format!("Failed to render PDF for {}", file.display()))?;

    trace!(
        file = %file.display(),
        output = %output.display(),
        pdf_size_bytes = bytes.len(),
        "Rendered PDF"
    );

    if let Some(parent) = output.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("Failed to create {}", parent.display()))?;
    }

    tokio::fs::write(output, &bytes)
        .await
        .with_context(|| format!("Failed to write {}", output.display()))?;

    Ok(())
}

/// Extract the template file name from a relative model path.
fn template_name(file: &Path) -> Result<String> {
    file.file_name()
        .and_then(|name| name.to_str())
        .map(str::to_owned)
        .with_context(|| format!("Failed to determine template name for {}", file.display()))
}

/// Load the example JSON input associated with a model template from `example-inputs/`.
async fn load_render_input(root: &Path, template: &str) -> Result<serde_json::Value> {
    let template = template
        .replace(MODEL_H_TEMPLATE_PREFIX, MODEL_H_INPUT_PREFIX)
        .replace(FRY_TEMPLATE_SUFFIX, DEFAULT_EXAMPLE_INPUT_FILE)
        .replace(NL_TEMPLATE_SUFFIX, DEFAULT_EXAMPLE_INPUT_FILE);

    let path = root.join(EXAMPLE_INPUTS_DIR).join(template);

    let input = tokio::fs::read_to_string(&path)
        .await
        .with_context(|| format!("Failed to read {}", path.display()))?;

    serde_json::from_str(&input)
        .with_context(|| format!("Failed to parse JSON from {}", path.display()))
}

/// Run `diff-pdf` for two rendered PDFs and report whether their contents differ.
async fn diff_pdfs(current_pdf: &Path, main_pdf: &Path, diff_pdf: &Path) -> Result<bool> {
    let status = Command::new(DIFF_PDF_BINARY)
        .arg(format!("--output-diff={}", diff_pdf.display()))
        .arg("--skip-identical")
        .arg(main_pdf)
        .arg(current_pdf)
        .status()
        .await
        .context("Failed to run diff-pdf")?;

    match status.code() {
        Some(0) => Ok(false),
        Some(1) => Ok(true),
        Some(code) => anyhow::bail!("diff-pdf failed with exit code {code}"),
        None => anyhow::bail!("diff-pdf terminated by signal"),
    }
}

/// Compare PDFs rendered from the current and `main` model trees and summarize file changes.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::fmt::layer().with_filter(tracing_subscriber::filter::filter_fn(
                |metadata| metadata.target().starts_with(env!("CARGO_CRATE_NAME")),
            )),
        )
        .init();

    // Verify `diff-pdf` is installed and available in the PATH
    if !binary_in_path(DIFF_PDF_BINARY) {
        // `sudo apt-get install -y diff-pdf-wx` or `brew install diff-pdf`
        anyhow::bail!(
            "`diff-pdf` is not installed or not found in PATH. Please install it to use this tool."
        );
    }

    let project_dir = env::current_dir().context("Failed to get current directory")?;
    let tmp_dir = project_dir.join(TMP_DIR_NAME);
    tracing::info!("Current directory: {}", tmp_dir.display());

    let models_dir = project_dir.join(MODELS_DIR_NAME);
    let current_root = tmp_dir.join(CURRENT_MODELS_DIR_NAME);
    let main_root = tmp_dir.join(MAIN_MODELS_DIR_NAME);
    let diffs_root = tmp_dir.join(DIFFS_DIR_NAME);
    let current_pdfs_root = tmp_dir.join(CURRENT_PDFS_DIR_NAME);
    let main_pdfs_root = tmp_dir.join(MAIN_PDFS_DIR_NAME);

    // Clean the tmp directory if it exists
    if tmp_dir.exists() {
        Command::new("rm")
            .args(["-rf", tmp_dir.to_string_lossy().as_ref()])
            .output()
            .await
            .context("Failed to clean tmp directory")?;
    }

    // Create a tmp directory to hold the checked out models from the main branch
    Command::new("mkdir")
        .args(["-p", &main_root.to_string_lossy().as_ref()])
        .output()
        .await
        .context("Failed to create tmp directory")?;

    // Move `models/` to `tmp/current-models/`
    tokio::fs::rename(&models_dir, &current_root)
        .await
        .context("Failed to move models/ to tmp/current-models/")?;

    // Checkout `models/` from the main branch into `tmp/main-models/`
    Command::new("git")
        .args(["checkout", GIT_MAIN_BRANCH, MODELS_DIR_NAME])
        .output()
        .await
        .context("Failed to checkout models/ from main branch")?;

    // Move `models/` to `tmp/main-models/`
    tokio::fs::rename(&models_dir, &main_root)
        .await
        .context("Failed to move models/ to tmp/main-models/")?;

    // Restore the current `models/` from ``tmp/current-models/` to avoid any issues with the current working directory
    Command::new("cp")
        .arg("-r")
        .args([
            current_root.to_string_lossy().as_ref(),
            project_dir.to_string_lossy().as_ref(),
        ])
        .output()
        .await
        .context("Failed to restore models/ from tmp/current-models/")?;

    // Rename `current-models/` to `models/` to restore the current working directory
    tokio::fs::rename(&project_dir.join(CURRENT_MODELS_DIR_NAME), &models_dir)
        .await
        .context("Failed to rename tmp/current-models/ to models/")?;

    let current_files = collect_typst_files(&current_root)?;
    tracing::info!(
        "Found {} typst files in current branch",
        current_files.len()
    );

    let main_files = collect_typst_files(&main_root)?;
    tracing::info!("Found {} typst files in main branch", main_files.len());

    let current_set: HashSet<PathBuf> = current_files.into_iter().collect();
    let main_set: HashSet<PathBuf> = main_files.into_iter().collect();

    let mut new_files = Vec::new();
    let mut deleted_files = Vec::new();
    let mut common_files = Vec::new();

    for file in &current_set {
        if main_set.contains(file) {
            common_files.push(file.clone());
        } else {
            new_files.push(file.clone());
        }
    }

    for file in &main_set {
        if !current_set.contains(file) {
            deleted_files.push(file.clone());
        }
    }

    new_files.sort_unstable();
    deleted_files.sort_unstable();
    common_files.sort_unstable();

    // Log the new and deleted and common files
    if !new_files.is_empty() {
        info!("New files:");
        for file in &new_files {
            info!("  🟢 {}", file.display());
        }
    }

    if !deleted_files.is_empty() {
        info!("Deleted files:");
        for file in &deleted_files {
            info!("  🔴 {}", file.display());
        }
    }

    if !common_files.is_empty() {
        info!("Common files:");
        for file in &common_files {
            info!("  🔵 {}", file.display());
        }
    }

    tokio::fs::create_dir_all(&diffs_root)
        .await
        .context("Failed to create tmp/diffs")?;

    let current_context = Arc::new(
        PdfContext::from_directory(&current_root)
            .with_context(|| format!("Failed to load {}", current_root.display()))?,
    );
    let main_context = Arc::new(
        PdfContext::from_directory(&main_root)
            .with_context(|| format!("Failed to load {}", main_root.display()))?,
    );
    info!("Typst contexts loaded");

    let mut results = Vec::new();

    for rel in new_files {
        let template = template_name(&rel)?;
        let pdf_rel = rel.with_extension(PDF_FILE_EXTENSION);
        let added_pdf = diffs_root.join(&pdf_rel);

        let input = load_render_input(&current_root, &template).await?;
        render_pdf(
            Arc::clone(&current_context),
            template,
            input,
            &rel,
            &added_pdf,
        )
        .await?;

        results.push((
            rel,
            STATUS_ADDED,
            Some(Path::new(DIFFS_DIR_NAME).join(pdf_rel)),
        ));
    }

    for rel in deleted_files {
        results.push((rel, STATUS_DELETED, None));
    }

    for rel in common_files {
        let template = template_name(&rel)?;
        let pdf_rel = rel.with_extension(PDF_FILE_EXTENSION);
        let current_pdf = current_pdfs_root.join(&pdf_rel);
        let main_pdf = main_pdfs_root.join(&pdf_rel);
        let diff_pdf = diffs_root.join(&pdf_rel);

        let input = load_render_input(&current_root, &template).await?;
        render_pdf(
            Arc::clone(&current_context),
            template.clone(),
            input,
            &rel,
            &current_pdf,
        )
        .await?;

        let input = load_render_input(&main_root, &template).await?;
        render_pdf(Arc::clone(&main_context), template, input, &rel, &main_pdf).await?;

        let changed = diff_pdfs(&current_pdf, &main_pdf, &diff_pdf).await?;
        if !changed {
            let _ = tokio::fs::remove_file(&diff_pdf).await;
        }
        let status = if changed {
            STATUS_CHANGED
        } else {
            STATUS_IDENTICAL
        };
        let diff_link = changed.then(|| Path::new(DIFFS_DIR_NAME).join(&pdf_rel));
        results.push((rel, status, diff_link));
    }

    results.sort_unstable_by(|(left, _, _), (right, _, _)| left.cmp(right));

    let mut report = String::new();
    writeln!(
        report,
        "| {TABLE_TEMPLATE_HEADER} | {TABLE_STATUS_HEADER} | {TABLE_DIFF_HEADER} |"
    )?;
    writeln!(report, "| --- | --- | --- |")?;
    for (template, status, diff_link) in results {
        let diff_cell = diff_link
            .map(|path| format!("[pdf]({})", path.display()))
            .unwrap_or_default();
        writeln!(
            report,
            "| {} | {status} | {diff_cell} |",
            template.display()
        )?;
    }
    let results_path = tmp_dir.join(RESULTS_FILE_NAME);
    tokio::fs::write(&results_path, report)
        .await
        .with_context(|| format!("Failed to write {}", results_path.display()))?;
    info!("Wrote results to {}", results_path.display());

    Ok(())
}
