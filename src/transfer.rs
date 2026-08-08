//! Versioned, bounded HuntProxy project bundles.

use crate::config::{create_private_dir, write_private_file, Config};
use crate::domain::*;
use crate::storage::{reconcile_project_usage_conn, Db};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

pub const BUNDLE_FORMAT: &str = "huntproxy-project";
pub const BUNDLE_VERSION: u32 = 2;
const MAX_BUNDLE_COMPRESSED: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_BUNDLE_UPLOAD_BYTES: u64 = MAX_BUNDLE_COMPRESSED;
const MAX_BUNDLE_EXPANDED: u64 = 8 * 1024 * 1024 * 1024;
const MAX_BUNDLE_ENTRIES: usize = 200_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretMode {
    Sanitized,
    Full,
}

#[derive(Debug, Clone)]
pub struct BundleExportOptions {
    pub secrets: SecretMode,
    pub include_chromium_profile: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleManifest {
    pub format: String,
    pub version: u32,
    pub archive_id: String,
    pub created_at: String,
    pub producer_version: String,
    pub source_schema: i32,
    pub secrets: String,
    pub chromium_profile: bool,
    pub database_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BundleImportResult {
    pub project: Project,
    pub secrets_included: bool,
    pub browser_state_imported: bool,
    pub chromium_profile_imported: bool,
}

impl Db {
    pub async fn export_bundle(
        &self,
        config: &Config,
        project_id: ProjectId,
        destination: PathBuf,
        options: BundleExportOptions,
    ) -> DomainResult<PathBuf> {
        self.get_project(project_id).await?;
        if options.include_chromium_profile && options.secrets != SecretMode::Full {
            return Err(DomainError::invalid(
                "Chromium profile export requires include_secrets",
            ));
        }
        let staging = private_staging(&config.runtime_dir, "bundle-export")?;
        let profiles_root = config.browser_profiles_dir();
        let snapshot = staging.join("project.sqlite3");
        self.backup_to(snapshot.clone()).await?;
        let schema = self.schema_version().await?;
        let secrets = options.secrets;
        tokio::task::spawn_blocking(move || {
            prune_snapshot(&snapshot, project_id, secrets)?;
            let database_sha256 = sha256_file(&snapshot)?;
            let manifest = BundleManifest {
                format: BUNDLE_FORMAT.into(),
                version: BUNDLE_VERSION,
                archive_id: uuid::Uuid::new_v4().to_string(),
                created_at: crate::storage::now_rfc3339(),
                producer_version: env!("CARGO_PKG_VERSION").into(),
                source_schema: schema,
                secrets: match secrets {
                    SecretMode::Sanitized => "sanitized",
                    SecretMode::Full => "full",
                }
                .into(),
                chromium_profile: options.include_chromium_profile,
                database_sha256,
            };
            write_private_file(
                &staging.join("manifest.json"),
                &serde_json::to_vec_pretty(&manifest).map_err(storage_error)?,
            )?;
            let source_profile = profiles_root
                .join("projects")
                .join(project_id.get().to_string());
            if secrets == SecretMode::Full {
                let state = source_profile.join("state.json");
                if state.is_file() {
                    let target = staging.join("browser/state.json");
                    if let Some(parent) = target.parent() {
                        create_private_dir(parent)?;
                    }
                    std::fs::copy(&state, &target)
                        .map_err(|error| storage_error(format!("copy browser state: {error}")))?;
                }
                if options.include_chromium_profile {
                    let chromium = source_profile.join("chromium");
                    if chromium.is_dir() {
                        copy_tree_safe(&chromium, &staging.join("browser/chromium"))?;
                    }
                }
            }
            if let Some(parent) = destination.parent() {
                create_private_dir(parent)?;
            }
            let output = std::fs::OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&destination)
                .map_err(|error| storage_error(format!("create bundle: {error}")))?;
            let encoder = zstd::Encoder::new(output, 3).map_err(storage_error)?;
            let mut tar = tar::Builder::new(encoder);
            tar.append_path_with_name(staging.join("manifest.json"), "manifest.json")
                .map_err(storage_error)?;
            tar.append_path_with_name(&snapshot, "project.sqlite3")
                .map_err(storage_error)?;
            let browser = staging.join("browser");
            if browser.is_dir() {
                tar.append_dir_all("browser", &browser)
                    .map_err(storage_error)?;
            }
            let encoder = tar.into_inner().map_err(storage_error)?;
            let mut output = encoder.finish().map_err(storage_error)?;
            output.flush().map_err(storage_error)?;
            secure_file(&destination)?;
            let _ = std::fs::remove_dir_all(&staging);
            Ok(destination)
        })
        .await
        .map_err(|error| storage_error(format!("bundle export task: {error}")))?
    }

    pub async fn import_bundle(
        &self,
        config: &Config,
        source: PathBuf,
        name_override: Option<String>,
    ) -> DomainResult<BundleImportResult> {
        let metadata = std::fs::metadata(&source)
            .map_err(|error| DomainError::invalid(format!("read bundle: {error}")))?;
        if metadata.len() > MAX_BUNDLE_COMPRESSED {
            return Err(DomainError::invalid(
                "bundle exceeds 4 GiB compressed limit",
            ));
        }
        let staging = private_staging(&config.runtime_dir, "bundle-import")?;
        let extracted = staging.clone();
        tokio::task::spawn_blocking(move || extract_bundle(&source, &extracted))
            .await
            .map_err(|error| storage_error(format!("bundle extraction task: {error}")))??;
        let manifest: BundleManifest = serde_json::from_slice(
            &std::fs::read(staging.join("manifest.json")).map_err(storage_error)?,
        )
        .map_err(|error| DomainError::invalid(format!("invalid bundle manifest: {error}")))?;
        if manifest.format != BUNDLE_FORMAT || manifest.version != BUNDLE_VERSION {
            return Err(DomainError::invalid("unsupported HuntProxy bundle"));
        }
        let current_schema = self.schema_version().await?;
        if manifest.source_schema != current_schema {
            return Err(DomainError::invalid(format!(
                "bundle schema {} is incompatible with local schema {current_schema}",
                manifest.source_schema
            )));
        }
        let archive_db = staging.join("project.sqlite3");
        if sha256_file(&archive_db)? != manifest.database_sha256 {
            return Err(DomainError::invalid("bundle database checksum mismatch"));
        }
        let archive_db_for_import = archive_db.clone();
        let name_override_for_import = name_override.clone();
        let project = self
            .with_conn(move |conn| {
                import_snapshot(conn, &archive_db_for_import, name_override_for_import)
            })
            .await?;
        let source_browser = staging.join("browser");
        let target_browser = config
            .browser_profiles_dir()
            .join("projects")
            .join(project.id.get().to_string());
        let browser_state_imported = source_browser.join("state.json").is_file();
        let chromium_profile_imported = source_browser.join("chromium").is_dir();
        if source_browser.is_dir() {
            if let Err(error) = copy_tree_safe(&source_browser, &target_browser) {
                let _ = self.delete_project(project.id).await;
                let _ = std::fs::remove_dir_all(&staging);
                return Err(error);
            }
        }
        let _ = std::fs::remove_dir_all(&staging);
        Ok(BundleImportResult {
            project,
            secrets_included: manifest.secrets == "full",
            browser_state_imported,
            chromium_profile_imported,
        })
    }
}

fn prune_snapshot(path: &Path, project_id: ProjectId, secrets: SecretMode) -> DomainResult<()> {
    let conn = rusqlite::Connection::open(path).map_err(storage_error)?;
    conn.pragma_update(None, "foreign_keys", true)
        .map_err(storage_error)?;
    let tx = conn.unchecked_transaction().map_err(storage_error)?;
    tx.execute(
        "DELETE FROM projects WHERE id<>?1",
        params![project_id.get()],
    )
    .map_err(storage_error)?;
    tx.execute(
        "DELETE FROM audit_events WHERE project_id IS NULL OR project_id<>?1",
        params![project_id.get()],
    )
    .map_err(storage_error)?;
    tx.execute(
        "DELETE FROM search_fts WHERE project_id<>?1",
        params![project_id.get()],
    )
    .map_err(storage_error)?;
    tx.execute("DELETE FROM bodies WHERE id NOT IN (SELECT request_body_id FROM exchanges WHERE request_body_id IS NOT NULL UNION SELECT response_body_id FROM exchanges WHERE response_body_id IS NOT NULL)", []).map_err(storage_error)?;
    if secrets == SecretMode::Sanitized {
        let names = crate::policy::SENSITIVE_HEADERS
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!("DELETE FROM message_headers WHERE lower(name) IN ({names})");
        tx.execute(
            &sql,
            rusqlite::params_from_iter(crate::policy::SENSITIVE_HEADERS.iter()),
        )
        .map_err(storage_error)?;
        tx.execute("DELETE FROM project_cookies", [])
            .map_err(storage_error)?;
        tx.execute("DELETE FROM capture_sessions", [])
            .map_err(storage_error)?;
        tx.execute("DELETE FROM reply_revisions", [])
            .map_err(storage_error)?;
        tx.execute("DELETE FROM reply_tabs", [])
            .map_err(storage_error)?;
        tx.execute("DELETE FROM reply_workspaces", [])
            .map_err(storage_error)?;
        tx.execute("DELETE FROM fuzz_cases", [])
            .map_err(storage_error)?;
        tx.execute("DELETE FROM fuzz_jobs", [])
            .map_err(storage_error)?;
        tx.execute("DELETE FROM websocket_messages", [])
            .map_err(storage_error)?;
        tx.execute("DELETE FROM websocket_connections", [])
            .map_err(storage_error)?;
        tx.execute("DELETE FROM exchange_request_rules", [])
            .map_err(storage_error)?;
        tx.execute("DELETE FROM request_rules", [])
            .map_err(storage_error)?;
        tx.execute(
            "UPDATE exchanges SET request_body_id=NULL,response_body_id=NULL,
             request_body_hash=NULL,response_body_hash=NULL,body_representation='unavailable'",
            [],
        )
        .map_err(storage_error)?;
        tx.execute("DELETE FROM bodies", [])
            .map_err(storage_error)?;
        tx.execute("UPDATE exchanges SET capture_session_id=NULL, reply_tab_id=NULL, fuzz_job_id=NULL, fuzz_case_id=NULL", []).map_err(storage_error)?;
    }
    tx.commit().map_err(storage_error)?;
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;")
        .map_err(storage_error)?;
    secure_file(path)
}

fn import_snapshot(
    conn: &rusqlite::Connection,
    archive: &Path,
    name_override: Option<String>,
) -> DomainResult<Project> {
    conn.execute(
        "ATTACH DATABASE ?1 AS hp_archive",
        params![archive.to_string_lossy()],
    )
    .map_err(storage_error)?;
    let result = (|| {
        let old_project: i64 = conn
            .query_row("SELECT id FROM hp_archive.projects LIMIT 1", [], |row| {
                row.get(0)
            })
            .map_err(storage_error)?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM hp_archive.projects", [], |row| {
                row.get(0)
            })
            .map_err(storage_error)?;
        if count != 1 {
            return Err(DomainError::invalid(
                "bundle must contain exactly one project",
            ));
        }
        let tx = conn.unchecked_transaction().map_err(storage_error)?;
        tx.execute(
            "INSERT INTO projects (name,target_url,created_at,updated_at,scope_json,limits_json,default_browser_profile,noise_policy)
             SELECT COALESCE(?1,name),target_url,created_at,updated_at,scope_json,limits_json,default_browser_profile,noise_policy FROM hp_archive.projects WHERE id=?2",
            params![name_override, old_project],
        ).map_err(storage_error)?;
        let new_project = tx.last_insert_rowid();
        let offsets = IdOffsets::load(&tx)?;
        let sql = import_sql(old_project, new_project, &offsets);
        tx.execute_batch(&sql).map_err(storage_error)?;
        materialize_reply_placeholders(&tx, old_project, new_project)?;
        reconcile_project_usage_conn(&tx, ProjectId(new_project))?;
        tx.commit().map_err(storage_error)?;
        let (name,target_url,created,updated,scope,limits,profile,noise): (String,String,String,String,String,String,String,String) = conn.query_row(
            "SELECT name,target_url,created_at,updated_at,scope_json,limits_json,default_browser_profile,noise_policy FROM projects WHERE id=?1",
            params![new_project], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?))
        ).map_err(storage_error)?;
        Ok(Project {
            id: ProjectId(new_project),
            name,
            target_url,
            created_at: crate::storage::parse_time(&created),
            updated_at: crate::storage::parse_time(&updated),
            scope: serde_json::from_str(&scope).unwrap_or_default(),
            limits: serde_json::from_str(&limits).unwrap_or_default(),
            default_browser_profile: profile,
            noise_policy: noise,
        })
    })();
    let _ = conn.execute_batch("DETACH DATABASE hp_archive");
    result
}

fn materialize_reply_placeholders(
    conn: &rusqlite::Connection,
    old_project: i64,
    new_project: i64,
) -> DomainResult<()> {
    let mut statement = conn
        .prepare("SELECT id,draft_json FROM reply_tabs WHERE project_id=?1")
        .map_err(storage_error)?;
    let rows = statement
        .query_map(params![new_project], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    drop(statement);
    for (tab_id, encoded) in rows {
        let mut draft: ReplyDraft = serde_json::from_str(&encoded)
            .map_err(|error| storage_error(format!("invalid archived Reply draft: {error}")))?;
        resolve_draft_placeholders(conn, old_project, &mut draft)?;
        conn.execute(
            "UPDATE reply_tabs SET draft_json=?1 WHERE id=?2",
            params![
                serde_json::to_string(&draft).map_err(storage_error)?,
                tab_id
            ],
        )
        .map_err(storage_error)?;
    }
    let mut statement = conn
        .prepare(
            "SELECT rr.id,rr.draft_json FROM reply_revisions rr
             JOIN reply_tabs rt ON rt.id=rr.tab_id WHERE rt.project_id=?1",
        )
        .map_err(storage_error)?;
    let rows = statement
        .query_map(params![new_project], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(storage_error)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(storage_error)?;
    drop(statement);
    for (revision_id, encoded) in rows {
        let mut draft: ReplyDraft = serde_json::from_str(&encoded)
            .map_err(|error| storage_error(format!("invalid archived Reply revision: {error}")))?;
        resolve_draft_placeholders(conn, old_project, &mut draft)?;
        conn.execute(
            "UPDATE reply_revisions SET draft_json=?1 WHERE id=?2",
            params![
                serde_json::to_string(&draft).map_err(storage_error)?,
                revision_id
            ],
        )
        .map_err(storage_error)?;
    }
    Ok(())
}

fn resolve_draft_placeholders(
    conn: &rusqlite::Connection,
    old_project: i64,
    draft: &mut ReplyDraft,
) -> DomainResult<()> {
    for override_header in &mut draft.header_overrides {
        let Ok(value) = std::str::from_utf8(&override_header.value) else {
            continue;
        };
        let Some(inner) = value
            .strip_prefix("{{bb:v1:")
            .and_then(|value| value.strip_suffix("}}"))
        else {
            continue;
        };
        let parts = inner.split(':').collect::<Vec<_>>();
        if parts.len() != 6 {
            return Err(DomainError::invalid("invalid archived Reply placeholder"));
        }
        let token_project = parts[1]
            .parse::<i64>()
            .map_err(|_| DomainError::invalid("invalid archived Reply placeholder project"))?;
        let exchange_id = parts[2]
            .parse::<i64>()
            .map_err(|_| DomainError::invalid("invalid archived Reply placeholder exchange"))?;
        if token_project != old_project || parts[3] != "request" {
            return Err(DomainError::invalid(
                "archived Reply placeholder references external evidence",
            ));
        }
        override_header.value = conn
            .query_row(
                "SELECT value FROM hp_archive.message_headers
                 WHERE project_id=?1 AND exchange_id=?2 AND side='request' AND lower(name)=lower(?3)
                 ORDER BY ordinal LIMIT 1",
                params![old_project, exchange_id, parts[4]],
                |row| row.get(0),
            )
            .map_err(|error| match error {
                rusqlite::Error::QueryReturnedNoRows => {
                    DomainError::invalid("archived Reply placeholder header is missing")
                }
                other => storage_error(other),
            })?;
    }
    Ok(())
}

struct IdOffsets {
    body: i64,
    capture: i64,
    label: i64,
    workspace: i64,
    tab: i64,
    revision: i64,
    job: i64,
    case_id: i64,
    browser: i64,
    action: i64,
    annotation: i64,
    finding: i64,
    audit: i64,
    websocket_connection: i64,
    websocket_message: i64,
    request_rule: i64,
}
impl IdOffsets {
    fn load(c: &rusqlite::Connection) -> DomainResult<Self> {
        fn max(c: &rusqlite::Connection, t: &str) -> DomainResult<i64> {
            c.query_row(&format!("SELECT COALESCE(MAX(id),0) FROM {t}"), [], |r| {
                r.get(0)
            })
            .map_err(storage_error)
        }
        Ok(Self {
            body: max(c, "bodies")?,
            capture: max(c, "capture_sessions")?,
            label: max(c, "labels")?,
            workspace: max(c, "reply_workspaces")?,
            tab: max(c, "reply_tabs")?,
            revision: max(c, "reply_revisions")?,
            job: max(c, "fuzz_jobs")?,
            case_id: max(c, "fuzz_cases")?,
            browser: max(c, "browser_sessions")?,
            action: max(c, "browser_actions")?,
            annotation: max(c, "annotations")?,
            finding: max(c, "findings")?,
            audit: max(c, "audit_events")?,
            websocket_connection: max(c, "websocket_connections")?,
            websocket_message: max(c, "websocket_messages")?,
            request_rule: max(c, "request_rules")?,
        })
    }
}

fn import_sql(old: i64, new: i64, o: &IdOffsets) -> String {
    format!(
        r#"
INSERT INTO bodies SELECT id+{body},sha256,original_length,stored_length,codec,mime_class,content FROM hp_archive.bodies;
INSERT INTO browser_sessions (id,project_id,engine,engine_policy,current_url,state,fallback_used,checkpoint_status,checkpoint_hash,checkpoint_version,created_at,updated_at,current_title)
 SELECT id+{browser},{new},'chromium','chromium',current_url,'interrupted',0,CASE WHEN checkpoint_status='fallback_chromium' THEN 'ok' ELSE checkpoint_status END,checkpoint_hash,checkpoint_version,created_at,updated_at,current_title FROM hp_archive.browser_sessions WHERE project_id={old};
INSERT INTO browser_actions SELECT id+{action},session_id+{browser},{new},action_type,CASE WHEN status IN ('running','queued') THEN 'failed' ELSE status END,error_code,created_at,finished_at FROM hp_archive.browser_actions WHERE project_id={old};
INSERT INTO capture_sessions SELECT id+{capture},{new},CASE WHEN browser_session_id IS NULL THEN NULL ELSE browser_session_id+{browser} END,CASE WHEN browser_action_id IS NULL THEN NULL ELSE browser_action_id+{action} END,created_at,expires_at,COALESCE(revoked_at,created_at),'revoked',is_browser_bound,randomblob(32),randomblob(16) FROM hp_archive.capture_sessions WHERE project_id={old};
INSERT INTO labels SELECT id+{label},{new},name FROM hp_archive.labels WHERE project_id={old};
INSERT INTO reply_workspaces SELECT id+{workspace},{new},name,created_at FROM hp_archive.reply_workspaces WHERE project_id={old};
INSERT INTO reply_tabs SELECT id+{tab},{new},CASE WHEN workspace_id IS NULL THEN NULL ELSE workspace_id+{workspace} END,name,base_exchange_id,revision,protocol,draft_json,created_at,updated_at FROM hp_archive.reply_tabs WHERE project_id={old};
INSERT INTO reply_revisions SELECT id+{revision},tab_id+{tab},revision,draft_json,created_at FROM hp_archive.reply_revisions WHERE tab_id IN (SELECT id FROM hp_archive.reply_tabs WHERE project_id={old});
INSERT INTO fuzz_jobs SELECT id+{job},{new},base_exchange_id,CASE WHEN state IN ('queued','running','cancelling') THEN 'interrupted' ELSE state END,strategy,template_json,estimated_cases,completed_cases,failed_cases,limits_json,created_at,updated_at,error FROM hp_archive.fuzz_jobs WHERE project_id={old};
INSERT INTO fuzz_cases SELECT id+{case_id},job_id+{job},case_index,exchange_id,status_code,error,body_hash,payload_summary,CASE WHEN state IN ('queued','running') THEN 'cancelled' ELSE state END,payloads_json,response_length,duration_ms,created_at,started_at,finished_at FROM hp_archive.fuzz_cases WHERE job_id IN (SELECT id FROM hp_archive.fuzz_jobs WHERE project_id={old});
INSERT INTO exchanges SELECT {new},exchange_id,source,started_at,duration_ms,protocol,method,scheme,authority,host,port,path,query,status_code,mime,request_length,response_length,completion,capture_quality,header_representation,body_representation,cache_provenance,transport_provenance,transport_profile,page_title,display_title,parent_exchange_id,redirect_parent_id,CASE WHEN reply_tab_id IS NULL THEN NULL ELSE reply_tab_id+{tab} END,CASE WHEN fuzz_job_id IS NULL THEN NULL ELSE fuzz_job_id+{job} END,CASE WHEN fuzz_case_id IS NULL THEN NULL ELSE fuzz_case_id+{case_id} END,CASE WHEN browser_session_id IS NULL THEN NULL ELSE browser_session_id+{browser} END,CASE WHEN browser_action_id IS NULL THEN NULL ELSE browser_action_id+{action} END,CASE WHEN capture_session_id IS NULL THEN NULL ELSE capture_session_id+{capture} END,CASE WHEN request_body_id IS NULL THEN NULL ELSE request_body_id+{body} END,CASE WHEN response_body_id IS NULL THEN NULL ELSE response_body_id+{body} END,request_body_hash,response_body_hash,error_message FROM hp_archive.exchanges WHERE project_id={old};
INSERT INTO message_headers SELECT {new},exchange_id,side,ordinal,name,value FROM hp_archive.message_headers WHERE project_id={old};
INSERT INTO annotations SELECT id+{annotation},{new},exchange_id,display_title,note,created_at,updated_at,revision FROM hp_archive.annotations WHERE project_id={old};
INSERT INTO exchange_labels SELECT {new},exchange_id,label_id+{label} FROM hp_archive.exchange_labels WHERE project_id={old};
INSERT INTO findings SELECT id+{finding},{new},exchange_id,title,description,created_at,updated_at FROM hp_archive.findings WHERE project_id={old};
INSERT INTO project_cookies SELECT {new},host,target_url,cookie_header,names_json,created_at,updated_at FROM hp_archive.project_cookies WHERE project_id={old};
INSERT INTO javascript_provenance SELECT {new},javascript_url,javascript_host,javascript_path,source_page_url,source_page_host,CASE WHEN browser_session_id IS NULL THEN NULL ELSE browser_session_id+{browser} END,discovery_kind,created_at FROM hp_archive.javascript_provenance WHERE project_id={old};
INSERT INTO audit_events SELECT id+{audit},{new},event_type,actor,target_type,target_id,metadata_json,created_at FROM hp_archive.audit_events WHERE project_id={old};
INSERT INTO websocket_connections SELECT id+{websocket_connection},{new},handshake_exchange_id,url,protocol,CASE WHEN state='open' THEN 'interrupted' ELSE state END,opened_at,COALESCE(closed_at,opened_at),message_count,client_bytes,server_bytes,last_error FROM hp_archive.websocket_connections WHERE project_id={old};
INSERT INTO websocket_messages SELECT id+{websocket_message},{new},connection_id+{websocket_connection},direction,opcode,payload,payload_length,truncated,created_at FROM hp_archive.websocket_messages WHERE project_id={old};
INSERT INTO request_rules SELECT id+{request_rule},{new},name,enabled,position,host_pattern,target,operation,header_name,match_kind,pattern,replacement,replace_all,revision,created_at,updated_at FROM hp_archive.request_rules WHERE project_id={old};
INSERT INTO exchange_request_rules SELECT {new},exchange_id,CASE WHEN rule_id IS NULL THEN NULL ELSE rule_id+{request_rule} END,rule_name FROM hp_archive.exchange_request_rules WHERE project_id={old};
INSERT INTO project_seq (project_id,next_exchange_id) SELECT {new},COALESCE(MAX(exchange_id),0)+1 FROM hp_archive.exchanges WHERE project_id={old};
INSERT INTO project_usage (project_id,updated_at) VALUES ({new},strftime('%Y-%m-%dT%H:%M:%fZ','now'));
INSERT INTO search_fts (project_id,exchange_id,title,preview,labels) SELECT {new},exchange_id,title,preview,labels FROM hp_archive.search_fts WHERE project_id={old};
"#,
        body = o.body,
        capture = o.capture,
        label = o.label,
        workspace = o.workspace,
        tab = o.tab,
        revision = o.revision,
        job = o.job,
        case_id = o.case_id,
        browser = o.browser,
        action = o.action,
        annotation = o.annotation,
        finding = o.finding,
        audit = o.audit,
        websocket_connection = o.websocket_connection,
        websocket_message = o.websocket_message,
        request_rule = o.request_rule,
        old = old,
        new = new
    )
}

fn extract_bundle(source: &Path, target: &Path) -> DomainResult<()> {
    let file = std::fs::File::open(source).map_err(storage_error)?;
    let decoder = zstd::Decoder::new(file).map_err(storage_error)?;
    let mut archive = tar::Archive::new(decoder);
    let mut total = 0_u64;
    let mut count = 0_usize;
    for entry in archive.entries().map_err(storage_error)? {
        let mut entry = entry.map_err(storage_error)?;
        count += 1;
        if count > MAX_BUNDLE_ENTRIES {
            return Err(DomainError::invalid("bundle has too many entries"));
        }
        let path = entry.path().map_err(storage_error)?.into_owned();
        validate_relative(&path)?;
        let kind = entry.header().entry_type();
        if !(kind.is_file() || kind.is_dir()) {
            return Err(DomainError::invalid(
                "bundle contains unsupported link or special entry",
            ));
        }
        total = total.saturating_add(entry.size());
        if total > MAX_BUNDLE_EXPANDED {
            return Err(DomainError::invalid("bundle exceeds expanded size limit"));
        }
        let output = target.join(&path);
        if kind.is_dir() {
            create_private_dir(&output)?;
        } else {
            if let Some(parent) = output.parent() {
                create_private_dir(parent)?;
            }
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&output)
                .map_err(storage_error)?;
            std::io::copy(&mut entry, &mut file).map_err(storage_error)?;
            secure_file(&output)?;
        }
    }
    if !target.join("manifest.json").is_file() || !target.join("project.sqlite3").is_file() {
        return Err(DomainError::invalid(
            "bundle is missing manifest or project database",
        ));
    }
    Ok(())
}

fn validate_relative(path: &Path) -> DomainResult<()> {
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        Err(DomainError::invalid("unsafe bundle path"))
    } else {
        Ok(())
    }
}
fn private_staging(root: &Path, prefix: &str) -> DomainResult<PathBuf> {
    create_private_dir(root)?;
    let path = root.join(format!(".{prefix}-{}", uuid::Uuid::new_v4()));
    create_private_dir(&path)?;
    Ok(path)
}
fn sha256_file(path: &Path) -> DomainResult<String> {
    let mut file = std::fs::File::open(path).map_err(storage_error)?;
    let mut hash = Sha256::new();
    let mut buf = [0_u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(storage_error)?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}
fn copy_tree_safe(source: &Path, target: &Path) -> DomainResult<()> {
    create_private_dir(target)?;
    for entry in std::fs::read_dir(source).map_err(storage_error)? {
        let entry = entry.map_err(storage_error)?;
        let metadata = entry.file_type().map_err(storage_error)?;
        if metadata.is_symlink() {
            continue;
        }
        let dst = target.join(entry.file_name());
        if metadata.is_dir() {
            copy_tree_safe(&entry.path(), &dst)?;
        } else if metadata.is_file() {
            std::fs::copy(entry.path(), &dst).map_err(storage_error)?;
            secure_file(&dst)?;
        }
    }
    Ok(())
}
#[cfg(unix)]
fn secure_file(path: &Path) -> DomainResult<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(storage_error)
}
#[cfg(not(unix))]
fn secure_file(_: &Path) -> DomainResult<()> {
    Ok(())
}
fn storage_error(error: impl std::fmt::Display) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::NewExchange;
    #[test]
    fn rejects_unsafe_paths() {
        assert!(validate_relative(Path::new("../secret")).is_err());
        assert!(validate_relative(Path::new("/absolute")).is_err());
        assert!(validate_relative(Path::new("safe/project.sqlite3")).is_ok());
    }

    fn test_config(root: &Path) -> Config {
        let mut config = Config::default();
        config.data_dir = root.join("data");
        config.spool_dir = config.data_dir.join("spool");
        config.export_dir = config.data_dir.join("exports");
        config.runtime_dir = config.data_dir.join("runtime");
        config.plugin_dir = config.data_dir.join("plugins");
        config.ensure_layout().unwrap();
        config
    }

    fn sample_exchange(project_id: ProjectId) -> NewExchange {
        NewExchange {
            project_id,
            source: ExchangeSource::Reply,
            protocol: "HTTP/1.1".into(),
            method: "POST".into(),
            scheme: "https".into(),
            authority: "example.test".into(),
            host: "example.test".into(),
            port: 443,
            path: "/api".into(),
            query: Some("a=1&a=2".into()),
            status_code: Some(200),
            mime: Some("application/octet-stream".into()),
            completion: CompletionState::Complete,
            capture_quality: CaptureQuality::Semantic,
            header_representation: HeaderRepresentation::Semantic,
            body_representation: BodyRepresentation::SemanticEncoded,
            cache_provenance: CacheProvenance::None,
            transport_provenance: Some(TransportProvenance::SemanticProxy),
            transport_profile: None,
            request_headers: vec![HeaderEntry {
                name: "Authorization".into(),
                value: b"Bearer secret".to_vec(),
                ordinal: 0,
            }],
            response_headers: vec![],
            request_body: Some(vec![0, 255]),
            response_body: Some(vec![1, 2, 3]),
            duration_ms: Some(5),
            lineage: ExchangeLineage::default(),
            page_title: None,
            error_message: None,
        }
    }

    #[tokio::test]
    async fn full_bundle_round_trip_preserves_evidence_and_browser_state() {
        let directory = tempfile::tempdir().unwrap();
        let config = test_config(directory.path());
        let db = Db::open(&config).await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "bundle".into(),
                target_url: "https://example.test/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        db.insert_exchange(sample_exchange(project.id))
            .await
            .unwrap();
        let profile = config
            .browser_profiles_dir()
            .join("projects")
            .join(project.id.get().to_string());
        create_private_dir(&profile).unwrap();
        write_private_file(&profile.join("state.json"), br#"{"cookies":[]}"#).unwrap();
        let bundle = directory.path().join("project.huntproxy");
        db.export_bundle(
            &config,
            project.id,
            bundle.clone(),
            BundleExportOptions {
                secrets: SecretMode::Full,
                include_chromium_profile: false,
            },
        )
        .await
        .unwrap();
        let imported = db
            .import_bundle(&config, bundle, Some("imported".into()))
            .await
            .unwrap();
        let headers = db
            .load_raw_headers(imported.project.id, ExchangeId(1), MessageSide::Request)
            .await
            .unwrap();
        assert_eq!(headers[0].value, b"Bearer secret");
        assert_eq!(
            db.load_raw_body(imported.project.id, ExchangeId(1), MessageSide::Response)
                .await
                .unwrap()
                .unwrap(),
            vec![1, 2, 3]
        );
        assert!(config
            .browser_profiles_dir()
            .join("projects")
            .join(imported.project.id.get().to_string())
            .join("state.json")
            .is_file());
    }

    #[tokio::test]
    async fn sanitized_bundle_reports_no_secrets_or_browser_state() {
        let directory = tempfile::tempdir().unwrap();
        let config = test_config(directory.path());
        let db = Db::open(&config).await.unwrap();
        let project = db
            .create_project(CreateProjectRequest {
                name: "safe".into(),
                target_url: "https://example.test/".into(),
                advanced: None,
            })
            .await
            .unwrap();
        db.insert_exchange(sample_exchange(project.id))
            .await
            .unwrap();
        let profile = config
            .browser_profiles_dir()
            .join("projects")
            .join(project.id.get().to_string());
        create_private_dir(&profile).unwrap();
        write_private_file(
            &profile.join("state.json"),
            br#"{"cookies":[{"value":"secret"}]}"#,
        )
        .unwrap();
        let bundle = directory.path().join("safe.huntproxy");
        db.export_bundle(
            &config,
            project.id,
            bundle.clone(),
            BundleExportOptions {
                secrets: SecretMode::Sanitized,
                include_chromium_profile: false,
            },
        )
        .await
        .unwrap();
        let imported = db.import_bundle(&config, bundle, None).await.unwrap();
        assert!(!imported.secrets_included);
        assert!(!imported.browser_state_imported);
        assert!(db
            .load_raw_headers(imported.project.id, ExchangeId(1), MessageSide::Request)
            .await
            .unwrap()
            .is_empty());
        assert!(db
            .load_raw_body(imported.project.id, ExchangeId(1), MessageSide::Request)
            .await
            .unwrap()
            .is_none());
    }
}
