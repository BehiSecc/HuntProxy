use huntproxy::config::{Config, DB_FILE_NAME};
use huntproxy::domain::*;
use huntproxy::storage::{Db, NewExchange};
use huntproxy::transfer::{BundleExportOptions, BundleManifest, SecretMode};
use rusqlite::{params, types::Value, Connection};
use sha2::{Digest, Sha256};
use std::path::Path;

fn test_config(root: &Path) -> Config {
    let data = root.join("data");
    let config = Config {
        data_dir: data.clone(),
        spool_dir: data.join("spool"),
        export_dir: data.join("exports"),
        runtime_dir: data.join("runtime"),
        plugin_dir: data.join("plugins"),
        ..Config::default()
    };
    config.ensure_layout().unwrap();
    config
}

fn exchange(project_id: ProjectId, marker: &str) -> NewExchange {
    NewExchange {
        project_id,
        source: ExchangeSource::Proxy,
        protocol: "HTTP/1.1".into(),
        method: "POST".into(),
        scheme: "https".into(),
        authority: "example.test".into(),
        host: "example.test".into(),
        port: 443,
        path: format!("/{marker}"),
        query: Some("a=1&a=2".into()),
        status_code: Some(200),
        mime: Some("text/plain".into()),
        completion: CompletionState::Complete,
        capture_quality: CaptureQuality::Semantic,
        header_representation: HeaderRepresentation::Semantic,
        body_representation: BodyRepresentation::SemanticEncoded,
        cache_provenance: CacheProvenance::None,
        transport_provenance: Some(TransportProvenance::SemanticProxy),
        transport_profile: None,
        request_headers: vec![
            HeaderEntry {
                name: "AUTHORIZATION".into(),
                value: format!("Bearer {marker}-authorization").into_bytes(),
                ordinal: 0,
            },
            HeaderEntry {
                name: "Accept".into(),
                value: b"text/plain".to_vec(),
                ordinal: 1,
            },
        ],
        response_headers: vec![HeaderEntry {
            name: "Set-Cookie".into(),
            value: format!("sid={marker}-cookie-secret").into_bytes(),
            ordinal: 0,
        }],
        // Bodies are globally deduplicated. Both projects reference this one.
        request_body: Some(b"shared request body".to_vec()),
        response_body: Some(format!("{marker}-response-body").into_bytes()),
        duration_ms: Some(4),
        lineage: ExchangeLineage::default(),
        page_title: None,
        error_message: None,
    }
}

async fn seed_project(db: &Db, config: &Config, marker: &str) -> ProjectId {
    let project = db
        .create_project(CreateProjectRequest {
            name: marker.into(),
            target_url: "https://example.test/".into(),
            advanced: None,
        })
        .await
        .unwrap();
    let exchange_id = db
        .insert_exchange(exchange(project.id, marker))
        .await
        .unwrap();
    db.upsert_annotation(
        project.id,
        exchange_id,
        AnnotationUpdate {
            display_title: Some(format!("{marker} title")),
            note: Some(format!("{marker} note")),
            labels: vec![format!("{marker}-label")],
            expected_revision: None,
        },
    )
    .await
    .unwrap();
    db.create_finding(
        project.id,
        exchange_id,
        format!("{marker} finding"),
        format!("{marker} description"),
    )
    .await
    .unwrap();

    // Populate parent and child tables so a scoped copy must follow indirect
    // relationships as well as the tables carrying project_id directly.
    let conn = Connection::open(config.data_dir.join(DB_FILE_NAME)).unwrap();
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    let pid = project.id.get();
    let eid = exchange_id.get();
    conn.execute_batch(&format!(
        r#"
        INSERT INTO browser_sessions (project_id,engine,engine_policy,state,created_at,updated_at,profile_name)
        VALUES ({pid},'chromium','chromium','starting','2024-01-01','2024-01-01','account');
        INSERT INTO browser_actions (session_id,project_id,action_type,status,created_at)
        VALUES ((SELECT id FROM browser_sessions WHERE project_id={pid}),{pid},'navigate','done','2024-01-01');
        INSERT INTO capture_sessions (project_id,browser_session_id,browser_action_id,created_at,status,is_browser_bound,token_hash,token_salt)
        VALUES ({pid},(SELECT id FROM browser_sessions WHERE project_id={pid}),(SELECT id FROM browser_actions WHERE project_id={pid}),
                '2024-01-01','active',1,CAST('{marker}-token' AS BLOB),CAST('salt' AS BLOB));
        INSERT INTO reply_workspaces (project_id,name,created_at) VALUES ({pid},'{marker} workspace','2024-01-01');
        INSERT INTO reply_tabs (project_id,workspace_id,name,base_exchange_id,draft_json,created_at,updated_at)
        VALUES ({pid},(SELECT id FROM reply_workspaces WHERE project_id={pid}),'{marker} tab',{eid},'{{}}','2024-01-01','2024-01-01');
        INSERT INTO reply_revisions (tab_id,revision,draft_json,created_at)
        VALUES ((SELECT id FROM reply_tabs WHERE project_id={pid}),1,'{{}}','2024-01-01');
        INSERT INTO fuzz_jobs (project_id,base_exchange_id,state,strategy,template_json,created_at,updated_at)
        VALUES ({pid},{eid},'queued','sniper','{{}}','2024-01-01','2024-01-01');
        INSERT INTO fuzz_cases (job_id,case_index,exchange_id,payload_summary)
        VALUES ((SELECT id FROM fuzz_jobs WHERE project_id={pid}),0,{eid},'{marker} case');
        INSERT INTO project_cookies (project_id,host,target_url,cookie_header,names_json,created_at,updated_at)
        VALUES ({pid},'example.test','https://example.test/','sid={marker}-cookie-secret','["sid"]','2024-01-01','2024-01-01');
        INSERT INTO named_cookie_profiles (project_id,name,target_url,cookie_header,names_json,created_at,updated_at)
        VALUES ({pid},'account','https://example.test/','sid={marker}-cookie-secret','["sid"]','2024-01-01','2024-01-01');
        INSERT INTO javascript_provenance (project_id,javascript_url,javascript_host,javascript_path,source_page_url,source_page_host,browser_session_id,discovery_kind,created_at)
        VALUES ({pid},'https://example.test/{marker}.js','example.test','/{marker}.js','https://example.test/','example.test',
                (SELECT id FROM browser_sessions WHERE project_id={pid}),'browser','2024-01-01');
        INSERT INTO audit_events (project_id,event_type,metadata_json,created_at)
        VALUES ({pid},'{marker}-event','{{}}','2024-01-01');
        INSERT INTO websocket_connections (project_id,handshake_exchange_id,url,opened_at)
        VALUES ({pid},{eid},'wss://example.test/{marker}','2024-01-01');
        INSERT INTO websocket_messages (project_id,connection_id,direction,opcode,payload,payload_length,created_at)
        VALUES ({pid},(SELECT id FROM websocket_connections WHERE project_id={pid}),'client','text',CAST('{marker}' AS BLOB),length('{marker}'),'2024-01-01');
        INSERT INTO request_rules (project_id,name,target,operation,match_kind,created_at,updated_at)
        VALUES ({pid},'{marker} rule','header','replace','literal','2024-01-01','2024-01-01');
        INSERT INTO exchange_request_rules (project_id,exchange_id,rule_id,rule_name)
        VALUES ({pid},{eid},(SELECT id FROM request_rules WHERE project_id={pid}),'{marker} rule');
        INSERT INTO ip_rotation_profiles (project_id,target_origin,stage_name,created_at,updated_at)
        VALUES ({pid},'https://example.test','{marker}','2024-01-01','2024-01-01');
        INSERT INTO ip_rotation_gateways (profile_id,region,rest_api_id,endpoint)
        VALUES ((SELECT id FROM ip_rotation_profiles WHERE project_id={pid}),'us-east-1','{marker}','https://example.test/{marker}');
        INSERT INTO search_fts (project_id,exchange_id,title,preview,labels)
        VALUES ({pid},{eid},'{marker} title','{marker} preview','{marker} label');
        UPDATE exchanges SET browser_session_id=(SELECT id FROM browser_sessions WHERE project_id={pid}),
            browser_action_id=(SELECT id FROM browser_actions WHERE project_id={pid}),
            capture_session_id=(SELECT id FROM capture_sessions WHERE project_id={pid}),
            reply_tab_id=(SELECT id FROM reply_tabs WHERE project_id={pid}),
            fuzz_job_id=(SELECT id FROM fuzz_jobs WHERE project_id={pid}),
            fuzz_case_id=(SELECT fc.id FROM fuzz_cases fc JOIN fuzz_jobs fj ON fj.id=fc.job_id WHERE fj.project_id={pid})
        WHERE project_id={pid} AND exchange_id={eid};
        "#
    ))
    .unwrap();
    drop(conn);

    let profile = config
        .browser_profiles_dir()
        .join("projects")
        .join(pid.to_string());
    std::fs::create_dir_all(profile.join("profiles/account")).unwrap();
    std::fs::create_dir_all(profile.join("chromium/default")).unwrap();
    std::fs::write(
        profile.join("state.json"),
        format!("{marker}-browser-state"),
    )
    .unwrap();
    std::fs::write(
        profile.join("profiles/account/state.json"),
        format!("{marker}-named-state"),
    )
    .unwrap();
    std::fs::write(
        profile.join("chromium/default/Preferences"),
        format!("{marker}-chromium"),
    )
    .unwrap();
    project.id
}

// The pre-scoped exporter backed up the database, then applied these filters.
// Keep a reference snapshot to detect changes in any table's exported rows.
fn legacy_prune(path: &Path, project_id: ProjectId, mode: SecretMode) {
    let conn = Connection::open(path).unwrap();
    conn.pragma_update(None, "foreign_keys", true).unwrap();
    conn.execute(
        "DELETE FROM projects WHERE id<>?1",
        params![project_id.get()],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM audit_events WHERE project_id IS NULL OR project_id<>?1",
        params![project_id.get()],
    )
    .unwrap();
    conn.execute(
        "DELETE FROM search_fts WHERE project_id<>?1",
        params![project_id.get()],
    )
    .unwrap();
    conn.execute("DELETE FROM bodies WHERE id NOT IN (SELECT request_body_id FROM exchanges WHERE request_body_id IS NOT NULL UNION SELECT response_body_id FROM exchanges WHERE response_body_id IS NOT NULL)", []).unwrap();
    if mode == SecretMode::Sanitized {
        let placeholders = huntproxy::policy::SENSITIVE_HEADERS
            .iter()
            .map(|_| "?")
            .collect::<Vec<_>>()
            .join(",");
        conn.execute(
            &format!("DELETE FROM message_headers WHERE lower(name) IN ({placeholders})"),
            rusqlite::params_from_iter(huntproxy::policy::SENSITIVE_HEADERS.iter()),
        )
        .unwrap();
        conn.execute_batch(
            "DELETE FROM project_cookies; DELETE FROM named_cookie_profiles; DELETE FROM ip_rotation_profiles;
             DELETE FROM capture_sessions; DELETE FROM reply_revisions; DELETE FROM reply_tabs;
             DELETE FROM reply_workspaces; DELETE FROM fuzz_cases; DELETE FROM fuzz_jobs;
             DELETE FROM websocket_messages; DELETE FROM websocket_connections;
             DELETE FROM exchange_request_rules; DELETE FROM request_rules;
             UPDATE exchanges SET request_body_id=NULL,response_body_id=NULL,request_body_hash=NULL,
                 response_body_hash=NULL,body_representation='unavailable';
             DELETE FROM bodies;
             UPDATE exchanges SET capture_session_id=NULL,reply_tab_id=NULL,fuzz_job_id=NULL,fuzz_case_id=NULL;",
        ).unwrap();
    }
    conn.execute_batch("VACUUM;").unwrap();
}

fn rows(conn: &Connection, table: &str) -> Vec<Vec<Value>> {
    let mut query = conn
        .prepare(&format!("SELECT * FROM \"{}\"", table.replace('"', "\"\"")))
        .unwrap();
    let count = query.column_count();
    let mut rows = query
        .query_map([], |row| (0..count).map(|i| row.get(i)).collect())
        .unwrap()
        .collect::<rusqlite::Result<Vec<Vec<Value>>>>()
        .unwrap();
    rows.sort_by_key(|row| format!("{row:?}"));
    rows
}

fn compare_snapshots(reference: &Path, actual: &Path) {
    let old = Connection::open(reference).unwrap();
    let new = Connection::open(actual).unwrap();
    let version = |conn: &Connection| {
        conn.pragma_query_value(None, "user_version", |r| r.get::<_, i32>(0))
            .unwrap()
    };
    assert_eq!(version(&old), version(&new));
    let tables = |conn: &Connection| {
        let mut stmt = conn.prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'search_fts_%' ORDER BY name").unwrap();
        let names = stmt
            .query_map([], |r| r.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        names
    };
    let names = tables(&old);
    assert_eq!(names, tables(&new));
    for table in names {
        assert_eq!(
            rows(&old, &table),
            rows(&new, &table),
            "snapshot table {table}"
        );
    }
    assert_eq!(rows(&old, "sqlite_sequence"), rows(&new, "sqlite_sequence"));
    let integrity: String = new
        .pragma_query_value(None, "integrity_check", |r| r.get(0))
        .unwrap();
    assert_eq!(integrity, "ok");
    assert!(!new
        .prepare("PRAGMA foreign_key_check")
        .unwrap()
        .exists([])
        .unwrap());
}

fn unpack(bundle: &Path, target: &Path) {
    std::fs::create_dir_all(target).unwrap();
    let decoder = zstd::Decoder::new(std::fs::File::open(bundle).unwrap()).unwrap();
    tar::Archive::new(decoder).unpack(target).unwrap();
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn scoped_exports_match_legacy_rows_isolate_projects_and_roundtrip() {
    std::fs::create_dir_all("/tmp/artis").unwrap();
    let directory = tempfile::Builder::new()
        .prefix("transfer-scoped-")
        .tempdir_in("/tmp/artis")
        .unwrap();
    let config = test_config(&directory.path().join("source"));
    let db = Db::open(&config).await.unwrap();
    let other = seed_project(&db, &config, "other-project-private").await;
    let selected = seed_project(&db, &config, "selected").await;
    db.store_body(b"unreferenced-private-body".to_vec(), None)
        .await
        .unwrap();
    db.audit(
        None,
        "global-private-event",
        None,
        None,
        None,
        serde_json::json!({}),
    )
    .await
    .unwrap();

    for (label, mode) in [
        ("full", SecretMode::Full),
        ("sanitized", SecretMode::Sanitized),
    ] {
        let reference = directory.path().join(format!("{label}-legacy.sqlite3"));
        db.backup_to(reference.clone()).await.unwrap();
        legacy_prune(&reference, selected, mode);
        let bundle = directory.path().join(format!("{label}.huntproxy"));
        db.export_bundle(
            &config,
            selected,
            bundle.clone(),
            BundleExportOptions {
                secrets: mode,
                include_chromium_profile: mode == SecretMode::Full,
            },
        )
        .await
        .unwrap();
        let unpacked = directory.path().join(format!("{label}-unpacked"));
        unpack(&bundle, &unpacked);
        let archive_db = unpacked.join("project.sqlite3");
        compare_snapshots(&reference, &archive_db);
        let archive_bytes = std::fs::read(&archive_db).unwrap();
        for secret in [
            b"other-project-private".as_slice(),
            b"unreferenced-private-body",
            b"global-private-event",
        ] {
            assert!(
                !contains_bytes(&archive_bytes, secret),
                "unrelated data appeared in the {label} archive"
            );
        }
        let manifest: BundleManifest =
            serde_json::from_slice(&std::fs::read(unpacked.join("manifest.json")).unwrap())
                .unwrap();
        assert_eq!(manifest.secrets, label);
        assert_eq!(manifest.chromium_profile, mode == SecretMode::Full);
        assert_eq!(
            manifest.database_sha256,
            hex::encode(Sha256::digest(&archive_bytes))
        );
        if mode == SecretMode::Sanitized {
            assert!(!unpacked.join("browser").exists());
            for secret in [
                b"selected-authorization".as_slice(),
                b"selected-cookie-secret",
                b"selected-response-body",
                b"shared request body",
            ] {
                assert!(
                    !contains_bytes(&archive_bytes, secret),
                    "sensitive data appeared in sanitized archive"
                );
            }
        } else {
            assert_eq!(
                std::fs::read(unpacked.join("browser/state.json")).unwrap(),
                b"selected-browser-state"
            );
            assert_eq!(
                std::fs::read(unpacked.join("browser/profiles/account/state.json")).unwrap(),
                b"selected-named-state"
            );
            assert_eq!(
                std::fs::read(unpacked.join("browser/chromium/default/Preferences")).unwrap(),
                b"selected-chromium"
            );
        }

        let dest_config = test_config(&directory.path().join(format!("destination-{label}")));
        let dest = Db::open(&dest_config).await.unwrap();
        let existing = seed_project(&dest, &dest_config, "destination").await;
        let imported = dest
            .import_bundle(&dest_config, bundle, Some(format!("imported-{label}")))
            .await
            .unwrap();
        assert_eq!(imported.secrets_included, mode == SecretMode::Full);
        assert_eq!(imported.browser_state_imported, mode == SecretMode::Full);
        assert_eq!(imported.chromium_profile_imported, mode == SecretMode::Full);
        assert_eq!(
            dest.get_annotation(imported.project.id, ExchangeId(1))
                .await
                .unwrap()
                .unwrap()
                .labels,
            vec!["selected-label"]
        );
        assert_eq!(
            dest.list_findings(imported.project.id).await.unwrap()[0].title,
            "selected finding"
        );
        let headers = dest
            .load_raw_headers(imported.project.id, ExchangeId(1), MessageSide::Request)
            .await
            .unwrap();
        assert_eq!(headers.len(), if mode == SecretMode::Full { 2 } else { 1 });
        assert_eq!(headers.last().unwrap().value, b"text/plain");
        let request = dest
            .load_raw_body(imported.project.id, ExchangeId(1), MessageSide::Request)
            .await
            .unwrap();
        let response = dest
            .load_raw_body(imported.project.id, ExchangeId(1), MessageSide::Response)
            .await
            .unwrap();
        assert_eq!(
            request,
            (mode == SecretMode::Full).then(|| b"shared request body".to_vec())
        );
        assert_eq!(
            response,
            (mode == SecretMode::Full).then(|| b"selected-response-body".to_vec())
        );
        let cookie = dest
            .get_named_cookie_profile(imported.project.id, "account")
            .await
            .unwrap();
        assert_eq!(
            cookie.map(|profile| profile.cookie_header),
            (mode == SecretMode::Full).then(|| "sid=selected-cookie-secret".to_string())
        );
        assert_eq!(
            dest.list_ip_rotation_profiles(imported.project.id)
                .await
                .unwrap()
                .len(),
            usize::from(mode == SecretMode::Full)
        );
        assert_eq!(
            dest.list_findings(existing).await.unwrap()[0].title,
            "destination finding"
        );
        assert_eq!(
            dest.insert_exchange(exchange(imported.project.id, "next"))
                .await
                .unwrap(),
            ExchangeId(2)
        );
    }
    assert_eq!(
        db.get_project(other).await.unwrap().name,
        "other-project-private"
    );
    assert_eq!(
        db.load_raw_body(selected, ExchangeId(1), MessageSide::Response)
            .await
            .unwrap()
            .unwrap(),
        b"selected-response-body"
    );
}
