//! Credential selection checks use isolated stores and local/mock transports.
use huntproxy::domain::*;
use huntproxy::fuzzer::{FuzzTemplate, FuzzerService};
use huntproxy::reply::{PlaceholderKey, ReplyService};
use huntproxy::storage::Db;
use huntproxy::transport::{OutboundRequest, OutboundResponse, SemanticTransport};
use std::sync::{Arc, Mutex};
use std::time::Duration;

type RecordedRequest = (String, Vec<(String, Vec<u8>)>);

#[derive(Default)]
struct Recorder {
    requests: Mutex<Vec<RecordedRequest>>,
    hold_first: std::sync::atomic::AtomicBool,
    first_seen: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[async_trait::async_trait]
impl SemanticTransport for Recorder {
    async fn send(
        &self,
        _dial: &ValidatedDial,
        request: OutboundRequest,
    ) -> DomainResult<OutboundResponse> {
        let redirect = request.url.ends_with("/redirect");
        self.requests
            .lock()
            .unwrap()
            .push((request.url, request.headers));
        if self
            .hold_first
            .swap(false, std::sync::atomic::Ordering::SeqCst)
        {
            self.first_seen.notify_one();
            self.release.notified().await;
        }
        Ok(OutboundResponse {
            status: if redirect {
                http::StatusCode::FOUND
            } else {
                http::StatusCode::OK
            },
            headers: if redirect {
                vec![
                    ("Location".into(), b"http://127.0.0.2/destination".to_vec()),
                    ("Set-Cookie".into(), b"sid=response; Path=/".to_vec()),
                ]
            } else {
                vec![]
            },
            body: bytes::Bytes::new(),
            body_truncated: false,
            protocol: "HTTP/1.1".into(),
            transport_provenance: TransportProvenance::GenericUnprofiled,
            transport_profile: "identity_fixture".into(),
            duration: Duration::from_millis(1),
        })
    }
    fn profile_name(&self) -> &str {
        "identity_fixture"
    }
    fn provenance(&self) -> TransportProvenance {
        TransportProvenance::GenericUnprofiled
    }
}

struct Fixture {
    db: Arc<Db>,
    project: ProjectId,
    reply: Arc<ReplyService>,
    recorder: Arc<Recorder>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        // A file-backed fixture gives every pooled connection the same store
        // during concurrent Reply calls and asynchronous job execution.
        let directory = tempfile::tempdir().unwrap();
        let config = huntproxy::config::Config {
            data_dir: directory.path().to_path_buf(),
            spool_dir: directory.path().join("spool"),
            export_dir: directory.path().join("exports"),
            runtime_dir: directory.path().join("runtime"),
            plugin_dir: directory.path().join("plugins"),
            ..Default::default()
        };
        let db = Arc::new(Db::open(&config).await.unwrap());
        let project = db
            .create_project(CreateProjectRequest {
                name: "identity fixture".into(),
                target_url: "http://127.0.0.1".into(),
                advanced: None,
            })
            .await
            .unwrap()
            .id;
        let limits = ProjectLimits {
            max_concurrent_requests: 1,
            ..ProjectLimits::default()
        };
        db.update_project_scope(project, ScopePolicy::default(), Some(limits))
            .await
            .unwrap();
        db.upsert_cookie_profile(
            project,
            huntproxy::cookies::validate_cookie_profile("http://127.0.0.1", "sid=primary".into())
                .unwrap(),
        )
        .await
        .unwrap();
        db.upsert_named_cookie_profile(
            project,
            "secondary",
            huntproxy::cookies::validate_cookie_profile("http://127.0.0.1", "sid=secondary".into())
                .unwrap(),
        )
        .await
        .unwrap();
        let recorder = Arc::new(Recorder::default());
        let reply = Arc::new(ReplyService {
            db: db.clone(),
            transport: recorder.clone(),
            placeholder_key: PlaceholderKey::from_bytes(vec![9; 32]),
            upstream_proxies: Default::default(),
        });
        Self {
            db,
            project,
            reply,
            recorder,
            _directory: directory,
        }
    }

    async fn send(
        &self,
        draft: ReplyDraft,
        base: Option<ExchangeId>,
    ) -> DomainResult<huntproxy::reply::ReplySendResult> {
        self.reply
            .send(self.project, None, base, &draft, ProtocolPreference::H1, 0)
            .await
    }

    async fn rule(&self, header: &str, value: &str) {
        use huntproxy::request_rules::*;
        self.db
            .create_request_rule(
                self.project,
                RequestRuleInput {
                    name: format!("fixture {header}"),
                    enabled: true,
                    position: 0,
                    host_pattern: Some("127.0.0.1".into()),
                    target: RequestRuleTarget::Header,
                    operation: RequestRuleOperation::Set,
                    header_name: Some(header.into()),
                    match_kind: RequestRuleMatchKind::Literal,
                    pattern: String::new(),
                    replacement: Some(value.into()),
                    replace_all: true,
                },
            )
            .await
            .unwrap();
    }
}

fn draft(identity: Option<ReplyIdentity>) -> ReplyDraft {
    ReplyDraft {
        url: Some("http://127.0.0.1/".into()),
        identity,
        ..Default::default()
    }
}
fn named() -> Option<ReplyIdentity> {
    Some(ReplyIdentity::Named {
        profile: "secondary".into(),
    })
}
fn header<'a>(headers: &'a [(String, Vec<u8>)], name: &str) -> Option<&'a [u8]> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_slice())
}

#[test]
fn identity_contract_is_exclusive_and_omission_is_compatible() {
    for value in [
        serde_json::json!({"mode":"default"}),
        serde_json::json!({"mode":"anonymous"}),
        serde_json::json!({"mode":"named","profile":"secondary"}),
    ] {
        let parsed: ReplyIdentity = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), value);
    }
    for value in [
        serde_json::json!({"mode":"named"}),
        serde_json::json!({"mode":"anonymous","profile":"secondary"}),
        serde_json::json!({"mode":"default","profile":"secondary"}),
        serde_json::json!({"mode":"unknown"}),
    ] {
        assert!(serde_json::from_value::<ReplyIdentity>(value).is_err());
    }
    assert!(serde_json::from_value::<ReplyDraft>(serde_json::json!({}))
        .unwrap()
        .identity
        .is_none());
    assert!(serde_json::to_value(ReplyDraft::default())
        .unwrap()
        .get("identity")
        .is_none());
}

#[tokio::test]
async fn concurrent_requests_select_identity_without_mutating_default() {
    let f = Fixture::new().await;
    let (a, b, c) = tokio::join!(
        f.send(draft(Some(ReplyIdentity::Default {})), None),
        f.send(draft(named()), None),
        f.send(draft(Some(ReplyIdentity::Anonymous {})), None),
    );
    for result in [a, b, c] {
        assert!(result.unwrap().identity.is_some());
    }
    let omitted = f.send(draft(None), None).await.unwrap();
    assert!(serde_json::to_value(&omitted)
        .unwrap()
        .get("identity")
        .is_none());
    let requests = f.recorder.requests.lock().unwrap();
    let mut cookies = requests[..3]
        .iter()
        .map(|(_, h)| header(h, "Cookie").map(Vec::from))
        .collect::<Vec<_>>();
    cookies.sort();
    assert_eq!(
        cookies,
        vec![
            None,
            Some(b"sid=primary".to_vec()),
            Some(b"sid=secondary".to_vec())
        ]
    );
    assert_eq!(
        header(&requests[3].1, "Cookie"),
        Some(b"sid=primary".as_slice())
    );
}

#[tokio::test]
async fn named_removes_inherited_credentials_and_blocks_rule_credentials() {
    let f = Fixture::new().await;
    let base = f
        .send(
            ReplyDraft {
                header_overrides: vec![
                    HeaderPatch {
                        name: "Cookie".into(),
                        value: b"sid=captured".to_vec(),
                    },
                    HeaderPatch {
                        name: "Authorization".into(),
                        value: b"Bearer captured".to_vec(),
                    },
                    HeaderPatch {
                        name: "X-Api-Key".into(),
                        value: b"captured-key".to_vec(),
                    },
                ],
                ..draft(None)
            },
            None,
        )
        .await
        .unwrap()
        .exchange_id;
    f.rule("Cookie", "sid=rule").await;
    f.rule("Authorization", "Bearer rule").await;
    f.rule("X-Api-Key", "rule-key").await;
    f.send(draft(named()), base).await.unwrap();
    f.send(
        ReplyDraft {
            header_overrides: vec![HeaderPatch {
                name: "Authorization".into(),
                value: b"Bearer deliberate".to_vec(),
            }],
            ..draft(named())
        },
        base,
    )
    .await
    .unwrap();
    f.send(
        ReplyDraft {
            header_tombstones: vec!["Cookie".into()],
            ..draft(named())
        },
        base,
    )
    .await
    .unwrap();
    f.send(
        ReplyDraft {
            header_overrides: vec![HeaderPatch {
                name: "Authorization".into(),
                value: b"Bearer explicit".to_vec(),
            }],
            ..draft(Some(ReplyIdentity::Anonymous {}))
        },
        base,
    )
    .await
    .unwrap();
    let requests = f.recorder.requests.lock().unwrap();
    assert_eq!(
        header(&requests[1].1, "Cookie"),
        Some(b"sid=secondary".as_slice())
    );
    assert!(header(&requests[1].1, "Authorization").is_none());
    assert!(header(&requests[1].1, "X-Api-Key").is_none());
    assert_eq!(
        header(&requests[2].1, "Authorization"),
        Some(b"Bearer deliberate".as_slice())
    );
    assert_eq!(
        header(&requests[2].1, "Cookie"),
        Some(b"sid=secondary".as_slice())
    );
    for (_, headers) in &requests[3..] {
        assert!(header(headers, "Cookie").is_none());
        assert!(header(headers, "Authorization").is_none());
        assert!(header(headers, "X-Api-Key").is_none());
    }
}

#[tokio::test]
async fn invalid_named_selection_fails_before_traffic() {
    let f = Fixture::new().await;
    for profile in ["missing", "invalid/profile"] {
        assert!(f
            .send(
                draft(Some(ReplyIdentity::Named {
                    profile: profile.into()
                })),
                None
            )
            .await
            .is_err());
    }
    f.db.upsert_named_cookie_profile(
        f.project,
        "other",
        huntproxy::cookies::validate_cookie_profile("http://127.0.0.2", "sid=other".into())
            .unwrap(),
    )
    .await
    .unwrap();
    let e = f
        .send(
            draft(Some(ReplyIdentity::Named {
                profile: "other".into(),
            })),
            None,
        )
        .await
        .unwrap_err();
    assert!(e.to_string().contains("no applicable cookies"));
    assert!(f
        .send(
            ReplyDraft {
                header_overrides: vec![HeaderPatch {
                    name: "Cookie".into(),
                    value: b"sid=override".to_vec()
                }],
                ..draft(named())
            },
            None
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("Cookie override"));
    let mut expired = huntproxy::cookies::validate_cookie_profile("http://127.0.0.1",
        r#"[{"name":"sid","value":"expired","domain":"127.0.0.1","path":"/","expirationDate":4102444800}]"#.into()).unwrap();
    expired.managed_cookies.as_mut().unwrap()[0].expires = Some(1.0);
    f.db.upsert_named_cookie_profile(f.project, "expired", expired)
        .await
        .unwrap();
    assert!(f
        .send(
            draft(Some(ReplyIdentity::Named {
                profile: "expired".into()
            })),
            None
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("no applicable cookies"));
    assert!(f.recorder.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn identity_checks_effective_destination_after_url_rules() {
    use huntproxy::request_rules::*;
    let f = Fixture::new().await;
    f.db.create_request_rule(
        f.project,
        RequestRuleInput {
            name: "fixture destination".into(),
            enabled: true,
            position: 0,
            host_pattern: Some("127.0.0.1".into()),
            target: RequestRuleTarget::Url,
            operation: RequestRuleOperation::Replace,
            header_name: None,
            match_kind: RequestRuleMatchKind::Literal,
            pattern: "127.0.0.1".into(),
            replacement: Some("127.0.0.2".into()),
            replace_all: true,
        },
    )
    .await
    .unwrap();
    assert!(f
        .send(draft(named()), None)
        .await
        .unwrap_err()
        .to_string()
        .contains("no applicable cookies"));
    f.send(draft(Some(ReplyIdentity::Anonymous {})), None)
        .await
        .unwrap();
    {
        let requests = f.recorder.requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].0, "http://127.0.0.2/");
        assert!(header(&requests[0].1, "Cookie").is_none());
    }
    assert!(f
        .send(
            ReplyDraft {
                url: Some("http://fixture:password@127.0.0.1/".into()),
                ..draft(Some(ReplyIdentity::Anonymous {}))
            },
            None
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("URL credentials"));
    assert_eq!(f.recorder.requests.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn anonymous_does_not_dispatch_redirects_or_store_response_cookie() {
    let f = Fixture::new().await;
    let result = f
        .reply
        .send(
            f.project,
            None,
            None,
            &ReplyDraft {
                url: Some("http://127.0.0.1/redirect".into()),
                ..draft(Some(ReplyIdentity::Anonymous {}))
            },
            ProtocolPreference::H1,
            5,
        )
        .await
        .unwrap();
    assert_eq!(result.status_code, 302);
    assert_eq!(f.recorder.requests.lock().unwrap().len(), 1);
    assert!(header(&f.recorder.requests.lock().unwrap()[0].1, "Cookie").is_none());
    f.send(draft(None), None).await.unwrap();
    assert_eq!(
        header(&f.recorder.requests.lock().unwrap()[1].1, "Cookie"),
        Some(b"sid=primary".as_slice())
    );
}

#[tokio::test]
async fn real_semantic_transport_keeps_anonymous_redirect_request_credential_free() {
    use wiremock::{matchers::path, Mock, MockServer, ResponseTemplate};
    let server = MockServer::start().await;
    Mock::given(path("/baseline"))
        .respond_with(
            ResponseTemplate::new(200).insert_header("Set-Cookie", "sid=response; Path=/"),
        )
        .mount(&server)
        .await;
    Mock::given(path("/redirect"))
        .respond_with(
            ResponseTemplate::new(302)
                .insert_header("Location", format!("{}/destination", server.uri())),
        )
        .mount(&server)
        .await;
    let f = Fixture::new().await;
    let reply = ReplyService {
        db: f.db.clone(),
        transport: Arc::new(huntproxy::transport::WreqTransport::new()),
        placeholder_key: f.reply.placeholder_key.clone(),
        upstream_proxies: Default::default(),
    };
    reply
        .send(
            f.project,
            None,
            None,
            &ReplyDraft {
                url: Some(format!("{}/baseline", server.uri())),
                ..draft(None)
            },
            ProtocolPreference::H1,
            0,
        )
        .await
        .unwrap();
    let result = reply
        .send(
            f.project,
            None,
            None,
            &ReplyDraft {
                url: Some(format!("{}/redirect", server.uri())),
                ..draft(Some(ReplyIdentity::Anonymous {}))
            },
            ProtocolPreference::H1,
            5,
        )
        .await
        .unwrap();
    assert_eq!(result.status_code, 302);
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].headers.get("Cookie").unwrap(), "sid=primary");
    assert!(requests[1].headers.get("Cookie").is_none());
    assert!(requests[1].headers.get("Authorization").is_none());
}

#[tokio::test]
async fn fuzz_missing_named_identity_does_not_queue_job() {
    let f = Fixture::new().await;
    let fuzzer = FuzzerService::new(
        f.db.clone(),
        f.reply.clone(),
        f.reply.placeholder_key.clone(),
    );
    let template: FuzzTemplate = serde_json::from_value(serde_json::json!({
        "draft":{"url":"http://127.0.0.1/?view=§view§","identity":{"mode":"named","profile":"missing"}},
        "insertion_points":[{"name":"view","location":"url"}],
        "wordlists":[["summary"]]
    })).unwrap();
    assert!(fuzzer.start(f.project, template, false).await.is_err());
    assert!(fuzzer.list(f.project).await.unwrap().is_empty());
    assert!(f.recorder.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn fuzz_job_pins_named_cookie_and_preserves_case_provenance() {
    use std::sync::atomic::Ordering;
    let f = Fixture::new().await;
    f.recorder.hold_first.store(true, Ordering::SeqCst);
    let fuzzer = FuzzerService::new(
        f.db.clone(),
        f.reply.clone(),
        f.reply.placeholder_key.clone(),
    );
    let template: FuzzTemplate = serde_json::from_value(serde_json::json!({
        "draft":{"url":"http://127.0.0.1/?view=§view§","identity":{"mode":"named","profile":"secondary"}},
        "insertion_points":[{"name":"view","location":"url"}],
        "wordlists":[["summary","detail"]]
    })).unwrap();
    let job = fuzzer.start(f.project, template, false).await.unwrap();
    tokio::time::timeout(Duration::from_secs(5), f.recorder.first_seen.notified())
        .await
        .unwrap();
    assert_eq!(f.recorder.requests.lock().unwrap().len(), 1);
    f.db.upsert_named_cookie_profile(
        f.project,
        "secondary",
        huntproxy::cookies::validate_cookie_profile("http://127.0.0.1", "sid=replaced".into())
            .unwrap(),
    )
    .await
    .unwrap();
    f.recorder.release.notify_one();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let state = fuzzer.get(f.project, job.id).await.unwrap().state;
            if matches!(
                state,
                FuzzJobState::Completed | FuzzJobState::Failed | FuzzJobState::Interrupted
            ) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let job = fuzzer.get(f.project, job.id).await.unwrap();
    assert_eq!(job.state, FuzzJobState::Completed);
    let (cases, _) = fuzzer
        .list_cases(f.project, job.id, 10, None)
        .await
        .unwrap();
    assert_eq!(cases.len(), 2);
    for case in cases {
        let detail =
            f.db.get_exchange_detail(f.project, case.exchange_id.unwrap(), Default::default())
                .await
                .unwrap();
        assert_eq!(detail.summary.source, ExchangeSource::Fuzzer);
        assert_eq!(detail.lineage.fuzz_job_id, Some(job.id));
        assert_eq!(detail.lineage.fuzz_case_id, Some(case.id));
        let headers =
            f.db.load_raw_headers(f.project, case.exchange_id.unwrap(), MessageSide::Request)
                .await
                .unwrap();
        assert!(headers
            .iter()
            .any(|h| h.name.eq_ignore_ascii_case("Cookie") && h.value == b"sid=secondary"));
    }
    for (_, headers) in f.recorder.requests.lock().unwrap().iter() {
        assert_eq!(header(headers, "Cookie"), Some(b"sid=secondary".as_slice()));
    }
    let saved_template =
        f.db.load_fuzz_template_for_project(f.project, job.id)
            .await
            .unwrap();
    assert!(!saved_template.contains("sid="));
}
