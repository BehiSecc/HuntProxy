//! Sitemap projection over saved project history.

use crate::domain::*;
use crate::storage::Db;
use rusqlite::params_from_iter;
use rusqlite::types::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct RouteAggregate {
    methods: BTreeSet<String>,
    statuses: BTreeSet<u16>,
    parameters: BTreeSet<String>,
    content_types: BTreeSet<String>,
    count: u64,
}

#[derive(Default)]
struct TreeBuilder {
    route: Option<SitemapRoute>,
    children: BTreeMap<String, TreeBuilder>,
}

impl Db {
    pub async fn list_sitemap(
        &self,
        project_id: ProjectId,
        host: Option<String>,
    ) -> DomainResult<Vec<SitemapHost>> {
        self.get_project(project_id).await?;
        let host = host
            .map(|value| value.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|value| !value.is_empty());
        self.with_conn(move |conn| {
            let mut binds = vec![Value::Integer(project_id.get())];
            let host_clause = if let Some(host) = host {
                binds.push(Value::Text(host));
                " AND lower(host)=?2"
            } else {
                ""
            };
            let sql = format!(
                "SELECT lower(host), path, method, status_code, mime, query FROM exchanges
                 WHERE project_id=?1{host_clause}
                 ORDER BY lower(host) COLLATE NOCASE, path COLLATE NOCASE, path, exchange_id"
            );
            let mut statement = conn.prepare(&sql).map_err(storage_error)?;
            let rows = statement
                .query_map(params_from_iter(binds.iter()), |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                    ))
                })
                .map_err(storage_error)?;
            let mut hosts = BTreeMap::<String, BTreeMap<String, RouteAggregate>>::new();
            for row in rows {
                let (host, path, method, status, mime, query) = row.map_err(storage_error)?;
                let route = hosts.entry(host).or_default().entry(path).or_default();
                route.count += 1;
                route.methods.insert(method.to_ascii_uppercase());
                if let Some(status) = status.and_then(|value| u16::try_from(value).ok()) {
                    route.statuses.insert(status);
                }
                if let Some(mime) = mime {
                    let content_type = mime
                        .split(';')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_ascii_lowercase();
                    if !content_type.is_empty() {
                        route.content_types.insert(content_type);
                    }
                }
                if let Some(query) = query {
                    for (name, _) in url::form_urlencoded::parse(query.as_bytes()) {
                        if !name.is_empty() {
                            route.parameters.insert(name.into_owned());
                        }
                    }
                }
            }
            Ok(hosts
                .into_iter()
                .map(|(host, aggregates)| {
                    let routes = aggregates
                        .into_iter()
                        .map(|(path, route)| SitemapRoute {
                            path,
                            methods: route.methods.into_iter().collect(),
                            status_codes: route.statuses.into_iter().collect(),
                            parameters: route.parameters.into_iter().collect(),
                            content_types: route.content_types.into_iter().collect(),
                            exchange_count: route.count,
                        })
                        .collect::<Vec<_>>();
                    let paths = routes.iter().map(|route| route.path.clone()).collect();
                    let tree = build_tree(&routes);
                    SitemapHost {
                        host,
                        paths,
                        routes,
                        tree,
                    }
                })
                .collect())
        })
        .await
    }
}

fn build_tree(routes: &[SitemapRoute]) -> Vec<SitemapNode> {
    let mut root = TreeBuilder::default();
    for route in routes {
        let mut node = &mut root;
        let segments = route
            .path
            .trim_start_matches('/')
            .split('/')
            .filter(|part| !part.is_empty());
        let mut saw_segment = false;
        for segment in segments {
            saw_segment = true;
            node = node.children.entry(segment.to_string()).or_default();
        }
        if !saw_segment {
            node = node.children.entry("/".to_string()).or_default();
        }
        node.route = Some(route.clone());
    }
    tree_nodes(root.children, "")
}

fn tree_nodes(children: BTreeMap<String, TreeBuilder>, parent: &str) -> Vec<SitemapNode> {
    children
        .into_iter()
        .map(|(segment, builder)| {
            let path = if segment == "/" {
                "/".to_string()
            } else if parent.is_empty() || parent == "/" {
                format!("/{segment}")
            } else {
                format!("{parent}/{segment}")
            };
            SitemapNode {
                segment,
                route: builder.route,
                children: tree_nodes(builder.children, &path),
                path,
            }
        })
        .collect()
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}
