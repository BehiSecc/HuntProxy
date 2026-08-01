//! Sitemap projection over saved project history.

use crate::domain::*;
use crate::storage::Db;
use rusqlite::params_from_iter;
use rusqlite::types::Value;

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
                "SELECT lower(host), path FROM exchanges
                 WHERE project_id=?1{host_clause}
                 GROUP BY lower(host), path
                 ORDER BY lower(host) COLLATE NOCASE, path COLLATE NOCASE, path"
            );
            let mut statement = conn.prepare(&sql).map_err(storage_error)?;
            let rows = statement
                .query_map(params_from_iter(binds.iter()), |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                })
                .map_err(storage_error)?;
            let mut output = Vec::<SitemapHost>::new();
            for row in rows {
                let (host, path) = row.map_err(storage_error)?;
                if output.last().is_none_or(|entry| entry.host != host) {
                    output.push(SitemapHost {
                        host,
                        paths: Vec::new(),
                    });
                }
                output
                    .last_mut()
                    .expect("sitemap host exists")
                    .paths
                    .push(path);
            }
            Ok(output)
        })
        .await
    }
}

fn storage_error(error: rusqlite::Error) -> DomainError {
    DomainError::new(ErrorCode::StorageError, error.to_string())
}
