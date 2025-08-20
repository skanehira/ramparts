use crate::types::MCPTool;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::fs;
use tracing::{debug, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSnapshot {
    pub url: String,
    pub tools: Vec<MCPTool>,
    pub timestamp: DateTime<Utc>,
    pub version_hash: String,
    pub tool_count: usize,
    pub server_info: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolHistory {
    pub url: String,
    pub snapshots: Vec<ToolSnapshot>,
    pub last_updated: DateTime<Utc>,
    pub total_versions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChangeDetectionConfig {
    pub enabled: bool,
    pub compare_schemas: bool,
    pub compare_descriptions: bool,
    pub ignore_fields: Vec<String>,
    pub sensitivity: String, // "strict", "moderate", "loose"
}

impl Default for ChangeDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            compare_schemas: true,
            compare_descriptions: true,
            ignore_fields: vec!["timestamp".to_string(), "raw_json".to_string()],
            sensitivity: "moderate".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ChangeSummary {
    pub tools_added: Vec<String>,
    pub tools_removed: Vec<String>,
    pub tools_modified: Vec<ToolChange>,
    pub total_changes: usize,
    pub change_types: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolChange {
    pub tool_name: String,
    pub change_type: String,
    pub old_value: Option<serde_json::Value>,
    pub new_value: Option<serde_json::Value>,
    pub diff: Option<String>,
}

pub struct ToolStorage {
    storage_dir: PathBuf,
}

impl ToolStorage {
    pub fn new(storage_dir: impl AsRef<Path>) -> Result<Self> {
        let storage_dir = storage_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&storage_dir)?;
        Ok(Self { storage_dir })
    }

    /// Store current tool definitions as a new snapshot
    pub async fn store_snapshot(&self, url: &str, tools: Vec<MCPTool>) -> Result<ToolSnapshot> {
        let snapshot = ToolSnapshot {
            url: url.to_string(),
            tools: tools.clone(),
            timestamp: Utc::now(),
            version_hash: self.calculate_tools_hash(&tools),
            tool_count: tools.len(),
            server_info: None,
        };

        // Load existing history or create new
        let mut history = self
            .load_history(url)
            .await
            .unwrap_or_else(|_| ToolHistory {
                url: url.to_string(),
                snapshots: Vec::new(),
                last_updated: Utc::now(),
                total_versions: 0,
            });

        // Check if this is actually a new version
        if let Some(last_snapshot) = history.snapshots.last() {
            if last_snapshot.version_hash == snapshot.version_hash {
                debug!("No changes detected for {}, reusing existing snapshot", url);
                return Ok(last_snapshot.clone());
            }
        }

        // Add new snapshot
        history.snapshots.push(snapshot.clone());
        history.last_updated = Utc::now();
        history.total_versions += 1;

        // Keep only last 10 versions to prevent unlimited growth
        if history.snapshots.len() > 10 {
            history.snapshots.remove(0);
        }

        // Save updated history
        if let Err(e) = self.save_history(&history).await {
            warn!("Failed to save tool history for {}: {}", url, e);
        } else {
            debug!("Stored new snapshot for {} with {} tools", url, tools.len());
        }

        Ok(snapshot)
    }

    /// Get the latest tool snapshot for a URL
    pub async fn get_latest_snapshot(&self, url: &str) -> Result<Option<ToolSnapshot>> {
        match self.load_history(url).await {
            Ok(history) => Ok(history.snapshots.last().cloned()),
            Err(_) => Ok(None),
        }
    }

    /// Get the previous tool snapshot for comparison
    #[allow(dead_code)] // Future feature - will be used when scheduler is re-enabled
    pub async fn get_previous_snapshot(&self, url: &str) -> Result<Option<ToolSnapshot>> {
        match self.load_history(url).await {
            Ok(history) => {
                if history.snapshots.len() >= 2 {
                    Ok(history.snapshots.get(history.snapshots.len() - 2).cloned())
                } else {
                    Ok(None)
                }
            }
            Err(_) => Ok(None),
        }
    }

    /// Check if tools have changed since last snapshot
    #[allow(dead_code)] // Future feature - will be used when scheduler is re-enabled
    pub async fn has_changed(&self, url: &str, tools: &[MCPTool]) -> Result<bool> {
        let current_hash = self.calculate_tools_hash(tools);

        if let Ok(Some(latest)) = self.get_latest_snapshot(url).await {
            Ok(latest.version_hash != current_hash)
        } else {
            // No previous snapshot, consider it changed
            Ok(true)
        }
    }

    /// Calculate hash of tool definitions for change detection
    fn calculate_tools_hash(&self, tools: &[MCPTool]) -> String {
        use sha2::{Digest, Sha256};

        // Create a normalized representation for hashing
        let mut normalized = tools
            .iter()
            .map(|tool| {
                format!(
                    "{}:{}:{:?}:{:?}",
                    tool.name,
                    tool.description.as_deref().unwrap_or(""),
                    tool.input_schema,
                    tool.output_schema
                )
            })
            .collect::<Vec<_>>();

        normalized.sort(); // Ensure consistent ordering
        let combined = normalized.join("|");

        let mut hasher = Sha256::new();
        hasher.update(combined.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Load tool history from disk
    async fn load_history(&self, url: &str) -> Result<ToolHistory> {
        let file_path = self.get_history_file_path(url);
        let content = fs::read_to_string(&file_path).await?;
        let history: ToolHistory = serde_json::from_str(&content)?;
        Ok(history)
    }

    /// Save tool history to disk
    async fn save_history(&self, history: &ToolHistory) -> Result<()> {
        let file_path = self.get_history_file_path(&history.url);
        let content = serde_json::to_string_pretty(history)?;
        fs::write(&file_path, content).await?;
        Ok(())
    }

    /// Get file path for storing tool history
    fn get_history_file_path(&self, url: &str) -> PathBuf {
        // Create a safe filename from URL
        let safe_name = url
            .replace("://", "_")
            .replace("/", "_")
            .replace(":", "_")
            .replace("?", "_")
            .replace("&", "_");

        self.storage_dir.join(format!("{safe_name}.json"))
    }
}
