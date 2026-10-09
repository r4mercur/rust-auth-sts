use std::{collections::HashMap, path::Path, sync::Arc};
use anyhow::Context;
use serde::Deserialize;
use crate::crypto::password::{hash_secret, validate_hash};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Client {
    pub id: String,
    pub secret_hash: String,
    pub allowed_scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
}

#[derive(Clone)]
pub struct ClientStore {
    map: Arc<HashMap<String, Client>>,
    dummy_hash: Arc<String>,
}

impl ClientStore {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let clients: Vec<Client> = read_json(path)?;
        let mut map = HashMap::new();
        for c in clients {
            validate_hash(&c.secret_hash).with_context(|| format!("client {}", c.id))?;
            let id = c.id.clone();
            if map.insert(id.clone(), c).is_some() {
                anyhow::bail!("duplicate client id {id} in {}", path.display());
            }
        }
        Ok(Self { map: Arc::new(map), dummy_hash: Arc::new(dummy_hash()?) })
    }
    pub fn get(&self, id: &str) -> Option<&Client> { self.map.get(id) }
    pub fn dummy_hash(&self) -> &str { &self.dummy_hash }
    pub fn len(&self) -> usize { self.map.len() }
    pub fn is_empty(&self) -> bool { self.map.is_empty() }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password_hash: String,
    pub allowed_scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
}

#[derive(Clone)]
pub struct UserStore {
    map: Arc<HashMap<String, User>>,
    dummy_hash: Arc<String>,
}

impl UserStore {
    pub fn from_file(path: &Path) -> anyhow::Result<Self> {
        let users: Vec<User> = read_json(path)?;
        let mut map = HashMap::new();
        for u in users {
            validate_hash(&u.password_hash).with_context(|| format!("user {}", u.username))?;
            let username = u.username.clone();
            if map.insert(username.clone(), u).is_some() {
                anyhow::bail!("duplicate username {username} in {}", path.display());
            }
        }
        Ok(Self { map: Arc::new(map), dummy_hash: Arc::new(dummy_hash()?) })
    }
    pub fn get(&self, username: &str) -> Option<&User> { self.map.get(username) }
    pub fn dummy_hash(&self) -> &str { &self.dummy_hash }
    pub fn len(&self) -> usize { self.map.len() }
    pub fn is_empty(&self) -> bool { self.map.is_empty() }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

fn dummy_hash() -> anyhow::Result<String> {
    hash_secret(&uuid::Uuid::new_v4().to_string())
}
