use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Client {
    pub id: String,
    pub secret: String,
    pub allowed_scopes: Vec<String>,
    pub allowed_audiences: Vec<String>,
}

#[derive(Clone, Default)]
pub struct ClientStore {
    map: HashMap<String, Client>,
}

impl ClientStore {
    pub fn with_example() -> Self {
        let mut s = Self::default();
        s.map.insert("service-a".into(), Client {
            id: "service-a".into(),
            secret: "super-secret".into(),
            allowed_scopes: vec!["service.read".into()],
            allowed_audiences: vec!["service-b".into()],
        });
        s
    }
    pub fn get(&self, id: &str) -> Option<&Client> { self.map.get(id) }
}

#[derive(Clone, Debug)]
pub struct User {
    pub id: String,
    pub username: String,
    pub password: String,
    pub allowed_scopes: Vec<String>,
}

#[derive(Clone, Default)]
pub struct UserStore {
    map: HashMap<String, User>,
}

impl UserStore {
    pub fn with_example() -> Self {
        let mut s = Self::default();
        s.map.insert("alice".into(), User {
            id: "user-001".into(),
            username: "alice".into(),
            password: "hunter2".into(),
            allowed_scopes: vec!["profile".into(), "read".into()],
        });
        s
    }
    pub fn get(&self, username: &str) -> Option<&User> { self.map.get(username) }
}
