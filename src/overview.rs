use serde_json as json;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    title: Option<String>,
    ainfo: Option<String>,
    #[serde(rename = "URLs", default)]
    urls: Vec<URL>,
    url: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
    ps: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct URL {
    u: String,
}

impl Overview {
    // Parse an overview object from a JSON slice
    pub fn from_slice(s: &[u8]) -> json::Result<Self> {
        json::from_slice(s)
    }
}
