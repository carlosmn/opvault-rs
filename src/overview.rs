use serde_json as json;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    pub title: Option<String>,
    pub ainfo: Option<String>,
    #[serde(rename = "URLs", default)]
    pub urls: Vec<URL>,
    pub url: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    pub ps: Option<i64>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct URL {
    pub u: String,
}

impl Overview {
    // Parse an overview object from a JSON slice
    pub fn from_slice(s: &[u8]) -> json::Result<Self> {
        json::from_slice(s)
    }
}
