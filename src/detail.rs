use serde_json as json;

#[derive(Debug)]
pub enum Detail {
    Login(Login),
    Generic(Generic),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Login {
    pub html_form: Option<HtmlForm>,
    #[serde(default)]
    pub fields: Vec<LoginField>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HtmlForm {
    pub html_id: Option<String>,
    pub html_name: Option<String>,
    pub html_method: String,
}

#[derive(Debug, Deserialize)]
pub enum LoginFieldKind {
    #[serde(rename = "T")]
    Text,
    #[serde(rename = "P")]
    Password,
    #[serde(rename = "I")]
    I,
    #[serde(rename = "C")]
    Checkbox,
    #[serde(rename = "B")]
    Button,
    #[serde(rename = "E")]
    Email,
    #[serde(rename = "S")]
    S,
}

#[derive(Debug, Deserialize)]
pub struct LoginField {
    #[serde(rename = "type")]
    pub kind: LoginFieldKind,
    pub name: String,
    pub value: String,
    pub designation: Option<String>,
}

impl Login {
    // Parse a login object from a JSON slice
    pub fn from_slice(s: &[u8]) -> json::Result<Self> {
        json::from_slice(s)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Generic {
    #[serde(default)]
    pub sections: Vec<Section>,
    pub notes_plain: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Section {
    pub name: String,
    pub title: String,
    pub fields: Vec<Field>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FieldKind {
    String,
    Gender,
    Date,
    MonthYear,
    Menu,
    Cctype,
    Concealed,
    Address,
    Email,
    Phone,
    #[serde(rename = "URL")]
    URL
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum FieldValue {
    String(String),
    Address(Address),
    I64(i64),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Field {
    #[serde(rename = "k")]
    pub kind: FieldKind,
    #[serde(rename = "n")]
    pub name: String,
    #[serde(rename = "v", default)]
    pub value: Option<FieldValue>,
    #[serde(rename = "a")]
    pub attr: Option<Attributes>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Address {
    pub city: Option<String>,
    pub zip: Option<String>,
    pub state: Option<String>,
    pub country: Option<String>,
    pub street: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attributes {
    pub guarded: Option<String>,
    pub clipboard_filter: Option<String>,
    pub generate: Option<String>,
}

impl Generic {
    // Parse a login object from a JSON slice
    pub fn from_slice(s: &[u8]) -> json::Result<Self> {
        json::from_slice(s)
    }
}
