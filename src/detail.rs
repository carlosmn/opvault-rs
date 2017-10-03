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
#[serde(tag = "k")]
pub enum Field {
    String {n: String, v: Option<String>, t: String, a: Option<Attributes>},
    Gender {n: String, v: Option<String>, t: String, a: Option<Attributes>},
    Date {n: String, v: Option<i64>, t: String, a: Option<Attributes>},
    MonthYear {n: String, v: Option<i64>, t: String, a: Option<Attributes>},
    Menu {n: String, v: Option<String>, t: String, a: Option<Attributes>},
    Cctype {n: String, v: Option<String>, t: String, a: Option<Attributes>},
    Concealed {n: String, v: Option<String>, t: String, a: Option<Attributes>},
    Address {n: String, v: Address, t: String, a: Option<Attributes>},
    Email {n: String, v: Option<String>, t: String, a: Option<Attributes>},
    Phone {n: String, v: Option<String>, t: String, a: Option<Attributes>},
    #[serde(rename = "URL")]
    URL {n: String, v: Option<String>, t: String, a: Option<Attributes>},
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
