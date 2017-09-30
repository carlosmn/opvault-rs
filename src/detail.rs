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
#[serde(tag = "type")]
pub enum LoginField {
    T{value: String, name: String, designation: Option<String>},
    P{value: String, name: String, designation: Option<String>},
    I{value: String, name: String, designation: Option<String>},
    C{value: String, name: String, designation: Option<String>},
    B{value: String, name: String, designation: Option<String>},
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
    sections: Vec<Section>,
    notes_plain: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Section {
    name: String,
    title: String,
    fields: Vec<Field>,
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
    city: Option<String>,
    zip: Option<String>,
    state: Option<String>,
    country: Option<String>,
    street: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attributes {
    guarded: Option<String>,
    clipboard_filter: Option<String>,
    generate: Option<String>,
}

impl Generic {
    // Parse a login object from a JSON slice
    pub fn from_slice(s: &[u8]) -> json::Result<Self> {
        json::from_slice(s)
    }
}
