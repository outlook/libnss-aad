
extern crate hyper;
extern crate hyper_native_tls;
extern crate serde_json;
extern crate url;

use AadConfig;
use UserInfo;

use error::{UserInfoResult, UserInfoRetrievalError};
use self::hyper::header::{Authorization, Bearer, Headers};
use self::hyper::net::HttpsConnector;
use self::hyper_native_tls::NativeTlsClient;
use self::serde_json::Value;
use self::url::form_urlencoded;
use std::io::Read;

type Query<'a> = Vec<(&'a str, &'a str)>;

fn get_ssl_client() -> hyper::Client {
    let ssl = NativeTlsClient::new().unwrap();
    let connector = HttpsConnector::new(ssl);
    hyper::Client::with_connector(connector)
}

fn post_query(url: &str, query: &Query) -> UserInfoResult<String> {
    let client = get_ssl_client();
    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(query.iter())
        .finish();
    let mut response = client.post(url).body(&body[..]).send()?;
    if response.status != hyper::status::StatusCode::Ok {
        return Err(UserInfoRetrievalError::BadHTTPResponse{ status: response.status });
    }
    let mut buf = String::new();
    response.read_to_string(&mut buf)?;
    Ok(buf)
}

fn get_content(content_url: &str, headers: Option<Headers>) -> UserInfoResult<String> {
    let client = get_ssl_client();
    let request = if let Some(h) = headers {
        client.get(content_url).headers(h)
    } else {
        client.get(content_url)
    };
    let mut response = request.send()?;
    if response.status != hyper::status::StatusCode::Ok {
        return Err(UserInfoRetrievalError::BadHTTPResponse{ status: response.status });
    }
    let mut buf = String::new();
    response.read_to_string(&mut buf)?;
    Ok(buf)
}

fn extract_token(json: &str) -> UserInfoResult<String> {
    Ok(
        serde_json::from_str::<Value>(json)?["access_token"]
        .as_str()
        .ok_or(UserInfoRetrievalError::NoAccessToken{response: json.to_string()})?
        .to_string()
        )
}


fn extract_user_info(json: &str) -> UserInfoResult<UserInfo> {
    let userinfo = serde_json::from_str::<Value>(json)?;
    let user_principal_name = userinfo["userPrincipalName"]
        .as_str()
        .ok_or(UserInfoRetrievalError::BadJSONResponse)?
        .to_string();
    let user_display_name = userinfo["displayName"]
        .as_str()
        .ok_or(UserInfoRetrievalError::BadJSONResponse)?
        .to_string();
    let user_id = userinfo["immutableId"]
        .as_str()
        .ok_or(UserInfoRetrievalError::BadJSONResponse)?
        .to_string()
        .parse::<u32>()?;
    if user_id == 0 {
        return Err(UserInfoRetrievalError::UnusableImmutableID);
    }
    Ok(UserInfo {
        username: user_principal_name,
        fullname: user_display_name,
        userid: user_id
    })
}


pub fn get_user_info(config: &AadConfig, username: &str) -> UserInfoResult<UserInfo> {

    let auth_url = format!("https://login.microsoftonline.com/{}/oauth2/token?api-version=1.0",
                           config.tenant);
    let auth_params = vec![
        ("resource", "https://graph.windows.net/"),
        ("grant_type", "client_credentials"),
        ("client_id", &config.client_id),
        ("client_secret", &config.client_secret)];
    let token_json = post_query(&auth_url, &auth_params)?;

    let token = extract_token(&token_json)?;

    let mut auth_header = Headers::new();
    auth_header.set(Authorization(Bearer { token: token }));
    let info_json = get_content(
        &format!("https://graph.windows.net/{}/users/{}?api-version=1.6", config.tenant, username),
        Some(auth_header)
        )?;
    extract_user_info(&info_json)
}
