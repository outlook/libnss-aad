
extern crate hyper;
extern crate hyper_native_tls;
extern crate serde_json;
extern crate url;

use AadConfig;
use UserInfo;
use GroupInfo;

use error::{GraphInfoResult, GraphInfoRetrievalError};
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

/// Issue an HTTPS POST request, and return the response body text
fn post_query(url: &str, query: &Query) -> GraphInfoResult<String> {
    let client = get_ssl_client();
    let body = form_urlencoded::Serializer::new(String::new())
        .extend_pairs(query.iter())
        .finish();
    let mut response = client.post(url).body(&body[..]).send()?;
    let mut buf = String::new();
    response.read_to_string(&mut buf)?;
    if response.status != hyper::status::StatusCode::Ok {
        return Err(GraphInfoRetrievalError::BadHTTPResponse {
                       status: response.status,
                       data: buf,
                   });
    }
    Ok(buf)
}

/// Issue an HTTPS GET request, and return the response body text.
fn get_content(content_url: &str, headers: Option<Headers>) -> GraphInfoResult<String> {
    let client = get_ssl_client();
    let request = if let Some(h) = headers {
        client.get(content_url).headers(h)
    } else {
        client.get(content_url)
    };
    let mut response = request.send()?;
    let mut buf = String::new();
    response.read_to_string(&mut buf)?;
    if response.status != hyper::status::StatusCode::Ok {
        return Err(GraphInfoRetrievalError::BadHTTPResponse {
                       status: response.status,
                       data: buf,
                   });
    }
    Ok(buf)
}

/// Extract the OAuth2 Bearer token from the provided JSON
///
/// # Example
///
/// ```
/// let json: &str = "{\"access_token\": \"aaaabbbbccccdddd...\"}";
/// assert_eq!(extract_token(json).unwrap(), "aaaabbbbccccdddd....");
/// ```
fn extract_token(json: &str) -> GraphInfoResult<String> {
    Ok(serde_json::from_str::<Value>(json)?["access_token"]
           .as_str()
           .ok_or(GraphInfoRetrievalError::NoAccessToken { response: json.to_string() })?
           .to_string())
}

/// Gather information out of the Graph API User json object.
///
/// This should probably be obviated by having UserInfo derive Deserialize and using the (kind
/// of ugly) attribute names that the Graph API uses.
fn extract_user_info(userinfo: &Value) -> GraphInfoResult<UserInfo> {
    let user_principal_name = userinfo["userPrincipalName"]
        .as_str()
        .ok_or(GraphInfoRetrievalError::BadJSONResponse)?
        .to_string();
    let user_display_name = userinfo["displayName"]
        .as_str()
        .ok_or(GraphInfoRetrievalError::BadJSONResponse)?
        .to_string();
    // was immutableId
    let mut sid_parts : Vec<&str> = userinfo["onPremisesSecurityIdentifier"]
        .as_str()
        .ok_or(GraphInfoRetrievalError::BadJSONResponse)?
        .split('-').collect();
    let user_id = sid_parts.pop().unwrap().parse::<u32>()?;
    // rid < 1000 should only be built-in users
    if user_id < 1000 {
        return Err(GraphInfoRetrievalError::UnusableImmutableID);
    }

    Ok(UserInfo {
           username: user_principal_name,
           fullname: user_display_name,
           userid: user_id,
       })
}

/// Gather information out of the Graph API Group json object.
///
/// This should probably be obviated by having GroupInfo derive Deserialize and using the (kind
/// of ugly) attribute names that the Graph API uses.
fn extract_group_info(group: &Value) -> GraphInfoResult<GroupInfo> {
    let group_name = group["displayName"]
        .as_str()
        .ok_or(GraphInfoRetrievalError::BadJSONResponse)?
        .to_string();
    let object_id = group["objectId"]
        .as_str()
        .ok_or(GraphInfoRetrievalError::BadJSONResponse)?
        .to_string();
    let mut sid_parts : Vec<&str> = group["onPremisesSecurityIdentifier"]
        .as_str()
        .ok_or(GraphInfoRetrievalError::BadJSONResponse)?
        .split('-').collect();
    let group_id = sid_parts.pop().unwrap().parse::<u32>()?;
    // rid < 1000 should only be built-in groups
    if group_id < 1000 {
        return Err(GraphInfoRetrievalError::UnusableImmutableID);
    }

    Ok(GroupInfo {
           groupname: group_name,
           object_id: object_id,
           group_id: group_id,
       })
}

/// Collects and returns UserInfo objects created from the raw results of a Graph API call.
fn extract_group_members(json: &str) -> GraphInfoResult<Vec<UserInfo>> {
    let values = &serde_json::from_str::<Value>(json)?["value"];
    let members = values
        .as_array()
        .ok_or(GraphInfoRetrievalError::BadJSONResponse)?
        .into_iter()
        .filter_map(|v| match extract_user_info(v) {
            Ok(m) => Some(m),
            Err(_) => None // we don't particularly care if we get a badly-formed json object
        })
        .collect::<Vec<UserInfo>>();
    Ok(members)
}

/// Collects and returns GroupInfo objects created from the raw results of a Graph API call.
fn extract_user_groups(json: &str) -> GraphInfoResult<Vec<GroupInfo>> {
    let values = &serde_json::from_str::<Value>(json)?["value"];
    if values.is_null() {
        return Err(GraphInfoRetrievalError::NotFound);
    }
    let groups = values
        .as_array()
        .ok_or(GraphInfoRetrievalError::BadJSONResponse)?
        .into_iter()
        .filter_map(|v| match extract_group_info(v) {
                        Ok(g) => Some(g),
                        Err(_) => None,
                    })
        .collect::<Vec<GroupInfo>>();
    Ok(groups)
}

/// Extracts and returns the PageToken from a paged response.
fn has_another_page(json: &str) -> GraphInfoResult<Option<String>> {
    let link = &serde_json::from_str::<Value>(json)?["odata.nextLink"];
    if link.is_null() {
        return Ok(None);
    }
    Ok(Some(link.as_str()
                .ok_or(GraphInfoRetrievalError::BadJSONResponse)?
                .to_string()))
}

/// Fetch a UserInfo object for the named user
pub fn get_user_info(config: &AadConfig, username: &str) -> GraphInfoResult<UserInfo> {
    let query_url = &format!("https://graph.windows.net/{}/users/{}?api-version=1.6",
                             config.tenant,
                             username);
    let info_json = get_graph_info(config, query_url)?;
    let user_info = &serde_json::from_str::<Value>(&info_json)?;
    extract_user_info(user_info)
}

/// Fetch a GroupInfo object for the named group
pub fn get_group_info(config: &AadConfig, groupname: &str) -> GraphInfoResult<GroupInfo> {
    let group_info_json = get_graph_info(config,
                                         &format!("https://graph.windows.net/{}/groups/?api-version=1.6&$filter=displayName+eq+'{}'",
                                                  config.tenant,
                                                  groupname))?;

    let group_results = serde_json::from_str::<Value>(&group_info_json)?;
    let group_values = group_results["value"]
        .as_array()
        .ok_or(GraphInfoRetrievalError::BadJSONResponse)?;
    if group_values.len() > 1 {
        return Err(GraphInfoRetrievalError::TooManyResults);
    }
    if group_values.len() < 1 {
        return Err(GraphInfoRetrievalError::NotFound);
    }
    extract_group_info(&group_values[0])
}

/// Fetch a GroupInfo object for the named group
pub fn get_group_info_by_sid(config: &AadConfig, sid: &str) -> GraphInfoResult<GroupInfo> {
    let query_url = &format!("https://graph.windows.net/{}/groups?$filter=onPremisesSecurityIdentifier+eq+'{}'&api-version=1.6",
                             config.tenant,
                             sid);
    let info_json = get_graph_info(config, query_url)?;
    let values = &serde_json::from_str::<Value>(&info_json)?["value"];
    let groups = values
        .as_array()
        .ok_or(GraphInfoRetrievalError::BadJSONResponse)?;

    if groups.len() > 1 {
        return Err(GraphInfoRetrievalError::TooManyResults);
    }
    if groups.len() < 1 {
        return Err(GraphInfoRetrievalError::NotFound);
    }
    extract_group_info(&groups[0])
}

/// Return a vector of UserInfo objects representing the members of the group identified by the
/// supplied group's object ID
pub fn get_group_members(config: &AadConfig, object_id: &str) -> GraphInfoResult<Vec<UserInfo>> {
    let group_members_json = get_graph_info(config,
                                            &format!("https://graph.windows.net/{}/groups/{}/members?api-version=1.6",
                                                     config.tenant,
                                                     object_id))?;
    extract_group_members(&group_members_json)
}

/// Return a vector of GroupInfo objects representing the groups to which the named user belongs
pub fn get_user_groups(config: &AadConfig, username: &str) -> GraphInfoResult<Vec<GroupInfo>> {
    let mut url = format!("https://graph.windows.net/{}/users/{}/memberOf?api-version=1.6",
                          config.tenant,
                          username);
    let mut user_groups = vec![];
    let mut retries = 5;
    loop {
        #[cfg(debug_assertions)]
        println!("libnss-aad::azure getting a batch of groups for {}",
                 username);
        let user_groups_json = match get_graph_info(config, &url) {
            Ok(j) => j,
            Err(e) => {
                match e {
                    GraphInfoRetrievalError::BadHTTPResponse { status, data } => {
                        if data.contains("Directory_ExpiredPageToken") && retries > 0 {
                        #[cfg(debug_assertions)]
                            println!("libnss-aad::azure got an ExpiredPageToken; retrying");
                            retries -= 1;
                            continue; // no kidding, this is the recommended approach.
                        }
                        return Err(GraphInfoRetrievalError::BadHTTPResponse { status, data });
                    }
                    _ => {
                        return Err(e);
                    }
                }
            }
        };
        let mut group_batch = extract_user_groups(&user_groups_json)?;
        user_groups.append(&mut group_batch);
        let link = match has_another_page(&user_groups_json)? {
            Some(link) => link,
            None => {
                break;
            }
        };
        url = format!("https://graph.windows.net/{}/{}&api-version=1.6",
                      config.tenant,
                      link);
    }
    Ok(user_groups)
}

/// Fetch the text of the HTTP response at `query_url`
///
/// Using the client credentials in the `config` argument, obtain an OAuth2 Bearer token from
/// the OAuth2 endpoint. Using that token, make a request for `query_url`, and return whatever
/// text is in the response body.
fn get_graph_info(config: &AadConfig, query_url: &str) -> GraphInfoResult<String> {
    let auth_url = format!("https://login.microsoftonline.com/{}/oauth2/token?api-version=1.0",
                           config.tenant);
    let auth_params = vec![("resource", "https://graph.windows.net/"),
                           ("grant_type", "client_credentials"),
                           ("client_id", &config.client_id),
                           ("client_secret", &config.client_secret)];
    let token_json = post_query(&auth_url, &auth_params)?;

    let token = extract_token(&token_json)?;

    let mut auth_header = Headers::new();
    auth_header.set(Authorization(Bearer { token: token }));

    get_content(query_url, Some(auth_header))
}
