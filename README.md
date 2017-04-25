
LibNSS-AAD: Linux Name Switch Service plugin for passwd and group lookups into Azure Active Directory
=====================================================================================================

Introduction
------------

This is a glibc NSS plugin that will query Azure Active Directory for information about users,
written in Rust. It is very, very simple, and does not even go so far as to properly use OAuth2.
It implements the following libc functions:
* `getpwnam`
* `getgrnam`
* `getgrgid`
* `initgroups_dyn`

This plugin works best with (and basically, though not actually, requires) nscd. Because nscd can
have unintended effects on hosts, it is highly recommended that you refer to `nscd.conf(5)` and
enable nscd caching only for `passwd` and `group` services, and set the various configuration
options appropriately for your environment.

This plugin was written as a compliment to OpenSSH certificate authentication.

Security Considerations
-----------------------

This plugin provides a limited set of information to the system, and has some aspects that are
worth mentioning.

* UIDs are not sanity-checked, except for uid `0` (which the plugin will refuse to honor and return `NSS_STATUS_NOTFOUND`).
* As currently implemented, UIDs are retrieved from the `immutableId` user attribute. This may not be appropriate in your environment.
* GIDs are not checked, not even for GID `0`.
* The user password field returned is `.`, because OpenSSH considers a password field of `*` to indicate a locked account.

The `/etc/nssaad.conf` file must be readable by any user (privileged or not) that wants to obtain information from AAD (akin to the `passwd` service), and thus the Azure AD Application's client secret will be world-readable. Careful use of NSCD may alleviate this (as it may when using the `bindpw` option libnss-ldap), but very well may not. It is recommended that you limit the permissions granted to the Application, and not grant shell access to users whom you do not want querying the Directory.

Configuration
-------------

### Plugin Configuration ###
The plugin expects to read from `/etc/nssaad.conf`, which is a YAML file:

```yaml
client_id: "..."
client_secret: "..."
tenant: "..."
group_ids:
  ...: ###
  ...
```

* `client_id`: is the Application ID of the [AAD Application](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-integrating-applications) that you have created, and to which you have granted it [the necessary permissions](https://msdn.microsoft.com/en-us/library/azure/ad/graph/howto/azure-ad-graph-api-permission-scopes) (namely, `Directory.Read.All`, or a combination of `User.ReadBasic.All` and `Group.Read.All`) to query data from the Graph API.
* `client_secret`: is a key that the client can use to obtain an [OAuth2 bearer token](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code).
* `tenant`: is your [Azure AD tenant](https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-howto-tenant) name, or its GUID.
* `group_ids`: This library does not (yet) make allowances for storing GIDs in AAD. As a workaround, you must specify GIDs within the config file. The config expects a dict named `group_ids` that maps group names to GIDs:

### NSS Configuration ###
Add the `aad` service to the `/etc/nsswitch.conf` file. Probably something like:
```
passwd:         compat aad
group:          compat aad
```

Installation
------------

Upon building the library, copy the `target/release/libnss_aad.so` file to `/lib/???-linux-gnu/libnss_aad.so.2`.

Known Issues
------------

* Every call to the plugin results in at least one connection to the OAuth2 endpoint for a new token.
* OpenSSH may consider a user account with a password field of `*` to be locked, and thus this plugin returns `.` instead.
