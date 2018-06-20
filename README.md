# certmgr

ACME protocol automatic certitificate manager.

This tool acquires and maintains certificates from a certificate
authority using the ACME protocol, similar to EFF's Certbot. While
developed and tested using Let's Encrypt, the tool should work with any
certificate authority using the ACME v2 protocol.

## Features

This tool is not intended as a replacement for Certbot and does not
attempt to replicate all of Certbot's functionality, notably it does not
modify configuration files of other services, or provide a server to
perform stand-alone domain validation. It does however, do a few things
that Certbot does not, simplifying certificate manangement in more
advanced environments.

### Master/Follower Mode

This tool separates the authorization (domain validation) and
certificate issuance processes allowing one machine to maintain
authorizations (the master), while another machine issues certificates
(the follower). This is useful for situations where an isolated server
is providing a service, such as XMPP, behind a firewall and does not
have the ability to perform authorizations over http or configure DNS
records, but still needs to obtain and periodically renew one or more
certificates.

### Parallel RSA and ECDSA Certificates

This tool can generate both RSA and ECDSA certificates. By default it
will generate and maintain both types of certificates in parallel.

### Certificate Transparency / Signed Certificate Timestamp Support

This tool can automatically register your certificates with multiple
certificate transparency logs and retrieve Signed Certificate Timestamps
(SCTs) for each. The retrieved SCTs are suitable to be deilvered via a
TLS extension, SCT TLS extension modules are available for
[Apache](https://httpd.apache.org/docs/trunk/mod/mod_ssl_ct.html) and
[Nginx](https://github.com/grahamedgecombe/nginx-ct).

Note that this is not very usefull as letsencrypt generated certificates already embeds SCT extensions.

### OCSP Response File Support

This tool automatically obtains and maintains OCSP response files for
each configured certificate. These files may be used to serve stapled
OCSP responses from your server without relying on the server's OCSP
stapling mechanisms. Some servers, such as Nginx, obtain stapled OCSP
responses lazily and cache the response in memory. When using the OCSP
Must-Staple extension this can result in your server being unreachable
until the OCSP response is refreshed, during OCSP responder outages,
this can be a significant interval. Using OCSP responses from disk will
alleviate this issue. Only OCSP responses with a "good" status will be
stored.

### Encrypted Private Keys

Domain and acme client private keys can optionally be encrypted using a
passphrase.

### Output File Names

To simplify service configuration, this tool output certifiates, keys
and other files using stables predictables names. If system
administrators need special naming conventions, the recommanded way is
to create symlinks.

This tool generates certificate using the following layout:

       data_dir/
           account/
               client.key
               registration.json
           archives/
               …
           <common_name>/
               params.pem
               <key_type>/
                   cert.pem
                   chain.pem
                   cert+root.pem
                   oscp.der
                   keys/
                       key.pem
                       key+cert.pem
                   scts/
                       <ct_log_name>.sct
           <alt_name>/ -> <common_name>

When configuring a service, you should always use the path that match
the domain you need (even if this is an alt name and not a common name).
So if you later change your configuration to generate a certificate per
domain name instead of one with alt names, your service configuration
will still be working.

For instance, you may want a certificate with common name
`www.example.com` and alt name `example.com`, and then create 2 virtual
hosts in nginx:

    server {
        server_name example.com;

        ssl_certificate         /etc/certmgr/example.com/rsa/cert.pem;
        …

        return  301 https://www.example.com$request_uri;
    }

    server {
        server_name www.example.com;

        ssl_certificate         /etc/certmgr/www.example.com/rsa/cert.pem;
        …

    }

You may want to use `/etc/certmgr/www.example.com/rsa/cert.pem` for both
server, but if you later change the certmgr config to generate 2
certificates instead of one, or switch the common name and alt name,
your nginx configuration will be broken.

### Configurable Deployment Hooks

Each operation that writes key, certificate, or related files have
optional hooks that can call user-specified programs to assist in
deploying resources to remote servers or coordinating with other
tooling.

### Certificate Installation Verification

This tool can automatically connect to configured servers and verify
that the generated certificates are properly served via TLS. Additional
checks are made for OSCP staples.

### ACME Protocol V2 Support

This tool supports only ACME V2 APIs. Wildcard certificates may be
issued when using the V2 API (but it requires DNS challenge which is not
supported by this tool).

## Installation

Requires Python 3.5+ and the acme packages.

On Debian Jessie, these can be installed via:

    sudo apt-get install build-essential libssl-dev libffi-dev python3-dev python3-pip
    sudo pip3 install -r requirements.txt

On Debian Stretch:

    sudo apt-get install python3-pip libssl-dev libffi-dev
    sudo pip3 install -r requirements.txt

Clone this repository and install it on your server. Copy the
`certmgr.example.json` file to `certmgr.json` and edit the configuration
options. The configuration file can be placed in the current directory
that the tool is run from, in the /etc/certmgr directory, or int the
same directory that the certmgr tool is installed in.

By default, info level output will be written to a log file. A
configuration file for logrotate is provided in the logrotate.d
directory, you may want to copy, or create a link to this file in
/etc/logrotate.d.

Optional: some services require a full certificate chain including the
root (OSCP stapling on Nginx, for example). In order to generate these
files, place a copy of the root certificates from your certificate
authority of choice in the same directory as the configuration file with
the file names `root_cert.rsa.pem` and `root_cert.ecdsa.pem` for RSA and
ECDSA certificate roots respectively. Note that the root certificates
are the those used to sign RSA and ECDSA client certificates, and may
not necessarily be of the same type, e.g. Let's Encrypt currently signs
ECDSA certificates with an RSA root. If your certificate authority uses
RSA certificate to sign ECDSA certificates types, place that RSA root
certificate in `root_cert.ecdsa.pem`. The root certificate for Let's
Encrypt can be obtained [here](https://letsencrypt.org/certificates/).

## Quick Start

### Basic Configuration

While the example configuration file may appear complicated, it is meant
to show all possible configuration options and their defaults, rather
than demonstrate a basic simple configuration.

The only items that must be present in the configuration file to create
and maintain a certificate are your account email address, and the file
name, and subject alternative names for the certificate.

For example:

```json
  {
      "account": {
          "email": "admin@example.com"
      },
      "certificates": [
          {
              "name": example.com,
              "alt_names": {
                  "example.com": ["@", "www"]
              }
          }
      ]
  }
```

will create a certificate named `example.com`, with the common name of `example.com`,
and the subject alternative names of `example.com` and `www.example.com`.

As many certificates as desired may be configured. The number of alternative names is limited by the certificate authority
(Let's Encrypt currently allows 100). Alternative names are specified on a DNS zone
basis, multiple zones may be specified per certificate. The host name `"@"` is used for the name of the zone itself.

### Authorization Setup

The tool supports only http-01 authorizations which requires to
configure an `http_challenges` section of the configuration file
specifying a challenge directory for each fully qualified host name.

For example:

```json
  {
      ...
      "http_challenges": {
          "example.com": "/var/www/htdocs/.well-known/acme-challenge",
          "www.example.com": "/var/www/htdocs/.well-known/acme-challenge"
      }
  }
```

See the [HTTP Challenges](#http-challenges) section for more
information.

### First Run

Once the configuration file is in place, simply execute the tool. For
the first run you may wish to select detailed output to see exactly what
the tool is doing:

    acmebot --debug

If all goes well, the tool will:

- generate a public/private key pair used for client authentication to the certificate authority
- register an account with the certificate authority
- prompt to accept the certificate authority's terms of service
- obtain authorizations for each configured domain name
- generate primary private keys as needed for the configured certificates
- issue certificates
- generate or fetch custom Diffie-Hellman parameters
- retrieve OCSP responses
- retrieve Signed Certificate Timestamps from certificate transparency logs.

If desired, you can test the tool using Let's Encrypt's staging server.
To do this, specify the staging server's directory URL in the `acme_directory_url` setting. 
See [Staging Environment](https://letsencrypt.org/docs/staging-environment/) for details.
When switching from the staging to production servers, the tool will archive the client key and 
registration files to ensure a fresh registration in the production environment.

## File Location

After a successful certificate issuance, thirty files will be created per certificate.

Output files will be written as a single transaction, either all files
will be written, or no files will be written. This is designed to
prevent a mismatch between certificates and private keys should an error
happen during file creation.

### Private Keys

One private key files will be created for each key type.

The private key files will be written in PEM format and will only be
readable by owner and group.

### Certificate Files

Two certificates files may be created for each key type. One named
`cert.pem`, containing the certificate, followed by any intermediate
certificates sent by the certificate authority, followed by custom
Diffie-Hellman and elliptic curve paramaters; The second file may be
created in `` `keys ``, named `key+cert.key`, and will contain the
private key, followed by the certificate, followed by any intermediate
certificates sent by the certificate authority, followed by custom
Diffie-Hellman and elliptic curve paramaters.

The `key+cert.key` file is useful for services that require both the
private key and certificate to be in the same file, such as ZNC.

### Intermediate Certificate Chain File

If the certificate authority uses intermediate certificates to sign your
certificates, a file will be created named `chain.pem` for each key
type, containing the intermediate certificates sent by the certificate
authority.

Note that the certificate authority may use a different type of
certificate as intermediates, e.g. an ECDSA client certificate may be
signed by an RSA intermediate, and therefore the intermediate
certificate key type may not match the file name (or certificate type).

### Full Chain Certificate File

If the `root_cert.<key-type>.pem` file is present (see
[Installation](#installation)), then an additional certificate file will
be generated, named `cert+root.pem` for each key type. This file will
contain the certificate, followed by any intermediate certificates sent
by the certificate authority, followed by the root certificate, followed
by custom Diffie-Hellman and elliptic curve paramaters.

If the `root_cert.<key-type>.pem` file is not found in the same
directory as the configuration file, this certificate file will not be
created.

This file is useful for configuring OSCP stapling on Nginx servers.

### Diffie-Hellman Parameter File

If custom Diffie-Hellman parameters or a custom elliptical curve are
configured, a file `params.pem` will be created, containing the
Diffie-Hellman parameters and elliptical curve paramaters.

This file will not be created if `dhparam_size` is 0 and `ecparam_curve`
is `null`.

### Signed Certificate Timestamp (SCT) Files

One additional file will be created for each key type and configured
certificate transparency log in `sct/<log-name>.sct`. These files
contain SCT information in binary form suitable to be included in a TLS
extension. By default, SCTs will be retrieved from the Google Icarus and
Google Pilot certificate transparency logs. The Google Test Tube
certificate transparency log can be used with the Let's Encrypt staging
environment for testing.

### OCSP Response Files

One OCSP response file `ocsp.der` will be created for each key type.
These files contain OCSP responses in binary form suitable to be used as
stapled OCSP responses.

### Archive Directory

Whenever existing files are replaced by subsequent runs of the tool, for
example during certificate renewal or private key rollover, all existing
files are preserved in the `archives` directory.

Within the archive directory, a directory will be created with the name
of the certificate, containing a datestamped directory with the time of
the file transaction (YYYY\_MM\_DD\_HHMMSS). All existing files will be
moved into the datestamped directory should they need to be recovered.

Archived directory are automatically deleted after `archive_days` days (defaults to 30 days).

## Server Configuration

Because certificate files will be periodically replaced as certificates
need to be renewed, it is best to have your server configurations simply
refer to the certificate and key files in the locations they are
created. This will prevent server configurations from having to be
updated as certificate files are replaced.

If the server requires the certificate or key file to be in a particular
location or have a different file name, it is best to simply create a
soft link to the certificate or key file rather than rename or copy the files.

Another good practice it to isolate the configuration for each
certificate into a snippet file, for example using Apache, create the
file /etc/apache2/snippets/ssl/example.com containing:

    SSLCertificateFile    /etc/certmgr/example.com/rsa/cert.pem
    SSLCertificateKeyFile /etc/certmgr/example.com/rsa/keys/key.pem
    CTStaticSCTs          /etc/certmgr/example.com/rsa/cert.pem /etc/certmgr/example.com/rsa/scts        # requires mod_ssl_ct to be installed

    SSLCertificateFile    /etc/certmgr/example.com/ecdsa/cert.pem
    SSLCertificateKeyFile /etc/certmgr/example.com/ecdsa/keys/key.pem
    CTStaticSCTs          /etc/certmgr/example.com/ecdsa/cert.pem /etc/certmgr/example.com/ecdsa/scts    # requires mod_ssl_ct to be installed

    Header always set Strict-Transport-Security "max-age=63072000"

and then in each host configuration using that certificate, simply add:

    Include snippets/ssl/example.com

For Nginx the /etc/nginx/snippets/ssl/example.com file would contain:

    ssl_ct on;                                                          # requires nginx-ct module to be installed

    ssl_certificate         /etc/certmgr/example.com/rsa/cert.pem;
    ssl_certificate_key     /etc/certmgr/example.com/rsa/keys/key.pem;
    ssl_ct_static_scts      /etc/certmgr/example.com/rsa/scts;              # requires nginx-ct module to be installed
    ssl_stapling_file       /etc/certmgr/example.com/rsa/ocsp.der;

    ssl_certificate         /etc/certmgr/example.com/ecdsa/cert.pem;       # requires nginx 1.11.0+ to use multiple certificates
    ssl_certificate_key     /etc/certmgr/example.com/ecdsa/keys/key.pem;
    ssl_ct_static_scts      /etc/certmgr/example.com/ecdsa/scts;           # requires nginx-ct module to be installed
    ssl_stapling_file       /etc/certmgr/example.com/ecdsa/ocsp.der;       # requires nginx 1.1x+ to use with multiple stapling file support (not supported in 1.14.0)

    ssl_trusted_certificate /etc/certmgr/example.com/rsa/cert+root.pem;    # not required if using ssl_stapling_file

    ssl_dhparam             /etc/certmgr/example.com/params.pem;
    ssl_ecdh_curve          secp384r1;

    add_header Strict-Transport-Security "max-age=63072000" always;

and can be used via:

    include snippets/ssl/example.com;

## Configuration

The configuration file `certmgr.json` may be placed in the current
working directory, in /etc/certmgr, or in the same directory as the
certmgr tool is installed in. A different configuration file name may be
specified on the command line. If the specified file name is not an
absolute path, it will be searched for in the same locations, e.g.
`certmgr --config config.json` will load `./config.json`,
`/etc/certmgr/config.json`, or `<install-dir>/config.json`. The file
must adhere to standard JSON format.

The file `certmgr.example.json` provides a template of all configuration
options and their default values. Entries inside angle brackets
`"<example>"` must be replaced (without the angle brackets), all other
values may be removed unless you want to override the default values.

### Account

-   `email` specifies the email address you wish to associate with your
    account on the certificate authority. This email address may be
    useful in recovering your account should you lose access to your
    client key.
-   `passphrase` specifies the passphrase used to encrypt client key.
    The default value is `null`. A value of `null` or `false` will
    result in keys being written unencrypted. A value of `true` will
    cause the password to be read from the command line, the
    environment, a prompt, or stdin. A string value will be used as the
    passphrase without further input.

Example:

```json
  {
      "account": {
          "email": "admin@example.com",
          "passphrase": true
      },
      ...
  }
```

### Settings

Various settings for the tool. All of these need only be present when
the desired value is different from the default.

-   `log_file` specifies the log file path. log file can be turned off
    by setting this value to `null`. The default value is
    `/var/log/certmgr/certmgr.log`.
-   `log_level` specifies the amount of information written into the log
    file. Possible values are `null`, `"normal"`, `"verbose"`,
    `"debug"`. `"verbose"`, `"debug"` settings correlate to the
    `--verbose` and `--debug` command-line options. `null` correlate to
    the `--quiet` command-line option.
-   `data_dir` specifies the path where the tool save all the generated
    files. defaults to `/etc/certmgr`.
-   `"http_challenge_dir"` specifies the path where to save the http
    challenges. (see [HTTP Challenges](#http-challenges)),
-   `color_output` specifies if the output should be colorized.
    Colorized output will be suppressed on non-tty devices. This option
    may be overridden via command line options. The default value is
    `true`.
-   `key_size` specifies the size (in bits) for RSA private keys. The
    default value is `4096`. RSA certificates can be turned off by
    setting this value to `0` or `null`.
-   `key_curve` specifies the curve to use for ECDSA private keys. The
    default value is `"secp384r1"`. Available curves are `"secp256r1"`,
    `"secp384r1"`, and `"secp521r1"`. ECDSA certificates can be turned
    off by setting this value to `null`.
-   `key_passphrase` specifies the passphrase used to encrypt private
    keys. The default value is `null`. A value of `null` or `false` will
    result in private keys being written unencrypted. A value of `true`
    will cause the password to be read from the command line, the
    environment, a prompt, or stdin. A string value will be used as the
    passphrase without further input.
-   `dhparam_size` specifies the size (in bits) for custom
    Diffie-Hellman parameters. The default value is `2048`. Custom
    Diffie-Hellman parameters can be turned off by setting this value to
    `0` or `null`. This value should be at least be equal to half the
    `key_size`.
-   `ecparam_curve` speficies the curve to use for ECDHE negotiation.
    The default value is `"secp384r1"`. Custom EC parameters can be
    turned off by setting this value to `null`. You can run
    `openssl ecparam -list_curves` to find a list of available curves.
-   `file_user` specifies the name of the user that will own certificate
    and private key files. The default value is `null` which corresponds
    user currently running the tool. Note that this tool must run as
    root, or another user that has rights to set the file ownership to
    this user.
-   `file_group` speficies the name of the group that will own
    certificate and private key files. The default value is `null` which
    corresponds to the group of the user currently running the tool.
    Note that this tool must run as root, or another user that has
    rights to set the file ownership to this group.
-   `ocsp_must_staple` specifies if the OCSP Must-Staple extension is
    added to certificates. The default value is `false`.
-   `ocsp_responder_urls` specifies the list of OCSP responders to use
    if a certificate doesn't provide them. The default value is
    `["http://ocsp.int-x3.letsencrypt.org"]`.
-   `ct_submit_logs` specifies the list of certificate transparency logs
    to submit certificates to. The default value is
    `["google_icarus", "google_pilot"]`. The value `["google_testtube"]`
    can be used with the Let's Encrypt staging environment for testing.
-   `renewal_days` specifies the number of days before expiration when
    the tool will attempt to renew a certificate. The default value is
    `30`.
-   `max_authorization_attempts` specifies the number of times to check
    for completed authorizations. The default value is `30`.
-   `authorization_delay` specifies the number of seconds to wait
    between authorization checks. The default value is `10`.
-   `cert_poll_time` specifies the number of seconds to wait for a
    certificate to be issued. The default value is `30`.
-   `max_ocsp_verify_attempts` specifies the number of times to check
    for OCSP staples during verification. Retries will only happen when
    the certificate has the OCSP Must-Staple extension. The default
    value is `10`.
-   `ocsp_verify_retry_delay` specifies the number of seconds to wait
    between OCSP staple verification attempts. The default value is `5`.
-   `min_run_delay` specifies the minimum number of seconds to wait if
    the `--randomwait` command line option is present. The default value
    is `300`.
-   `max_run_delay` specifies the maximum number of seconds to wait if
    the `--randomwait` command line option is present. The default value
    is `3600`.
-   `acme_directory_url` specifies the primary URL for the ACME service.
    The default value is
    `"https://acme-v02.api.letsencrypt.org/directory"`, the Let's
    Encrypt production API. You can substitute the URL for Let's
    Encrypt's staging environment or another certificate authority.
-   `verify` specifies the default ports to perform installation
    verification on. The default value is `null`.
-   `lock_file` path of the lock file used to ensure only a single
    instance of the tool run at once. The default value is
    `/var/run/certmgr.lock`.

Example:

```json
  {
      "settings": {
          "log_level": "debug",
          "key_size": 4096,
          "key_curve": "secp384r1",
          "key_passphrase": null,
          "dhparam_size": 2048,
          "ecparam_curve": "secp384r1",
          "file_user": "root",
          "file_group": "ssl-cert",
          "ocsp_must_staple": false,
          "ocsp_responder_urls": ["http://ocsp.int-x3.letsencrypt.org"],
          "ct_submit_logs": ["google_icarus", "google_pilot"],
          "renewal_days": 30,
          "max_authorization_attempts": 30,
          "authorization_delay": 10,
          "min_run_delay": 300,
          "max_run_delay": 3600,
          "acme_directory_url": "https://acme-v02.api.letsencrypt.org/directory",
          "verify": [443]
      }
  }
```

### Services

This specifies a list of services that are used by issued certificates
and the commands necessary to restart or reload the service when a
certificate is issued or changed. You may add or remove services as
needed. The list of services is arbritrary and they are referenced from
individual certificate definitions.

Example:

```json
  {
      "services": {
          "apache": "systemctl reload apache2",
          "coturn": "systemctl restart coturn",
          "dovecot": "systemctl restart dovecot",
          "etherpad": "systemctl restart etherpad",
          "mysql": "systemctl reload mysql",
          "nginx": "systemctl reload nginx",
          "postfix": "systemctl reload postfix",
          "postgresql": "systemctl reload postgresql",
          "prosody": "systemctl restart prosody",
          "slapd": "systemctl restart slapd",
          "synapse": "systemctl restart matrix-synapse",
          "znc": "systemctl restart znc"
      }
  }
```

To specify one or more services used by a certificate, add a `services`
section to the certificate definition listing the services using that
certificate.

For example:

```json
  {
      "certificates": {
          "example.com": {
              "alt_names": {
                  "example.com": ["@", "www"]
              }
          },
          "services": ["nginx"]
      }
  }
```

This will cause the command `"systemctl reload nginx"` to be executed
any time the certificate `example.com` is issued, renewed, or updated.

### Certificates

This section defines the set of certificates to issue and maintain. The
name of each certificate is used as the name of the certificate files.

-   `name` specifies the common name for the certificate.
-   `alt_names` specifies the set of subject alternative names for the
    certificate. If specified, the common name of the certificate must
    be included as one of the alternative names. The alternative names
    are specified as a list of host names per DNS zone, so that
    associated DNS updates happen in the correct zone. The zone name may
    be used directly by specifying `"@"` for the host name. Multiple
    zones may be specified. The default value is
    `{ <common_name>: ["@"] }`.
-   `services` specifies the list of services to be reloaded when the
    certificate is issued, renewed, or modified. This may be omitted.
-   `dhparam_size` specifies the number of bits to use for custom
    Diffie-Hellman paramaters for the certificate. The default value is
    the value specified in the `settings` section. Custom Diffie-Hellman
    paramaters may be ommitted from the certificate by setting this to
    `0` or `null`. The value should be at least equal to half the number
    of bits used for the private key.
-   `ecparam_curve` specified the curve used for elliptical curve
    paramaters. The default value is the value specified in the
    `settings` section. Custom elliptical curve paramaters may be
    ommitted from the certificate by setting this to `null`.
-   `key_types` specifies the types of keys to create for this
    certificate. The default value is all available key types. Provide a
    list of key types to restrict the certificate to only those types.
    Available types are `"rsa"` and `"ecdsa"`.
-   `key_size` specifies the number of bits to use for the certificate's
    RSA private key. The default value is the value specified in the
    `settings` section. RSA certificates can be turned off by setting
    this value to `0` or `null`.
-   `key_curve` specifies the curve to use for ECDSA private keys. The
    default value is the value specified in the `settings` section.
    Available curves are `"secp256r1"`, `"secp384r1"`, and
    `"secp521r1"`. ECDSA certificates can be turned off by setting this
    value to `null`.
-   `key_passphrase` specifies the passphrase used to encrypt private
    keys. The default value is the value specified in the `settings`
    section. A value of `null` or `false` will result in private keys
    being written unencrypted. A value of `true` will cause the password
    to be read from the command line, the environment, a prompt, or
    stdin. A string value will be used as the passphrase without further
    input.
-   `ocsp_must_staple` specifies if the OCSP Must-Staple extension is
    added to certificates. The default value is the value specified in
    the `settings` section.
-   `ocsp_responder_urls` specifies the list of OCSP responders to use
    if a certificate doesn't provide them. The default value is the
    value specified in the `settings` section. If set to empty list, it
    disables OCSP for taht certificate.
-   `ct_submit_logs` specifies the list of certificate transparency logs
    to submit the certificate to. The default value is the value
    specified in the `settings` section. The value `["google_testtube"]`
    can be used with the Let's Encrypt staging environment for testing.
-   `verify` specifies the list of ports to perform certificate
    installation verification on. The default value is the value
    specified in the `settings` section.

Example:

```json
  {
      "certificates": [
          {
              "name": "example.com",
              "alt_names": {
                  "example.com": ["@", "www"]
              },
              "services": ["nginx"],
              "dhparam_size": 2048,
              "ecparam_curve": "secp384r1",
              "key_types": ["rsa", "ecdsa"],
              "key_size": 4096,
              "key_curve": "secp384r1",
              "key_passphrase": null,
              "ocsp_must_staple": false,
              "ocsp_responder_urls": ["http://ocsp.int-x3.letsencrypt.org"],
              "ct_submit_logs": ["google_icarus", "google_pilot"],
              "verify": [443]
          }
      ]
  }
```

### HTTP Challenges

This tool uses http-01 authorizations that requires to configure the
`http_challenges` section of the configuration file specifying a
challenge directory for each fully qualified domain name, or configure a `http_challenge` directory.

Example:

```json
  {
      "http_challenges": {
          "example.com": "/var/www/htdocs/.well-known/acme-challenge"
          "www.example.com": "/var/www/htdocs/.well-known/acme-challenge"
      }
  }
```

The `http_challenges` must specify a directory on the local file system
such that files placed there will be served via an already running http
server for each given domain name. In the above example, files placed in
`/var/www/htdocs/.well-known/acme-challenge` must be publicly available
at: `http://example.com/.well-known/acme-challenge/file-name` and
`http://www.example.com/.well-known/acme-challenge/file-name`

Alternatively, if all challenge directories have a similar path, you may
configure a single `http_challenge` directory using a python format
string with the field `fqdn`.

Example:

```json
  {
      "settings": {
          "http_challenge_dir": "/var/www/{fqdn}/.well-known/acme-challenge"
      }
  }
```

### Certificate Transparency Logs

This section defines the set of certificate transparency logs available
to submit certificates to and retrieve SCTs from. Additional logs can be
aded at will. Each log definition requires the primary API URL of the
log, and the log's ID in base64 format. A list of currently active logs
and their IDs can be found at
[certificate-transparency.org](https://www.certificate-transparency.org/known-logs).

Example:

```json
  {
      "ct_logs": {
          "google_pilot": {
              "url": "https://ct.googleapis.com/pilot",
              "id": "pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA="
          },
          "google_icarus": {
              "url": "https://ct.googleapis.com/icarus",
              "id": "KTxRllTIOWW6qlD8WAfUt2+/WHopctykwwz05UVH9Hg="
          }
      }
  }
```

### Deployment Hooks

This section defines the set of hooks that can be called via the shell
when given actions happen. Paramaters to hooks are specified using
Python format strings. Fields available for each hook are described
below. Output from the hooks will be captured in the log. Hooks returing
a non-zero status code will generate warnings, but will not otherwise
affect the operation of this tool.

-   `set_http_challenge` is called for each HTTP challenge file that is
    installed. Available fields are `domain`, and `challenge_file`.
-   `clear_http_challenge` is called for each HTTP challenge file that
    is removed. Available fields are `domain`, and `challenge_file`.
-   `private_key_installed` is called when a private key is installed.
    Available fields are `key_name`, `key_type`, `private_key_file`, and
    `passphrase`.
-   `certificate_installed` is called when a certificate file is
    installed. Available fields are `key_name`, `key_type`,
    `certificate_name`, and `certificate_file`.
-   `full_certificate_installed` is called when a certificate file that
    includes the root is installed. Available fields are `key_name`,
    `key_type`, `certificate_name`, and `full_certificate_file`.
-   `chain_installed` is called when a certificate intermediate chain
    file is installed. Available fields are `key_name`, `key_type`,
    `certificate_name`, and `chain_file`.
-   `full_key_installed` is called when a private key including the full
    certificate chain file is installed. Available fields are
    `key_name`, `key_type`, `certificate_name`, and `full_key_file`.
-   `params_installed` is called when a params file is installed.
    Available fields are `key_name`, `certificate_name`, and
    `params_file`.
-   `sct_installed` is called when a SCT file is installed. Available
    fields are `key_name`, `key_type`, `certificate_name`,
    `ct_log_name`, and `sct_file`.
-   `ocsp_installed` is called when an OSCP file is installed. Available
    fields are `key_name`, `key_type`, `certificate_name`, and
    `ocsp_file`.

Example:

```json
  {
      "hooks": {
          certificate_installed": [
              { args: ["scp", "{certificate_file}", "remote-server:/etc/ssl/certs/" ] },
              "scp {certificate_file} remote-server2:/etc/ssl/certs/"
          ]
      }
  }
```

### Certificate Installation Verification

The tool may be configured to perform installation verification of
certificates. When verifying installation, the tool will connect to
every subject alternative host name for each certificate on all
avaialable IP addresses, per each configured port, perform a TLS
handshake, and compare the served certificate chain to the specified
certificate.

Each configured port may be an integer port number, or an object
specifying connection details.

When using an object, the avaialable fields are:

-   `port` specifies the port number to connect to. Required.
-   `starttls` specifies the STARTTLS mechanism that should be used to
    initiate a TLS session. Allowed values are: `null`, `smtp`, `pop3`,
    `imap`, `sieve`, `ftp`, and `xmpp`. The default value is `null`.
-   `hosts` specifies a list of fully qualified domain names to test.
    This allows testing only a subset of the alternative names specified
    for the certificate. Each host name must be present as an
    alternative name for the certificate. The default value is all
    alternative names.
-   `key_types` specifies a list of key types to test. This allows
    testing only a subset of the avaialable key types. The default value
    is all avaialable key types.

Example:

```json
  {
      "verify": [
          {
              "port": 443
          },
          {
              "port": 25,
              "starttls": "smtp",
              "hosts": "smtp.example.com",
              "key_types": "rsa"
          },
          993
      ]
  }
```

## Running the Tool

The tool support many actions. When no action are specified, the tool
defaults to `update`.

Any command that require a valid acme account will first generate a
client key and register that key with the certificate authority if
needed.

For all commands, if you want to process only some certificates (and not
all), you can pass the certificates' common name as parameter.

### update

For each certificate:
- perform all needed domain authorizations (unless --no-auth parameter is present)
- generate private keys (if the key parameters did change or if the certificate need to be generated)
- issue certificates (if certificate's expiration dates is within the renewal window, or if the configured common name, or subject alternative names did change)
- generate custom Diffie-Hellman parameters (if the parameters did change or if the certificate need to be generated)
- retrieve current Signed Certificate Timestamps (SCTs) from configured certificate transparency logs
- retrieve OCSP staples
- install all updated files
- update symlinks
- delete old archives

Once all certificates are updated:
- reload services associated to the certificates
- perform configured certificate installation verification (if --verify is passed)

### check

For each certificate:
- verify if installed files permissions match the settings, and fix them if not.

### revoke

- revoke the certificates passed as parameter.

### auth

For each certificate:
- perform all needed domain authorizations

This action can be used if you need to process the authorizations on a different server than the one that need the certificates.
Then, on the other server, run  `certmgr update --no-auth`  to generate the required files.

### verify

For each certificate:
- perform configured certificate installation verification

### cleanup

For each certificate:
- delete old archives

### Daily Run Via cron

In order to ensure that certificates in use do not expire, it is
recommended that the tool be run at least once per day via a cron job.

By default, the tool only generates output when actions are taken making
it cron friendly. Normal output can be supressed via the `--quiet`
command line option.

To prevent multiple instances running at the same time, a random wait
can be introduced via the `--randomwait` command line option. The
minimum and maximum wait times can be controlled via the `min_run_delay`
and `max_run_delay` settings.

Example cron entry, in file /etc/cron.d/certmgr:

    MAILTO=admin@example.com

    20 0 * * * root /usr/local/bin/certmgr --randomwait update

This will run the tool as root every day at 20 minutes past midnight
plus a random delay of five minutes to an hour. Any output will be
mailed to <admin@example.com>.

If using OCSP response files, it may be desirable to refresh OCSP
responses at a shorter interval. (Currently Let's Encrypt updates OCSP
responses every three days.) To refresh OCSP responses every six hours,
add the line:

    20 6,12,18 \* \* \* root /usr/local/bin/certmgr --randomwait update --ocsp

### Output Options

Normally the tool will only generate output to stdout when certificates
are issued or other file updated. More detailed output can be obtained
by using any of the `--verbose` and `--debug` options on the command
line.

Normal output may be supressed by using the `--quiet` option.

Error output will be sent to stderr and cannot be supressed.

The output can be colorized by type by adding the `--color` option, or
colorized output can be suppressed via the `--no-color` option.

### Forced Certificate Renewal

Normally certificates will be automatically renewed when the tool is run
within the certificate renewal window, e.g. within `renewal_days` of the
certificate's expiration date. To cause certificates to be renewed
before this time, run the tool `update` with the `--force` option on the
command line.

### Revoking Certificates

Should it become necessary to revoke a certificate, for example if it is
believed that the private key has been compromised, run the tool with
the `revoke` action on the command line.

When revoking certificates, as a safety measure, it is necessary to also
specify the common name of certificate that should be revoked. The
certificate files and the primary private key file will be moved to the
archive.

### Authorization Only

Use of the `auth` action on the command line will limit the tool to only
performing domain authorizations.

### Certificates Only

Use of the `update --certs` option on the command line will limit the
tool to only issuing and renewing certificates and keys, and updating
related files such as Diffie-Hellman paramaters.

### Signed Certificate Timestamp Updates

Use of the `update --sct` option on the command line will limit the tool
to only verifying and updating configured Signed Certificate Timestamp
files.

### OCSP Response Updates

Use of the `update --ocsp` option on the command line will limit the
tool to only updating configured OCSP response files.

### Certificate Installation Verification

Use of the `verify` option on the command line will limit the tool to
only performing certificate installation verification.

### Private Key Encryption

When encrypting private keys, a passphrase must be provided. There are
several options for providing the key.

Passphrases may be specified directly in the configuration file, both as
a default passphrase applying to all keys, or specific passphrases for
each key. Storing passphrases in cleartext in the configuration file
obviously does little to protect the private keys if the configuration
file is stored on the same machine. Either protect the configuration
file or use an alternate method of providing passphrases.

Alternatively, by setting the passphrase to `true` in the configuration
file (the binary value, not the string `"true"`), the tool will attempt
to obtain the passphrases at runtime.

Runtime passphrases may be provided on the command line, via an
environment variable, via a text prompt, or via an input file.

A command line passphrase is passed via the `--pass` option, e.g.:

    certmgr --pass "passphrase"

To use an environment variable, set the passphrase in `<COMMON_NAME>_PASSPHRASE` or  `ACME_CLIENT_PASSPHRASE` for the client key.

A passphrase passed at the command line or an environment variable will
be used for every private key that has it's `key_passphrase` set to
`true`. If different passphrases are desired for different keys, run the
tool for each key specifying the private key name on the command line to
restrict processing to that key.

If the passphrase is not provided on the command line or an environment
variable, and the tool is run via a TTY device (e.g. manually in a
terminal), it will prompt the user for each passphrase as needed.
Different passphrases may be provided for each private key (the same
passphrase will be used for all key types of that key).

Finally, the passphrases may be stored in a file, one per line, and
input redirected from that file, e.g.:

    certmgr < passphrase_file.txt

Passphrases passed via an input file will be used in the order that the
private keys are defined in the configuration file. If both certificates
and private key sections are defined, the private keys will be processed
first, then the certificates. You may wish to run the tool without the
input file first to verify the private key order.

## Master/Follower Setup

In some circumstances, it is useful to run the tool in a master/follower
configuration. In this setup, the master performs domain authorizations
while the follower issues and maintains certificates.

This setup is useful when the follower machine does not have the ability
to perform domain authorizations, for example, an XMPP server behind a
firewall that does not have port 80 open or access to a DNS server.

To create a master/follower setup, first install and configure the tool
on the master server as normal. The master server may also issue
certificates, but it is not necessary.

Then install the tool on the follower server. It is not necessary to configure HTTP challenges on the follower.

Before running the tool on the follower server, copy the client key and
registration files from the master server. These files are normally
found in `/etc/certmgr/account` but an alternate location can be
configured using the `data_dir` setting.

If the master server also issues certificates for the same domain names
or parent domain names as the follower, you may want to copy the primary
and backup private keys for those certificates to the follower.

Run the tool on the follower server passing `--no-auth` parameter.

When setting up cron jobs for the master and follower, be sure the
follower runs several minutes after the master so that all
authorizations will be complete. The master can theoretically take
(`max_authorization_attempts` x `authorization_delay`) seconds to obtain
domain authorizations.

It is possible to run several follower servers for each master, the
follower cron jobs should not all run at the same time.
