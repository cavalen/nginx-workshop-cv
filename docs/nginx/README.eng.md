# NGINX Plus Lab 

## Content:
[1. NGINX Plus Installation](#1-nginx-plus-installation)\
[2. NGINX Base Configuration](#2-nginx-base-configuration)\
[3. Configuration Files](#3-configuration-files)\
  . [3.1 First App - f5app.example.com](#create-configuration-for-the-first-app---f5appexamplecom)\
  . [3.2 Second App - echo.example.com](#create-configuration-for-the-second-app---echoexamplecom)\
[4. Web Application Firewall (WAF)](#4-web-application-firewall-waf)\
[5. OpenID Connect (OIDC) Auth](#5-auth-using-openid-connect-oidc)


## 1. NGINX Plus Installation
Note: Installation and configuration of NGINX Plus is done via command line and editing text configuration files.\
Some experience with the Linux CLI is recommended.

Throughout the guide, `vim` will be used to create and modify configuration files, however you can use any editor of your choice.

> [!NOTE]
> Remote Desktop and WebShell (UDF) can cause difficulties when copying and pasting text from configuration files. 
> 
> To create or edit NGINX configuration files with vscode, double-click the `nginx.code-workspace` shortcut on the Jumphost desktop and use the password `HelloUDF`
> 
> ![vscode](./vscode-workspace.png)
> 
> ![vscode-root](./root-password.png)
>
> 
> I case you need to reload NGINX configuration you can use the vscode terminal.
> 
> The rest of the instructions assume that you are editing files via the command line with `vim`.

> [!NOTE]
> <mark>IMPORTANT: All of the configuration steps are done in the `nginx` server \
>  Log-in with user `ubuntu` and password `HelloUDF`</mark>

Open a terminal and SSH to the `nginx` server:
```
ssh ubuntu@10.1.1.7
```
To validate we are in the correct server, chech the CLI prompt  `ubuntu@nginx ~`
![SSH Nginx](./ssh-nginx.png)

This Lab steps can be summarized like this flow:
![Configuration flow](./install-flow.png)
And those are the steps we will follow next:

- OS Pre-requisites:
  ```sh
  sudo apt-get install -y apt-transport-https lsb-release ca-certificates wget gnupg2 ubuntu-keyring
  ```
- Signing Keys:
  ```sh
  wget -qO - https://cs.nginx.com/static/keys/nginx_signing.key | gpg --dearmor | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
  ```
  ```sh
  wget -qO - https://cs.nginx.com/static/keys/app-protect-security-updates.key | gpg --dearmor | sudo tee /usr/share/keyrings/app-protect-security-updates.gpg >/dev/null
- Add NGINX Repositories:
  ```sh
  printf "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://pkgs.nginx.com/plus/ubuntu `lsb_release -cs` nginx-plus\n" | sudo tee /etc/apt/sources.list.d/nginx-plus.list
  ```
  ```sh
  printf "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://pkgs.nginx.com/app-protect/ubuntu `lsb_release -cs` nginx-plus\n" | sudo tee /etc/apt/sources.list.d/nginx-app-protect.list
  ```
  ```sh
  printf "deb [signed-by=/usr/share/keyrings/app-protect-security-updates.gpg] https://pkgs.nginx.com/app-protect-security-updates/ubuntu `lsb_release -cs` nginx-plus\n" | sudo tee -a /etc/apt/sources.list.d/nginx-app-protect.list
  ```
  ```sh
  sudo wget -P /etc/apt/apt.conf.d https://cs.nginx.com/static/files/90pkgs-nginx
  ```
- Install packages:\
  NGINX Plus installation requires a certificate/key pair to authenticate into the F5/NGINX repositories and should be located in `/etc/ssl/nginx/nginx-repo.crt` & `/etc/ssl/nginx/nginx-repo.key` (This is already done)

  ```sh
  sudo apt update && sudo apt install -y nginx-plus app-protect nginx-plus-module-njs
  ```

  `nginx-plus` is NGINX Plus main package\
  `app-protect` is the WAF package\
  `nginx-plus-module-njs` is the NGINX JavaScript (NJS) package, and it is needed by the OIDC integration

- Enable NGINX at boot time and validate the install:
  ```sh
  sudo systemctl enable nginx
  sudo systemctl start nginx
  nginx -v
  ```
  ```
  curl http://0:80
  ```
  `nginx -v` Show NGINX version\
  `curl http://0:80` Returns the default NGINX web site

- Delete the "default site" config file, this one is not needed
  ```sh
  sudo rm /etc/nginx/conf.d/default.conf
  ```

## 2. NGINX Base Configuration
- Edit `/etc/nginx/nginx.conf` to add the WAF and NJS dynamic modules\
  `load_module modules/ngx_http_app_protect_module.so;`\
  `load_module modules/ngx_http_js_module.so;`\
  \
  Aditionaly, we need to configure 2 internal variables that are recommended when using NJS and OIDC integration\
  `variables_hash_max_size 2048;`\
  `variables_hash_bucket_size 128;`
  ```sh
  sudo vim /etc/nginx/nginx.conf
  ```
  The `nginx.conf` config file should look like this:
  ```nginx
  user  nginx;
  worker_processes  auto;

  error_log  /var/log/nginx/error.log notice;
  pid        /var/run/nginx.pid;

  load_module modules/ngx_http_app_protect_module.so;
  load_module modules/ngx_http_js_module.so;

  events {
      worker_connections  1024;
  }

  http {
      # Necesarias a la hora de configurar OIDC. Si no se incluyen, se va a presentar un Warning.
      variables_hash_max_size 2048;
      variables_hash_bucket_size 128;

      include       /etc/nginx/mime.types;
      default_type  application/octet-stream;

      log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                        '$status $body_bytes_sent "$http_referer" '
                        '"$http_user_agent" "$http_x_forwarded_for"';

      access_log  /var/log/nginx/access.log  main;

      sendfile        on;
      #tcp_nopush     on;

      keepalive_timeout  65;

      #gzip  on;

      include /etc/nginx/conf.d/*.conf;
  }

  # TCP/UDP proxy and load balancing block
  #
  #stream {
      # Example configuration for TCP load balancing

      #upstream stream_backend {
      #    zone tcp_servers 64k;
      #    server backend1.example.com:12345;
      #    server backend2.example.com:12345;
      #}

      #server {
      #    listen 12345;
      #    status_zone tcp_server;
      #    proxy_pass stream_backend;
      #}
  #}

  # NGINX Plus Usage Reporting
  #
  # By default, every 30 minutes, NGINX Plus will send usage information
  # to NGINX Instance Manager, resolved by a "nginx-mgmt.local" DNS entry.
  # Alternate settings can be configured by uncommenting the "mgmt" block
  # and optional directives.
  #
  #mgmt {
      #usage_report endpoint=nginx-mgmt.local interval=30m;
      #resolver DNS_IP;

      #uuid_file /var/lib/nginx/nginx.id;

      #ssl_protocols TLSv1.2 TLSv1.3;
      #ssl_ciphers DEFAULT;

      #ssl_certificate          client.pem;
      #ssl_certificate_key      client.key;

      #ssl_trusted_certificate  trusted_ca_cert.crt;
      #ssl_verify               on;
      #ssl_verify_depth         2;
  #}
  ```

- Create the configuration to expose the NGINX Plus Dashboard and API endpoint. By default port 8080 is used.
  ```sh
  sudo vim /etc/nginx/conf.d/api.conf
  ```
  ```nginx
  server {
      listen 8080;
      access_log off; # reduce noise in access logs

      location /api/ {
          api write=on;
          #allow 127.0.0.1;
          #allow 192.168.0.0/20;
          allow 0.0.0.0/0;
          deny all;
      }

      # Conventional location of the NGINX Plus dashboard
      location = /dashboard.html {
          root /usr/share/nginx/html;
      }

      # Redirect requests for "/" to "/dashboard.html"
      location / {
          return 301 /dashboard.html;
      }

      # Enable Swagger UI
      location /swagger-ui {
          root   /usr/share/nginx/html;
      }
  }
  ```
- Reload NGINX configuration:
  ```sh
  sudo nginx -s reload
  ```
  Test from the browser - **http://dashboard.example.com:8080**

  ![NGINX Dashboard](./nginx-dashboard.png)
  The Dashboard is not showing much information yet, because there are no applications configured to be proxied by NGINX.
 ---
## 3. Configuration Files
It is recommended to create independant configuration files (one per site) with extension `.conf` and located inside the folder `/etc/nginx/conf.d/` and using a name related to the site/app to be exposed, example: `api.mysite.com.conf`. But any name with a `conf` extension will work.

- ### Create configuration for the first App - *f5app.example.com*
  ```sh
  sudo vim /etc/nginx/conf.d/f5app.example.com.conf
  ```
  The file `f5app.example.com.conf` should look like this:
  ```nginx
  # Custom Health Check
  match f5app_health {
      status 200;
      body ~ "F5 K8S vLab";
  }

  server {
      listen 80 default_server;
      server_name www.example.com;
      status_zone www.example.com_http;

      location / {
          # Active Health Check
          health_check match=f5app_health interval=10 fails=3 passes=2 uri=/;

          proxy_pass http://f5app-backend;
      }
  }

  upstream f5app-backend {
      # Load Balancing Algorithm, Default = RoundRobin
      # random;
      keepalive 16;
      zone backend 64k;
      server 10.1.1.6:8080;
      #server 10.1.1.6:8090;
      #sticky cookie helloworld expires=1h domain=.example.com path=/;  ## SESSION PERSISTENCE
  }
  ```
  Reload NGINX configuration:
  ```sh
  sudo nginx -s reload
  ```

  Test from the browser - **http://f5app.example.com**

  ![f5app](./f5app.png)

  This application is being exposed through the reverse-proxy, but it is not protected: 
  - Go to Demos > Credit Cards :arrow_right: Note that the server is exposing sensitive information (credit card numbers).
  - Run a XSS - `http://f5app.example.com/<script>Danger!</script>` (The App return a 404 Not Found, however the server processes the request)

  Validate in the NGINX Plus Dashboard, now we can see information from f5app, metrics, health state and monitores - **http://dashboard.example.com:8080**

  Now, let's modify the Heath-Check configuration:
  ```sh
  sudo vim /etc/nginx/conf.d/f5app.example.com.conf
  ```
  We must change the block `match f5app_health` like this: 
  ```
  match f5app_health {
      status 200;
      body ~ "Workshop K8S vLab";
  }
  ```
  The Body section now contains a string that the server's answer do not contain.
  Reload the configuration with `sudo nginx -s reload` y test the application again.
  ![502 error](./f5app-502.png)

  **What is happening?** The App does not work, this is expected, and the answer from NGINX is `502 Bad Gateway` because there are no healthy upstreams (The string **"Workshop K8S vLab** is not found in the reponse body)


  In the NGINX Plus Dashboard we can see the number of successful healthchecks and the upstream health.
  ![Dashboard f5app](./f5app-dashboard.png)

  > [!NOTE]
  > ### <mark>**Please reverse the changes to the health check (body = F5 K8S vLab) and reload NGINX configuration before continuing with the lab**</mark>
    ```
  match f5app_health {
      status 200;
      body ~ "F5 K8S vLab";
  }
  ```
  #### Load Balancing:

  In the next step we are going to configure Load Balancing.
  To do this, remove the comment `#` from the second `server` inside the block `upstream f5app-backend`, towards the end of the file. Finally reload NGINX configuration. 
  
  The default Load Balancing method is Round Robin.

  Test from the browser - **http://f5app.example.com**. Note how the app now is pulling content from 2 different upstream servers (in 2 different colors). If you check the NGINX Plus Dashboad now there are 2 upstream servers in the f5app application.

- ### Create configuration for the second App - *echo.example.com*
  ```sh
  sudo vim /etc/nginx/conf.d/echo.example.com.conf
  ```
  The configuration file `echo.example.com.conf` should loook like this:
  ```nginx
  server {
      listen 443 ssl;
      server_name echo.example.com;
      status_zone echo.example.com_http;

      ssl_certificate /etc/ssl/nginx/echo.example.com.crt;
      ssl_certificate_key /etc/ssl/nginx/echo.example.com.key;
      ssl_ciphers TLS_AES_256_GCM_SHA384:HIGH:!aNULL:!MD5;
      ssl_prefer_server_ciphers on;

      location / {
          proxy_pass http://10.1.1.6:8081;
      }
  }
  ```
  Note in the configuration how this second application is using TLS termination in the NGINX proxy. Another thing to notice is that there is no `upstream` block in the configureation, and the traffic is being proxied directly to an existing backend and is not doing Load Balancing.

Reload NGINX configuration:
  ```sh
  sudo nginx -s reload
  ```

  Test from the browser - **https://echo.example.com**

  This is a simple application that show information from the request (including Headers) in JSON format.

  ![echo](./echo.png)

  Now let's configure *"header insertion"*, we should be able to see the new injected headers in the "echo" application..

  ```
  sudo vim /etc/nginx/conf.d/echo.example.com.conf
  ```
  Add this directives to the existing configuration inside the `location /` block:
  ```
  add_header X-ServerIP $server_addr;
  add_header X-srv-hostname $hostname;

  proxy_set_header X-Client-IP $remote_addr;
  proxy_set_header X-Hola "Mundo";
  ```

  The configuration file `echo.example.com.conf` should look like this:
  ```nginx
  server {
      listen 443 ssl;
      server_name echo.example.com;
      status_zone echo.example.com_http;

      ssl_certificate /etc/ssl/nginx/echo.example.com.crt;
      ssl_certificate_key /etc/ssl/nginx/echo.example.com.key;
      ssl_ciphers TLS_AES_256_GCM_SHA384:HIGH:!aNULL:!MD5;
      ssl_prefer_server_ciphers on;

      location / {
          add_header X-ServerIP $server_addr;
          add_header X-srv-hostname $hostname;

          proxy_set_header X-Client-IP $remote_addr;
          proxy_set_header X-Hola "Mundo";

          proxy_pass http://10.1.1.6:8081;
      }
  }
  ```
  `add_header` Adds a header to server's response\
  `proxy_set_header` Adds a header to the customer request before sending to the upstream/backend server\
  
  The parameters `$server_addr`, `$hostname`, `$remote_addr` are internal NGINX variables. The full list of variables used by NGNIX is in the documentation - **http://nginx.org/en/docs/http/ngx_http_core_module.html#variables** 

  **NOTE:** Reponse headers (add_header) can be seen using the Browser's Developer Tools.

---

## 4. Web Application Firewall (WAF)
NGINX App Protect (v4) use JSON config files for its declarative security policy. These files can be on any location in the filesystem, for this lab we will use the path `/etc/nginx/waf/`

It is also possible to have the security policy as a binary file or "policy bundle", that is created using a software called [NGINX App Protect Policy Compiler](https://docs.nginx.com/nginx-app-protect-waf/v5/admin-guide/compiler/), but for this lab we will use JSON files.

The security policy used for this lab is composed of:
- A JSON file with the WAF's logging format definition
- A JSON file with the base security policy, this file is referenced from `nginx.conf`
- Several optional JSON files referencing various parts or  blocks from the security policy, in this case:
  - JSON for the "Server Technologies" used in the App we are going to protect
  - JSON with a white-list of IP addresses, to wich the WAF will skip enforcing the WAF policy
  -  JSON with specific HTTP Protocol violations.
  -  JSON with Evasion-type violations

Now, we will proceed to create all of the configuration files needed for the WAF policy and enable the WAF for one of the applications deployed in a previous step.

:bulb: Remember, all the files we need can be created/edited via CLI in the `nginx` server, or using vscode from the jumphost ubuntu-server

-  Create the log profile definition in `/etc/nginx/waf/`
   ```sh
   sudo mkdir /etc/nginx/waf
   sudo vim /etc/nginx/waf/log-grafana.json
   ```
   This file use an specific log format suited for a Grafana Dashboard.\
   There is also a `default` format recommended for basic logging using `syslog` and there are other pre-defined formats like `big-iq`, `arcsight`, `grpc`, `splunk` and `user-defined` (this is the one used in this lab).

   The logging profile should look like this:
   ```json
   {
     "filter": {
       "request_type": "illegal"
     },
     "content": {
       "format": "user-defined",
       "format_string": "{\"campaign_names\":\"%threat_campaign_names%\",\"bot_signature_name\":\"%bot_signature_name%\",\"bot_category\":\"%bot_category%\",\"bot_anomalies\":\"%bot_anomalies%\",\"enforced_bot_anomalies\":\"%enforced_bot_anomalies%\",\"client_class\":\"%client_class%\",\"client_application\":\"%client_application%\",\"json_log\":%json_log%}",
       "max_request_size": "500",
       "max_message_size": "30k",
       "escaping_characters": [
         {
           "from": "%22%22",
           "to": "%22"
         }
       ]
     }
   }
   ```
- Create the base security policy in `/etc/nginx/waf/`
   ```sh
   sudo vim /etc/nginx/waf/NginxCustomPolicy.json
   ```
   ```json
   {
       "policy": {
           "name": "NGINX_Base_with_modifications",
           "template": { "name": "POLICY_TEMPLATE_NGINX_BASE" },
           "applicationLanguage": "utf-8",
           "enforcementMode": "blocking",
           "blocking-settings": {
              "violations": [
                  {
                      "name": "VIOL_RATING_THREAT",
                      "alarm": true,
                      "block": true
                  },
                  {
                      "name": "VIOL_RATING_NEED_EXAMINATION",
                      "alarm": false,
                      "block": false
                  },
                  {
                      "name": "VIOL_THREAT_CAMPAIGN",
                      "alarm": true,
                      "block": true
                  },
                  {
                      "name": "VIOL_FILETYPE",
                      "alarm": true,
                      "block": true
                  },
                  {
                       "name": "VIOL_EVASION",
                       "alarm": true,
                       "block": true
                   },
                   {
                       "name": "VIOL_METHOD",
                       "alarm": true,
                       "block": true
                   },
                   {
                       "name": "VIOL_HTTP_PROTOCOL",
                       "alarm": false,
                       "block": false
                   },
                   {
                       "name": "VIOL_DATA_GUARD",
                       "alarm": false,
                       "block": false
                   },
                   {
                       "name": "VIOL_HTTP_RESPONSE_STATUS",
                       "alarm": true,
                       "block": true
                   },
                   {
                       "name": "VIOL_BLACKLISTED_IP",
                       "alarm": true,
                       "block": true
                   }
              ],
              "httpProtocolReference": {
                   "link": "file:///etc/nginx/waf/http-protocols.json"
              },
              "evasionReference": {
                  "link": "file:///etc/nginx/waf/evasions.json"
              }
           },
           "general": {
               "allowedResponseCodes": [
                   400,
                   401,
                   403,
                   404,
                   502
               ],
               "trustXff": true
           },
           "header-settings": {
               "maximumHttpHeaderLength": 4096
           },
           "serverTechnologyReference": {
               "link": "file:///etc/nginx/waf/server-technologies.json"
           },
           "responsePageReference": {
               "link": "https://raw.githubusercontent.com/cavalen/acme/master/response-pages-v2.json"
           },
           "whitelistIpReference": {
               "link": "file:///etc/nginx/waf/whitelist-ips.json"
           },
           "data-guard": {
               "enabled": true,
               "maskData": true,
               "creditCardNumbers": true,
               "usSocialSecurityNumbers": true,
               "enforcementMode": "ignore-urls-in-list",
               "enforcementUrls": [],
               "lastCcnDigitsToExpose": 4,
               "lastSsnDigitsToExpose": 4
           }
       }
   }
   ```
   If we check the file structure, we can see the different configuration blocks or parts, like violations, enforcement mode (Blocking / Transparent), DataGuard (Sensitive Data exfiltration by the server), response Pages (response presented when there is a violation), valid HTTP response codes and some other options documented in our [NGINX App Protect declarative policy documentation]( https://docs.nginx.com/nginx-app-protect-waf/v4/declarative-policy/policy/)\
   **https://docs.nginx.com/nginx-app-protect-waf/v4/declarative-policy/policy/**

- Create the "Server Technologies" definition in `/etc/nginx/waf/`
   ```sh
   sudo vim /etc/nginx/waf/server-technologies.json
   ```
   ```json
   [
     {
       "serverTechnologyName": "MySQL"
     },
     {
       "serverTechnologyName": "Unix/Linux"
     },
     {
       "serverTechnologyName": "Node.js"
     },
     {
       "serverTechnologyName": "Nginx"
     }
   ]
   ```
- Create the Whitelist configuration in `/etc/nginx/waf/`
   ```sh
   sudo vim /etc/nginx/waf/whitelist-ips.json
   ```
   ```json
   [
       {
           "blockRequests": "never",
           "neverLogRequests": false,
           "ipAddress": "1.1.1.1",
           "ipMask": "255.255.255.255"
       },
       {
           "blockRequests": "always",
           "ipAddress": "2.2.2.2",
           "ipMask": "255.255.255.255"
       },
       {
           "blockRequests": "never",
           "neverLogRequests": false,
           "ipAddress": "3.3.3.0",
           "ipMask": "255.255.255.0"
       },
       {
           "blockRequests": "always",
           "neverLogRequests": false,
           "ipAddress": "180.18.19.20",
           "ipMask": "255.255.255.255"
       }
   ]
   ```
- Create the "HTTP Protocol Compliance" configuration in `/etc/nginx/waf/`
   ```sh
   sudo vim /etc/nginx/waf/http-protocols.json
   ```
   ```json
   [
       {
           "description": "Header name with no header value",
           "enabled": true
       },
       {
           "description": "Chunked request with Content-Length header",
           "enabled": true
       },
       {
           "description": "Check maximum number of parameters",
           "enabled": true,
           "maxParams": 5
       },
       {
           "description": "Check maximum number of headers",
           "enabled": true,
           "maxHeaders": 20
       },
       {
           "description": "Body in GET or HEAD requests",
           "enabled": true
       },
       {
           "description": "Bad multipart/form-data request parsing",
           "enabled": true
       },
       {
           "description": "Bad multipart parameters parsing",
           "enabled": true
       },
       {
           "description": "Unescaped space in URL",
           "enabled": true
       },
       {
           "description": "Host header contains IP address",
           "enabled": false
       }
   ]
   ```
- Create the Evasion Settings configuration file in `/etc/nginx/waf/`
   ```sh
   sudo vim /etc/nginx/waf/evasions.json
   ```
   ```json
   [
       {
           "description": "Bad unescape",
           "enabled": true
       },
       {
           "description": "Directory traversals",
           "enabled": true
       },
       {
           "description": "Bare byte decoding",
           "enabled": true
       },
       {
           "description": "Apache whitespace",
           "enabled": false
       },
       {
           "description": "Multiple decoding",
           "enabled": true,
           "maxDecodingPasses": 2
       },
       {
           "description": "IIS Unicode codepoints",
           "enabled": true
       },
       {
           "description": "IIS backslashes",
           "enabled": true
       },
       {
           "description": "%u decoding",
           "enabled": true
       }
   ]
   ```
- The first thing we need to do to enable NAP (NGINX App Protect) is to load the WAF dynamic module inside `nginx.conf`, this was done in a previous step in this lab, by adding the directive `load_module` [in this section](#2-nginx-base-configuration)

   Next step is to activate the WAF for the `f5app` application, editing the file `/etc/nginx/conf.d/f5app.example.com.conf`

   WAF configurations can be added at the `server {}` level and apply to all of the application ("global") or can be added inside a specific `location` only. In this case we will add the waf for the `f5app` application in the server block.

   The lines we need to add to the configuration file in the `server` block are:
   ```
   app_protect_enable on;
   app_protect_security_log_enable on;
   app_protect_security_log "/etc/nginx/waf/log-grafana.json" syslog:server=grafana.example.com:8515;
   app_protect_policy_file "/etc/nginx/waf/NginxCustomPolicy.json";
   ```

   `app_protect_enable on;` Activates the WAF.\
   `app_protect_security_log_enable on;` Activates logging for the WAF.\
   `app_protect_security_log "/etc/nginx/waf/log-grafana.json" syslog:server=grafana.example.com:8515;` Specifies the logging format to be used (by referencing a JSON configuration) and the destination for the logs (a grafana server in this case). This directive can be used multiple times to send logs to several destinations.\
   `app_protect_policy_file "/etc/nginx/waf/NginxCustomPolicy.json";` Indicates the WAF policy to use.

   Enable WAF for f5app.example.com: 
   ```
   sudo vim /etc/nginx/conf.d/f5app.example.com.conf
   ```

   The file `f5app.example.com.conf` should look like this:
   ```nginx
   # Custom Health Check
   match f5app_health {
       status 200;
       body ~ "F5 K8S vLab";
   }

   server {
       listen 80 default_server;
       server_name f5app.example.com;
       status_zone f5app.example.com_http;

       app_protect_enable on;
       app_protect_security_log_enable on;
       app_protect_security_log "/etc/nginx/waf/log-grafana.json" syslog:server=grafana.example.com:8515;
       app_protect_policy_file "/etc/nginx/waf/NginxCustomPolicy.json";

       location / {
           # Active Health Check
           health_check match=f5app_health interval=10 fails=3 passes=2 uri=/;
           proxy_pass http://f5app-backend;
       }
   }

   upstream f5app-backend {
       # Load Balancing Algorithm, Default = RoundRobin
       # random;
       keepalive 16;
       zone backend 64k;
       server 10.1.1.6:8080;
       server 10.1.1.6:8090;
       #sticky cookie helloworld expires=1h domain=.example.com path=/;  ## SESSION PERSISTENCE
   }
   ```

  Reload NGINX configuration:
  ```
  sudo nginx -s reload
  ```
  Validate the configuration is ok with:
  ```
  sudo nginx -t
  ```

  Test from the browser - **http://f5app.example.com**

  Now, let's make some ilegal requests to the application and <mark> take note of the SupportID</mark>
    - XSS example: `http://f5app.example.com/<script>Danger!</script>`
    - SQLi example: `http://f5app.example.com/?a='or 1=1#'`
    - Navegate to: Demos > CC Numbers and note that the DataGuard feature obfuscates sensitive information (credit card numbers).

  Go to the Grafana Dashboard and have a look at the logs sent by the WAF - **http://grafana.example.com:3000**

  Browse the Attack Signatures, Main Dashboard y SupportIDs dashboards:
  ![Grafana Dashboars](./grafana1.png)

  ![Grafana Dashboars](./grafana2.png)

## 5. Auth using OpenID Connect (OIDC)
NGINX Plus allows the integration with an Identity Provider (IdP) to authenticate users before "proxying" them to the application or backend.

:warning: This integration us a manual process, it is done with an additional component that must be downloaded from [GitHub](https://github.com/nginxinc/nginx-openid-connect) and configured according to your OIDC environment. 

```mermaid
flowchart BT
    subgraph " "
        direction LR
        id1(User)==>|Request for app|id2
        id2-. Unauthenticated .->id1
        id2(NGINX+)-->|Authenticated|id3(Backend app)
    end
    subgraph IDP
        id4(Authorization Server)
    end
    id1<-. User authenticates directly with IdP .->IDP
    IDP<-. NGINX exchanges authorization code for ID token .->id2
    style id1 fill:#fff,stroke:#444,stroke-width:3px,color:#222
    style id3 fill:#fff,stroke:#444,stroke-width:3px,color:#222
    style id2 fill:#009639,stroke:#215732,stroke-width:2px,color:#fff
    style id4 fill:#666,stroke:#222,stroke-width:1px,color:#fff
```
`Figure 1. High level components of an OpenID Connect environment`

This implementation assumes the following environment:
  * The identity provider (IdP) supports OpenID Connect 1.0
  * The authorization code flow is in use
  * NGINX Plus is configured as a relying party
  * The IdP knows NGINX Plus as a confidential client or a public client using PKCE

Detailed documentation is available at https://github.com/nginxinc/nginx-openid-connect

With this environment, both the client and NGINX Plus communicate directly with the IdP at different stages during the initial authentication event.

```mermaid
sequenceDiagram
    autonumber
    actor User
    participant Browser
    participant IdP
    participant NGINX Plus
    participant Web App
    User->>NGINX Plus: Requests protected resource
    NGINX Plus->>Browser: Sends redirect to IdP for authentication
    Browser->>IdP: Requests login page
    User->>IdP: Provides authentication and consent
    IdP->>Browser: Sends redirect w/ authZ code
    Browser->>NGINX Plus: Redirected for code exchange
    NGINX Plus->>IdP: Sends authZ code
    IdP->>NGINX Plus: Sends ID(+refresh) token
    NGINX Plus-->>NGINX Plus: Validates ID token, stores in keyval, creates session cookie
    Note right of NGINX Plus: keyvals zone for ID token (JWT)
    Note right of NGINX Plus: keyval zone for refresh token
    NGINX Plus->>Browser: Sends redirect to original URI with session cookie
    Browser->>NGINX Plus: Requests original URI, supplies session cookie
    NGINX Plus-->>NGINX Plus: Obtains ID token from keyval, validates JWT
    NGINX Plus->>Web App: Proxies request
    Web App->>Browser: Sends resource
```
`Figure 2. OpenID Connect authorization code flow protocol`

This lab includes a `keycloak` deployment used as Identity Provider (IdP), here we will validate user credentials.

Keycloak is pre-configured, and can be accesed at **https://keycloak.example.com** using `admin/admin` credentials. There is also a `nginx-plus` client and a `test` user (password = test)

| Client                        | User                          |
|-------------------------------|-------------------------------|
| ![Keycloak1](./keycloak1.png) | ![Keycloak2](./keycloak2.png) |

- At a high level, the configuration process have 5 steps:
   1. Download the needed software from GitHub, this software provides the integration with OIDC.
   2. Run a configuration script via command line.
   3. Validate the output of the script (a set of files) against your Identity Provider settings.
   4. Copy the new files created by the script where the nginx configuration for the application we want to integrate with OIDC is located (Usually `/etc/nginx/conf.d`)
   5. Edit the site's configuraion (`/etc/nginx/conf.d/<your-app>.conf`) and add the needed directives generated by the script.

- First, create a new "app", to wich we will add an authentication layer using NGINX and OIDC. Let's name this app `oidc.example.com`
  ```
  sudo vim /etc/nginx/conf.d/oidc.example.com.conf
  ```
  ```nginx
  server {
      listen 443 ssl;
      server_name oidc.example.com;
      status_zone oidc.example.com_http;

      ssl_certificate /etc/ssl/nginx/oidc.example.com.crt;
      ssl_certificate_key /etc/ssl/nginx/oidc.example.com.key;
      ssl_ciphers TLS_AES_256_GCM_SHA384:HIGH:!aNULL:!MD5;
      ssl_prefer_server_ciphers on;

      location / {
          add_header X-ServerIP $server_addr;
          add_header X-srv-hostname $hostname;

          proxy_set_header X-Client-IP $remote_addr;
          proxy_set_header X-Hola "Mundo";

          proxy_pass http://10.1.1.6:8081;
      }
  }
  ```
  ```
  sudo nginx -s reload
  ```

- Download software from GitHub.\
  NOTE: there is a recommended branch for every NGINX Plus release. As an example: if you are using NGINX Plus R31 the git command to pull the repository should include the recommended branch (`git clone -b R31 <REPO>`)\
  
  In this case, download the latest version.
  ```sh
  git clone https://github.com/nginxinc/nginx-openid-connect
  ```
  ```sh
  cd nginx-openid-connect
  ```

  The configuration script requires some information that must be provided by the IdP admin:
  ```sh
  ./configure.sh -x -h oidc.example.com -k request -i nginx-plus -s 1234567890ABCDEF http://keycloak.example.com/realms/master/.well-known/openid-configuration
  ```
  `-h` IdP Hostname or FQDN\
  `-x` Insecure, ignore invalid TLS certificates (OK in testing environments)\
  `-i nginx-plus` Client ID, as configured in the Identity Provider (IdP)\
  `-s 1234567890ABCDEF` Client Secret, as configured in the Identity Provider (IdP)\
  `http://keycloak.example.com/realms/master/.well-known/openid-configuration` IdP Discovery interface.

- OIDC Parameter Configuration (1)

  After running the configuration script, we need to edit some files. The first one we need to edit is `openid_connect_configuration.conf`

  The only change we need to is the `resolver` directive at the top of the file.\
  We are using a test domain `example.com`, this will not resolve by the public DNS server that the script use by default (8.8.8.8), because of this, we need to use an internal DNS `127.0.0.53`

  ```sh
  sudo vim openid_connect.server_conf
  ```
  The file `openid_connect.server_conf` should look like this:
  ```nginx
      # Advanced configuration START
    set $internal_error_message "NGINX / OpenID Connect login failure\n";
    set $pkce_id "";
    resolver 127.0.0.53; # For DNS lookup of IdP endpoints;
    subrequest_output_buffer_size 32k; # To fit a complete tokenset response
    gunzip on; # Decompress IdP responses if necessary
    # Advanced configuration END

    location = /_jwks_uri {
        internal;
        proxy_cache jwk;                              # Cache the JWK Set received from IdP
        proxy_cache_valid 200 12h;                    # How long to consider keys "fresh"
        proxy_cache_use_stale error timeout updating; # Use old JWK Set if cannot reach IdP
        proxy_ssl_server_name on;                     # For SNI to the IdP
        proxy_method GET;                             # In case client request was non-GET
        proxy_set_header Content-Length "";           # ''
        proxy_pass $oidc_jwt_keyfile;                 # Expecting to find a URI here
        proxy_ignore_headers Cache-Control Expires Set-Cookie; # Does not influence caching
    }

    location @do_oidc_flow {
        status_zone "OIDC start";
        js_content oidc.auth;
        default_type text/plain; # In case we throw an error
    }

    set $redir_location "/_codexch";
    location = /_codexch {
        # This location is called by the IdP after successful authentication
        status_zone "OIDC code exchange";
        js_content oidc.codeExchange;
        error_page 500 502 504 @oidc_error;
    }

    location = /_token {
        # This location is called by oidcCodeExchange(). We use the proxy_ directives
        # to construct the OpenID Connect token request, as per:
        #  http://openid.net/specs/openid-connect-core-1_0.html#TokenRequest
        internal;
        proxy_ssl_server_name on; # For SNI to the IdP
        proxy_set_header      Content-Type "application/x-www-form-urlencoded";
        proxy_set_header      Authorization $arg_secret_basic;
        proxy_pass            $oidc_token_endpoint;
   }

    location = /_refresh {
        # This location is called by oidcAuth() when performing a token refresh. We
        # use the proxy_ directives to construct the OpenID Connect token request, as per:
        #  https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken
        internal;
        proxy_ssl_server_name on; # For SNI to the IdP
        proxy_set_header      Content-Type "application/x-www-form-urlencoded";
        proxy_set_header      Authorization $arg_secret_basic;
        proxy_pass            $oidc_token_endpoint;
    }

    location = /_id_token_validation {
        # This location is called by oidcCodeExchange() and oidcRefreshRequest(). We use
        # the auth_jwt_module to validate the OpenID Connect token response, as per:
        #  https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation
        internal;
        auth_jwt "" token=$arg_token;
        js_content oidc.validateIdToken;
        error_page 500 502 504 @oidc_error;
    }

    location = /logout {
        status_zone "OIDC logout";
        add_header Set-Cookie "auth_token=; $oidc_cookie_flags";
        add_header Set-Cookie "auth_nonce=; $oidc_cookie_flags";
        add_header Set-Cookie "auth_redir=; $oidc_cookie_flags";
        js_content oidc.logout;
    }

    location = /_logout {
        # This location is the default value of $oidc_logout_redirect (in case it wasn't configured)
        default_type text/plain;
        return 200 "Logged out\n";
    }

    location @oidc_error {
        # This location is called when oidcAuth() or oidcCodeExchange() returns an error
        status_zone "OIDC error";
        default_type text/plain;
        return 500 $internal_error_message;
    }

    location /api/ {
        api write=on;
        allow 127.0.0.1; # Only the NGINX host may call the NGINX Plus API
        deny all;
        access_log off;
    }

    # vim: syntax=nginx
    ```

- OIDC Parameter Configuration (2)

  The seconf file to edit is `openid_connect_configuration.conf`.
  We must validate that the content of the file matches the OIDC endpoints from the IdP (Keycloak). 

  The IdP administrator must provide the correct values and  debe conocer estos valores, Additionally, the `openid-configurations` URL from the IdP can help us with this validation:

  **http://keycloak.example.com/realms/master/.well-known/openid-configuration**
  
  ![Keycloak3](./keycloak3.png)

  The values we need to configure are in the `map` directives:
  | Parameter | Value |
  |-----------|-------|
  | `$oidc_authz_endpoint` | `oidc.example.com https://keycloak.example.com/realms/master/protocol/openid-connect/auth;` |
  | `$oidc_token_endpoint` | `oidc.example.com https://keycloak.example.com/realms/master/protocol/openid-connect/token;` |
  | `$oidc_jwt_keyfile` | `oidc.example.com https://keycloak.example.com/realms/master/protocol/openid-connect/certs;` |
  | `$host $oidc_client` | `oidc.example.com nginx-plus;` |
  | `$oidc_client_secret` | `oidc.example.com 1234567890ABCDEF;` |
  
  Modify the configuration accordingly:
  ```sh
  sudo vim openid_connect_configuration.conf
  ```
  The file `openid_connect_configuration.conf` should look like this:
  ```nginx
  # OpenID Connect configuration
  #
  # Each map block allows multiple values so that multiple IdPs can be supported,
  # the $host variable is used as the default input parameter but can be changed.
  #
  map $host $oidc_authz_endpoint {
      oidc.example.com https://keycloak.example.com/realms/master/protocol/openid-connect/auth;

      default "http://127.0.0.1:8080/auth/realms/master/protocol/openid-connect/auth";
      #www.example.com "https://my-idp/oauth2/v1/authorize";
  }

  map $host $oidc_authz_extra_args {
      # Extra arguments to include in the request to the IdP's authorization
      # endpoint.
      # Some IdPs provide extended capabilities controlled by extra arguments,
      # for example Keycloak can select an IdP to delegate to via the
      # "kc_idp_hint" argument.
      # Arguments must be expressed as query string parameters and URL-encoded
      # if required.
      default "";
      #www.example.com "kc_idp_hint=another_provider"
  }

  map $host $oidc_token_endpoint {
      oidc.example.com https://keycloak.example.com/realms/master/protocol/openid-connect/token;

      default "http://127.0.0.1:8080/auth/realms/master/protocol/openid-connect/token";
  }

  map $host $oidc_jwt_keyfile {
      oidc.example.com https://keycloak.example.com/realms/master/protocol/openid-connect/certs;

      default "http://127.0.0.1:8080/auth/realms/master/protocol/openid-connect/certs";
  }

  map $host $oidc_end_session_endpoint {
      oidc.example.com https://keycloak.example.com/realms/master/protocol/openid-connect/certs;


      # Specifies the end_session_endpoint URL for RP-initiated logout.
      # If this variable is empty or not set, the default behavior is maintained,
      # which logs out only on the NGINX side.
      default "";
  }

  map $host $oidc_client {
      oidc.example.com nginx-plus;

      default "my-client-id";
  }

  map $host $oidc_pkce_enable {
      default 0;
  }

  map $host $oidc_client_secret {
      oidc.example.com 1234567890ABCDEF;


      default "my-client-secret";
  }

  map $host $oidc_client_auth_method {
      # Choose either "client_secret_basic" for sending client credentials in the
      # Authorization header, or "client_secret_post" for sending them in the
      # body of the POST request. This setting is used for confidential clients.
      default "client_secret_post";
  }

  map $host $oidc_scopes {
      default "openid+profile+email+offline_access";
  }

  map $host $oidc_logout_redirect {
      # Where to send browser after requesting /logout location. This can be
      # replaced with a custom logout page, or complete URL.
      default "/_logout"; # Built-in, simple logout page
  }

  map $host $oidc_hmac_key {
      oidc.example.com MPjqIKKjiKExZPKj3B7Q4xCV;

      # This should be unique for every NGINX instance/cluster
      default "ChangeMe";
  }

  map $host $zone_sync_leeway {
      # Specifies the maximum timeout for synchronizing ID tokens between cluster
      # nodes when you use shared memory zone content sync. This option is only
      # recommended for scenarios where cluster nodes can randomly process
      # requests from user agents and there may be a situation where node "A"
      # successfully received a token, and node "B" receives the next request in
      # less than zone_sync_interval.
      default 0; # Time in milliseconds, e.g. (zone_sync_interval * 2 * 1000)
  }

  map $proto $oidc_cookie_flags {
      http  "Path=/; SameSite=lax;"; # For HTTP/plaintext testing
      https "Path=/; SameSite=lax; HttpOnly; Secure;"; # Production recommendation
  }

  map $http_x_forwarded_port $redirect_base {
      ""      $proto://$host:$server_port;
      default $proto://$host:$http_x_forwarded_port;
  }

  map $http_x_forwarded_proto $proto {
      ""      $scheme;
      default $http_x_forwarded_proto;
  }

  # ADVANCED CONFIGURATION BELOW THIS LINE
  # Additional advanced configuration (server context) in openid_connect.server_conf

  # JWK Set will be fetched from $oidc_jwks_uri and cached here - ensure writable by nginx user
  proxy_cache_path /var/cache/nginx/jwk levels=1 keys_zone=jwk:64k max_size=1m;

  # Change timeout values to at least the validity period of each token type
  keyval_zone zone=oidc_id_tokens:1M     state=/var/lib/nginx/state/oidc_id_tokens.json     timeout=1h;
  keyval_zone zone=oidc_access_tokens:1M state=/var/lib/nginx/state/oidc_access_tokens.json timeout=1h;
  keyval_zone zone=refresh_tokens:1M     state=/var/lib/nginx/state/refresh_tokens.json     timeout=8h;
  keyval_zone zone=oidc_pkce:128K timeout=90s; # Temporary storage for PKCE code verifier.

  keyval $cookie_auth_token $session_jwt   zone=oidc_id_tokens;     # Exchange cookie for JWT
  keyval $cookie_auth_token $access_token  zone=oidc_access_tokens; # Exchange cookie for access token
  keyval $cookie_auth_token $refresh_token zone=refresh_tokens;     # Exchange cookie for refresh token
  keyval $request_id $new_session          zone=oidc_id_tokens;     # For initial session creation
  keyval $request_id $new_access_token     zone=oidc_access_tokens;
  keyval $request_id $new_refresh          zone=refresh_tokens; # ''
  keyval $pkce_id $pkce_code_verifier      zone=oidc_pkce;

  auth_jwt_claim_set $jwt_audience aud; # In case aud is an array
  js_import oidc from conf.d/openid_connect.js;

  # vim: syntax=nginx
  ```
- Copy the files created by the script to the same location where the Application's configuration resides (usually `/etc/nginx/conf.d/`).
  ```sh
  sudo cp openid_connect* /etc/nginx/conf.d/
  ```
- Finally, we need to edit our Web Application to integrate OIDC.

  One of the first steps we did in the OIDC configuration was to create a file for a new application `oidc.example.com` `. Now we need to edit this file to include some directives created by the script. This step is done by hand.

  The script creates a file `frontend.conf`, this file is no used directly, it is provided as an example and provides the directives that we need to add to our application to enable the OIDC integration.

  Review the contents of this file, and for the last step we need to edit `oidc.example.com.conf`

  ```sh
  sudo vim /etc/nginx/conf.d/oidc.example.com.conf
  ```
  The file `oidc.example.com.conf` should look like this:
  ```nginx
  # Custom log format to include the 'sub' claim in the REMOTE_USER field
  log_format main_jwt '$remote_addr - $jwt_claim_sub [$time_local] "$request" $status '
                      '$body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"';
  server {
      include conf.d/openid_connect.server_conf; # Authorization code flow and Relying Party processing
      error_log /var/log/nginx/error.log debug;  # Reduce severity level as required

      listen 443 ssl;
      server_name oidc.example.com;
      status_zone oidc.example.com_http;

      ssl_certificate /etc/ssl/nginx/oidc.example.com.crt;
      ssl_certificate_key /etc/ssl/nginx/oidc.example.com.key;
      ssl_ciphers TLS_AES_256_GCM_SHA384:HIGH:!aNULL:!MD5;
      ssl_prefer_server_ciphers on;

      location / {
          # This site is protected with OpenID Connect
          auth_jwt "" token=$session_jwt;
          error_page 401 = @do_oidc_flow;

          #auth_jwt_key_file $oidc_jwt_keyfile; # Enable when using filename
          auth_jwt_key_request /_jwks_uri; # Enable when using URL

          # Successfully authenticated users are proxied to the backend,
          # with 'sub' claim passed as HTTP header
          proxy_set_header username $jwt_claim_sub;

          # Bearer token is uses to authorize NGINX to access protected backend
          proxy_set_header Authorization "Bearer $access_token";
          # Intercept and redirect "401 Unauthorized" proxied responses to nginx
          # for processing with the error_page directive. Necessary if Access Token
          # can expire before ID Token.
          #proxy_intercept_errors on;

          add_header X-ServerIP $server_addr;
          add_header X-srv-hostname $hostname;

          proxy_set_header X-Client-IP $remote_addr;
          proxy_set_header X-Hola "Mundo";

          proxy_pass http://10.1.1.6:8081;

          access_log /var/log/nginx/access.log main_jwt;
      }
  }
  ```
  Reload NGINX Plus configuration:
  ```sh
  sudo nginx -s reload
  ```
  Validate in a browser - **https://oidc.example.com**

  The application should now ask for credentials using Keycloak before allowing access. Use `test:test`
  |                               |                               |
  |-------------------------------|-------------------------------|
  | ![Keycloak4](./keycloak4.png) | ![Keycloak5](./keycloak5.png) |

### -FIN- 
