# Instrucciones Lab NGINX Plus

## Contenido:
[1. Instalacion Nginx Plus](#1-instalacion-nginx-plus)\
[2. Configuracion base de nginx](#2-configuracion-base-de-nginx)\
[3. Archivos de Configuracion](#3-archivos-de-configuracion)\
[4. Web Application Firewall (WAF)](#4-web-application-firewall-waf)\
[5. Auth con OpenID Connect (OIDC)](#5-auth-con-openid-connect-oidc)


### 1. Instalación Nginx Plus
Nota: La instalacion y la configuracion de NGINX Plus se realizar por linea de comandos y editando archivos de configuracion de texto.\
Se recomienda tener alguna experiencia en el CLI de Linux.

En la guia se utilizará `vim` para crear y modificar los archivos de configuración, sin embargo el editor de su preferencia puede ser utilizado.

<mark>IMPORTANTE: Los pasos de configuracion de esta guia se hacen sobre el servidor `nginx`\
Usuario `ubuntu` con password `HelloUDF`</mark>
```
ssh ubuntu@10.1.1.7
```
Para validar que estemos en el servidor correcto, podemos fijarnos en el prompt de la linea de comandos `ubuntu@nginx ~`
![SSH Nginx](./ssh-nginx.png)

El flujo del despliegue se puede ver de esta forma
![Flujo Instalacion](./install-flow.png)
Y son los pasos que seguiremos a continuacion:

- Pre-requisitos del sistema operativo:
  ```
  sudo apt-get install -y apt-transport-https lsb-release ca-certificates wget gnupg2 ubuntu-keyring
  ```
- Signing Keys:
  ```
  wget -qO - https://cs.nginx.com/static/keys/nginx_signing.key | gpg --dearmor | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
  ```
  ```
  wget -qO - https://cs.nginx.com/static/keys/app-protect-security-updates.key | gpg --dearmor | sudo tee /usr/share/keyrings/app-protect-security-updates.gpg >/dev/null
- Adicionar repositorios de Nginx:
  ```
  printf "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://pkgs.nginx.com/plus/ubuntu `lsb_release -cs` nginx-plus\n" | sudo tee /etc/apt/sources.list.d/nginx-plus.list
  ```
  ```
  printf "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] https://pkgs.nginx.com/app-protect/ubuntu `lsb_release -cs` nginx-plus\n" | sudo tee /etc/apt/sources.list.d/nginx-app-protect.list
  ```
  ```
  printf "deb [signed-by=/usr/share/keyrings/app-protect-security-updates.gpg] https://pkgs.nginx.com/app-protect-security-updates/ubuntu `lsb_release -cs` nginx-plus\n" | sudo tee -a /etc/apt/sources.list.d/nginx-app-protect.list
  ```
  ```
  sudo wget -P /etc/apt/apt.conf.d https://cs.nginx.com/static/files/90pkgs-nginx
  ```
- Instalar paquetes:\
  La instalación de NGINX Plus requiere un certificado y una llave para autenticarse contra el repositorio de F5/NGINX.\
  Estos ya se encuentran en `/etc/ssl/nginx/nginx-repo.crt` y `/etc/ssl/nginx/nginx-repo.key`

  ```
  sudo apt update && sudo apt install -y nginx-plus app-protect nginx-plus-module-njs
  ```

  `nginx-plus` es el paquete principal de nginx\
  `app-protect` es el paquete del WAF\
  `nginx-plus-module-njs` es el paquete de NGINX JavaScript (NJS), utilizado por la integracion de OIDC
- Activar nginx a la hora de iniciar el sistema y validar la instalación:
  ```
  sudo systemctl enable nginx
  sudo systemctl start nginx
  nginx -v
  curl http://0:80
  ```
  `nginx -v` muestra la version de nginx instalada\
  `curl http://0:80` retorna la pagina por defecto de nginx
- Borrar archivo de configuracion del sitio "default", ya que no lo usaremos
  ```
  sudo rm /etc/nginx/conf.d/default.conf
  ```

### 2. Configuracion base de nginx
- Editar el archivo `/etc/nginx/nginx.conf` para cargar los modulos de WAF y NJS\
  `load_module modules/ngx_http_app_protect_module.so;`\
  `load_module modules/ngx_http_js_module.so;`\
  \
  Adicionalmente para configurar 2 variables que se recomienda modificar a la hora de usar NGINX JavaScript y la integracion con OIDC\
  `variables_hash_max_size 2048;`\
  `variables_hash_bucket_size 128;`\
  ```
  sudo vim /etc/nginx/nginx.conf
  ```
  El archivo de configuracion `nginx.conf` debe quedar como este:
  ```
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

- Crear configuracion para la exponer el Dashboard y el API de NGINX Plus.
  Por defecto este Dashboard se expone en el puerto 8080 y se consulta via Browser
  ```
  sudo vim /etc/nginx/conf.d/api.conf
  ```
  ```
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
- Recargar la configuracion de nginx con el comando
  ```
  sudo nginx -s reload
  ```
  Probar desde el browser en **http://dashboard.example.com:8080**

  ![NGINX Dashboard](./nginx-dashboard.png)
 ---
### 3. Archivos de Configuracion
Los archivos de configuracion de los sitios, se recomienda crearlos en la ruta `/etc/nginx/conf.d/` y que cada sitio tenga un archivo `.conf` propio, con un nombre significativo, por ejemplo `api.misitio.com.conf`

- #### Crear configuracion del primer sitio - *f5app*
  ```
  sudo vim /etc/nginx/conf.d/f5app.example.com.conf
  ```
  El archivo de configuracion `f5app.example.com.conf` debe quedar como este:
  ```
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
  Recargar la configuracion de nginx:
  ```
  sudo nginx -s reload
  ```

  Probar desde el browser en **http://f5app.example.com**

  ![f5app](./f5app.png)

  La App solo esta expuesta a traves del reverse-proxy, pero no esta protegida:
  - ir a Demos > Credit Cards
  - Correr un XSS - `http://f5app.example.com/<script>`

  Validar el Dashboard de NGINX que ya podemos ver informacion sobre f5app, su estado de salud y monitores en **http://dashboard.example.com:8080**

  Realicemos una modificacion al Heath-Check:
  ```
  sudo vim /etc/nginx/conf.d/f5app.example.com.conf
  ```
  Cambiamos el segmento `match f5app_health` que quede así:
  ```
  match f5app_health {
      status 200;
      body ~ "Workshop K8S vLab";
  }
  ```
  Recargamos la configuracion de nginx con `sudo nginx -s reload` y probamos de nuevo el app
  ![502 error](./f5app-502.png)
  
  **Que sucede?** El aplicativo no carga y responde con un error 502 pues no hay backends/upstreams saludables.

  En el Dashboard de NGINX podemos ver tambien los health checks realizados y el estado del servidor
  ![Dashboard f5app](./f5app-dashboard.png)

  ### <mark>**Reversemos los cambios en el Health Check y recargamos la configuracion de nginx antes de continuar**</mark>
    ```
  match f5app_health {
      status 200;
      body ~ "F5 K8S vLab";
  }
  ```
  Como siguiente prueba, activaremos el LoadBalancing en Nginx.
  Para esto, quitamos el comentario `#` en del segundo `server` en el bloque `upstream f5app-backend` hacia el final del archivo y recargamos la configuracion de nginx.\

  Probando desde el browser en **http://f5app.example.com** podemos notar por los colores del app, que ahora los request del cliente se envian hacia dos instancias del backend. También se puede validar en el Dashboard.

- #### Crear configuracion del segundo sitio - *echo*
  ```
  sudo vim /etc/nginx/conf.d/echo.example.com.conf
  ```
  El archivo de configuracion `echo.example.com.conf` debe quedar como este:
  ```
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
  Notese como esta segunda aplicacion usa terminacion TLS en nginx, y no tiene un bloque de `upstream` sino que directamente está enviando el request a un backend existente.

  Recargar la configuracion de nginx:
  ```
  sudo nginx -s reload
  ```

  Probar desde el browser **https://echo.example.com**

  Esta es una aplicacion sencilla que muestra informacion sobre el request en formato json.

  ![echo](./echo.png)

  Configuremos ahora *"header insertion"*, ya que esta aplicacion permite facilmente ver los Headers.

  ```
  sudo vim /etc/nginx/conf.d/echo.example.com.conf
  ```
  El archivo de configuracion echo.example.com.conf debe quedar como este:
  ```
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
  `add_header` Adiciona headers a la respuesta del server\
  `proxy_set_header` Adiciona headers al request que se envia al server\
  
  El parametro `$server_addr` es una variable interna de nginx. El listado de variables se pueden consultar en la documentacion en **http://nginx.org/en/docs/http/ngx_http_core_module.html#variables** 

---

### 4. Web Application Firewall (WAF)
NGINX App Protect (v4) utiliza archivos en formato JSON para la definicion de la politica de seguridad declarativa. Estos archivos pueden estar en cualquier ubucacion en el filesystem, para este Lab los colocaremos en la ruta `/etc/nginx/waf/`

También es posible tener la politica como un archivo binario llamado "policy bundle" que se compila por medio de un software llamado [NGINX App Protect Policy Compiler](https://docs.nginx.com/nginx-app-protect-waf/v5/admin-guide/compiler/), pero para este Lab usaremos los archivos JSON

La política de seguridad que usaremos se compone de:
- Un archivo JSON con la configuracion del formato del log del WAF
- Un archivo JSON con la politica base, el cual se referencia desde `nginx.conf`
- Archivos JSON con referencias a varios bloques de configuracion (opcionales), en nuestro caso tenemos:
  - JSON para definicion de "Server Technologies" usadas en el App a proteger
  - JSON con lista blanca de direcciones IP a los cuales no se le aplica validacion por parte del WAF
  -  JSON con violaciones especificas a nivel protocolo HTTP
  -  JSON con violaciones tipo Evasion

Ahora procederemos a crear todos los archivos de configuracion del WAF y activarlo para una de las aplicaciones desplegadas en un paso anterior

-  Crear archivo de log profile en `/etc/nginx/waf/`
   ```
   sudo mkdir /etc/nginx/waf
   sudo vim /etc/nginx/waf/log-grafana.json
   ```
   Este archivo usa un formato de log especifico para un dashboard de Grafana.\
   Existe un formato `default` orientado a logs basicos via syslog y otros formatos predefinidos como `big-iq`, `arcsight`, `grpc`, `splunk` y `user-defined` que es el utilizado en este Lab.
   ```
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
- Crear archivo de la politica de seguridad base en `/etc/nginx/waf/`
   ```
   sudo vim /etc/nginx/waf/NginxCustomPolicy.json
   ```
   ```
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
   Si revisamos la estructura del archivo podemos ver los diferentes bloques de configuracion, como las violaciones, el modo de bloqueo (Blocking / Transparent), DataGuard (Validar data sensible expuesta por el servidor), response Pages (Pagina de respuesta a Violaciones), Codigos de respuesta HTTP validos y algunos otras configuraciones que se encuentran en la [documentacion de la politica declarativa de NGINX App Protect]( https://docs.nginx.com/nginx-app-protect-waf/v4/declarative-policy/policy/)\
   **https://docs.nginx.com/nginx-app-protect-waf/v4/declarative-policy/policy/**

- Crear archivo de definicion de "Server Technologies" para la politica de seguridad en `/etc/nginx/waf/`
   ```
   sudo vim /etc/nginx/waf/server-technologies.json
   ```
   ```
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
- Crear archivo de definicion de "IP Whitelist" para la politica de seguridad en `/etc/nginx/waf/`
   ```
   sudo vim /etc/nginx/waf/whitelist-ips.json
   ```
   ```
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
- Crear archivo de definicion de "HTTP Protocol Compliance" para la politica de seguridad en `/etc/nginx/waf/`
   ```
   sudo vim /etc/nginx/waf/http-protocols.json
   ```
   ```
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
- Crear archivo de definicion de "Tecnicas de Evasion" para la politica de seguridad en `/etc/nginx/waf/`
   ```
   sudo vim /etc/nginx/waf/evasions.json
   ```
   ```
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
- Como ultimo paso, activamos el WAF para la aplicacion `f5app`, editando el archivo `/etc/nginx/conf.d/f5app.example.com.conf`
   ```
   sudo vim /etc/nginx/conf.d/f5app.example.com.conf
   ```
   Las configuraciones a nivel WAF adicionan a nivel de la directiva `server {}` de forma "global" (para toda la aplicacion f5app) o en un `location` especifico. En este caso lo hacemos para toda la aplicacion.

   Como requisito, el modulo de WAF debe estar cargado a NGINX, esto lo hicimos en un paso anterior agreagando la directiva `load_module` en `nginx.conf`

   `app_protect_enable on;` Activa el WAF.\
   `app_protect_security_log_enable on;` Activa logs para el WAF.\
   `app_protect_security_log "/etc/nginx/waf/log-grafana.json" syslog:server=grafana.example.com:8515;` Indica el formato a usar para los logs de WAF y el destino. Puede usarse multiples veces para hacer logs a varios destinos.\
   `app_protect_policy_file "/etc/nginx/waf/NginxCustomPolicy.json";` Indica la politica de WAF a usar.

   El archivo `f5app.example.com.conf` queda de la siguiente manera:
   ```
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

  Recargar la configuracion de nginx:
  ```
  sudo nginx -s reload
  ```
  Validar configuracion:
  ```
  sudo nginx -t
  ```

  Probar desde el browser **http://f5app.example.com**\
  Hacer algunas simulaciones de ataques a la aplicacion, <mark>y tomar nota del SupportID</mark>
    - Adicionar al path un XSS `http://f5app.example.com/<script>`
    - Adicionar al path un SQLi `http://f5app.example.com/?a='or 1=1#'`
    - Navegar en la aplicacion al menu Demos > CC Numbers y validar que la configuracion de DataGuard ofusca informacion sensible.

  En Grafana validar logs del WAF:\
  Ir a **http://grafana.example.com:3000** y ver los Dashboards Attack Signatures, Main Dashboard y SupportIDs\
  ![Grafana Dashboars](./grafana1.png)

  ![Grafana Dashboars](./grafana2.png)

### 5. Auth con OpenID Connect (OIDC)
NGINX Plus permite utilizar un Identity Provider (IdP) para autenticar usuarios antes de "proxearlos" hacia la aplicacion o el backend.\
Esta integracion es un proceso manual y se realiza por medio de un componente adicional que debe ser descargado y configurado.\
\
El laboratorio cuenta con un despliegue de `Keycloak`, corriendo como un contenedor Docker en un servidor.\
Ya esta pre-configurado, y se puede acceder via **https://keycloak.example.com** con las credenciales `admin/admin` y en este hay un client llamado `nginx-plus` y un usuario `test` con password `test`

| Client                        | User                          |
|-------------------------------|-------------------------------|
| ![Keycloak1](./keycloak1.png) | ![Keycloak2](./keycloak2.png) |

- La configuracion a grandes razgos consta de 5 pasos:
   1. Descargar el software necesario para la integracion de OIDC desde GitHub
   2. Ejecutar un script de configuracion via linea de comandos
   3. Validar la configuracion generada por el script (Datos y rutas del Identity Provider)
   4. Copiar la configuracion generada por el script a la misma ruta donde se encuentra el archivo de configuracion de la aplicacion a la que queremos integrar autenticacion (generalmente `/etc/nginx/conf.d`)
   5. Editar la configuracion del aplicativo (`/etc/nginx/conf.d/<nombre-app>.conf`) y adicionar las directivas generadas por el script.

- Crear un nuevo "sitio" al cual habilitar autenticacion por medio de OIDC
  ```
  sudo vim /etc/nginx/conf.d/oidc.example.com.conf
  ```
  ```
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

- Descargar el software desde GitHub.\
  Hay un branch recomendado para cada version de NGINX Plus, por ejemplo para NGINX Plus R31 el comando git debe especificar el branch adecuado (ej, `git clone -b R31 <REPO>`)\
En este caso descargaremos la ultima version (latest)
  ```
  git clone https://github.com/nginxinc/nginx-openid-connect
  ```
  ```
  cd nginx-openid-connect
  ```
  ```
  ./configure.sh -x -h oidc.example.com -k request -i nginx-plus -s 1234567890ABCDEF http://keycloak.example.com/realms/master/.well-known/openid-configuration
  ```
  `-h` indica el FQDN del IdP\
  `-x` Insecure, no valida el certificado HTTPS (OK para entornos de prueba)\
  `-i nginx-plus` Client ID tal como esta configurado en el OpenID Connect Provider\
  `-s 1234567890ABCDEF` Client Secret tal como esta configurado en el OpenID Connect Provider\
  `http://keycloak.example.com/realms/master/.well-known/openid-configuration` Discovery interface del IdP.

- Configurar Parametros de OIDC (1)

  El script crea varios archivos, el primero a editar es `openid_connect_configuration.conf`

  Solo es necesario editar la directiva `resolver` al comienzo del archivo.\
  Como estamos usando el dominio de pruebas `example.com` este no resuelve con el DNS publico por defecto que utiliza el script (8.8.8.8) y debemos indicar la direccion IP del servicio DNS interno `127.0.0.53`.

  ```
  sudo vim openid_connect.server_conf
  ```
  El archivo final queda asi:
  ```
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

- Configurar Parametros de OIDC (2)

  El segundo archivo a configurar es `openid_connect_configuration.conf`.
  Debemos validar que el contenido del archivo sea el correcto respecto a los endpoints de OIDC de Keycloak.

  El administrador de Identity Provider debe conocer estos valores, adicionalmente el URL de `openid-configurations` nos puede ayudar en esta validacion:
  ![Keycloak3](./keycloak3.png)

  ```
  sudo vim openid_connect.server_conf
  ```
  Los valores importantes a configurar estan en las directivas `map` del archivo
  | Parametro | Valor |
  |-----------|-------|
  | `$oidc_authz_endpoint` | `oidc.example.com https://keycloak.example.com/realms/master/protocol/openid-connect/auth;` |
  | `$oidc_token_endpoint` | `oidc.example.com https://keycloak.example.com/realms/master/protocol/openid-connect/token;` |
  | `$oidc_jwt_keyfile` | `oidc.example.com https://keycloak.example.com/realms/master/protocol/openid-connect/certs;` |
  | `$host $oidc_client` | `oidc.example.com nginx-plus;` |
  | `$oidc_client_secret` | `oidc.example.com 1234567890ABCDEF;` |

  ```
  sudo vim openid_connect_configuration.conf
  ```
  El archivo final queda asi:
  ```
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
- Copiar archivos de configuracion a carpeta de nginx, donde estan los archivos de configuracion de la app a la que vamos a integrar autenticacion.
  ```
  sudo cp openid_connect* /etc/nginx/conf.d/
  ```
- Editar aplicacion Web para integrar OIDC
  
  En uno de los primeros pasos de la configuracion de OIDC, creamos un archivo para el sitio `oidc.example.com`. Ahora debemos editarlo para incluir lo que el script de configuracion creo y lo que hemos editado de forma manual.

  El script crea un archivo llamado `frontend.conf`, este archivo no es necesario, pero muestra las directivas que debe tener una aplicacion para hacer la integracion de OIDC y se usa como ejemplo de configuracion.

  ```
  sudo vim /etc/nginx/conf.d/oidc.example.com.conf
  ```
  ```
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
  Recargamos la configuración de Nginx.
  ```
  sudo nginx -s reload
  ```
  Validamos en un browser en **https://oidc.example.com**\
  La aplicacion debe ahora solicitar credenciales a Keycloak antes de permitir acceso a la App.
  
