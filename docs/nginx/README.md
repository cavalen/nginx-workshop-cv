# Instrucciones Lab NGINX Plus

### 1. Instalación Nginx Plus
Nota: La instalacion y la configuracion de NGINX Plus se realizar por linea de comandos y editando archivos de configuracion de texto.\
Se recomienda tener alguna experiencia en el CLI de Linux.\

En la guia se utilizará `vim` para crear y modificar los archivos de configuración, sin embargo el editor de su preferencia puede ser utilizado.

- Pre-requisitos del sistema operativo:
  ```
  sudo apt-get install -y apt-transport-https lsb-release ca-certificates wget gnupg2 ubuntu-keyring
  ```
- Signing Keys:
  ```
  wget -qO - https://cs.nginx.com/static/keys/nginx_signing.key | gpg --dearmor | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null

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
  sudo apt update
  sudo apt install -y nginx-plus app-protect nginx-plus-module-njs
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

### 2. Archivos de Configuracion, para los sitios a exponer

- Crear configuracion del primer sitio - *f5app*
