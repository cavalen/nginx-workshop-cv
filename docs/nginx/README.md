# Instrucciones Lab NGINX Plus

### 1. Instalación Nginx Plus
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
- Borrar archivo de configuracion del sitio "default"
  ```
  sudo rm /etc/nginx/conf.d/default.conf
  ```
