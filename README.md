# Laboratorio NGINX Plus & NGINX Ingress Controller

### IMPORTANTE: Todas las configuraciones del Lab se haran desde un cliente Linux via RDP (ubuntu-desktop)

Para conectar, en UDF ir a ubuntu-desktop -> ACCESS -> XRDP
| Usuario | Password  |
|---------|-----------|
| ubuntu  | HelloUDF  |

\
Abrir la consola del Jumphost y clonar el repositorio del Lab

`git clone https://github.com/cavalen/nginx-workshop-cv`

---

## Descripcion del Entorno:

El laboratorio cuenta con:
- Un cliente Linux con RDP desde donde se haran todas las configuracions via Controla y las pruebas via Browser
- Un servidor Ubuntu con K3s, donde se hará el despliegue del Ingress Controller
- Un servidor Ubuntu donde se instalará NGINX Plus
- Un servidor Ubuntu con Docker haciendo la labor de Application Server.

![Topologia](docs/topology-lab.png)

| **Servicio**          | **Dirección IP** |
|-----------------------|------------------|
| brewz.example.com     | 10.1.1.5         |
| dashboard.example.com | 10.1.1.7         |
| echo.example.com      | 10.1.1.7         |
| f5app.example.com     | 10.1.1.7         |
| grafana.example.com   | 10.1.1.6         |
| keycloak.example.com  | 10.1.1.6         |
| oidc.example.com      | 10.1.1.5         |


## GUIAS:
### [Parte 1: Laboratorio NGINX Plus](https://github.com/cavalen/nginx-workshop-cv/tree/main/docs/k8s)

### [Parte 2: Laboratorio NGINX Ingress Controller](https://github.com/cavalen/nginx-workshop-cv/tree/main/docs/nginx)
