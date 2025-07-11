<img src="https://www.ucu.edu.uy/plantillas/images/logo_ucu.svg" alt="UCU" width="200"/>

# Universidad Católica del Uruguay

## Facultad de Ingeniería y Tecnologías

### Análisis y diseño de aplicaciones II

<br/>

# Demo de seguridad

Esta demo tiene una sencilla [aplicación web](./main.py) que expone una API
REST; está implementada en Python usando [fastapi](https://fastapi.tiangolo.com)
y la ejecutamos con [uvicorn](https://www.uvicorn.org).

En esta demo ...

Para ejecutar esta demo usa los comandos que están [aquí](./commands.azcli). Con
el complemento [Azure CLI
Tools](https://marketplace.visualstudio.com/items?itemName=ms-vscode.azurecli)
es posible ejecutar los comandos directamente desde Visual Studio Code.

Una vez que ejecutes la aplicación, puedes ver la documentación de los endpoints
con [Swagger](http://localhost:5003/docs).

# Requisitos

* Python

* Docker

# Actividades

Analiza cómo se implementan en esta demo los siguientes conceptos:

* Confidencialidad: Endpoint que solo puede ser accedido por usuarios
  autenticados y con un rol específico.

* Integridad: Endpoint que permite modificar datos, pero solo si el token es
  válido y no ha sido alterado.

* No-repudio: Registro de acciones de los usuarios mediante logs firmados o
  inmutables.

* Rendición de cuentas: Endpoint que muestra el historial de acciones del
  usuario autenticado.

* Autenticidad: Endpoint que retorna la identidad autenticada por Keycloak.
