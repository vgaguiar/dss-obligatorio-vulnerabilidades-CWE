# AltoroJ - Mitigación de Vulnerabilidades

## Descripción del Proyecto

AltoroJ es una aplicación web diseñada para facilitar la práctica de detección y mitigación de vulnerabilidades de software comúnmente listadas en el CWE (Common Weakness Enumeration). Este proyecto tiene como objetivo identificar, explotar y mitigar vulnerabilidades de seguridad, ayudando a los desarrolladores a aprender sobre buenas prácticas en el desarrollo de software seguro.

En este proyecto, trabajaremos con una versión vulnerable de AltoroJ y aplicaremos técnicas de mitigación para corregir problemas de seguridad. El entorno de desarrollo se ejecuta en una máquina virtual (VM), que contiene todo lo necesario para llevar a cabo las pruebas y correcciones.

## Vulnerabilidades Detectadas y Mitigadas

En la práctica, abordaremos las siguientes vulnerabilidades:

### 1. Cross Site Scripting (XSS)
- **Descripción:** La aplicación es vulnerable a un ataque XSS en el parámetro `query` de la URL `search.jsp`.
- **Solución:** Aplicación de sanitización de entradas utilizando el método `ServletUtil.sanitzieHtmlWithRegex`.

### 2. SQL Injection
- **Descripción:** Existe una vulnerabilidad de inyección SQL en la funcionalidad de inicio de sesión.
- **Solución:** Se modifica el código para utilizar consultas preparadas y evitar la inyección de código SQL.

### 3. Improper Input Validation
- **Descripción:** Los usuarios autenticados pueden acceder a información sensible debido a una validación de entrada incorrecta en la funcionalidad de visualización de historial de cuenta.
- **Solución:** Implementación de validación robusta de entrada en el código fuente.

### 4. OS Command Injection
- **Descripción:** El parámetro `content` de la página `index.jsp` permite la ejecución de comandos del sistema operativo.
- **Solución:** Se neutralizan las entradas maliciosas que podrían ser ejecutadas como comandos del sistema.

### 5. Path Traversal
- **Descripción:** El mismo parámetro `content` de la página `index.jsp` es vulnerable a ataques de Path Traversal, permitiendo al atacante acceder a archivos fuera del directorio autorizado.
- **Solución:** Se implementan restricciones de acceso a archivos para mitigar esta vulnerabilidad.

### 6. Use of Hard-coded Credentials
- **Descripción:** La interfaz de administración (`/AltoroJ/admin/login.jsp`) utiliza credenciales codificadas directamente en el código fuente.
- **Solución:** Las credenciales se extraen a un archivo de configuración externo (`app.properties`) para evitar su exposición en el código fuente.

### 7. Missing Authorization
- **Descripción:** Los usuarios autenticados pueden acceder a información de cuentas que no les pertenecen.
- **Solución:** Implementación de controles de autorización para verificar que el usuario tiene los permisos adecuados.

### 8. Missing Authentication for Critical Function
- **Descripción:** Existe una API que permite obtener el saldo de una cuenta sin necesidad de autenticación.
- **Solución:** Se añade autenticación obligatoria para acceder a las funciones críticas de la API.

## Entorno de Desarrollo

Este proyecto se ejecuta en una Máquina Virtual previamente configurada para correr el software vulnerable AltoroJ. La VM está disponible para su uso con VirtualBox o UTM, lo que asegura un entorno aislado y seguro para realizar pruebas y aplicar mitigaciones de vulnerabilidades.

## Requisitos del Sistema

- [VirtualBox](https://www.virtualbox.org/) o [UTM](https://mac.getutm.app/)
- Máquina Virtual proporcionada en la web de la asignatura
- Navegador web para interactuar con la aplicación


## Notas Adicionales

El propósito de esta práctica es educativo. Las técnicas y vulnerabilidades cubiertas aquí son comunes en muchas aplicaciones web, por lo que aprender a detectarlas y mitigarlas es crucial para garantizar la seguridad en el desarrollo de software.

**Disclaimer:** Esta aplicación se proporciona únicamente con fines de formación. 

## Licencia

Este proyecto está destinado solo para fines educativos y no debe utilizarse en proyectos de producción.
