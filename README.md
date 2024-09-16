# 🔐 AltoroJ - Mitigación de Vulnerabilidades

## 📋 Descripción del Proyecto

AltoroJ es una aplicación web diseñada para facilitar la práctica de detección y mitigación de vulnerabilidades de software comúnmente listadas en el CWE (Common Weakness Enumeration). Este proyecto tiene como objetivo identificar, explotar y mitigar vulnerabilidades de seguridad, ayudando a los desarrolladores a aprender sobre buenas prácticas en el desarrollo de software seguro.

En este proyecto, trabajaremos con una versión vulnerable de AltoroJ y aplicaremos técnicas de mitigación para corregir problemas de seguridad. El entorno de desarrollo se ejecuta en una máquina virtual (VM), que contiene todo lo necesario para llevar a cabo las pruebas y correcciones.

## 🛡️ Vulnerabilidades Detectadas y Mitigadas

En la práctica, abordaremos las siguientes vulnerabilidades:

### 1. 🖥️ Cross Site Scripting (XSS)
- **Descripción:** La aplicación es vulnerable a un ataque XSS en el parámetro `query` de la URL `search.jsp`.
- **Solución:** Aplicación de sanitización de entradas utilizando el método `ServletUtil.sanitzieHtmlWithRegex`.

### 2. 💉 SQL Injection
- **Descripción:** Existe una vulnerabilidad de inyección SQL en la funcionalidad de inicio de sesión.
- **Solución:** Se modifica el código para utilizar consultas preparadas y evitar la inyección de código SQL.

### 3. 🚦 Improper Input Validation
- **Descripción:** Los usuarios autenticados pueden acceder a información sensible debido a una validación de entrada incorrecta en la funcionalidad de visualización de historial de cuenta.
- **Solución:** Implementación de validación robusta de entrada en el código fuente.

### 4. 🖱️ OS Command Injection
- **Descripción:** El parámetro `content` de la página `index.jsp` permite la ejecución de comandos del sistema operativo.
- **Solución:** Se neutralizan las entradas maliciosas que podrían ser ejecutadas como comandos del sistema.

### 5. 🗂️ Path Traversal
- **Descripción:** El mismo parámetro `content` de la página `index.jsp` es vulnerable a ataques de Path Traversal, permitiendo al atacante acceder a archivos fuera del directorio autorizado.
- **Solución:** Se implementan restricciones de acceso a archivos para mitigar esta vulnerabilidad.

### 6. 🔐 Use of Hard-coded Credentials
- **Descripción:** La interfaz de administración (`/AltoroJ/admin/login.jsp`) utiliza credenciales codificadas directamente en el código fuente.
- **Solución:** Las credenciales se extraen a un archivo de configuración externo (`app.properties`) para evitar su exposición en el código fuente.

### 7. 🚫 Missing Authorization
- **Descripción:** Los usuarios autenticados pueden acceder a información de cuentas que no les pertenecen.
#### **Desarrollo de la Vulnerabilidad**

**Problema Original:**

Antes de implementar la corrección, la funcionalidad de visualización de cuentas en AltoroJ permitía que cualquier usuario autenticado accediera al historial de transacciones de cuentas que no le pertenecían. Esto se debía a la falta de validación de la propiedad de la cuenta por parte del usuario autenticado.

Por ejemplo, un usuario malintencionado podía modificar el parámetro `acctId` en la URL de la página `balance.jsp` para acceder a los detalles de cualquier cuenta, lo cual representa una violación crítica de la privacidad y una falta de control de acceso en el sistema.

**Solución Aplicada:**

Para mitigar esta vulnerabilidad, se implementaron controles adicionales en el servlet encargado de manejar la visualización de cuentas. Ahora, cuando un usuario solicita ver el balance de una cuenta, el sistema verifica si el usuario autenticado es el propietario legítimo de la cuenta antes de permitir el acceso a la información. Esto se logra con la siguiente lógica:

``` java
// Obtain the authenticated user from the session
User authenticatedUser = (User) request.getSession().getAttribute("user");
if (authenticatedUser == null) {
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "User not authenticated.");
    return;
}

// Verify if the account belongs to the authenticated user
if (!isAccountOwnedByUser(authenticatedUser, Long.parseLong(accountName))) {
    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "You are not authorized to access this account.");
    return;
}
```

```java
private boolean isAccountOwnedByUser(User user, Long accountId) {
    Account[] accounts = user.getAccounts();
    if (accounts != null) {
        for (Account account : accounts) {
            if (account.getAccountId() == accountId) {
                return true;  // The user owns the account
            }
        }
    }
    return false;  // The user does not own the account
}
```


![image](https://github.com/user-attachments/assets/77eaf8d8-3be8-49e5-b414-9300be89cd8c)
![image](https://github.com/user-attachments/assets/c342fcb3-05aa-45a3-ad39-18df3f5ac21a)

Con estos cambios, se garantiza que un usuario solo pueda acceder a la información de las cuentas que le pertenecen, mitigando el riesgo de acceso no autorizado.

![image](https://github.com/user-attachments/assets/3c079033-8368-44d8-8195-b08ee63f87aa)


### 8. 🔓 Missing Authentication for Critical Function
- **Descripción:** Existe una API que permite obtener el saldo de una cuenta sin necesidad de autenticación.
- **Solución:** Se añade autenticación obligatoria para acceder a las funciones críticas de la API.

## 💻 Entorno de Desarrollo

Este proyecto se ejecuta en una Máquina Virtual previamente configurada para correr el software vulnerable AltoroJ. La VM está disponible para su uso con VirtualBox o UTM, lo que asegura un entorno aislado y seguro para realizar pruebas y aplicar mitigaciones de vulnerabilidades.

## 🖥️ Requisitos del Sistema

- [VirtualBox](https://www.virtualbox.org/) o [UTM](https://mac.getutm.app/)
- Máquina Virtual proporcionada en la web de la asignatura
- Navegador web para interactuar con la aplicación

## ⚙️ Cómo Usar

1. Descarga e importa la Máquina Virtual en tu sistema usando VirtualBox o UTM.
2. Inicia la VM y accede a la aplicación web AltoroJ desde el navegador en la URL proporcionada.
3. Identifica y explota cada una de las vulnerabilidades listadas.
4. Realiza las modificaciones en el código fuente para mitigar cada vulnerabilidad.
5. Utiliza las herramientas proporcionadas en la VM para ejecutar las pruebas y verificar que las vulnerabilidades han sido corregidas.

## 📝 Notas Adicionales

El propósito de esta práctica es educativo. Las técnicas y vulnerabilidades cubiertas aquí son comunes en muchas aplicaciones web, por lo que aprender a detectarlas y mitigarlas es crucial para garantizar la seguridad en el desarrollo de software.

**Disclaimer:** Esta aplicación se proporciona únicamente con fines de formación. No intentes explotar vulnerabilidades en aplicaciones de producción o fuera de un entorno controlado.

## 📄 Licencia

Este proyecto está destinado únicamente para fines educativos.
