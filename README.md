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
- **Descripción:** Existía una API que permitía obtener el saldo de una cuenta sin necesidad de autenticación.
- **Problema Original:** La API no exigía que el usuario autenticado solo pudiera acceder a la información de sus propias cuentas. Esto permitía que cualquier persona pudiera consultar información sensible de otras cuentas.
- **Solución:**

  - **Autenticación mediante `ApiAuthFilter`:**
    - Se modificó el filtro de autenticación (`ApiAuthFilter`) para validar los tokens de autenticación antes de acceder a la API.
    - El filtro revisa el token y verifica que las credenciales sean correctas antes de permitir la operación solicitada.
    - Además, se corrigió un error en el filtro que hacía doble decodificación del token, lo que provocaba problemas al validar las credenciales del usuario.
    - **Código del `ApiAuthFilter` Corregido:**
      ```java
      public void filter(ContainerRequestContext requestContext) throws IOException {
          final MultivaluedMap<String, String> headers = requestContext.getHeaders();
          final List<String> authorization = headers.get("Authorization");

          if (authorization == null || authorization.isEmpty()) {
              requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED)
                  .entity("Please log in first").build());
              return;
          }

          String encodedToken = authorization.get(0).replaceFirst("Bearer" + " ", "");
          String accessToken = new String(Base64.decodeBase64(encodedToken));

          StringTokenizer tokenizer = new StringTokenizer(accessToken, ":");
          String username = tokenizer.nextToken();  
          String password = tokenizer.nextToken();

          // Verificar si el usuario es válido
          try {
              if (DBUtil.isValidUser(username, password)) {
                  User authenticatedUser = DBUtil.getUserInfo(username);
                  request.getSession().setAttribute("user", authenticatedUser);
                  System.out.println("User stored in session: " + authenticatedUser.getUsername());
              } else {
                  requestContext.abortWith(Response.status(Response.Status.UNAUTHORIZED)
                      .entity("Invalid credentials").build());
              }
          } catch (SQLException e) {
              requestContext.abortWith(Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                  .entity("An error has occurred: " + e.getLocalizedMessage()).build());
          }
      }
      ```

![image](https://github.com/user-attachments/assets/8a0a2677-6906-4064-961c-e49a39b510f0)
  - **Validación de Propiedad de Cuenta en `AccountAPI`:**
    - La API de `AccountAPI` no validaba si el usuario autenticado era el dueño de la cuenta antes de proporcionar el saldo.
    - **Problema Original:** El usuario podía acceder a la información de cuentas que no le pertenecían, lo que representaba un riesgo de exposición de datos.
    - **Solución:**
      - Se añadió una verificación para asegurar que el usuario autenticado solo pueda acceder a sus propias cuentas.
      - El método `getAccountBalance` se modificó para obtener al usuario autenticado de la sesión y luego verificar si la cuenta pertenece a dicho usuario.
      - **Código Corregido del `getAccountBalance`:**
        ```java
        @GET
        @Path("/{accountNo}")
        public Response getAccountBalance(@PathParam("accountNo") String accountNo,
                                          @Context HttpServletRequest request) {
            String response;
            try {
                // Obtener el usuario autenticado de la sesión
                User currentUser = (User) request.getSession().getAttribute("user");

                if (currentUser == null) {
                    return Response.status(Response.Status.UNAUTHORIZED)
                        .entity("{ \"Error\": \"User not authenticated.\" }")
                        .build();
                }

                // Verificar si la cuenta pertenece al usuario autenticado
                Account[] userAccounts = currentUser.getAccounts();
                boolean authorized = Arrays.stream(userAccounts)
                                           .anyMatch(account -> account.getAccountId() == Long.parseLong(accountNo));

                if (!authorized) {
                    return Response.status(Response.Status.FORBIDDEN)
                        .entity("{ \"Error\": \"Unauthorized access to account.\" }")
                        .build();
                }

                // Obtener el balance de la cuenta
                double dblBalance = Account.getAccount(accountNo).getBalance();
                String format = (dblBalance < 1) ? "$0.00" : "$.00";
                String balance = new DecimalFormat(format).format(dblBalance);
                response = "{\"balance\" : \"" + balance + "\" ,\n";

            } catch (Exception e) {
                return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("{Error : " + e.getLocalizedMessage())
                    .build();
            }

            return Response.status(Response.Status.OK).entity(response).build();
        }
        ```
![image](https://github.com/user-attachments/assets/6eee6c90-1bc2-45c9-a2d1-d7bbc4f5cfd2)

   - 💉 **Prevención de Inyección SQL en `isValidUser`:**
        - **Descripción:** El método `isValidUser` contenía una vulnerabilidad de inyección SQL.
        - **Problema Original:** Las entradas de usuario y contraseña se concatenaban directamente en la consulta SQL, lo cual permitía inyecciones SQL.
        - **Solución:** 
          - Se modificó el método `isValidUser` para usar consultas preparadas, lo que evita que los datos de entrada se interpreten como parte de la consulta SQL.
          - **Código Corregido:**
            ```java
            public static boolean isValidUser(String user, String password) throws SQLException {
                String query = "SELECT COUNT(*) FROM PEOPLE WHERE USER_ID = ? AND PASSWORD = ?";
                try (Connection connection = getConnection();
                     PreparedStatement statement = connection.prepareStatement(query)) {
                    
                    statement.setString(1, user);
                    statement.setString(2, password);
                    
                    try (ResultSet resultSet = statement.executeQuery()) {
                        if (resultSet.next()) {
                            return resultSet.getInt(1) > 0;
                        }
                    }
                }
                return false;
            }
            ```
            ![image](https://github.com/user-attachments/assets/0ce5ceec-a69b-421d-96a9-92f428e720d5)



#### 🧪 Proceso de Prueba del Token de Autenticación
- **Generación del Token:**
  - Usamos el siguiente comando en la consola para generar un token codificado en base64 con las credenciales `jsmith:demo1234`.
  - **Comando**:
    ```bash
    echo -n 'jsmith:demo1234' | base64
    ```
    Resultado: `anNtaXRoOmRlbW8xMjM0`

- **Prueba del Token con cURL:**
  - Usamos `curl` para realizar una petición a la API utilizando el token generado.
  - **Comando de cURL**:
    ```bash
    curl -H "Authorization: Bearer anNtaXRoOmRlbW8xMjM0" http://localhost:8080/AltoroJ/api/account/800002
    ```
- **Verificación Exitosa (Intentando acceder a la información de la cuenta de un usuario que NO es el logueado:**
  - La solicitud pasó a través del filtro de autenticación (`ApiAuthFilter`), validando correctamente el token y evitando que se acceda a la infromación de una cuenta que no pertenece al usuario logueado.
    ![image](https://github.com/user-attachments/assets/e4ba85b8-b0c3-4db4-b336-15b40f407e8d)

    
- **Verificación Exitosa (Intentando acceder a una cuenta que pertenece al usuario logueado):**
  - La solicitud pasó a través del filtro de autenticación (`ApiAuthFilter`), validando correctamente el token y permitiendo el acceso a la información de la cuenta del usuario logueado.
    ![image](https://github.com/user-attachments/assets/a1aa9028-b022-4873-98dd-7dc7368c0661)
  



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
