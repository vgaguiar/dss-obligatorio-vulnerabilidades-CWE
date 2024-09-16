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

#### PoC
1.	Se ingresa a la máquina virtual
2.	Levantar el servicio de Altoro desde Eclipse
3.	Ingreso en http://localhost:8080/AltoroJ/
4.	Ingreso en http://localhost:8080/AltoroJ/index.jsp?content=personal_deposit.htm
5.	Ingreso al final de la dirección “ ';ls' ” quedando tal que localhost:8080/AltoroJ/index.jsp?content=personal_deposit.htm';ls'

#### **Desarrollo de la Vulnerabilidad**

**Problema Original:**

Antes de implementar la corrección, el content estaba vulnerable ante factores de inserciones de OS command, permitiendo ejecutar una amplia variedad de comandos del sistema operativo en cuestión.

Por ejemplo, un atacante podría hacer un ;ls y visualizar todos los directorios y archivos en la ubicación actual

**Solución Aplicada:**

Para mitigar esta vulnerabilidad, se implementaron controles adicionales específicos evitando de esta manera el uso ";" además de sanitizar la entrada.

``` java
		<%		
		java.lang.String content = request.getParameter("content");
		if (content == null)
			content = "default.htm";
		else
			content = request.getParameter("content");
		
		if (ServletUtil.isAppPropertyTrue("advancedStaticPageProcessing")){
			String path  = request.getSession().getServletContext().getRealPath("/static");

	        %>
```

``` java
		<%		
		java.lang.String content = request.getParameter("content");
		if (content == null)
			content = "default.htm";
		else
			content = content.replace(";", "");
            content = ServletUtil.sanitzieHtmlWithRegex(content);
		
		if (ServletUtil.isAppPropertyTrue("advancedStaticPageProcessing")){
			String path  = request.getSession().getServletContext().getRealPath("/static");

	        %>
```
### 5. 🗂️ Path Traversal
- **Descripción:** El mismo parámetro `content` de la página `index.jsp` es vulnerable a ataques de Path Traversal, permitiendo al atacante acceder a archivos fuera del directorio autorizado.

#### PoC
1.	Se ingresa a la máquina virtual
2.	Levantar el servicio de Altoro desde Eclipse
3.	Ingreso en http://localhost:8080/AltoroJ/
4.	Ingreso en http://localhost:8080/AltoroJ/index.jsp?content=personal_deposit.htm
5.	Ingreso al final de la dirección “ ';cd ../../../../../../../../../../../../etc;ls' ”quedando tal que localhost:8080/AltoroJ/index.jsp?content=personal_deposit.htm ';cd ../../../../../../../../../../../../etc;ls'

#### **Desarrollo de la Vulnerabilidad**

**Problema Original:**

Antes de implementar la corrección, el content estaba vulnerable ante factores de inserciones de comandos de movimiento entre directorios, permitiendo acceder a archivos y directorios privados.

Por ejemplo, un atacante podría hacer un ../ de manera arbitraria hasta llegar a la raíz del sistema y de ahí a acceder a directorios tales como etc.

**Solución Aplicada:**

Para mitigar esta vulnerabilidad, se implementaron controles adicionales específicos evitando de esta manera el uso ../ además de sanitizar la entrada.

``` java
		<%		
		java.lang.String content = request.getParameter("content");
		if (content == null)
			content = "default.htm";
		else
			content = request.getParameter("content");
		
		if (ServletUtil.isAppPropertyTrue("advancedStaticPageProcessing")){
			String path  = request.getSession().getServletContext().getRealPath("/static");

	        %>
```

``` java
		<%		
		java.lang.String content = request.getParameter("content");
		if (content == null)
			content = "default.htm";
		else
			content = content.replace("../", "");
            content = ServletUtil.sanitzieHtmlWithRegex(content);
		
		if (ServletUtil.isAppPropertyTrue("advancedStaticPageProcessing")){
			String path  = request.getSession().getServletContext().getRealPath("/static");

	        %>
```

Vulnerabilidades(1-3)

Vulnerabilidad 1 - Cross Site Scripting
PoC
1-Se ingresa a la maquina virtual
2-Levantar el servicio de Altoro desde Eclipse
3- Ingreso en  http://localhost:8080/AltoroJ/  
4- Ingresamos al parametro query de a url search.jsp http://localhost:8080/AltoroJ/search.jsp?query=
5- Nos damos cuenta de que al estar el parámetro query al descubierto en la URL, podemos ejecutar, por ejemplo, un script. Para explotar la vulnerabilidad, podemos cargar este script con código malicioso.
Un ejemplo de un script básico que lance una alerta es el siguiente.
<script> alert('Esta alerta se va a ejecutar')</script>

Mitigación de la vulnerabilidad:

Debemos sanitizar el parámetro query para que así no se pueda ejecutar nada dentro de él.
 


Vulnerabilidad 2 – SQL Injection
PoC
1- Se ingresa a la máquina virtual
2- Levantar el servicio de Altoro desde Eclipse
3- Ingreso en http://localhost:8080/AltoroJ/
4-Ingreso a la url del formulario de login: http://localhost:8080/AltoroJ/login.jsp
5- Como vemos, podemos escribir cualquier tipo de carácter en el formulario, por lo que debemos manipular la consulta SQL para que siempre sea verdadera y así podamos loguearnos de forma satisfactoria.
Un ejemplo de cómo podríamos realizar esto es si en el campo de usuario y contraseña escribimos lo siguiente: ' OR '1'='1.
Si nos damos cuenta, esta consulta siempre será verdadera. La consulta que Altoro le hace a la base de datos sería algo como esto:

SELECT * FROM usuarios WHERE usuario = 'input' AND contraseña = 'input';
Al manipular los datos, la consulta se vería así:
SELECT * FROM usuarios WHERE usuario = ' ' or '1'='1' AND contraseña = ' ' or '1'='1';
Como tenemos un OR en los dos parámetros, siempre que se cumpla una de las dos condiciones, esto será verdadero, y ' 1'='1' siempre será verdadero.

Mitigación de la vulnerabilidad:

Debemos hacer una función que básicamente verifique si el usuario está escribiendo alguno de los caracteres que no deben ser permitidos. Si encontramos algún carácter no permitido en el input de login, devolvemos false, mostrando una alerta al usuario que le indique que debe escribir un nombre de usuario o una contraseña válidos (que no contengan caracteres inválidos).
 

Vulnerabilidad 3 – Improper Input Validation:
PoC
1- Se ingresa a la máquina virtual
2- Levantar el servicio de Altoro desde Eclipse
3- Ingreso en http://localhost:8080/AltoroJ/
4-Ingreso a http://localhost:8080/AltoroJ/bank/showAccount?listAccounts=800002 , 
Allí podemos ver que el parámetro accounts es editable en la URL, por lo que simplemente podemos cambiar el número de cuenta y acceder a la cuenta de cualquier otro usuario.
Mitigación de la vulnerabilidad:
Lo que debemos hacer es validar que el usuario actual tenga las cuentas que tiene asignadas. Para ello, en AccountViewServlet, en el método doGet, accedemos al usuario actual e iteramos sobre la lista de cuentas asociadas a él. Si la cuenta a la que quiere acceder es una de las cuentas asociadas, entonces está en una cuenta autorizada; de lo contrario, la cuenta a la que quiere acceder no es una cuenta autorizada, por lo que hacemos que el servidor responda con un error al usuario.

 
 
![image](https://github.com/user-attachments/assets/6b596c10-bde4-4350-825f-01e312b982b9)

(Vulnerabilidad 4 & 5)
![image](https://github.com/user-attachments/assets/306d88c8-f1b1-467e-b739-91e7cfa958a6)


### 6. 🔐 Use of Hard-coded Credentials
- **Descripción:** La interfaz de administración (`/AltoroJ/admin/login.jsp`) utiliza credenciales codificadas directamente en el código fuente.
- **Solución:** Las credenciales se extraen a un archivo de configuración externo (`credenciales.properties`) para evitar su exposición en el código fuente.

#### PoC
1.	Se ingresa a la máquina virtual
2.	Levantar el servicio de Altoro desde Eclipse
3.	Ingreso en http://localhost:8080/AltoroJ/
4.	Ingreso a la dirección http://localhost:8080/AltoroJ/index.jsp?content=personal_loans.htm%27;cd%20git/AltoroJ/src/com/ibm/security/appscan/altoromutual/util/;%20cat%20ServletUtil.java%27 
Este rejunte de Path Traversal y OS Command Injection nos permite acceso a las credenciales hard-coded y poder acceder a ellas.
![image](https://github.com/user-attachments/assets/9318f8ac-f87b-41c4-8383-b65c57a0eb0a)


#### **Desarrollo de la Vulnerabilidad**

**Problema Original:**

Antes de implementar la corrección, Un atacante podía a través de otras vulnerabilidades en el sistema acceder a datos sensibles hard-coded, en este caso especifico a credenciales en el archivo servletUtils.java.

**Solución Aplicada:**

Para mitigar esta vulnerabilidad, se pueden recolocar estas credenciales al archivo credenciales.properties creado como hermano del archivo ServletUtil.java (aunque un caso mas idóneo sería el no ser ubicando en ningún sito accesible sino que activarlo mediante Docker por ejemplo). En esta solución obtenemos las credenciales de un archivo y no están directamente Hard-coded en el mismo archivo.

``` java
public class ServletUtil {

	public static final String SESSION_ATTR_USER = "user";
	public static final String SESSION_ATTR_ADMIN_VALUE = "altoroadmin";
	public static final String SESSION_ATTR_ADMIN_KEY = "admin";

```

``` java
import java.util.Properties;
...

public class ServletUtil {

    public static final String SESSION_ATTR_USER = "user";
    public static final String SESSION_ATTR_ADMIN_VALUE;
    public static final String SESSION_ATTR_ADMIN_KEY;
    
    static {
        Properties props = new Properties();
        InputStream input = ServletUtil.class.getClassLoader().getResourceAsStream("credenciales.properties");
        
        if (input != null) {
            loadProperties(props, input);
        }
        SESSION_ATTR_ADMIN_VALUE = props.getProperty("admin.username");
        SESSION_ATTR_ADMIN_KEY = props.getProperty("admin.password");
    }

    private static void loadProperties(Properties props, InputStream input) {
        try {
            props.load(input);
        } catch (Exception e) {
            props.setProperty("admin.username", "default_admin_value");
            props.setProperty("admin.password", "default_admin_password");
        }
    }
```
  
``` java
#credenciales

admin.username=altoroadmin
admin.password=admin
```


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
