## Conexión a MariaDB usando PDO  
Para conectar PHP con una base de datos MariaDB (compatible con el controlador MySQL de PDO, se utiliza la clase `PDO` con un **DSN** (Data Source Name) adecuado. Ejemplo:  
```php
$host = 'localhost';  
$db   = 'mi_base';  
$port = 3306;  
$charset = 'utf8mb4';  
$dsn = "mysql:host=$host;port=$port;dbname=$db;charset=$charset";
```  
Es importante incluir el parámetro `charset=utf8mb4` para garantizar la codificación correcta de caracteres. Al crear la instancia de PDO, se pasan también el usuario, la contraseña y opciones de configuración. Por ejemplo, es buena práctica activar el modo de excepciones y desactivar la emulación de sentencias preparadas:  
```php
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,    // Excepciones en caso de error
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,          // Fetch por defecto en array asociativo
    PDO::ATTR_EMULATE_PREPARES   => false,                     // Sentencias preparadas reales
];

try {
    $pdo = new PDO($dsn, $usuario, $password, $options);
} catch (PDOException $e) {
    // Manejar error de conexión (log y mensaje genérico al usuario)
    error_log($e->getMessage());
    exit('Error al conectarse a la base de datos.');
}
```  
Este ejemplo ilustra la creación de la conexión con `PDO` usando `mysql:` como driver. La directiva `PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION` asegura que PDO lance **PDOException** en caso de fallo (en lugar de advertencias silenciosas). Además, como nota importante, *el constructor de PDO siempre lanzará una excepción si la conexión falla*, por lo que el `try/catch` es necesario para capturar ese error. 

## Operaciones CRUD básicas  
Una vez establecida la conexión, podemos realizar operaciones CRUD (**Crear, Leer, Actualizar, Borrar**) usando sentencias SQL. Para cada operación se recomienda utilizar *sentencias preparadas* por seguridad y rendimiento, pero aquí mostramos ejemplos simples:

- **Crear (INSERT):** Insertar un registro en la tabla. Por ejemplo, para añadir un nuevo usuario:  
  ```php
  $sql = "INSERT INTO usuarios (nombre, email) VALUES (:nombre, :email)";
  $stmt = $pdo->prepare($sql);
  $stmt->execute([
      ':nombre' => $nombreUsuario,
      ':email'  => $emailUsuario
  ]);
  // Obtener ID insertado (si es necesario)
  $ultimoId = $pdo->lastInsertId();
  ```  
  Este código prepara la consulta con marcadores nombrados (`:nombre`, `:email`), asigna los valores y la ejecuta. Alternativamente, se puede usar `?` en lugar de nombres y pasar un arreglo indexado al `execute()`. Por ejemplo:  
  ```php
  $stmt = $pdo->prepare("INSERT INTO usuarios (nombre, email) VALUES (?, ?)");
  $stmt->execute([$nombreUsuario, $emailUsuario]);
  ```  
  *(Basado en ejemplos de MariaDB)* ([Developer Quickstart: PHP Data Objects and MariaDB | MariaDB](https://mariadb.com/resources/blog/developer-quickstart-php-data-objects-and-mariadb/)).

- **Leer (SELECT):** Obtener datos de la base. Por ejemplo, traer todos los usuarios:  
  ```php
  $stmt = $pdo->query("SELECT id, nombre, email FROM usuarios ORDER BY id DESC");
  $usuarios = $stmt->fetchAll();  // Como hemos establecido FETCH_ASSOC, fetchAll() retorna array asociativo
  ```  
  Si necesitamos filtrar por algún campo, se debe usar `prepare` con parámetros. Por ejemplo, buscar por correo:  
  ```php
  $sql = "SELECT * FROM usuarios WHERE email = :email";
  $stmt = $pdo->prepare($sql);
  $stmt->execute([':email' => $emailBuscado]);
  $usuario = $stmt->fetch();
  ```  

- **Actualizar (UPDATE):** Modificar datos existentes. Por ejemplo, cambiar el email de un usuario:  
  ```php
  $sql = "UPDATE usuarios SET email = :email WHERE id = :id";
  $stmt = $pdo->prepare($sql);
  $stmt->execute([
      ':email' => $nuevoEmail,
      ':id'    => $idUsuario
  ]);
  ```  

- **Borrar (DELETE):** Eliminar registros. Ejemplo de borrar un usuario por su ID:  
  ```php
  $sql = "DELETE FROM usuarios WHERE id = :id";
  $stmt = $pdo->prepare($sql);
  $stmt->execute([':id' => $idUsuario]);
  ```  

En todos los casos anteriores se demuestra el uso de **sentencias preparadas** con parámetros, lo cual sirve para prevenir inyecciones SQL ([PHP: PDO::prepare - Manual ](https://www.php.net/manual/es/pdo.prepare.php)). Las sentencias preparadas permiten separar la estructura SQL de los datos, evitando concatenar cadenas sin control. 

## Sentencias Preparadas y Prevención de Inyección SQL  
Las *prepared statements* son plantillas SQL compiladas a las que se adjuntan datos en forma de parámetros. Esto **mejora el rendimiento** en consultas repetidas y **previene las inyecciones SQL** al eliminar la necesidad de escapado manual. Usar `PDO::prepare()` y `PDOStatement::execute()` con diferentes parámetros optimiza recursos y ayuda a prevenir inyecciones SQL ([PHP: PDO::prepare - Manual ](https://www.php.net/manual/es/pdo.prepare.php)). 

Para implementar sentencias preparadas con PDO, el proceso es:  
1. **Preparar la consulta:** Crear la plantilla SQL con marcadores (por ejemplo, `:parametro` o `?`).  
2. **Vincular valores:** Asignar valores a los marcadores usando `bindParam()`, `bindValue()` o pasando un arreglo a `execute()`.  
3. **Ejecutar la consulta:** Llamar a `$stmt->execute()` para enviar la consulta con los valores.  

Por ejemplo:  
```php
// Ejemplo con marcadores nombrados
$stmt = $pdo->prepare("SELECT * FROM usuarios WHERE email = :email AND activo = :activo");
$stmt->bindValue(':email', $emailBuscado);
$stmt->bindValue(':activo', $activo);  // también podríamos usar bindParam
$stmt->execute();
$resultados = $stmt->fetchAll();

// Ejemplo con marcadores posicionales
$stmt = $pdo->prepare("INSERT INTO productos (nombre, precio) VALUES (?, ?)");
$stmt->execute([$nombreProducto, $precioProducto]);
```
Estos fragmentos ilustran cómo separar el SQL de los datos del usuario. Al usar marcadores en vez de concatenar variables, PDO maneja internamente el escape, eliminando el riesgo de **SQL injection** en esas partes de la consulta. Las buenas prácticas de seguridad recomiendan encarecidamente siempre preparar las consultas con variables externas ([PHP: PDO::prepare - Manual ](https://www.php.net/manual/es/pdo.prepare.php)).