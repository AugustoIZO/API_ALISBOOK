# Variables de entorno en PHP

## Introducción

En el desarrollo de software, es importante separar la **configuración de la lógica del código**. Las **variables de entorno** permiten almacenar información sensible o dependiente del entorno, como:

* Credenciales de bases de datos
* Claves de API
* URLs de servicios externos

Su uso garantiza:

* Seguridad, evitando que datos sensibles queden hardcodeados.
* Flexibilidad, permitiendo distintos comportamientos según el entorno (desarrollo, pruebas, producción).
* Escalabilidad y facilidad de despliegue en entornos automatizados.

En PHP, estas variables pueden accederse mediante funciones nativas (`getenv()`, `$_ENV`) o con librerías.

---

## Formas de acceder a variables de entorno en PHP

### a) `getenv()`

Función nativa de PHP que devuelve el valor de una variable de entorno.

```php
<?php
$dbUser = getenv('DB_USER');
$dbPass = getenv('DB_PASS');

echo "Usuario: $dbUser, Contraseña: $dbPass";
```

> Retorna `false` si la variable no está definida.

---

### b) `$_ENV`

Array global de PHP que contiene todas las variables de entorno disponibles en el contexto de ejecución.

```php
<?php
$dbUser = $_ENV['DB_USER'] ?? 'default_user';
$dbPass = $_ENV['DB_PASS'] ?? 'default_pass';
```

> Se recomienda usar el operador `??` para evitar errores si la variable no existe.

---

### c) Archivo `.env` con librería `vlucas/phpdotenv`

Para proyectos medianos o grandes, es recomendable usar un archivo `.env` para almacenar la configuración sin exponerla en el repositorio.

#### Instalación:

```bash
composer require vlucas/phpdotenv
```

#### Archivo `.env`:

```
DB_USER=root
DB_PASS=1234
```

#### Carga de variables en PHP:

```php
<?php
require __DIR__ . '/vendor/autoload.php';

$dotenv = Dotenv\Dotenv::createImmutable(__DIR__);
$dotenv->load();

$dbUser = $_ENV['DB_USER'];
$dbPass = $_ENV['DB_PASS'];
```

> La librería lee el archivo y carga las variables en el entorno de ejecución, haciéndolas accesibles como si fueran variables de sistema.

---

## Dónde se guardan las variables de entorno

Las variables de entorno **no se almacenan en PHP**, sino que se configuran en el **entorno de ejecución**:

### a) Localmente

* **Variables del sistema operativo**:

  * Linux/macOS:

    ```bash
    export DB_USER=root
    export DB_PASS=1234
    ```
  * Windows (PowerShell):

    ```powershell
    setx DB_USER "root"
    setx DB_PASS "1234"
    ```

* **Archivo `.env`**: leído en tiempo de ejecución por PHP con librerías como phpdotenv.

### GitHub Actions / CI/CD

* Se guardan como **Secrets** en el repositorio.
* Al ejecutar un workflow, se inyectan en el entorno de ejecución temporal.
* PHP puede leerlas mediante `getenv()` o `$_ENV`.

### Producción / Servidores

* En servidores Linux, se configuran en `.bashrc`, `.profile` o directamente en la configuración del servidor web.
* En servidores Windows, se configuran en “Variables de entorno del sistema”.
* En contenedores Docker, se configuran como variables del contenedor.
  
##  Buenas prácticas

* Nunca subir archivos `.env` a repositorios públicos.
* Usar `getenv()` o `$_ENV` para acceso consistente.
* Usar constantes (`define`) si se necesitan valores inmutables:

```php
define('DB_USER', getenv('DB_USER'));
```

* Proporcionar valores por defecto para evitar errores en caso de que la variable no esté definida:

```php
$dbUser = getenv('DB_USER') ?: 'default_user';
```

---

## Variables de entorno y despliegue con GitHub Actions

Para despliegues automáticos y seguros:

### a) Configuración de Secrets

1. Repositorio → Settings → Secrets → New repository secret.
2. Crear variables como:

   * `DB_USER`
   * `DB_PASS`

### b) Workflow de ejemplo

```yaml
name: Deploy PHP App

on:
  push:
    branches:
      - main

jobs:
  deploy:
    runs-on: ubuntu-latest
    env:
      DB_USER: ${{ secrets.DB_USER }}
      DB_PASS: ${{ secrets.DB_PASS }}

    steps:
      - uses: actions/checkout@v3
      - name: Set up PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.2'
      - name: Install dependencies
        run: composer install
      - name: Run PHP script
        run: php scripts/test_env.php
```

### c) Acceso en PHP

```php
<?php
$dbUser = getenv('DB_USER');
$dbPass = getenv('DB_PASS');
```

> Funciona igual que en local, pero seguro y sin exponer datos sensibles.

---

## Según contexto

| Contexto         | Método recomendado                             |
| ---------------- | ---------------------------------------------- |
| Local            | `.env` + phpdotenv                             |
| Despliegue CI/CD | GitHub Secrets → Variables de entorno          |
| Producción       | Variables de entorno del servidor o contenedor |


---

1. PHP Manual. *getenv — Obtiene una variable de entorno*. PHP.net. Disponible en: [https://www.php.net/manual/es/function.getenv.php](https://www.php.net/manual/es/function.getenv.php)
2. PHP Manual. *Variables predefinidas — `$_ENV`*. PHP.net. Disponible en: [https://www.php.net/manual/es/reserved.variables.env.php](https://www.php.net/manual/es/reserved.variables.env.php)
3. vlucas/phpdotenv. *PHP dotenv*. GitHub Repository. Disponible en: [https://github.com/vlucas/phpdotenv](https://github.com/vlucas/phpdotenv)
4. GitHub Docs. *Encrypted secrets for GitHub Actions*. GitHub. Disponible en: [https://docs.github.com/en/actions/security-guides/encrypted-secrets](https://docs.github.com/en/actions/security-guides/encrypted-secrets)
5. GitHub Docs. *Using environment variables in GitHub Actions*. GitHub. Disponible en: [https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#environment-files](https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions#environment-files)