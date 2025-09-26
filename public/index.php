<?php
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;
use Tuupola\Middleware\HttpBasicAuthentication;
use Slim\Middleware\Session;
use Psr\Http\Server\RequestHandlerInterface as RequestHandler;
use Tuupola\Middleware\JwtAuthentication;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

require __DIR__ . '/../vendor/autoload.php';
require_once __DIR__ . '/../src/db.php';

$app = AppFactory::create();
$app->addBodyParsingMiddleware();

// 1. Autenticación Básica
$app->add(new HttpBasicAuthentication([
    "path" => "/API_ALISBOOK/public/api/protected",
    "secure" => false,
    "users" => [
        "user" => "password",
        "augusto" => "izo"
    ]
]));

$app->get('/api/protected', function (Request $request, Response $response) {
    $response->getBody()->write("Ruta protegida accesible");
    return $response;
});

// 2. Autenticación Basada en Sesiones
$app->add(new Session([
    'name' => 'my_session',
    'autorefresh' => true,
    'lifetime' => '1 hour',
]));

// Ruta de login con sesiones
$app->post('/login', function (Request $request, Response $response) {
    $data = $request->getParsedBody();
    $username = $data['username'] ?? '';
    $password = $data['password'] ?? '';

    if ($username === 'user' && $password === 'password') {
        $_SESSION['user'] = $username;
        $response->getBody()->write("Inicio de sesión exitoso");
    } else {
        $response->getBody()->write("Credenciales inválidas");
        return $response->withStatus(401);
    }
    return $response;
});

// Middleware de autenticación por sesión
$authMiddleware = function (Request $request, RequestHandler $handler) {
    if (!isset($_SESSION['user'])) {
        $response = new \Slim\Psr7\Response();
        $response->getBody()->write("No autorizado");
        return $response->withStatus(401);
    }
    return $handler->handle($request);
};

// Ruta protegida por sesión
$app->get('/protected', function (Request $request, Response $response) {
    $response->getBody()->write("Ruta protegida: Bienvenido, " . $_SESSION['user']);
    return $response;
})->add($authMiddleware);

// 3. Autenticación JWT
$app->post('/loginjwt', function (Request $request, Response $response) use ($pdo) {
    $authHeader = $request->getHeaderLine('Authorization');

    if (!$authHeader || strpos($authHeader, 'Basic ') !== 0) {
        $response->getBody()->write(json_encode(["error" => "Authorization header requerido"]));
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
    }

    $encoded = substr($authHeader, 6);
    $decoded = base64_decode($encoded);
    $credentials = explode(':', $decoded, 2);

    if (count($credentials) !== 2) {
        $response->getBody()->write(json_encode(["error" => "Formato de credenciales inválido"]));
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
    }

    $username = $credentials[0];
    $password = $credentials[1];

    try {
        $stmt = $pdo->prepare("
            SELECT u.IDUSUARIO, u.DOCUMENTO, u.NOMBRECOMPLETO, u.CORREO, u.CLAVE, u.ESTADO, u.IDROL, r.DESCRIPCION as ROL
            FROM USUARIOS u 
            LEFT JOIN ROLES r ON u.IDROL = r.IDROL 
            WHERE (u.DOCUMENTO = :username OR u.CORREO = :username) AND u.ESTADO = 'Activo'
        ");
        $stmt->execute([':username' => $username]);
        $usuario = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($usuario && $usuario['CLAVE'] === $password) {
            $key = $_ENV['JWT_SECRET'];
            $payload = [
                "iss" => "example.com",
                "aud" => "example.com",
                "iat" => time(),
                "nbf" => time(),
                "exp" => time() + 3600,
                "data" => [
                    "id" => $usuario['IDUSUARIO'],
                    "username" => $usuario['DOCUMENTO'],
                    "nombre" => $usuario['NOMBRECOMPLETO'],
                    "correo" => $usuario['CORREO'],
                    "role" => $usuario['ROL'], 
                    "idrol" => $usuario['IDROL']
                ]
            ];
            $token = JWT::encode($payload, $key, 'HS256');

            $response->getBody()->write(json_encode([
                "token" => $token,
                "usuario" => [
                    "id" => $usuario['IDUSUARIO'],
                    "nombre" => $usuario['NOMBRECOMPLETO'],
                    "correo" => $usuario['CORREO'],
                    "role" => $usuario['ROL']
                ]
            ]));
        } else {
            $response->getBody()->write(json_encode(["error" => "Credenciales inválidas"]));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }
    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(["error" => "Error de base de datos"]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }

    return $response->withHeader('Content-Type', 'application/json');
});

// Middleware JWT
$app->add(new JwtAuthentication([
    "secret" => $_ENV['JWT_SECRET'],
    "secure" => false,
    "attribute" => "token",
    "path" => "/API_ALISBOOK/public/api/protectedjwt",
    "ignore" => ["/login"],
    "algorithm" => ["HS256"]
]));


// Ruta protegida con JWT
$app->get('/api/protectedjwt', function (Request $request, Response $response) {
    $token = $request->getAttribute('token');
    $userData = $token['data'];

    $response->getBody()->write(json_encode([
        "mensaje" => "Acceso autorizado con JWT",
        "usuario" => [
            "id" => $userData->id,
            "username" => $userData->username,
            "nombre" => $userData->nombre,
            "correo" => $userData->correo,
            "role" => $userData->role
        ],
    ]));
    return $response->withHeader('Content-Type', 'application/json');
});

// Middleware Auth
class AuthMiddleware {
    public function __invoke(Request $request, RequestHandler $handler): Response {
        $authHeader = $request->getHeaderLine('Authorization');
        if (!$authHeader) {
            $response = new \Slim\Psr7\Response();
            $response->getBody()->write(json_encode(['error' => 'Token requerido']));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }

        $token = str_replace('Bearer ', '', $authHeader);

        try {
            $decoded = JWT::decode($token, new Key($_ENV['JWT_SECRET'], 'HS256'));
            $request = $request->withAttribute('user', (array)$decoded->data);
        } catch (\Exception $e) {
            $response = new \Slim\Psr7\Response();
            $response->getBody()->write(json_encode(['error' => 'Token inválido']));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }

        return $handler->handle($request);
    }
}

// Middleware Roles
class RoleMiddleware {
    private array $allowedRoles;

    public function __construct(array $allowedRoles) {
        $this->allowedRoles = $allowedRoles;
    }

    public function __invoke(Request $request, RequestHandler $handler): Response {
        $user = $request->getAttribute('user');
        if (!$user || !in_array($user['role'], $this->allowedRoles)) {
            $response = new \Slim\Psr7\Response();
            $response->getBody()->write(json_encode(['error' => 'Acceso denegado']));
            return $response->withStatus(403)->withHeader('Content-Type', 'application/json');
        }
        return $handler->handle($request);
    }
}

// Ruta pública
$app->get('/public', function ($req, $res) {
    $res->getBody()->write("Acceso libre");
    return $res;
});

// Ruta protegida: solo administradores
$app->get('/admin', function ($req, $res) {
    $user = $req->getAttribute('user');
    $res->getBody()->write("Hola {$user['nombre']}");
    return $res;
})->add(new RoleMiddleware(['Administrador']))
  ->add(new AuthMiddleware());

// VARIABLES DE ENTORNO
$dotenv = Dotenv\Dotenv::createImmutable(__DIR__ . '/../');
$dotenv->load();

$dbUser = $_ENV['DB_USER'];
$dbPass = $_ENV['DB_PASS'];

$app->setBasePath('/API_ALISBOOK/public');
$app->run();
