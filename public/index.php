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

// Ruta de login
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

// Middleware de autenticación
$authMiddleware = function (Request $request, RequestHandler $handler) {
    if (!isset($_SESSION['user'])) {
        $response = new \Slim\Psr7\Response();
        $response->getBody()->write("No autorizado");
        return $response->withStatus(401);
    }
    return $handler->handle($request);
};

// Ruta protegida
$app->get('/protected', function (Request $request, Response $response) {
    $response->getBody()->write("Ruta protegida: Bienvenido, " . $_SESSION['user']);
    return $response;
})->add($authMiddleware);



// 3. Autenticación JWT
// Ruta de login para emitir token (usando Basic Authentication)
$app->post('/loginjwt', function (Request $request, Response $response) {
    $authHeader = $request->getHeaderLine('Authorization');
    
    $encoded = substr($authHeader, 6);
    $decoded = base64_decode($encoded);
    $credentials = explode(':', $decoded, 2);
    
    $username = $credentials[0];
    $password = $credentials[1];

    if ($username === 'user' && $password === 'password') {
        $key = "your_secret_key";
        $payload = [
            "iss" => "example.com",
            "aud" => "example.com",
            "iat" => time(),
            "nbf" => time(),
            "exp" => time() + 3600,
            "data" => [
                "username" => $username
            ]
        ];
        $token = JWT::encode($payload, $key, 'HS256');
        $response->getBody()->write(json_encode(["token" => $token]));
    } else {
        $response->getBody()->write(json_encode(["error" => "Credenciales inválidas"]));
        return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
    }
    return $response->withHeader('Content-Type', 'application/json');
});

// Middleware JWT
$app->add(new JwtAuthentication([
    "secret" => "your_secret_key",
    "secure" => false,
    "attribute" => "token",
    "path" => "/API_ALISBOOK/public/api/protectedjwt",
    "ignore" => ["/login"],
    "algorithm" => ["HS256"]
]));

// Ruta protegida
$app->get('/api/protectedjwt', function (Request $request, Response $response) {
    $token = $request->getAttribute('token');
    $username = $token['data']->username; 
    $response->getBody()->write(json_encode([
        "mensaje" => "Acceso autorizado con JWT",
        "usuario" => $username,
    ]));
    return $response->withHeader('Content-Type', 'application/json');
});

//la clase del middleware para jwt
//autorizacion
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
            $decoded = JWT::decode($token, new Key('your_secret_key', 'HS256'));
            $request = $request->withAttribute('user', (array)$decoded);
        } catch (\Exception $e) {
            $response = new \Slim\Psr7\Response();
            $response->getBody()->write(json_encode(['error' => 'Token inválido']));
            return $response->withStatus(401)->withHeader('Content-Type', 'application/json');
        }

        return $handler->handle($request);
    }
}

//los roles del middleware
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
    $res->getBody()->write("Hola Admin, {$user['name']}");
    return $res;
})->add(new RoleMiddleware(['admin']))
  ->add(new AuthMiddleware());



//RUTAASSS

$app->get('/productos', function (Request $request, Response $response) use ($pdo) {
    $stmt = $pdo->query("SELECT * FROM PRODUCTOS");
    $productos = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $response->getBody()->write(json_encode($productos));
    return $response->withHeader('Content-Type', 'application/json');
})->add(new AuthMiddleware());


$app->post('/productos', function (Request $request, Response $response) use ($pdo) {

    $data = $request->getParsedBody();

    $codigo        = $data['codigo'] ?? null;
    $nombre        = $data['nombre'] ?? null;
    $descripcion   = $data['descripcion'] ?? null;
    $stock         = $data['stock'] ?? 0;
    $precioCompra  = $data['preciocompra'] ?? 0;
    $precioVenta   = $data['precioventa'] ?? 0;
    $estado        = $data['estado'] ?? 'Activo';
    $fechaRegistro = $data['fecharegistro'] ?? date('Y-m-d H:i:s');
    $idCategoria   = $data['idcategoria'] ?? null;

    // Validación mínima
    if (!$codigo || !$nombre || !$idCategoria) {
        $response->getBody()->write(json_encode([
            'error' => 'Faltan campos requeridos: codigo, nombre o idcategoria'
        ]));
        return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
    }

    try {
        $sql = "INSERT INTO PRODUCTOS 
                (CODIGO, NOMBRE, DESCRIPCION, STOCK, PRECIOCOMPRA, PRECIOVENTA, ESTADO, FECHAREGISTRO, IDCATEGORIA)
                VALUES 
                (:codigo, :nombre, :descripcion, :stock, :preciocompra, :precioventa, :estado, :fecharegistro, :idcategoria)";
        
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':codigo'        => $codigo,
            ':nombre'        => $nombre,
            ':descripcion'   => $descripcion,
            ':stock'         => $stock,
            ':preciocompra'  => $precioCompra,
            ':precioventa'   => $precioVenta,
            ':estado'        => $estado,
            ':fecharegistro' => $fechaRegistro,
            ':idcategoria'   => $idCategoria
        ]);

        $nuevoId = $pdo->lastInsertId();

        $response->getBody()->write(json_encode([
            'mensaje' => 'Producto creado correctamente',
            'idproducto' => $nuevoId
        ]));
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(['error' => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }
})->add(new AuthMiddleware());

$app->delete('/productos/{id}', function (Request $request, Response $response, array $args) use ($pdo) {
$id = $args['id'];

if (!is_numeric($id)) {
    $response->getBody()->write(json_encode([
        'error' => 'Id invalido'
    ]));
    return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
}

try {
    $stmt = $pdo->prepare("SELECT * FROM PRODUCTOS WHERE idproducto = :id");
    $stmt->execute([':id' => $id]);
    $producto = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$producto) {
        $response->getBody()->write(json_encode([
            'error' => 'Producto no encontrado'
        ]));
        return $response->withStatus(404)->withHeader('Content-Type', 'application/json');
    }
    
    $stmt = $pdo->prepare("DELETE FROM PRODUCTOS WHERE idproducto = :id");
    $stmt->execute([':id' => $id]);

    $response->getBody()->write(json_encode([
        'mensaje' => 'Producto eliminado correctamente'
    ]));
    return $response->withHeader('Content-Type', 'application/json');

} catch (PDOException $e) {
    $response->getBody()->write(json_encode([
        'error' => $e->getMessage()
    ]));
    return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
}

})->add(new AuthMiddleware());

$app->get('/categorias', function (Request $request, Response $response) use ($pdo){
    $stmt = $pdo->query("SELECT * FROM CATEGORIAS");
    $categorias = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $response->getBody()->write(json_encode($categorias));
    return $response->withHeader('Content-Type', 'application/json');

})->add(new AuthMiddleware());

$app->post('/categorias', function (Request $request, Response $response) use ($pdo){

    $data = $request->getParsedBody();

    $idCategoria   = $data['idcategoria'] ?? null;
    $descripcion   = $data['descripcion'] ?? null;
    $estado        = $data['estado'] ?? 'Activo';
    $fechaRegistro = $data['fecharegistro'] ?? date('Y-m-d H:i:s');

    try {
        $sql = "INSERT INTO CATEGORIAS
        (IDCATEGORIA, DESCRIPCION, ESTADO, FECHAREGISTRO)
        VALUES
        (:idcategoria, :descripcion, :estado, :fecharegistro)";

        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':idcategoria'   => $idCategoria,
            ':descripcion'   => $descripcion,
            ':estado'        => $estado,
            ':fecharegistro' => $fechaRegistro
        ]);
        $nuevoId = $pdo->lastInsertId();

        $response->getBody()->write(json_encode([
            'mensaje' => 'Categoria creada correctamente',
            'idcategoria' => $nuevoId
        ]));
        return $response->withStatus(201)->withHeader('Content-Type', 'application/json');

    } catch (PDOException $e) {
        $response->getBody()->write(json_encode(['error' => $e->getMessage()]));
        return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
    }
})->add(new AuthMiddleware());

$app->delete('/categorias/{id}', function (Request $request, Response $response, array $args) use ($pdo) {
$id = $args['id'];

if (!is_numeric($id)) {
    $response->getBody()->write(json_encode([
        'error' => 'Id invalido'
    ]));
    return $response->withStatus(400)->withHeader('Content-Type', 'application/json');
}

try {
    $stmt = $pdo->prepare("SELECT * FROM CATEGORIAS WHERE idcategoria = :id");
    $stmt->execute([':id' => $id]);
    $categoria = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$categoria) {
        $response->getBody()->write(json_encode([
            'error' => 'Categoria no encontrada'
        ]));
        return $response->withStatus(404)->withHeader('Content-Type', 'application/json');
    }
    
    $stmt = $pdo->prepare("DELETE FROM CATEGORIAS WHERE idcategoria = :id");
    $stmt->execute([':id' => $id]);

    $response->getBody()->write(json_encode([
        'mensaje' => 'Categoria eliminada correctamente'
    ]));
    return $response->withHeader('Content-Type', 'application/json');

} catch (PDOException $e) {
    $response->getBody()->write(json_encode([
        'error' => $e->getMessage()
    ]));
    return $response->withStatus(500)->withHeader('Content-Type', 'application/json');
}
})->add(new AuthMiddleware());


$app->setBasePath('/API_ALISBOOK/public');
$app->run();