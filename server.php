<?php
header('Content-Type: application/json');

// Manejar CORS si el frontend y backend están en diferentes dominios
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type");

// Manejar solicitudes preflight
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    exit(0);
}

// Abrir o crear la base de datos SQLite
$db = new PDO('sqlite:../databases/forestgreen.sqlite');
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Crear tablas si no existen
$db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)");

$db->exec("CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    contact_id INTEGER
)");

$db->exec("CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    from_id INTEGER,
    to_id INTEGER,
    type TEXT, -- 'user' o 'group'
    message TEXT,
    read_at DATETIME DEFAULT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");

$db->exec("CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE,
    admin_id INTEGER
)");

$db->exec("CREATE TABLE IF NOT EXISTS group_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER,
    user_id INTEGER
)");

$db->exec("CREATE TABLE IF NOT EXISTS user_profiles (
    user_id INTEGER PRIMARY KEY,
    photo BLOB,
    mime_type TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
)");

$db->exec("CREATE TABLE IF NOT EXISTS chat_images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER,
    image BLOB,
    FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE
)");

// Crear tabla typing_status
$db->exec("CREATE TABLE IF NOT EXISTS typing_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    contact_id INTEGER,
    type TEXT, -- 'user' o 'group'
    is_typing INTEGER,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
)");

// Ensure the "General" group exists and all users are members
ensureGeneralGroupExists($db);

// Obtener acción de POST o GET
$action = isset($_POST['action']) ? $_POST['action'] : (isset($_GET['action']) ? $_GET['action'] : '');

switch ($action) {
    case 'signup':
        signup($db);
        break;
    case 'login':
        login($db);
        break;
    case 'add_contact':
        addContact($db);
        break;
    case 'get_contacts':
        getContacts($db);
        break;
    case 'send_message':
        sendMessage($db);
        break;
    case 'get_messages':
        getMessages($db);
        break;
    case 'create_group':
        createGroup($db);
        break;
    case 'rename_group':
        renameGroup($db);
        break;
    case 'delete_group':
        deleteGroup($db);
        break;
    case 'add_to_group':
        addToGroup($db);
        break;
    case 'remove_from_group':
        removeFromGroup($db);
        break;
    case 'get_groups':
        getGroups($db);
        break;
    case 'get_user_id':
        getUserId($db);
        break;
    case 'upload_profile_photo':
        uploadProfilePhoto($db);
        break;
    case 'get_profile_photo':
        getProfilePhoto($db);
        break;
    case 'get_image':
        getImage($db);
        break;
    case 'typing_status':
        updateTypingStatus($db);
        break;
    case 'get_typing_status':
        getTypingStatus($db);
        break;
    case 'mark_as_read':
        markAsRead($db);
        break;
    case 'get_read_receipts':
        getReadReceipts($db);
        break;
    default:
        echo json_encode(['success' => false, 'message' => 'Acción no válida']);
}

// ------------------ FUNCIONES ------------------

function ensureGeneralGroupExists($db) {
    // Check if the "General" group exists
    $stmt = $db->prepare("SELECT id FROM groups WHERE name = 'General'");
    $stmt->execute();
    $group = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$group) {
        // Create the "General" group
        $stmt = $db->prepare("INSERT INTO groups (name, admin_id) VALUES ('General', 1)");
        $stmt->execute();
        $groupId = $db->lastInsertId();

        // Add all users to the "General" group
        $stmt = $db->prepare("INSERT INTO group_members (group_id, user_id) SELECT ?, id FROM users");
        $stmt->execute([$groupId]);
    }
}

function signup($db) {
    $username = trim($_POST['username'] ?? '');
    $password = trim($_POST['password'] ?? '');

    if (!$username || !$password) {
        echo json_encode(['success' => false, 'message' => 'Por favor, proporciona nombre de usuario y contraseña.']);
        return;
    }

    // Verificar si el nombre de usuario ya existe
    $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row) {
        echo json_encode(['success' => false, 'message' => 'Nombre de usuario ya en uso.']);
        return;
    }

    // Insertar nuevo usuario
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $db->prepare("INSERT INTO users (username, password) VALUES (?, ?)");
    $stmt->execute([$username, $hashedPassword]);

    // Add the new user to the "General" group
    $stmt = $db->prepare("SELECT id FROM groups WHERE name = 'General'");
    $stmt->execute();
    $group = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($group) {
        $groupId = $group['id'];
        $stmt = $db->prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, (SELECT id FROM users WHERE username = ?))");
        $stmt->execute([$groupId, $username]);
    }

    echo json_encode(['success' => true]);
}

function login($db) {
    $username = trim($_POST['username'] ?? '');
    $password = trim($_POST['password'] ?? '');

    if (!$username || !$password) {
        echo json_encode(['success' => false, 'message' => 'Por favor, proporciona nombre de usuario y contraseña.']);
        return;
    }

    $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($user && password_verify($password, $user['password'])) {
        echo json_encode(['success' => true, 'user_id' => $user['id']]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Credenciales inválidas']);
    }
}

function addContact($db) {
    $userId = intval($_POST['user_id'] ?? 0);
    $contactUsername = trim($_POST['contact_username'] ?? '');

    if (!$userId || !$contactUsername) {
        echo json_encode(['success' => false, 'message' => 'Faltan parámetros']);
        return;
    }

    // Evitar agregarse a sí mismo como contacto
    $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->execute([$contactUsername]);
    $contactUser = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$contactUser) {
        echo json_encode(['success' => false, 'message' => 'Usuario no encontrado']);
        return;
    }

    $contactId = $contactUser['id'];

    if ($contactId === $userId) {
        echo json_encode(['success' => false, 'message' => 'No puedes agregarte a ti mismo como contacto']);
        return;
    }

    // Verificar si ya se ha agregado
    $stmt = $db->prepare("SELECT id FROM contacts WHERE user_id = ? AND contact_id = ?");
    $stmt->execute([$userId, $contactId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($row) {
        // Ya es un contacto
        echo json_encode(['success' => false, 'message' => 'El contacto ya existe']);
        return;
    }

    // Insertar ambos lados (simétrico)
    $stmt = $db->prepare("INSERT INTO contacts (user_id, contact_id) VALUES (?, ?)");
    $stmt->execute([$userId, $contactId]);

    $stmt = $db->prepare("INSERT INTO contacts (user_id, contact_id) VALUES (?, ?)");
    $stmt->execute([$contactId, $userId]);

    echo json_encode(['success' => true]);
}

function getContacts($db) {
    $userId = intval($_POST['user_id'] ?? 0);
    if (!$userId) {
        echo json_encode(['success' => false, 'message' => 'Faltan user_id']);
        return;
    }

    $stmt = $db->prepare("
        SELECT u.id, u.username
        FROM contacts c
        JOIN users u ON c.contact_id = u.id
        WHERE c.user_id = ?
        ORDER BY u.username
    ");
    $stmt->execute([$userId]);
    $contacts = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(['success' => true, 'contacts' => $contacts]);
}

function sendMessage($db) {
    $fromId = intval($_POST['user_id'] ?? 0);
    $toId = intval($_POST['contact_id'] ?? 0);
    $message = trim($_POST['message'] ?? '');
    $type = $_POST['type'] ?? 'user'; // 'user' o 'group'
    $hasImage = isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK;

    if ((!$fromId || !$toId) || (!$message && !$hasImage)) {
        echo json_encode(['success' => false, 'message' => 'Faltan parámetros']);
        return;
    }

    if ($type === 'group') {
        // Verificar que el usuario sea miembro del grupo
        $stmt = $db->prepare("SELECT id FROM group_members WHERE group_id = ? AND user_id = ?");
        $stmt->execute([$toId, $fromId]);
        if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
            echo json_encode(['success' => false, 'message' => 'No eres miembro de este grupo']);
            return;
        }
    }

    // Insertar el mensaje
    $stmt = $db->prepare("INSERT INTO messages (from_id, to_id, type, message) VALUES (?, ?, ?, ?)");
    $stmt->execute([$fromId, $toId, $type, $message]);
    $messageId = $db->lastInsertId();

    if ($hasImage) {
        $imageData = file_get_contents($_FILES['image']['tmp_name']);
        $stmt = $db->prepare("INSERT INTO chat_images (message_id, image) VALUES (?, ?)");
        $stmt->bindParam(1, $messageId, PDO::PARAM_INT);
        $stmt->bindParam(2, $imageData, PDO::PARAM_LOB);
        $stmt->execute();
    }

    echo json_encode(['success' => true]);
}

function getMessages($db) {
    $userId = intval($_POST['user_id'] ?? 0);
    $contactId = intval($_POST['contact_id'] ?? 0);
    $type = $_POST['type'] ?? 'user'; // 'user' o 'group'
    $lastMessageId = intval($_POST['last_message_id'] ?? 0);

    if (!$userId || !$contactId) {
        echo json_encode(['success' => false, 'message' => 'Faltan parámetros']);
        return;
    }

    if ($type === 'group') {
        // Verificar que el usuario sea miembro del grupo
        $stmt = $db->prepare("SELECT id FROM group_members WHERE group_id = ? AND user_id = ?");
        $stmt->execute([$contactId, $userId]);
        if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
            echo json_encode(['success' => false, 'message' => 'No eres miembro de este grupo']);
            return;
        }

        // Obtener mensajes enviados al grupo después de lastMessageId
        $stmt = $db->prepare("
            SELECT id, from_id, to_id, type, message, read_at, created_at
            FROM messages
            WHERE to_id = :groupId AND type = 'group' AND id > :lastId
            ORDER BY created_at ASC
        ");
        $stmt->execute([':groupId' => $contactId, ':lastId' => $lastMessageId]);
        $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        // Lógica existente para mensajes entre usuarios con type 'user'
        $stmt = $db->prepare("
            SELECT id, from_id, to_id, type, message, read_at, created_at
            FROM messages
            WHERE type = 'user' AND (
                (from_id = :userId AND to_id = :contactId)
                OR
                (from_id = :contactId AND to_id = :userId)
            ) AND id > :lastId
            ORDER BY created_at ASC
        ");
        $stmt->execute([':userId' => $userId, ':contactId' => $contactId, ':lastId' => $lastMessageId]);
        $messages = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    echo json_encode(['success' => true, 'messages' => $messages]);
}

function createGroup($db) {
    $name = trim($_POST['name'] ?? '');
    $adminId = intval($_POST['admin_id'] ?? 0);

    if (!$name || !$adminId) {
        echo json_encode(['success' => false, 'message' => 'Faltan parámetros']);
        return;
    }

    // Verificar si el nombre del grupo ya existe
    $stmt = $db->prepare("SELECT id FROM groups WHERE name = ?");
    $stmt->execute([$name]);
    if ($stmt->fetch(PDO::FETCH_ASSOC)) {
        echo json_encode(['success' => false, 'message' => 'Nombre del grupo ya en uso']);
        return;
    }

    // Insertar nuevo grupo
    $stmt = $db->prepare("INSERT INTO groups (name, admin_id) VALUES (?, ?)");
    $stmt->execute([$name, $adminId]);
    $groupId = $db->lastInsertId();

    // Agregar al administrador como miembro
    $stmt = $db->prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)");
    $stmt->execute([$groupId, $adminId]);

    echo json_encode(['success' => true, 'group_id' => $groupId]);
}

function renameGroup($db) {
    $groupId = intval($_POST['group_id'] ?? 0);
    $newName = trim($_POST['new_name'] ?? '');
    $userId = intval($_POST['user_id'] ?? 0);

    if (!$groupId || !$newName || !$userId) {
        echo json_encode(['success' => false, 'message' => 'Faltan parámetros']);
        return;
    }

    // Verificar que el usuario sea el administrador
    $stmt = $db->prepare("SELECT admin_id FROM groups WHERE id = ?");
    $stmt->execute([$groupId]);
    $group = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$group || $group['admin_id'] != $userId) {
        echo json_encode(['success' => false, 'message' => 'No autorizado']);
        return;
    }

    // Verificar si el nuevo nombre del grupo ya existe
    $stmt = $db->prepare("SELECT id FROM groups WHERE name = ? AND id != ?");
    $stmt->execute([$newName, $groupId]);
    if ($stmt->fetch(PDO::FETCH_ASSOC)) {
        echo json_encode(['success' => false, 'message' => 'Nombre del grupo ya en uso']);
        return;
    }

    // Actualizar el nombre del grupo
    $stmt = $db->prepare("UPDATE groups SET name = ? WHERE id = ?");
    $stmt->execute([$newName, $groupId]);

    echo json_encode(['success' => true]);
}

function deleteGroup($db) {
    $groupId = intval($_POST['group_id'] ?? 0);
    $userId = intval($_POST['user_id'] ?? 0);

    if (!$groupId || !$userId) {
        echo json_encode(['success' => false, 'message' => 'Faltan parámetros']);
        return;
    }

    // Verificar que el usuario sea el administrador
    $stmt = $db->prepare("SELECT admin_id FROM groups WHERE id = ?");
    $stmt->execute([$groupId]);
    $group = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$group || $group['admin_id'] != $userId) {
        echo json_encode(['success' => false, 'message' => 'No autorizado']);
        return;
    }

    // Eliminar miembros del grupo
    $stmt = $db->prepare("DELETE FROM group_members WHERE group_id = ?");
    $stmt->execute([$groupId]);

    // Eliminar mensajes asociados al grupo
    $stmt = $db->prepare("DELETE FROM messages WHERE to_id = ? AND type = 'group'");
    $stmt->execute([$groupId]);

    // Eliminar grupo
    $stmt = $db->prepare("DELETE FROM groups WHERE id = ?");
    $stmt->execute([$groupId]);

    echo json_encode(['success' => true]);
}

function addToGroup($db) {
    $groupId = intval($_POST['group_id'] ?? 0);
    $userId = intval($_POST['user_id'] ?? 0);
    $adminId = intval($_POST['admin_id'] ?? 0); // Solo el administrador puede agregar usuarios

    if (!$groupId || !$userId || !$adminId) {
        echo json_encode(['success' => false, 'message' => 'Faltan parámetros']);
        return;
    }

    // Verificar que el usuario sea el administrador
    $stmt = $db->prepare("SELECT admin_id FROM groups WHERE id = ?");
    $stmt->execute([$groupId]);
    $group = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$group || $group['admin_id'] != $adminId) {
        echo json_encode(['success' => false, 'message' => 'No autorizado']);
        return;
    }

    // Verificar si el usuario ya es miembro
    $stmt = $db->prepare("SELECT id FROM group_members WHERE group_id = ? AND user_id = ?");
    $stmt->execute([$groupId, $userId]);
    if ($stmt->fetch(PDO::FETCH_ASSOC)) {
        echo json_encode(['success' => false, 'message' => 'El usuario ya está en el grupo']);
        return;
    }

    // Agregar usuario al grupo
    $stmt = $db->prepare("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)");
    $stmt->execute([$groupId, $userId]);

    echo json_encode(['success' => true]);
}

function removeFromGroup($db) {
    $groupId = intval($_POST['group_id'] ?? 0);
    $userId = intval($_POST['user_id'] ?? 0);
    $adminId = intval($_POST['admin_id'] ?? 0); // Solo el administrador puede eliminar usuarios

    if (!$groupId || !$userId || !$adminId) {
        echo json_encode(['success' => false, 'message' => 'Faltan parámetros']);
        return;
    }

    // Verificar que el usuario sea el administrador
    $stmt = $db->prepare("SELECT admin_id FROM groups WHERE id = ?");
    $stmt->execute([$groupId]);
    $group = $stmt->fetch(PDO::FETCH_ASSOC);
    if (!$group || $group['admin_id'] != $adminId) {
        echo json_encode(['success' => false, 'message' => 'No autorizado']);
        return;
    }

    // Evitar que el administrador sea eliminado
    if ($userId == $adminId) {
        echo json_encode(['success' => false, 'message' => 'El administrador no puede ser eliminado del grupo']);
        return;
    }

    // Eliminar usuario del grupo
    $stmt = $db->prepare("DELETE FROM group_members WHERE group_id = ? AND user_id = ?");
    $stmt->execute([$groupId, $userId]);

    echo json_encode(['success' => true]);
}

function getGroups($db) {
    $userId = intval($_POST['user_id'] ?? 0);
    if (!$userId) {
        echo json_encode(['success' => false, 'message' => 'Faltan user_id']);
        return;
    }

    $stmt = $db->prepare("
        SELECT g.id, g.name, g.admin_id, u.username as admin_username
        FROM group_members gm
        JOIN groups g ON gm.group_id = g.id
        JOIN users u ON g.admin_id = u.id
        WHERE gm.user_id = ?
        ORDER BY g.name
    ");
    $stmt->execute([$userId]);
    $groups = $stmt->fetchAll(PDO::FETCH_ASSOC);

    echo json_encode(['success' => true, 'groups' => $groups]);
}

function getUserId($db) {
    $username = trim($_POST['username'] ?? '');
    if (!$username) {
        echo json_encode(['success' => false, 'message' => 'Nombre de usuario no proporcionado']);
        return;
    }

    $stmt = $db->prepare("SELECT id FROM users WHERE username = ?");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    if ($user) {
        echo json_encode(['success' => true, 'user_id' => $user['id']]);
    } else {
        echo json_encode(['success' => false, 'message' => 'Usuario no encontrado']);
    }
}

// Funciones de Subida de Fotos de Perfil

function uploadProfilePhoto($db) {
    $userId = intval($_POST['user_id'] ?? 0);
    if (!$userId) {
        echo json_encode(['success' => false, 'message' => 'Faltan user_id']);
        return;
    }

    if (!isset($_FILES['photo']) || $_FILES['photo']['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(['success' => false, 'message' => 'La subida de la foto falló']);
        return;
    }

    $photoData = file_get_contents($_FILES['photo']['tmp_name']);
    $mimeType = mime_content_type($_FILES['photo']['tmp_name']); // Obtener tipo MIME

    // Validar tipo MIME
    $allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!in_array($mimeType, $allowedMimeTypes)) {
        echo json_encode(['success' => false, 'message' => 'Formato de imagen no soportado.']);
        return;
    }

    // Insertar o actualizar la foto de perfil y su tipo MIME
    $stmt = $db->prepare("REPLACE INTO user_profiles (user_id, photo, mime_type) VALUES (?, ?, ?)");
    $stmt->bindParam(1, $userId, PDO::PARAM_INT);
    $stmt->bindParam(2, $photoData, PDO::PARAM_LOB);
    $stmt->bindParam(3, $mimeType, PDO::PARAM_STR);
    $stmt->execute();

    echo json_encode(['success' => true]);
}

function getProfilePhoto($db) {
    $userId = intval($_GET['user_id'] ?? 0);
    if (!$userId) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Faltan user_id']);
        return;
    }

    $stmt = $db->prepare("SELECT photo, mime_type FROM user_profiles WHERE user_id = ?");
    $stmt->execute([$userId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row && $row['photo']) {
        header('Content-Type: ' . $row['mime_type']);
        echo $row['photo'];
    } else {
        // Devolver una imagen por defecto o un error
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'No se encontró foto de perfil']);
    }
}

// Funciones de Imagen de Chat

function getImage($db) {
    $messageId = intval($_GET['message_id'] ?? 0);
    if (!$messageId) {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'Faltan message_id']);
        return;
    }

    $stmt = $db->prepare("SELECT image FROM chat_images WHERE message_id = ?");
    $stmt->execute([$messageId]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row && $row['image']) {
        // Intentar detectar tipo MIME
        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $mimeType = $finfo->buffer($row['image']);
        if ($mimeType) {
            header('Content-Type: ' . $mimeType);
        } else {
            header('Content-Type: image/jpeg'); // Fallback
        }
        echo $row['image'];
    } else {
        header('Content-Type: application/json');
        echo json_encode(['success' => false, 'message' => 'No se encontró imagen para este mensaje']);
    }
}

// Funciones de Indicador de Escritura

function updateTypingStatus($db) {
    $userId = intval($_POST['user_id'] ?? 0);
    $contactId = intval($_POST['contact_id'] ?? 0);
    $type = $_POST['type'] ?? 'user'; // 'user' o 'group'
    $isTyping = intval($_POST['is_typing'] ?? 0);

    if (!$userId || !$contactId) {
        echo json_encode(['success' => false, 'message' => 'Faltan parámetros']);
        return;
    }

    // Verificar si el estado de escritura ya existe
    $stmt = $db->prepare("SELECT id FROM typing_status WHERE user_id = ? AND contact_id = ? AND type = ?");
    $stmt->execute([$userId, $contactId, $type]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row) {
        // Actualizar existente
        $stmt = $db->prepare("UPDATE typing_status SET is_typing = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
        $stmt->execute([$isTyping, $row['id']]);
    } else {
        // Insertar nuevo
        $stmt = $db->prepare("INSERT INTO typing_status (user_id, contact_id, type, is_typing) VALUES (?, ?, ?, ?)");
        $stmt->execute([$userId, $contactId, $type, $isTyping]);
    }

    echo json_encode(['success' => true]);
}

function getTypingStatus($db) {
    $userId = intval($_POST['user_id'] ?? 0);
    $contactId = intval($_POST['contact_id'] ?? 0);
    $type = $_POST['type'] ?? 'user'; // 'user' o 'group'

    if (!$userId || !$contactId) {
        echo json_encode(['success' => false, 'message' => 'Faltan parámetros']);
        return;
    }

    $stmt = $db->prepare("SELECT is_typing FROM typing_status WHERE user_id = ? AND contact_id = ? AND type = ? AND updated_at > datetime('now', '-5 seconds')");
    $stmt->execute([$contactId, $userId, $type]); // Intercambiar usuario y contacto para recibir estado de escritura
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($row && $row['is_typing']) {
        echo json_encode(['success' => true, 'is_typing' => true]);
    } else {
        echo json_encode(['success' => true, 'is_typing' => false]);
    }
}

// Funciones de Recibos de Lectura

function markAsRead($db) {
    $userId = intval($_POST['user_id'] ?? 0);
    $contactId = intval($_POST['contact_id'] ?? 0);
    $type = $_POST['type'] ?? 'user'; // 'user' o 'group'

    if (!$userId || !$contactId) {
        echo json_encode(['success' => false, 'message' => 'Faltan parámetros']);
        return;
    }

    if ($type === 'group') {
        // Verificar que el usuario sea miembro del grupo
        $stmt = $db->prepare("SELECT id FROM group_members WHERE group_id = ? AND user_id = ?");
        $stmt->execute([$contactId, $userId]);
        if (!$stmt->fetch(PDO::FETCH_ASSOC)) {
            echo json_encode(['success' => false, 'message' => 'No eres miembro de este grupo']);
            return;
        }

        // Actualizar read_at para todos los mensajes enviados al grupo antes de ahora
        $stmt = $db->prepare("UPDATE messages SET read_at = datetime('now') WHERE to_id = ? AND type = 'group' AND from_id != ? AND read_at IS NULL");
        $stmt->execute([$contactId, $userId]);
    } else {
        // Actualizar read_at para todos los mensajes enviados al usuario antes de ahora
        $stmt = $db->prepare("UPDATE messages SET read_at = datetime('now') WHERE to_id = ? AND type = 'user' AND from_id != ? AND read_at IS NULL");
        $stmt->execute([$contactId, $userId]);
    }

    echo json_encode(['success' => true]);
}

function getReadReceipts($db) {
    $userId = intval($_POST['user_id'] ?? 0);
    $contactId = intval($_POST['contact_id'] ?? 0);
    $type = $_POST['type'] ?? 'user'; // 'user' o 'group'

    if (!$userId || !$contactId) {
        echo json_encode(['success' => false, 'message' => 'Faltan parámetros']);
        return;
    }

    if ($type === 'group') {
        // Obtener recibos de lectura para mensajes de grupo enviados por el usuario
        $stmt = $db->prepare("
            SELECT m.id as message_id, u.username
            FROM messages m
            JOIN users u ON m.from_id = u.id
            WHERE m.to_id = ? AND m.type = 'group' AND m.from_id = ? AND m.read_at IS NOT NULL
        ");
        $stmt->execute([$contactId, $userId]);
        $readReceipts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    } else {
        // Obtener recibos de lectura para mensajes entre usuarios enviados por el usuario
        $stmt = $db->prepare("
            SELECT m.id as message_id, u.username
            FROM messages m
            JOIN users u ON m.from_id = u.id
            WHERE m.to_id = ? AND m.type = 'user' AND m.from_id = ? AND m.read_at IS NOT NULL
        ");
        $stmt->execute([$contactId, $userId]);
        $readReceipts = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    // Preparar la respuesta
    $response = [];
    foreach ($readReceipts as $receipt) {
        $response[] = [
            'message_id' => $receipt['message_id'],
            'username' => $receipt['username']
        ];
    }

    echo json_encode(['success' => true, 'read_receipts' => $response]);
}
?>

