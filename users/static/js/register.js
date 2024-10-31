document.getElementById('register-form').addEventListener('submit', async function (event) {
    event.preventDefault();

    const email = document.getElementById('email').value;
    const masterPassword = document.getElementById('master_password').value;
    const confirmMasterPassword = document.getElementById('confirm_master_password').value;

    // Перевірка правильності email
    if (!validateEmail(email)) {
        document.getElementById('status').textContent = 'Invalid email address!';
        return;
    }

    // Перевірка, чи співпадають паролі
    if (masterPassword !== confirmMasterPassword) {
        document.getElementById('status').textContent = 'Passwords do not match!';
        return;
    }

    try {
        // Генеруємо сіль
        const salt = generateSalt();

        // Хешуємо пароль
        const hashedPassword = await hashMasterPassword(masterPassword, salt);

        // Перетворюємо сіль і хеш на Base64 для зручної передачі через JSON
        const saltBase64 = arrayBufferToBase64(salt);
        const hashedPasswordBase64 = arrayBufferToBase64(hashedPassword);

        // Відправляємо дані на сервер
        const response = await registerUser(email, hashedPasswordBase64, saltBase64);

        // Перевірка відповіді від сервера
        if (response.error) {
            // Виведення помилки на сторінці
            document.getElementById('status').textContent = 'Error: ' + response.error;
        } else {
            // Виведення успішного повідомлення
            document.getElementById('status').textContent = response.message;
        }
    } catch (error) {
        document.getElementById('status').textContent = 'Registration failed: ' + error;
    }
});

// Функція для перевірки форматування email
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(String(email).toLowerCase());
}

// Генерація випадкової солі
function generateSalt(length = 16) {
    return crypto.getRandomValues(new Uint8Array(length));
}

// Хешування пароля за допомогою PBKDF2 з сіллю
async function hashMasterPassword(password, salt) {
    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits", "deriveKey"]
    );
    const hashedBuffer = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        passwordKey,
        256 // 256 біт
    );
    return new Uint8Array(hashedBuffer);
}

// Перетворення ArrayBuffer на Base64 для передачі через JSON
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}

// Реєстрація користувача, відправка даних на сервер
async function registerUser(email, hashedPasswordBase64, saltBase64) {
    const data = {
        email: email,
        hashed_password: hashedPasswordBase64,
        salt: saltBase64
    };

    const response = await fetch('/users/register/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(data)
    });

    return await response.json();
}
