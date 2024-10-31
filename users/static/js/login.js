// LOGIN
document.getElementById('login-form').addEventListener('submit', async function (event) {
    event.preventDefault();

    const email = document.getElementById('email').value;
    const masterPassword = document.getElementById('master_password').value;

    try {
        // Отримуємо сіль для даного email з сервера
        const salt = await getSalt(email); // Зараз повертає ArrayBuffer

        if (!salt) {
            document.getElementById('status').textContent = 'Salt retrieval failed';
            return;
        }

        // Хешуємо masterPassword разом із сіллю
        const hashedPassword = await hashMasterPassword(masterPassword, salt);

        // Викликаємо функцію для відправки даних логіну на сервер
        const response = await loginUser(email, hashedPassword);
        const statusElement = document.getElementById('status');

        if (response.error) {
            // Виводимо помилку, якщо автентифікація неуспішна
            statusElement.textContent = 'Error: ' + response.error;
        } else {
            // Якщо логін успішний, генеруємо AES-ключ для шифрування/розшифрування паролів
            const key = await generateAESKey(masterPassword, salt);

            // Перевіряємо успішність генерації ключа
            if (!key) {
                console.error("Key generation error");
                statusElement.textContent = 'Key generation error';
                return;
            }

            // Записуємо ключ в session storage (не зберігаємо його на сервері!)
            sessionStorage.setItem('encryptionKey', arrayBufferToBase64(await crypto.subtle.exportKey('raw', key)));

            // Виводимо повідомлення про успішний логін
            statusElement.textContent = 'Success login';
        }
    } catch (error) {
        console.error('Error during login:', error);
        document.getElementById('status').textContent = 'Login error';
    }
});

// Функція для отримання солі для користувача з сервера
async function getSalt(email) {
    const response = await fetch('/users/get_salt/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrftoken, // Include CSRF token
        },
        body: JSON.stringify({ email: email })
    });

    if (response.ok) {
        const data = await response.json();

        // Декодуємо сіль з Base64
        const saltBase64 = data.salt;
        return base64ToArrayBuffer(saltBase64); // Функція для перетворення Base64 на Uint8Array
    } else {
        throw new Error('Failed to retrieve salt');
    }
}


// Допоміжна функція для перетворення Base64 на ArrayBuffer
function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const len = binaryString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer; // Повертаємо ArrayBuffer
}

// Function to get the CSRF token from the cookie
function getCookie(name) {
    let cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        const cookies = document.cookie.split(';');
        for (let i = 0; i < cookies.length; i++) {
            const cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}

// Get CSRF token
const csrftoken = getCookie('csrftoken');

// Функція для логіну користувача з відправкою хешованого пароля на сервер
async function loginUser(email, hashedPassword) {
    const data = {
        email: email,
        hashed_password: arrayBufferToBase64(hashedPassword),  // Конвертуємо в Base64
    };

    const response = await fetch('/users/login/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrftoken, // Include CSRF token
        },
        body: JSON.stringify(data)
    });

    return await response.json();
}

// Функція для хешування пароля за допомогою PBKDF2 з використанням солі
async function hashMasterPassword(password, salt) {
    const encoder = new TextEncoder();
    const passwordKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
    );

    const hashedBuffer = await crypto.subtle.deriveBits(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        passwordKey,
        256  // 256-бітний хеш
    );

    return new Uint8Array(hashedBuffer);
}

// Функція для генерації AES-ключа для шифрування/розшифрування паролів
async function generateAESKey(masterPassword, salt) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(masterPassword),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    return await crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
}

// Допоміжна функція для перетворення ArrayBuffer на Base64
function arrayBufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
}
