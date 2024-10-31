/**
 * Imports a JSON Web Key (JWK) and converts it to a CryptoKey suitable for use in AES-GCM operations.
 *
 * @param {string} jwk - A stringified JSON representation of the key in JWK format.
 * @return {Promise<CryptoKey>} A promise that resolves to a CryptoKey object.
 */
async function importCryptoKey(jwk) {
    const key = await crypto.subtle.importKey(
        "jwk",
        JSON.parse(jwk),
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"]
    );
    return key;
}

/**
 * Loads an encryption key from IndexedDB.
 *
 * @return {Promise<CryptoKey>} A promise that resolves to the imported encryption key.
 */
async function loadKeyFromIndexedDB() {
    return new Promise((resolve, reject) => {
        const dbRequest = indexedDB.open("crypto-keys", 1);

        dbRequest.onsuccess = (event) => {
            const db = event.target.result;
            const transaction = db.transaction(["keys"], "readonly");
            const store = transaction.objectStore("keys");
            const keyRequest = store.get("encryption-key");

            keyRequest.onsuccess = async (event) => {
                const result = event.target.result;
                if (result) {
                    const key = await importCryptoKey(result.key);
                    resolve(key);
                } else {
                    reject("Key not found");
                }
            };

            keyRequest.onerror = (event) => {
                reject("IndexedDB error: " + event.target.errorCode);
            };
        };

        dbRequest.onerror = (event) => {
            reject("IndexedDB error: " + event.target.errorCode);
        };
    });
}



