// ==========================================
// == MODUL KRIPTOGRAFI YANG DIIMPOR
// ==========================================
// Impor Pustaka Post-Quantum (Noble)
import { ml_kem1024 } from 'https://cdn.jsdelivr.net/npm/@noble/post-quantum@1.0.3/ml-kem.js';
import { ml_dsa87 } from 'https://cdn.jsdelivr.net/npm/@noble/post-quantum@1.0.3/ml-dsa.js';

// Impor Pustaka Hash (Noble)
import { sha512 } from 'https://cdn.jsdelivr.net/npm/@noble/hashes@1.4.0/sha512.js';
import { hkdf } from 'https://cdn.jsdelivr.net/npm/@noble/hashes@1.4.0/hkdf.js';


// ==========================================
// == FUNGSI KRIPTOGRAFI INTI (YANG HILANG)
// ==========================================

/**
 * Membuat Pasangan Kunci KEM Hibrida (ECDH P-521 + ML-KEM-1024)
 * Sesuai dengan NIST Level 5 untuk kerahasiaan.
 * @returns {Promise<Object>} Objek berisi kemPublicKey dan kemPrivateKey
 */
async function generateHybridKemKeys() {
  // 1. Buat dan ekspor kunci klasik ECDH P-521
  const classicPair = await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-521" },
    true,
   
  );
  const classicPublicKeyJwk = await window.crypto.subtle.exportKey(
    "jwk",
    classicPair.publicKey
  );
  const classicPrivateKeyJwk = await window.crypto.subtle.exportKey(
    "jwk",
    classicPair.privateKey
  );

  // 2. Buat dan konversi kunci PQC ML-KEM-1024
  const pqcPair = ml_kem1024.keygen();
  const pqcPublicKeyBase64 = arrayBufferToBase64(pqcPair.publicKey);
  const pqcPrivateKeyBase64 = arrayBufferToBase64(pqcPair.secretKey);

  // 3. Susun objek JSON final
  const kemPublicKey = {
    description: "Hybrid KEM Public Key (ECDH P-521 + ML-KEM-1024)",
    ecdh: classicPublicKeyJwk, // Format JWK
    mlkem: pqcPublicKeyBase64   // Format Base64
  };
  
  const kemPrivateKey = {
    description: "Hybrid KEM Private Key (ECDH P-521 + ML-KEM-1024)",
    ecdh: classicPrivateKeyJwk, // Format JWK
    mlkem: pqcPrivateKeyBase64   // Format Base64
  };

  // 4. Kembalikan sesuai kontrak API
  return { kemPublicKey, kemPrivateKey };
}


/**
 * Membuat Pasangan Kunci Tanda Tangan Hibrida (ECDSA P-521 + ML-DSA-87)
 * Sesuai dengan NIST Level 5 untuk autentikasi.
 * @returns {Promise<Object>} Objek berisi verifyPublicKey dan signPrivateKey
 */
async function generateHybridSignKeys() {
  // 1. Buat dan ekspor kunci klasik ECDSA P-521
  const classicPair = await window.crypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-521" },
    true,
    ["sign", "verify"]
  );
  const classicVerifyKeyJwk = await window.crypto.subtle.exportKey(
    "jwk",
    classicPair.publicKey
  );
  const classicSignKeyJwk = await window.crypto.subtle.exportKey(
    "jwk",
    classicPair.privateKey
  );

  // 2. Buat dan konversi kunci PQC ML-DSA-87
  const pqcPair = ml_dsa87.keygen();
  const pqcVerifyKeyBase64 = arrayBufferToBase64(pqcPair.publicKey);
  const pqcSignKeyBase64 = arrayBufferToBase64(pqcPair.secretKey);

  // 3. Susun objek JSON final
  const verifyPublicKey = {
    description: "Hybrid Verification Public Key (ECDSA P-521 + ML-DSA-87)",
    ecdsa: classicVerifyKeyJwk, // Format JWK
    mldsa: pqcVerifyKeyBase64   // Format Base64
  };
  
  const signPrivateKey = {
    description: "Hybrid Signing Private Key (ECDSA P-521 + ML-DSA-87)",
    ecdsa: classicSignKeyJwk, // Format JWK
    mldsa: pqcSignKeyBase64   // Format Base64
  };

  // 4. Kembalikan sesuai kontrak API
  return { verifyPublicKey, signPrivateKey };
}


/**
 * Mengenkripsi dan Menandatangani pesan menggunakan protokol hibrida penuh.
 * (Encrypt-then-Sign)
 * @param {string} plaintext - Teks biasa yang akan dikirim.
 * @param {string} recipientKemKeyJson - Kunci KEM Publik Penerima (JSON string).
 * @param {string} senderSignKeyJson - Kunci Tanda Tangan Privat Pengirim (JSON string).
 * @returns {Promise<string>} String Base64 dari payload JSON yang terenkripsi.
 */
async function hybridEncryptAndSign(plaintext, recipientKemKeyJson, senderSignKeyJson) {
  // --- LANGKAH 1: PARSING DAN IMPOR KUNCI ---
  const recipientKemKey = JSON.parse(recipientKemKeyJson);
  const senderSignKey = JSON.parse(senderSignKeyJson);
  const recipientEcdhKemPubCryptoKey = await window.crypto.subtle.importKey(
    "jwk", recipientKemKey.ecdh, { name: "ECDH", namedCurve: "P-521" }, true,
  );
  const recipientPqcKemPubUint8 = base64ToUint8Array(recipientKemKey.mlkem);
  const senderEcdsaSignPrivCryptoKey = await window.crypto.subtle.importKey(
    "jwk", senderSignKey.ecdsa, { name: "ECDSA", namedCurve: "P-521" }, true, ["sign"]
  );
  const senderMlDsaSignPrivUint8 = base64ToUint8Array(senderSignKey.mldsa);

  // --- LANGKAH 2 & 3: PENURUNAN KUNCI ENKRIPSI HIBRIDA (KEM & KDF) ---
  const { secret: pqcSecret, encapsulation: pqcEncapsulation } = 
    ml_kem1024.encapsulate(recipientPqcKemPubUint8);
  const ephemeralEcdhPair = await window.crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-521" }, true,
  );
  const ephemeralEcdhPublicKeyJwk = await window.crypto.subtle.exportKey(
    "jwk", ephemeralEcdhPair.publicKey
  );
  const ecdhSecret = await window.crypto.subtle.deriveBits(
    { name: "ECDH", public: recipientEcdhKemPubCryptoKey },
    ephemeralEcdhPair.privateKey, 521 
  );
  
  const combinedSecret = new Uint8Array(pqcSecret.length + ecdhSecret.byteLength);
  combinedSecret.set(pqcSecret, 0);
  combinedSecret.set(new Uint8Array(ecdhSecret), pqcSecret.length);
  
  const finalAesKeyBytes = hkdf(sha512, combinedSecret, null, 'aes-256-gcm-key', 32);
  const finalAesKey = await window.crypto.subtle.importKey(
    "raw", finalAesKeyBytes, { name: "AES-GCM" }, false, ["encrypt"]
  );

  // --- LANGKAH 4: ENKRIPSI DATA (AES-GCM) ---
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const plaintextBytes = textEncoder.encode(plaintext);
  const ciphertext = await window.crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, finalAesKey, plaintextBytes
  ); 

  // --- LANGKAH 5: TANDA TANGANI CIPHERTEXT HIBRIDA ---
  const ecdsaSignature = await window.crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-512" },
    senderEcdsaSignPrivCryptoKey,
    ciphertext
  );
  const mldsaSignature = ml_dsa87.sign(new Uint8Array(ciphertext), senderMlDsaSignPrivUint8);
  
  // --- LANGKAH 6: BUNGKUS PAYLOAD FINAL ---
  const payload = {
    pqcEncapsulation: arrayBufferToBase64(pqcEncapsulation),
    ephemeralEcdhPublicKeyJwk: ephemeralEcdhPublicKeyJwk,
    iv: arrayBufferToBase64(iv),
    ciphertext: arrayBufferToBase64(ciphertext),
    ecdsaSignature: arrayBufferToBase64(ecdsaSignature),
    mldsaSignature: arrayBufferToBase64(mldsaSignature)
  };
  
  const payloadJsonString = JSON.stringify(payload);
  return arrayBufferToBase64(textEncoder.encode(payloadJsonString));
}


/**
 * Memverifikasi dan Mendekripsi pesan yang diterima.
 * (Verify-then-Decrypt)
 * @param {string} payloadBase64 - String Base64 dari payload JSON yang diterima.
 * @param {string} senderVerifyKeyJson - Kunci Verifikasi Publik Pengirim (JSON string).
 * @param {string} recipientKemKeyJson - Kunci KEM Privat Penerima (JSON string).
 * @returns {Promise<string>} Teks biasa (plaintext) yang telah didekripsi.
 */
async function hybridVerifyAndDecrypt(payloadBase64, senderVerifyKeyJson, recipientKemKeyJson) {
  // --- LANGKAH 1: PARSING DAN IMPOR KUNCI & PAYLOAD ---
  const payloadJsonString = textDecoder.decode(base64ToUint8Array(payloadBase64));
  const payload = JSON.parse(payloadJsonString);
  
  const pqcEncapsulation = base64ToUint8Array(payload.pqcEncapsulation);
  const iv = base64ToUint8Array(payload.iv);
  const ciphertext = base64ToUint8Array(payload.ciphertext);
  const ecdsaSignature = base64ToUint8Array(payload.ecdsaSignature);
  const mldsaSignature = base64ToUint8Array(payload.mldsaSignature);
  const ephemeralEcdhPublicKeyJwk = payload.ephemeralEcdhPublicKeyJwk;

  const senderVerifyKey = JSON.parse(senderVerifyKeyJson);
  const recipientKemKey = JSON.parse(recipientKemKeyJson);

  const senderEcdsaVerifyPubCryptoKey = await window.crypto.subtle.importKey(
    "jwk", senderVerifyKey.ecdsa, { name: "ECDSA", namedCurve: "P-521" }, true, ["verify"]
  );
  const senderMlDsaVerifyPubUint8 = base64ToUint8Array(senderVerifyKey.mldsa);
  const recipientEcdhKemPrivCryptoKey = await window.crypto.subtle.importKey(
    "jwk", recipientKemKey.ecdh, { name: "ECDH", namedCurve: "P-521" }, true,
  );
  const recipientMlKemPrivUint8 = base64ToUint8Array(recipientKemKey.mlkem);
  const ephemeralEcdhPublicKey = await window.crypto.subtle.importKey(
    "jwk", ephemeralEcdhPublicKeyJwk, { name: "ECDH", namedCurve: "P-521" }, true,
  );

  // --- LANGKAH 2: VERIFIKASI TANDA TANGAN HIBRIDA (WAJIB PERTAMA!) ---
  const ecdsaValid = await window.crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-512" },
    senderEcdsaVerifyPubCryptoKey,
    ecdsaSignature,
    ciphertext
  );
  const mldsaValid = ml_dsa87.verify(
    mldsaSignature,
    ciphertext,
    senderMlDsaVerifyPubUint8
  );

  if (!ecdsaValid ||!mldsaValid) {
    throw new Error(`Verifikasi Tanda Tangan Gagal! (ECDSA: ${ecdsaValid}, ML-DSA: ${mldsaValid})`);
  }

  // --- LANGKAH 3 & 4: PENURUNAN KUNCI ENKRIPSI HIBRIDA (KEM & KDF) ---
  const pqcSecret = ml_kem1024.decapsulate(
    pqcEncapsulation,
    recipientMlKemPrivUint8
  );
  const ecdhSecret = await window.crypto.subtle.deriveBits(
    { name: "ECDH", public: ephemeralEcdhPublicKey },
    recipientEcdhKemPrivCryptoKey,
    521
  );
  
  const combinedSecret = new Uint8Array(pqcSecret.length + ecdhSecret.byteLength);
  combinedSecret.set(pqcSecret, 0);
  combinedSecret.set(new Uint8Array(ecdhSecret), pqcSecret.length);
  
  const finalAesKeyBytes = hkdf(sha512, combinedSecret, null, 'aes-256-gcm-key', 32);
  const finalAesKey = await window.crypto.subtle.importKey(
    "raw",
    finalAesKeyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  // --- LANGKAH 5: DEKRIPSI DATA (AES-GCM) ---
  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    finalAesKey,
    ciphertext
  );
  
  return textDecoder.decode(decryptedBuffer);
}


// ==========================================
// == LOGIKA UI ASLI 
// ==========================================

document.addEventListener('DOMContentLoaded', () => {
  // --- Pemilihan Elemen DOM
  const tabButtons = document.querySelectorAll('.tab-button');
  const contentSections = document.querySelectorAll('.content-section');
  // Tab Generate
  const generateKemBtn = document.getElementById('generateKemBtn');
  const generateSignBtn = document.getElementById('generateSignBtn');
  const kemPublicKeyEl = document.getElementById('kemPublicKey');
  const kemPrivateKeyEl = document.getElementById('kemPrivateKey');
  const verifyPublicKeyEl = document.getElementById('verifyPublicKey');
  const signPrivateKeyEl = document.getElementById('signPrivateKey');
  const copyKemPublicBtn = document.getElementById('copyKemPublicBtn');
  const copyKemPrivateBtn = document.getElementById('copyKemPrivateBtn');
  const copyVerifyPublicBtn = document.getElementById('copyVerifyPublicBtn');
  const copySignPrivateBtn = document.getElementById('copySignPrivateBtn');
  // Tab Encrypt
  const recipientKemPublicKeyEl = document.getElementById('recipientKemPublicKey');
  const senderSignPrivateKeyEl = document.getElementById('senderSignPrivateKey');
  const plainTextEl = document.getElementById('plainText');
  const encryptBtn = document.getElementById('encryptBtn');
  const encryptedTextEl = document.getElementById('encryptedText');
  const copyEncryptedBtn = document.getElementById('copyEncryptedBtn');
  // Tab Decrypt
  const recipientKemPrivateKeyEl = document.getElementById('recipientKemPrivateKey');
  const senderVerifyPublicKeyEl = document.getElementById('senderVerifyPublicKey');
  const cipherTextEl = document.getElementById('cipherText');
  const decryptBtn = document.getElementById('decryptBtn');
  const decryptedTextEl = document.getElementById('decryptedText');
  const copyDecryptedBtn = document.getElementById('copyDecryptedBtn');

  // --- Logika Pergantian Tab
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      tabButtons.forEach(btn => btn.classList.remove('active'));
      contentSections.forEach(sec => sec.classList.remove('active'));
      button.classList.add('active');
      const targetTab = button.getAttribute('data-tab');
      document.getElementById(`${targetTab}-view`).classList.add('active');
    });
  });

  // --- Fungsi Bantuan Konversi ---
  const arrayBufferToBase64 = (buffer) => btoa(String.fromCharCode(...new Uint8Array(buffer)));
  const base64ToUint8Array = (base64) => Uint8Array.from(atob(base64), c => c.charCodeAt(0));
  const textEncoder = new TextEncoder();
  const textDecoder = new TextDecoder();

  // --- Fungsi Bantuan Tombol Salin
  const setupCopyButton = (button, textarea) => {
    button.addEventListener('click', () => {
      const textToCopy = textarea.value;
      if (!textToCopy |

| textToCopy.startsWith('ERROR:') |
| textToCopy.startsWith('Harap tunggu')) return;
      
      navigator.clipboard.writeText(textToCopy).then(() => {
        const originalText = button.textContent;
        button.textContent = 'Tersalin!';
        button.classList.add('copied');
        setTimeout(() => {
          button.textContent = originalText;
          button.classList.remove('copied');
        }, 2000);
      });
    });
  };

  // --- PENANGAN EVENT LISTENER ---
  
  // Generate KEM Keys
  generateKemBtn.addEventListener('click', async () => {
    generateKemBtn.disabled = true;
    generateKemBtn.textContent = 'Membuat...';
    [kemPublicKeyEl, kemPrivateKeyEl].forEach(el => el.value = 'Harap tunggu, membuat kunci KEM Level 5...');
    try {
      // INI ADALAH FUNGSI YANG BARU DITAMBAHKAN
      const { kemPublicKey, kemPrivateKey } = await generateHybridKemKeys(); 
      kemPublicKeyEl.value = JSON.stringify(kemPublicKey, null, 2);
      kemPrivateKeyEl.value = JSON.stringify(kemPrivateKey, null, 2);
    } catch (error) {
      alert(`Gagal membuat kunci KEM: ${error.message}`);
      [kemPublicKeyEl, kemPrivateKeyEl].forEach(el => el.value = `ERROR: ${error.message}`);
    } finally {
      generateKemBtn.disabled = false;
      generateKemBtn.textContent = 'Buat Pasangan Kunci KEM (Level 5)';
    }
  });

  // Generate Sign Keys
  generateSignBtn.addEventListener('click', async () => {
    generateSignBtn.disabled = true;
    generateSignBtn.textContent = 'Membuat...';
    [verifyPublicKeyEl, signPrivateKeyEl].forEach(el => el.value = 'Harap tunggu, membuat kunci Tanda Tangan Level 5...');
    try {
      // INI ADALAH FUNGSI YANG BARU DITAMBAHKAN
      const { verifyPublicKey, signPrivateKey } = await generateHybridSignKeys();
      verifyPublicKeyEl.value = JSON.stringify(verifyPublicKey, null, 2);
      signPrivateKeyEl.value = JSON.stringify(signPrivateKey, null, 2);
    } catch (error) {
      alert(`Gagal membuat kunci Tanda Tangan: ${error.message}`);
      [verifyPublicKeyEl, signPrivateKeyEl].forEach(el => el.value = `ERROR: ${error.message}`);
    } finally {
      generateSignBtn.disabled = false;
      generateSignBtn.textContent = 'Buat Pasangan Kunci Tanda Tangan (Level 5)';
    }
  });

  // Encrypt & Sign
  encryptBtn.addEventListener('click', async () => {
    const recipientKemKey = recipientKemPublicKeyEl.value.trim();
    const senderSignKey = senderSignPrivateKeyEl.value.trim();
    const plaintext = plainTextEl.value;
    if (!recipientKemKey ||!senderSignKey ||!plaintext) {
      alert('Harap isi Kunci Publik KEM Penerima, Kunci Privat Tanda Tangan Anda, dan Teks Biasa.');
      return;
    }
    encryptBtn.disabled = true;
    encryptBtn.textContent = 'Mengenkripsi & Menandatangani...';
    encryptedTextEl.value = 'Memproses...';
    try {
      // INI ADALAH FUNGSI YANG BARU DITAMBAHKAN
      const resultB64 = await hybridEncryptAndSign(plaintext, recipientKemKey, senderSignKey);
      encryptedTextEl.value = resultB64;
    } catch (error) {
      encryptedTextEl.value = `ERROR: ${error.message}`;
      alert(`Terjadi kesalahan saat enkripsi: ${error.message}`);
    } finally {
      encryptBtn.disabled = false;
      encryptBtn.textContent = 'Enkripsi & Tanda Tangani Pesan';
    }
  });

  // Verify & Decrypt
  decryptBtn.addEventListener('click', async () => {
    const recipientKemKey = recipientKemPrivateKeyEl.value.trim();
    const senderVerifyKey = senderVerifyPublicKeyEl.value.trim();
    const ciphertext = cipherTextEl.value.trim();
    if (!recipientKemKey ||!senderVerifyKey ||!ciphertext) {
      alert('Harap isi Kunci Privat KEM Anda, Kunci Publik Verifikasi Pengirim, dan Pesan Terenkripsi.');
      return;
    }
    decryptBtn.disabled = true;
    decryptBtn.textContent = 'Memverifikasi & Mendekripsi...';
    decryptedTextEl.value = 'Memproses...';
    try {
      // INI ADALAH FUNGSI YANG BARU DITAMBAHKAN
      const decryptedText = await hybridVerifyAndDecrypt(ciphertext, senderVerifyKey, recipientKemKey);
      decryptedTextEl.value = decryptedText;
    } catch (error) {
      decryptedTextEl.value = `ERROR: ${error.message}`;
      alert(`Terjadi kesalahan saat dekripsi: ${error.message}`);
    } finally {
      decryptBtn.disabled = false;
      decryptBtn.textContent = 'Verifikasi & Dekripsi Pesan';
    }
  });

  // --- Inisialisasi Tombol Salin
  setupCopyButton(copyKemPublicBtn, kemPublicKeyEl);
  setupCopyButton(copyKemPrivateBtn, kemPrivateKeyEl);
  setupCopyButton(copyVerifyPublicBtn, verifyPublicKeyEl);
  setupCopyButton(copySignPrivateBtn, signPrivateKeyEl);
  setupCopyButton(copyEncryptedBtn, encryptedTextEl);
  setupCopyButton(copyDecryptedBtn, decryptedTextEl);
});
