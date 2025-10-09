import os
import struct
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import argparse

# --- Importaciones (Asegúrate de tener pycryptodome instalado) ---
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from oqs import KeyEncapsulation

# Definiciones para ML-KEM-1024 (Kyber1024)
OQS_ALGORITHM = 'Kyber1024'
RSA_PUB_FILE = "rsa_pub.pem"
OQS_PUB_FILE = "oqs_pub.bin"
OQS_PRIV_FILE = "oqs_priv.bin"
MESSAGE_FILE = "mensaje_claro.txt" 
HYBRID_FILE = "mensaje_cifrado.bin"
RECOVERED_FILE = "mensaje_recuperado.txt"
MARKER_LENGTH = len(b"HYBRID_RSA_OQS_MARKER")
AES_KEY_LENGTH = 32 # 256 bits

# ----------------------------------------------------------------------
# FUNCIONES PRINCIPALES
# ----------------------------------------------------------------------

def generate_keys():
    """Genera claves RSA y ML-KEM-1024 (Kyber)."""
    print("--- 1. GENERANDO CLAVES (PQC) ---")
    try:
        oqs_kem = KeyEncapsulation(OQS_ALGORITHM)
    except Exception as e:
        print(f"❌ ERROR al inicializar OQS: {e}")
        return
    
    # Generación RSA (Solo para comparación de tamaño)
    rsa_private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    with open(RSA_PUB_FILE, "wb") as f:
        f.write(rsa_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    # Generación ML-KEM-1024
    oqs_public_key = oqs_kem.generate_keypair()
    
    with open(OQS_PRIV_FILE, "wb") as f:
        f.write(oqs_kem.export_secret_key())
    with open(OQS_PUB_FILE, "wb") as f:
        f.write(oqs_public_key)
        
    print(f"✅ Claves ML-KEM-1024 y RSA generadas y guardadas.")
    
    print("\n--- 2. COMPARACIÓN DE TAMAÑOS ---")
    print(f"🔑 RSA Público: {os.path.getsize(RSA_PUB_FILE)} bytes")
    print(f"🔬 ML-KEM Público: {os.path.getsize(OQS_PUB_FILE)} bytes")


def encrypt_hybrid(message):
    """Cifra de forma híbrida: Kyber KEM + AES GCM DEM."""
    print("\n--- 3. CIFRADO HÍBRIDO ESTÁNDAR (KYBER KEM + AES GCM) ---")

    try:
        with open(OQS_PUB_FILE, "rb") as f:
            oqs_public_key = f.read()
    except FileNotFoundError:
        print("❌ Error: Clave pública PQC no encontrada. Ejecuta primero '--generate'.")
        return
    
    # Guarda el mensaje original para simular el descifrado final
    with open(MESSAGE_FILE, "w", encoding="utf-8") as f:
        f.write(message)
        
    # --- PASO 1: PROTEGER LA CLAVE DE SESIÓN CON KYBER (KEM) ---
    oqs_kem = KeyEncapsulation(OQS_ALGORITHM)
    ciphertext_oqs, aes_session_key = oqs_kem.encap_secret(oqs_public_key)
    
    # --- PASO 2: CIFRAR EL MENSAJE CON AES-GCM (DEM) ---
    nonce = get_random_bytes(16) 
    cipher = AES.new(aes_session_key, AES.MODE_GCM, nonce=nonce)
    ciphertext_aes, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    
    # --- PASO 3: EMPAQUETAR DATOS HÍBRIDOS ---
    ciphertext_len_bytes = struct.pack('>I', len(ciphertext_oqs))

    encrypted_data = (
        b"HYBRID_RSA_OQS_MARKER" + 
        nonce +                     
        tag +                       
        ciphertext_len_bytes +      
        ciphertext_oqs +            
        ciphertext_aes              
    )
    
    with open(HYBRID_FILE, "wb") as f:
        f.write(encrypted_data)
        
    print(f"🔒 Cifrado Híbrido TOTAL completado ({len(encrypted_data)} bytes). Archivo: {HYBRID_FILE}")


def decrypt_hybrid():
    """Descifra el secreto compartido con ML-KEM y luego descifra el mensaje con AES."""
    print("\n--- 4. DESCIFRADO HÍBRIDO ---")

    try:
        with open(OQS_PRIV_FILE, "rb") as f:
            oqs_private_key = f.read()
        with open(HYBRID_FILE, "rb") as f:
            encrypted_data = f.read()
    except FileNotFoundError:
        print("❌ Error: Asegúrate de haber ejecutado '--generate' y '--encrypt'.")
        return

    # B. Lógica de Desempaquetamiento (Inverso al cifrado)
    start_pos = MARKER_LENGTH
    nonce = encrypted_data[start_pos : start_pos + 16]
    tag = encrypted_data[start_pos + 16 : start_pos + 32]
    
    start_pos_len = start_pos + 32
    ciphertext_len_bytes = encrypted_data[start_pos_len : start_pos_len + 4]
    OQS_CIPHERTEXT_LENGTH = struct.unpack('>I', ciphertext_len_bytes)[0]
    
    start_ciphertext = start_pos_len + 4
    end_ciphertext = start_ciphertext + OQS_CIPHERTEXT_LENGTH
    
    ciphertext_oqs = encrypted_data[start_ciphertext : end_ciphertext]
    ciphertext_aes = encrypted_data[end_ciphertext : ]

    # --- PASO 2: DESCIFRADO DE LA CLAVE CON KYBER (KEM) ---
    print("🔑 Descapsulando la CLAVE AES con ML-KEM...")
    oqs_kem = KeyEncapsulation(OQS_ALGORITHM, oqs_private_key) 
    aes_session_key_recovered = oqs_kem.decap_secret(ciphertext_oqs)

    # --- PASO 3: DESCIFRADO DEL MENSAJE CON AES (DEM) ---
    print("🔓 Descifrando el MENSAJE con la clave AES recuperada...")
    
    try:
        cipher_decrypt = AES.new(aes_session_key_recovered, AES.MODE_GCM, nonce=nonce)
        decrypted_message_bytes = cipher_decrypt.decrypt_and_verify(ciphertext_aes, tag)
    except ValueError:
        print("❌ ERROR DE AUTENTICACIÓN/DESCIFRADO AES: El mensaje fue alterado o la clave PQC falló.")
        return
    
    decrypted_message_text = decrypted_message_bytes.decode('utf-8')

    # Escribir el mensaje descifrado en un nuevo archivo para la DEMO
    with open(RECOVERED_FILE, "w", encoding="utf-8") as f:
        f.write(decrypted_message_text)
    
    print(f"✅ ¡VERIFICACIÓN EXITOSA! Mensaje recuperado y escrito en: {RECOVERED_FILE}")
    print(f"Contenido Descifrado: '{decrypted_message_text}'")


def main():
    parser = argparse.ArgumentParser(description="Demo de Criptografía Post-Cuántica Híbrida (ML-KEM/Kyber) con OQS.")
    parser.add_argument("--generate", action="store_true", help="Genera las claves.")
    parser.add_argument("--encrypt", type=str, help="Cifra un mensaje.")
    parser.add_argument("--decrypt", action="store_true", help="Descifra el mensaje.")
    
    args = parser.parse_args()

    if args.generate:
        generate_keys()
    elif args.encrypt:
        encrypt_hybrid(args.encrypt)
    elif args.decrypt:
        decrypt_hybrid()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
