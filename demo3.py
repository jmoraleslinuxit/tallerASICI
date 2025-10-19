import os
import struct
import sys
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import argparse

# Importaciones para Cifrado Simétrico (AES)
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Importación OQS
try:
    from oqs import KeyEncapsulation
except ImportError:
    print("❌ ERROR: La librería 'oqs' no está instalada o el entorno no está activo.")
    sys.exit(1)

# Definiciones
OQS_ALGORITHM = 'Kyber1024'
RSA_KEY_SIZE = 2048
AES_KEY_LENGTH = 32 # 256 bits

# Longitud de los secretos que vamos a combinar
# Cada KEM protegerá 32 bytes.
SECRET_A_LENGTH = 32 # El que protegerá RSA
SECRET_B_LENGTH = 32 # El que protegerá ML-KEM

# --- CONSTANTES DE ARCHIVO ---
RSA_PUB_FILE = "rsa_pub.pem"
RSA_PRIV_FILE = "rsa_priv.pem"
OQS_PUB_FILE = "oqs_pub.bin"
OQS_PRIV_FILE = "oqs_priv.bin"
MESSAGE_FILE = "mensaje_claro.txt"
HYBRID_FILE = "mensaje_hibrido_seguro.bin" # Nuevo nombre
RECOVERED_FILE = "mensaje_recuperado.txt"
MARKER = b"HYBRID_SECURE_COMBINED"
MARKER_LENGTH = len(MARKER)

# ----------------------------------------------------------------------
# FUNCIONES AUXILIARES
# ----------------------------------------------------------------------

def load_rsa_private_key():
    """Intenta cargar la clave privada RSA. Devuelve None si falla (archivo no encontrado/corrupto)."""
    try:
        with open(RSA_PRIV_FILE, "rb") as key_file:
            return serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )
    except (FileNotFoundError, ValueError, TypeError):
        return None

def derive_aes_key(secret_a, secret_b):
    """
    Combina los dos secretos usando un HASH (KDF) para crear la clave AES final.
    """
    if secret_a is None or secret_b is None:
        return None
        
    print("🔑 Combinando Secreto_A (de RSA) y Secreto_B (de PQC) usando SHA-256...")
    combined_secret = secret_a + secret_b
    
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(combined_secret)
    final_aes_key = digest.finalize()
    
    # final_aes_key es de 32 bytes (256 bits), perfecto para AES
    return final_aes_key

# ----------------------------------------------------------------------
# FUNCIONES PRINCIPALES
# ----------------------------------------------------------------------

def generate_keys():
    """Genera TODAS las claves (RSA clásica y ML-KEM PQC)."""
    print("--- 1. GENERANDO CLAVES HÍBRIDAS (PARA MODELO SEGURO) ---")

    try:
        oqs_kem = KeyEncapsulation(OQS_ALGORITHM)
    except Exception as e:
        print(f"❌ ERROR al inicializar OQS: {e}")
        return
    
    # A. Generación RSA (Clásico)
    rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    
    with open(RSA_PRIV_FILE, "wb") as f:
        f.write(rsa_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(RSA_PUB_FILE, "wb") as f:
        f.write(rsa_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"✅ Claves RSA-{RSA_KEY_SIZE} (Clásico) generadas.")

    # B. Generación ML-KEM-1024 (PQC)
    oqs_public_key = oqs_kem.generate_keypair()
    
    with open(OQS_PRIV_FILE, "wb") as f:
        f.write(oqs_kem.export_secret_key())
    with open(OQS_PUB_FILE, "wb") as f:
        f.write(oqs_public_key)
    print(f"✅ Claves ML-KEM-1024 (PQC) generadas.")


def encrypt_hybrid(message):
    """Cifrado Híbrido Seguro: Dos KEMs, una clave AES combinada."""
    print("\n--- 3. CIFRADO HÍBRIDO SEGURO (COMBINACIÓN DE CLAVES) ---")

    try:
        # Cargar claves públicas
        with open(OQS_PUB_FILE, "rb") as f:
            oqs_public_key = f.read()
        with open(RSA_PUB_FILE, "rb") as f:
            rsa_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    except FileNotFoundError:
        print("❌ Error: Claves públicas no encontradas. Ejecuta primero '--generate'.")
        return
    
    # --- PASO 1: KEM 1 (CLÁSICO - RSA) ---
    # Generamos un secreto aleatorio A (32 bytes)
    secret_a = get_random_bytes(SECRET_A_LENGTH)
    ciphertext_rsa = rsa_public_key.encrypt(
        secret_a,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    print(f"✅ Secreto A ({SECRET_A_LENGTH}b) cifrado con RSA-OAEP.")

    # --- PASO 2: KEM 2 (PQC - ML-KEM) ---
    # Generamos un secreto aleatorio B (32 bytes) y lo encapsulamos
    oqs_kem = KeyEncapsulation(OQS_ALGORITHM)
    ciphertext_oqs, secret_b = oqs_kem.encap_secret(oqs_public_key)
    print(f"✅ Secreto B ({len(secret_b)}b) encapsulado con ML-KEM.")

    # --- PASO 3: DERIVACIÓN DE CLAVE (KDF) ---
    # Combinamos A y B para crear la clave AES final
    aes_session_key = derive_aes_key(secret_a, secret_b)
    if aes_session_key is None:
        print("❌ Error fatal al derivar la clave AES.")
        return

    # --- PASO 4: CIFRAR MENSAJE CON AES-GCM (DEM) ---
    nonce = get_random_bytes(16) 
    cipher = AES.new(aes_session_key, AES.MODE_GCM, nonce=nonce)
    ciphertext_aes, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    
    with open(MESSAGE_FILE, "w", encoding="utf-8") as f:
        f.write(message)
    print(f"📝 Mensaje ({len(message)} bytes) cifrado con AES-GCM.")

    # --- PASO 5: EMPAQUETAR DATOS HÍBRIDOS ---
    rsa_len_bytes = struct.pack('>I', len(ciphertext_rsa))
    oqs_len_bytes = struct.pack('>I', len(ciphertext_oqs))

    encrypted_data = (
        MARKER +                  # Marcador
        nonce +                     
        tag +                       
        rsa_len_bytes +             
        ciphertext_rsa +            # Bloque de RSA (Cifra el Secreto A)
        oqs_len_bytes +             
        ciphertext_oqs +            # Bloque de ML-KEM (Cifra el Secreto B)
        ciphertext_aes              # Datos cifrados con AES
    )
    
    with open(HYBRID_FILE, "wb") as f:
        f.write(encrypted_data)
        
    print(f"🔒 Cifrado Híbrido SEGURO completado ({len(encrypted_data)} bytes).")


def decrypt_hybrid():
    """Descifrado Híbrido: DEBE usar AMBAS claves (RSA y ML-KEM)."""
    print("\n--- 4. DESCIFRADO HÍBRIDO SEGURO ---")

    try:
        with open(HYBRID_FILE, "rb") as f:
            encrypted_data = f.read()
    except FileNotFoundError:
        print("❌ Error: Archivo cifrado binario no encontrado. Ejecuta primero '--encrypt'.")
        return

    # A. Lógica de Desempaquetamiento
    offset = MARKER_LENGTH
    nonce = encrypted_data[offset : offset + 16]
    tag = encrypted_data[offset + 16 : offset + 32]
    offset += 32
    
    rsa_len_bytes = encrypted_data[offset : offset + 4]
    RSA_CIPHERTEXT_LENGTH = struct.unpack('>I', rsa_len_bytes)[0]
    offset += 4
    ciphertext_rsa = encrypted_data[offset : offset + RSA_CIPHERTEXT_LENGTH]
    offset += RSA_CIPHERTEXT_LENGTH

    oqs_len_bytes = encrypted_data[offset : offset + 4]
    OQS_CIPHERTEXT_LENGTH = struct.unpack('>I', oqs_len_bytes)[0]
    offset += 4
    ciphertext_oqs = encrypted_data[offset : offset + OQS_CIPHERTEXT_LENGTH]
    offset += OQS_CIPHERTEXT_LENGTH

    ciphertext_aes = encrypted_data[offset:]

    # --- PASO B: RECUPERACIÓN DE AMBOS SECRETOS ---
    
    secret_a_recovered = None
    secret_b_recovered = None
    
    # 1. Intento Clásico (RSA) para recuperar Secreto A
    rsa_private_key = load_rsa_private_key()
    if rsa_private_key is not None:
        try:
            print("🔑 Intentando descifrar Secreto A con RSA (Clásico)...")
            secret_a_recovered = rsa_private_key.decrypt(
                ciphertext_rsa,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            print("✅ Éxito RSA: Secreto A recuperado.")
        except Exception:
            print("❌ Fallo RSA: La clave RSA estaba corrupta o era incorrecta.")
    else:
        print("⚠️ Advertencia: Clave privada RSA no encontrada. No se puede recuperar el Secreto A.")

    # 2. Intento PQC (ML-KEM) para recuperar Secreto B
    try:
        with open(OQS_PRIV_FILE, "rb") as f:
            oqs_private_key = f.read()
        
        print("🔑 Intentando descapsular Secreto B con ML-KEM (PQC)...")
        oqs_kem = KeyEncapsulation(OQS_ALGORITHM, oqs_private_key) 
        secret_b_recovered = oqs_kem.decap_secret(ciphertext_oqs)
        print("✅ Éxito PQC: Secreto B recuperado.")
        
    except FileNotFoundError:
        print("⚠️ Advertencia: Clave privada ML-KEM no encontrada. No se puede recuperar el Secreto B.")
    except Exception:
        print("❌ Fallo PQC: La clave ML-KEM estaba corrupta o era incorrecta.")

    # --- PASO C: DERIVACIÓN Y VERIFICACIÓN ---
    
    # ESTE ES EL PASO CRUCIAL
    if secret_a_recovered is None or secret_b_recovered is None:
        print("\n🛑 FALLO TOTAL: Se necesitan AMBOS secretos (A y B) para reconstruir la clave AES.")
        print("   No se puede continuar con el descifrado. Abortando.")
        return

    # Si llegamos aquí, tenemos ambos secretos. Los combinamos.
    aes_session_key = derive_aes_key(secret_a_recovered, secret_b_recovered)

    # --- PASO D: DESCIFRADO DEL MENSAJE (DEM) ---
    print(f"\n🔓 Descifrando el MENSAJE con la clave AES combinada...")
    
    try:
        cipher_decrypt = AES.new(aes_session_key, AES.MODE_GCM, nonce=nonce)
        decrypted_message_bytes = cipher_decrypt.decrypt_and_verify(ciphertext_aes, tag)
    except ValueError:
        print("❌ ERROR DE AUTENTICACIÓN: El mensaje fue alterado o las claves/secretos eran incorrectos.")
        return
    
    decrypted_message_text = decrypted_message_bytes.decode('utf-8')

    with open(RECOVERED_FILE, "w", encoding="utf-8") as f:
        f.write(decrypted_message_text)
    
    print(f"\n✅ ¡RECUPERACIÓN FINAL! El mensaje original fue reconstruido con éxito.")
    print(f"Contenido Descifrado: '{decrypted_message_text}'")


def main():
    parser = argparse.ArgumentParser(description="Demo de Criptografía Híbrida SEGURA (RSA + ML-KEM).")
    parser.add_argument("--generate", action="store_true", help="Genera todas las claves necesarias (RSA y PQC).")
    parser.add_argument("--encrypt", type=str, help="Cifra el mensaje con la doble encapsulación segura.")
    parser.add_argument("--decrypt", action="store_true", help="Descifra el mensaje (requiere AMBAS claves).")
    
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