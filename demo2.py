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

# Definiciones para ML-KEM-1024 (Kyber1024)
OQS_ALGORITHM = 'Kyber1024'
RSA_KEY_SIZE = 2048
AES_KEY_LENGTH = 32 # 256 bits

# --- CONSTANTES DE ARCHIVO ---
RSA_PUB_FILE = "rsa_pub.pem"
RSA_PRIV_FILE = "rsa_priv.pem"
OQS_PUB_FILE = "oqs_pub.bin"
OQS_PRIV_FILE = "oqs_priv.bin"
MESSAGE_FILE = "mensaje_claro.txt"
HYBRID_FILE = "mensaje_hibrido_doble.bin"
RECOVERED_FILE = "mensaje_recuperado.txt"
MARKER_LENGTH = len(b"HYBRID_DOUBLE_ENCAP")

# ----------------------------------------------------------------------
# FUNCIONES PRINCIPALES
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
        # Captura errores si el archivo no existe o si el contenido está corrupto (simulando ataque)
        return None

def generate_keys():
    """Genera TODAS las claves (RSA clásica y ML-KEM PQC)."""
    print("--- 1. GENERANDO CLAVES HÍBRIDAS ---")

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

    print("\n--- 2. COMPARACIÓN DE TAMAÑOS ---")
    print(f"🔑 RSA Público: {os.path.getsize(RSA_PUB_FILE)} bytes")
    print(f"🔬 ML-KEM Público: {os.path.getsize(OQS_PUB_FILE)} bytes")


def encrypt_hybrid(message):
    """Cifrado Híbrido de Máxima Seguridad: RSA ENCAP + ML-KEM ENCAP."""
    print("\n--- 3. CIFRADO HÍBRIDO AVANZADO (DOBLE ENCAPSULACIÓN) ---")

    try:
        # Cargar claves públicas
        with open(OQS_PUB_FILE, "rb") as f:
            oqs_public_key = f.read()
        with open(RSA_PUB_FILE, "rb") as f:
            rsa_public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    except FileNotFoundError:
        print("❌ Error: Claves públicas no encontradas. Ejecuta primero '--generate'.")
        return
    
    # --- PASO 1: ENCAPSULACIÓN DOBLE (PQC genera la clave de sesión) ---
    oqs_kem = KeyEncapsulation(OQS_ALGORITHM)
    ciphertext_oqs, aes_session_key = oqs_kem.encap_secret(oqs_public_key)
    
    # 1b. Encapsulación Clásica (RSA-OAEP)
    ciphertext_rsa = rsa_public_key.encrypt(
        aes_session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # --- PASO 2: CIFRAR MENSAJE CON AES-GCM (DEM) ---
    nonce = get_random_bytes(16) 
    
    cipher = AES.new(aes_session_key, AES.MODE_GCM, nonce=nonce)
    ciphertext_aes, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    
    with open(MESSAGE_FILE, "w", encoding="utf-8") as f:
        f.write(message)
        
    print(f"📝 Mensaje ({len(message)} bytes) cifrado con AES-GCM.")

    # --- PASO 3: EMPAQUETAR DATOS HÍBRIDOS ---
    
    rsa_len_bytes = struct.pack('>I', len(ciphertext_rsa))
    oqs_len_bytes = struct.pack('>I', len(ciphertext_oqs))

    encrypted_data = (
        b"HYBRID_DOUBLE_ENCAP" +  # Marcador
        nonce +                     
        tag +                       
        rsa_len_bytes +             
        ciphertext_rsa +            # Bloque de RSA
        oqs_len_bytes +             
        ciphertext_oqs +            # Bloque de ML-KEM
        ciphertext_aes              # Datos cifrados con AES
    )
    
    with open(HYBRID_FILE, "wb") as f:
        f.write(encrypted_data)
        
    print(f"🔒 Cifrado Híbrido TOTAL completado ({len(encrypted_data)} bytes).")


def decrypt_hybrid():
    """Descifrado Híbrido: Intenta descifrar con RSA o ML-KEM para recuperar la clave AES."""
    print("\n--- 4. DESCIFRADO HÍBRIDO AVANZADO ---")

    # Cargar datos cifrados (solo el binario)
    try:
        with open(HYBRID_FILE, "rb") as f:
            encrypted_data = f.read()
    except FileNotFoundError:
        print("❌ Error: Archivo cifrado binario no encontrado. Ejecuta primero '--encrypt'.")
        return

    # A. Lógica de Desempaquetamiento
    offset = MARKER_LENGTH
    
    # 1. Extraer Nonce y Tag
    nonce = encrypted_data[offset : offset + 16]
    tag = encrypted_data[offset + 16 : offset + 32]
    offset += 32

    # 2. Extraer Cifrado RSA
    rsa_len_bytes = encrypted_data[offset : offset + 4]
    RSA_CIPHERTEXT_LENGTH = struct.unpack('>I', rsa_len_bytes)[0]
    offset += 4
    ciphertext_rsa = encrypted_data[offset : offset + RSA_CIPHERTEXT_LENGTH]
    offset += RSA_CIPHERTEXT_LENGTH

    # 3. Extraer Cifrado OQS (ML-KEM)
    oqs_len_bytes = encrypted_data[offset : offset + 4]
    OQS_CIPHERTEXT_LENGTH = struct.unpack('>I', oqs_len_bytes)[0]
    offset += 4
    ciphertext_oqs = encrypted_data[offset : offset + OQS_CIPHERTEXT_LENGTH]
    offset += OQS_CIPHERTEXT_LENGTH

    # 4. Extraer Ciphertext AES (el resto)
    ciphertext_aes = encrypted_data[offset:]

    # --- PASO B: DESCIFRADO PARALELO DE LA CLAVE AES ---
    
    aes_key_recovered = None
    source = "N/A"
    
    # 1. Intento Clásico (RSA)
    rsa_private_key = load_rsa_private_key() # Intenta cargar la clave (devuelve None si no existe)
    
    if rsa_private_key is not None:
        try:
            print("🔑 Intentando descifrar la clave con RSA (Clásico)...")
            key = rsa_private_key.decrypt(
                ciphertext_rsa,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            if len(key) == AES_KEY_LENGTH:
                aes_key_recovered = key
                print("✅ Éxito RSA: La clave AES fue recuperada (Clásico).")
                source = "RSA"
        except Exception:
            print("❌ Fallo RSA: La clave RSA estaba ausente o corrupta.")
    else:
        print("⚠️ Advertencia: Clave privada RSA no encontrada. Saltando intento RSA.")


    # 2. Intento PQC (ML-KEM)
    if aes_key_recovered is None:
        try:
            with open(OQS_PRIV_FILE, "rb") as f:
                oqs_private_key = f.read()
            
            print("🔑 Intentando descifrar la clave con ML-KEM (PQC)...")
            oqs_kem = KeyEncapsulation(OQS_ALGORITHM, oqs_private_key) 
            key = oqs_kem.decap_secret(ciphertext_oqs)
            
            if len(key) == AES_KEY_LENGTH:
                aes_key_recovered = key
                print("✅ Éxito PQC: La clave AES fue recuperada (Cuántico).")
                source = "ML-KEM"
        except FileNotFoundError:
            print("🛑 FALLO TOTAL: Clave privada ML-KEM no encontrada. No se puede continuar.")
            return
        except Exception:
            print("❌ Fallo PQC: La clave ML-KEM no se pudo descifrar.")
    
    if aes_key_recovered is None:
        print("🛑 FALLO TOTAL: No se pudo recuperar la clave AES con ninguna primitiva. Mensaje irrecuperable.")
        return

    # --- PASO C: DESCIFRADO DEL MENSAJE (DEM) ---
    print(f"\n🔓 Descifrando el MENSAJE con la clave recuperada vía {source}...")
    
    try:
        cipher_decrypt = AES.new(aes_key_recovered, AES.MODE_GCM, nonce=nonce)
        decrypted_message_bytes = cipher_decrypt.decrypt_and_verify(ciphertext_aes, tag)
    except ValueError:
        print("❌ ERROR DE AUTENTICACIÓN: El mensaje fue alterado. Descifrado abortado.")
        return
    
    decrypted_message_text = decrypted_message_bytes.decode('utf-8')

    # Escribir el mensaje descifrado en un nuevo archivo para la DEMO
    with open(RECOVERED_FILE, "w", encoding="utf-8") as f:
        f.write(decrypted_message_text)
    
    print(f"\n✅ ¡RECUPERACIÓN FINAL! El mensaje original fue reconstruido con éxito.")
    print(f"Contenido Descifrado: '{decrypted_message_text}'")
    print(f"Fuente de la Clave: {source}")


def main():
    parser = argparse.ArgumentParser(description="Demo de Criptografía Híbrida de Máxima Seguridad (RSA + ML-KEM).")
    parser.add_argument("--generate", action="store_true", help="Genera todas las claves necesarias (RSA y PQC).")
    parser.add_argument("--encrypt", type=str, help="Cifra el mensaje con la doble encapsulación.")
    parser.add_argument("--decrypt", action="store_true", help="Descifra el mensaje usando la primera clave recuperada.")
    
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
