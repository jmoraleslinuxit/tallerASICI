import sys
import math
from collections import Counter
import os

# --- FIRMA BINARIA DE NUESTRO CIFRADO HÍBRIDO ---
CUSTOM_MARKER = b"HYBRID_DOUBLE_ENCAP" 
MARKER_LENGTH = len(CUSTOM_MARKER)

# ----------------------------------------------------------------------
# FUNCIONES DE ANÁLISIS
# ----------------------------------------------------------------------

def calculate_shannon_entropy(data):
    """Calcula la entropía de Shannon (en bits por byte)."""
    if not data: return 0.0
    byte_counts = Counter(data)
    data_size = len(data)
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / data_size
        entropy -= probability * math.log2(probability)
    return entropy

def analyze_bit_balance(data):
    """Calcula el porcentaje de bits 1s y 0s (la prueba del 50%)."""
    if not data: return 0.0, 0.0
    data = data[:1024 * 1024] 
    bit_string = ''.join(bin(byte)[2:].zfill(8) for byte in data)
    total_bits = len(bit_string)
    count_ones = bit_string.count('1')
    
    percent_ones = (count_ones / total_bits) * 100
    percent_zeros = 100.0 - percent_ones
    return percent_ones, percent_zeros

def find_leaks(file_data, target_string_list):
    """Busca fragmentos de texto plano (fugas) dentro del archivo binario."""
    leaks = []
    
    for target in target_string_list:
        try:
            # Codificar el string de búsqueda a ASCII para que coincida con el contenido de la fuga
            target_bytes = target.encode('ascii', errors='ignore')
            if target_bytes in file_data:
                leaks.append(target)
        except UnicodeEncodeError:
            pass # Ignora si el string tiene caracteres que no son ASCII
            
    return leaks

def get_file_type(file_data, entropy_score):
    """Identifica el archivo basado en la firma y la entropía."""
    
    if file_data.startswith(CUSTOM_MARKER):
        return "Cifrado Híbrido PQC Avanzado", "\033[96m" # Cyan
    elif entropy_score < 6.0:
        return "Texto Plano/Baja Entropía", "\033[91m" # Rojo
    else:
        return "Binario Cifrado/Alta Entropía", "\033[92m" # Verde


def analyze_file(file_path, target_strings):
    """Ejecuta todos los análisis sobre el archivo y muestra los resultados."""
    print("-" * 70)
    print(f"🔬 ANALIZANDO ARCHIVO: {file_path}")
    
    try:
        # Abrimos el archivo en modo binario para evitar errores de codificación inicial
        with open(file_path, 'rb') as f: 
            file_data = f.read()
    except FileNotFoundError:
        print(f"❌ ERROR: Archivo no encontrado en la ruta: {file_path}")
        return

    file_size_bytes = len(file_data)
    if file_size_bytes == 0:
        print("⚠️ Advertencia: El archivo está vacío. Entropía = 0.00")
        return

    # Ejecutar métricas
    entropy_score = calculate_shannon_entropy(file_data)
    percent_ones, percent_zeros = analyze_bit_balance(file_data)
    file_type, color = get_file_type(file_data, entropy_score)
    
    print("-" * 70)
    print(f"Tamaño del Archivo: {file_size_bytes} bytes")
    print(f"Tipo Detectado: {color}{file_type}\033[0m")
    
    # --- RESULTADOS CLAVE ---
    print("\n[📊 ANÁLISIS DE CALIDAD DE CIFRADO]")
    print(f"Puntuación de Entropía (Shannon): {entropy_score:.4f} bits (Ideal: 8.0)")
    
    # Análisis de Balance
    print(f"Balance de Bits (Ideal 50%): {'{:.2f}% de 1s | {:.2f}% de 0s'.format(percent_ones, percent_zeros)}")
    if 49.0 < percent_ones < 51.0 and file_type.startswith("Cifrado"):
        print("✅ BALANCE DE BITS: Excelente (Propio de un cifrado robusto).")
    elif file_type.startswith("Texto"):
        print("⚠️ BALANCE DE BITS: Sesgado (Propio de texto plano o datos con patrones).")

    # Análisis de Fugas
    print("\n[🚨 ANÁLISIS FORENSE (FUGA DE DATOS)]")
    leaks = find_leaks(file_data, target_strings)

    if leaks and file_type.startswith("Cifrado"):
        print(f"❌ FUGA ENCONTRADA: Se encontraron fragmentos de texto plano: {leaks}")
        print("   ¡ALERTA! Esto indicaría un fallo grave en la implementación.")
    elif file_type.startswith("Texto"):
        print("INFO: El texto plano es legible y es la base de la fuga.")
    else:
        print("✅ INTEGRIDAD PROBADA: No se encontraron fugas de las palabras clave.")
        
    print("-" * 70)

def extract_secret(file_path):
    """
    Intenta extraer las primeras palabras del archivo plano para usar como secreto de búsqueda.
    Usa 'ignore' para manejar el error de codificación.
    """
    try:
        # Abrimos el archivo en modo binario y luego decodificamos, ignorando errores
        with open(file_path, 'rb') as f: 
            content_bytes = f.read()
        
        # Intentar decodificar ignorando los caracteres problemáticos
        content = content_bytes.decode('utf-8', errors='ignore')
        
        # Dividir en palabras, tomar las primeras 15 y devolver para buscar
        secret_string = ' '.join(content.split()[:15])
        
        # Generar lista de strings para la búsqueda de fugas
        return [secret_string[:25], "ASICI", "CLAVE", "SECRETO"]
        
    except FileNotFoundError:
        return ["ASICI", "CLAVE", "SECRETO"] 


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("\nUso: python3 analizar.py <ruta_archivo_cifrado> <ruta_archivo_plano>")
        print('Ejemplo: python3 analizar.py mensaje_hibrido_doble.bin mensaje_recuperado.txt')
        sys.exit(1)
        
    # Archivos de entrada
    encrypted_file = sys.argv[1]
    plain_file = sys.argv[2]
    
    # Extraer el string secreto del archivo de texto plano para usar como base de la búsqueda
    # Esto ahora manejará el error UnicodeDecodeError
    target_strings = extract_secret(plain_file)
    
    print("\n" + "=" * 70)
    print(f"🔎 INICIANDO ANÁLISIS FORENSE COMPARATIVO")
    print(f"🔑 Palabras clave extraídas para la búsqueda: {target_strings[0]}...")
    print("=" * 70)
    
    # 1. Analizar el archivo cifrado
    analyze_file(encrypted_file, target_strings)

    # 2. Analizar el archivo plano
    analyze_file(plain_file, target_strings)
