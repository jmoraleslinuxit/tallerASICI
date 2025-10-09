import sys
import math
from collections import Counter
import os

def calculate_shannon_entropy(data):
    """Calcula la entropía de Shannon (en bits por byte)."""
    if not data:
        return 0.0

    byte_counts = Counter(data)
    data_size = len(data)
    entropy = 0.0
    
    for count in byte_counts.values():
        probability = count / data_size
        entropy -= probability * math.log2(probability)
    
    return entropy

def analyze_file(file_path):
    """Lee un archivo, calcula su entropía y clasifica el resultado."""
    print("-" * 50)
    print(f"🔬 ANALIZANDO ARCHIVO: {file_path}")
    print("-" * 50)
    
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
    except FileNotFoundError:
        print(f"❌ ERROR: Archivo no encontrado en la ruta: {file_path}")
        return

    file_size_bytes = len(file_data)
    if file_size_bytes == 0:
        print("⚠️ Advertencia: El archivo está vacío. Entropía = 0.00")
        return

    entropy_score = calculate_shannon_entropy(file_data)

    # Clasificación (Máxima entropía posible es 8.0)
    if entropy_score > 7.9:
        status = "CRIPTO-SEGURO (Cifrado Fuerte)"
        color = "\033[92m" # Verde
    elif entropy_score >= 7.0:
        status = "ALTA ENTROPÍA (Datos Cifrados o Comprimidos)"
        color = "\033[93m" # Amarillo
    else:
        status = "BAJA ENTROPÍA (Texto Plano o Datos Predecibles)"
        color = "\033[91m" # Rojo
        
    print(f"Tamaño del Archivo: {file_size_bytes} bytes")
    print(f"Puntuación de Entropía: {entropy_score:.4f} bits")
    print(f"Estado de Aleatoriedad: {color}{status}\033[0m")
    print("-" * 50)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("\nUso: python3 analizar.py <ruta_archivo_1> [ruta_archivo_2]...")
        sys.exit(1)
        
    for file_path in sys.argv[1:]:
        analyze_file(file_path)
