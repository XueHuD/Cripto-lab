#!/usr/bin/env python3
"""
Laboratorio 4 - CIT2113 Criptografía y Seguridad en Redes
Recuperación del PIN (RSA-OAEP/SHA-256), derivación de la clave AES-256 (Scrypt)
y descifrado/autenticación de transacciones (AES-256-GCM) desde una captura .pcap.

Formato de los paquetes (payload TCP):
    RSA_PIN| + salt (16 B) + PIN cifrado con RSA (256 B)
    AESGCM|  + nonce (12 B) + texto cifrado + tag GCM (16 B)

Uso:
    python3 lab4_descifrar.py transacciones_cifradas.pcap clave_privada.pem clave_publica.pem
Requiere:
    pip install scapy cryptography
"""
import hashlib
import sys

from scapy.all import rdpcap, IP, TCP, Raw
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

TAG_PIN = b"RSA_PIN|"
TAG_TX = b"AESGCM|"
SALT_LEN = 16
NONCE_LEN = 12
SCRYPT_N, SCRYPT_R, SCRYPT_P, KEY_LEN = 2**14, 8, 1, 32


def cargar_claves(ruta_priv, ruta_pub):
    with open(ruta_priv, "rb") as f:
        priv = serialization.load_pem_private_key(f.read(), password=None)
    with open(ruta_pub, "rb") as f:
        pub = serialization.load_pem_public_key(f.read())
    # Verifica que ambas claves formen un par (mismo módulo n y exponente e)
    if pub.public_numbers() != priv.public_key().public_numbers():
        sys.exit("La clave pública no corresponde a la clave privada")
    return priv


def leer_payloads(ruta_pcap):
    """Retorna [(n° de frame, origen, destino, payload)] de los segmentos TCP con datos."""
    paquetes = []
    for n, pkt in enumerate(rdpcap(ruta_pcap), start=1):
        if IP in pkt and TCP in pkt and Raw in pkt:
            origen = f"{pkt[IP].src}:{pkt[TCP].sport}"
            destino = f"{pkt[IP].dst}:{pkt[TCP].dport}"
            paquetes.append((n, origen, destino, bytes(pkt[Raw].load)))
    return paquetes


def recuperar_pin(payload, priv):
    """Extrae salt y PIN cifrado por posición fija y descifra con RSA-OAEP/SHA-256.
    No se separa por '|' porque los bytes aleatorios pueden contener ese carácter."""
    datos = payload[len(TAG_PIN):]
    salt = datos[:SALT_LEN]
    pin_cifrado = datos[SALT_LEN:]
    pin = priv.decrypt(
        pin_cifrado,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(), label=None),
    ).decode()
    return salt, pin_cifrado, pin


def derivar_clave(pin, salt):
    return hashlib.scrypt(pin.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R,
                          p=SCRYPT_P, dklen=KEY_LEN)


def descifrar_transaccion(payload, aes):
    """Separa nonce y texto cifrado (incluye el tag de 16 B al final) y descifra.
    AESGCM.decrypt lanza InvalidTag si el mensaje fue alterado."""
    datos = payload[len(TAG_TX):]
    nonce, cifrado = datos[:NONCE_LEN], datos[NONCE_LEN:]
    return nonce, cifrado[-16:], aes.decrypt(nonce, cifrado, None).decode()


def parsear(texto):
    """'TRANSACCION COMPLETADA|ID=..|DE=..|A=..|MONTO=..' -> dict"""
    campos = dict(c.split("=", 1) for c in texto.split("|")[1:])
    return campos["ID"], campos["DE"], campos["A"], int(campos["MONTO"])


def main():
    if len(sys.argv) != 4:
        sys.exit(f"Uso: {sys.argv[0]} captura.pcap clave_privada.pem clave_publica.pem")
    priv = cargar_claves(sys.argv[2], sys.argv[3])
    paquetes = leer_payloads(sys.argv[1])

    # 1) Paquete RSA_PIN
    frame, origen, destino, payload = next(p for p in paquetes if p[3].startswith(TAG_PIN))
    salt, pin_cifrado, pin = recuperar_pin(payload, priv)
    print(f"[1] Paquete RSA_PIN -> frame {frame} ({origen} -> {destino}), {len(payload)} bytes")
    print(f"    Salt (16 B)        : {salt.hex()}")
    print(f"    PIN cifrado ({len(pin_cifrado)} B): {pin_cifrado.hex()[:48]}...")
    print(f"    PIN recuperado     : {pin}")

    # 2) Derivación de la clave AES-256
    clave = derivar_clave(pin, salt)
    print(f"\n[2] Scrypt(PIN, salt, n=2^14, r=8, p=1, dklen=32)")
    print(f"    Clave AES-256      : {clave.hex()}")

    # 3) Descifrado y verificación de las transacciones
    aes = AESGCM(clave)
    tx = [p for p in paquetes if p[3].startswith(TAG_TX)]
    print(f"\n[3] Paquetes AESGCM encontrados: {len(tx)}")
    print(f"\n{'Frame':>5}  {'Nonce':<24}  {'Tag':<8}  {'ID':<10}  {'Remitente':<16}  {'Destinatario':<16}  {'Monto':>9}")
    print("-" * 102)
    ok = fallidos = 0
    for frame, _, _, payload in tx:
        try:
            nonce, tag, texto = descifrar_transaccion(payload, aes)
        except InvalidTag:
            fallidos += 1
            print(f"{frame:>5}  ERROR: tag GCM inválido (mensaje alterado o clave incorrecta)")
            continue
        ok += 1
        id_, de, a, monto = parsear(texto)
        print(f"{frame:>5}  {nonce.hex():<24}  {'OK':<8}  {id_:<10}  {de:<16}  {a:<16}  {monto:>9,}".replace(",", "."))
    print("-" * 102)
    print(f"Transacciones autenticadas: {ok}  |  Fallidas: {fallidos}")

    print("\n[4] Mensajes en su formato original:")
    for frame, _, _, payload in tx:
        try:
            print(f"    {descifrar_transaccion(payload, aes)[2]}")
        except InvalidTag:
            pass


if __name__ == "__main__":
    main()
