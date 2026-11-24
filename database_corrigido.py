import hashlib
import hmac
import re
import sqlite3
from pathlib import Path
from werkzeug.security import generate_password_hash, check_password_hash

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "unidin.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def encripta_password(password: str) -> str:
    # Usa scrypt/pbkdf2 com salt aleatório gerado automaticamente pelo Werkzeug
    return generate_password_hash(password)

def verifica_password(stored_hash: str, password: str) -> tuple[bool, bool]:
    """
    Retorna (valido, precisa_migrar).
    Valida hashes modernos com salt e permite migração transparente dos hashes
    SHA-512 legados já armazenados em unidin.db.
    """
    if stored_hash.startswith(("scrypt:", "pbkdf2:")):
        return check_password_hash(stored_hash, password), False

    legacy_hash = hashlib.sha512(password.encode("utf-8")).hexdigest()
    if hmac.compare_digest(stored_hash, legacy_hash):
        return True, True
    return False, False

def validar_politica_senha(password: str) -> tuple[bool, str]:
    """
    Validação para cadastro/alteração de senha (CWE-521): mínimo de 12 caracteres, 
    sem limite restritivo de 8, aceitando qualquer caractere especial e exigindo diversidade.
    """
    if len(password) < 12 or len(password) > 128:
        return False, "A senha deve ter entre 12 e 128 caracteres."
    if not (
        re.search(r"[A-Z]", password)
        and re.search(r"[a-z]", password)
        and re.search(r"\d", password)
        and re.search(r"[^A-Za-z0-9]", password)
    ):
        return False, "A senha deve conter maiúscula, minúscula, número e símbolo."
    return True, ""

def init_db():
    conn = get_connection()
    '''
        Essa função está intencionalmente 'vazia' para que você, caro(a) aluno(a), não veja o formato completo das tabelas, bem como ela está populada :)
    '''
    
    conn.close()
