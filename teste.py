"""Script de verificação defensiva das mitigações do UniDIN (V01–V06).

Executa testes funcionais em memória usando Flask test_client() sobre uma cópia
temporária de unidin.db (sem alterar o banco original) e salva o relatório em
log_testes_mitigacao.txt.

Uso:
    Coloque este arquivo na pasta raiz do projeto (junto com app_corrigido.py,
    database_corrigido.py e unidin.db) e execute:

        python testar_mitigacoes.py
"""

from __future__ import annotations

import datetime
import io
import shutil
import sqlite3
import sys
import tempfile
import traceback
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
LOG_PATH = BASE_DIR / "log_testes_mitigacao.txt"

TEST_EMAIL = "sspark@universidade.br"
TEST_VALID_PASSWORD = "s$A159cc"
TEST_WRONG_PASSWORD = "senha_incorreta_teste"


class TestLogger:
    def __init__(self) -> None:
        self.lines: list[str] = []
        self.passed = 0
        self.failed = 0

    def log(self, message: str = "") -> None:
        print(message)
        self.lines.append(message)

    def section(self, title: str) -> None:
        self.log("")
        self.log(f"=== {title} ===")

    def check(self, name: str, condition: bool, detail: str = "") -> None:
        status = "PASS" if condition else "FAIL"
        if condition:
            self.passed += 1
        else:
            self.failed += 1
        suffix = f" | {detail}" if detail else ""
        self.log(f"[{status}] {name}{suffix}")

    def save(self, path: Path) -> None:
        path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")


def read_user_password_hash(db_path: Path, email: str) -> str | None:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            "SELECT password FROM users WHERE email = ?", (email,)
        ).fetchone()
        return row[0] if row else None
    finally:
        conn.close()


def read_student_discipline_id(db_path: Path, email: str) -> int | None:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute(
            """
            SELECT e.discipline_id
            FROM enrollments e
            JOIN users u ON u.id = e.student_id
            WHERE u.email = ?
            LIMIT 1
            """,
            (email,),
        ).fetchone()
        return int(row[0]) if row else None
    finally:
        conn.close()


def reset_lockout_state(app_module) -> None:
    if hasattr(app_module, "failed_attempts"):
        app_module.failed_attempts.clear()
    if hasattr(app_module, "locked_until"):
        app_module.locked_until.clear()


def main() -> int:
    logger = TestLogger()
    logger.log("UniDIN - Log de Verificação das Mitigações")
    logger.log(f"Data/Hora: {datetime.datetime.now().isoformat(timespec='seconds')}")
    logger.log(f"Diretório: {BASE_DIR}")

    source_db = BASE_DIR / "unidin_backup.db"
    if not source_db.exists():
        source_db = BASE_DIR / "unidin.db"
    if not source_db.exists():
        logger.log("[ERRO] Nenhum banco unidin.db ou unidin_backup.db encontrado.")
        logger.save(LOG_PATH)
        return 1

    try:
        import database_corrigido
        import app_corrigido
    except Exception:
        logger.log("[ERRO] Falha ao importar database_corrigido ou app_corrigido:")
        logger.log(traceback.format_exc())
        logger.save(LOG_PATH)
        return 1

    with tempfile.TemporaryDirectory(prefix="unidin_qa_") as tmpdir:
        tmp_path = Path(tmpdir)
        temp_db = tmp_path / "unidin_test.db"
        temp_uploads = tmp_path / "uploads"
        temp_uploads.mkdir(exist_ok=True)
        shutil.copy2(source_db, temp_db)

        # Redireciona banco e diretório de uploads para cópia temporária
        database_corrigido.DB_PATH = temp_db
        app_corrigido.UPLOAD_DIR = temp_uploads

        client = app_corrigido.app.test_client()

        # ------------------------------------------------------------------
        # 1. V01 (CWE-307) - Bloqueio após excesso de tentativas de login
        # ------------------------------------------------------------------
        logger.section("1. V01 (CWE-307) - Restrição de tentativas excessivas em /login")
        reset_lockout_state(app_corrigido)
        max_attempts = getattr(app_corrigido, "MAX_LOGIN_ATTEMPTS", 5)
        logger.log(f"Limite configurado (MAX_LOGIN_ATTEMPTS): {max_attempts}")

        statuses_before_lock: list[int] = []
        for i in range(1, max_attempts + 1):
            resp = client.get(
                "/login",
                query_string={"email": TEST_EMAIL, "password": TEST_WRONG_PASSWORD},
            )
            statuses_before_lock.append(resp.status_code)
            logger.log(f"  Tentativa falha #{i}: HTTP {resp.status_code}")

        logger.check(
            f"Primeiras {max_attempts} falhas retornam HTTP 200",
            all(code == 200 for code in statuses_before_lock),
            f"status={statuses_before_lock}",
        )

        resp_locked = client.get(
            "/login",
            query_string={"email": TEST_EMAIL, "password": TEST_WRONG_PASSWORD},
        )
        body_locked = resp_locked.get_data(as_text=True)
        logger.log(f"  Tentativa #{max_attempts + 1} (bloqueada): HTTP {resp_locked.status_code}")
        logger.check(
            f"Tentativa #{max_attempts + 1} retorna HTTP 429 (bloqueio ativo)",
            resp_locked.status_code == 429,
            f"status={resp_locked.status_code}",
        )
        logger.check(
            "Mensagem de bloqueio exibida ao usuário",
            "Muitas tentativas" in body_locked or "Aguarde" in body_locked,
        )

        resp_valid_while_locked = client.get(
            "/login",
            query_string={"email": TEST_EMAIL, "password": TEST_VALID_PASSWORD},
        )
        logger.check(
            "Credencial válida continua bloqueada durante o período de lockout",
            resp_valid_while_locked.status_code == 429,
            f"status={resp_valid_while_locked.status_code}",
        )

        # ------------------------------------------------------------------
        # 2. V02 (CWE-916/759) - Login legítimo e migração para hash com salt
        # ------------------------------------------------------------------
        logger.section("2. V02 (CWE-916/CWE-759) - Login legítimo e migração de hash")
        reset_lockout_state(app_corrigido)

        hash_before = read_user_password_hash(temp_db, TEST_EMAIL)
        logger.log(
            f"Hash antes do login: tamanho={len(hash_before or '')}, "
            f"prefixo={(hash_before or '')[:24]}..."
        )
        logger.check(
            "Hash inicial no banco é SHA-512 legado (128 caracteres hex)",
            bool(hash_before) and len(hash_before) == 128,
            f"len={len(hash_before or '')}",
        )

        resp_login_ok = client.get(
            "/login",
            query_string={"email": TEST_EMAIL, "password": TEST_VALID_PASSWORD},
        )
        logger.check(
            "Login legítimo com conta de teste retorna redirecionamento (HTTP 302)",
            resp_login_ok.status_code == 302,
            f"status={resp_login_ok.status_code}, location={resp_login_ok.headers.get('Location')}",
        )

        resp_aluno = client.get("/aluno")
        logger.check(
            "Acesso à área autenticada /aluno funciona após login",
            resp_aluno.status_code == 200,
            f"status={resp_aluno.status_code}",
        )

        hash_after = read_user_password_hash(temp_db, TEST_EMAIL)
        logger.log(
            f"Hash após login: tamanho={len(hash_after or '')}, "
            f"prefixo={(hash_after or '')[:28]}..."
        )
        logger.check(
            "Hash migrado automaticamente para formato moderno com salt (scrypt/pbkdf2)",
            bool(hash_after) and hash_after.startswith(("scrypt:", "pbkdf2:")),
            f"prefixo={(hash_after or '')[:16]}",
        )

        client.get("/logout")
        resp_second_login = client.get(
            "/login",
            query_string={"email": TEST_EMAIL, "password": TEST_VALID_PASSWORD},
        )
        logger.check(
            "Segundo login usando o hash já migrado funciona (HTTP 302)",
            resp_second_login.status_code == 302,
            f"status={resp_second_login.status_code}",
        )

        # ------------------------------------------------------------------
        # 3. V02 (CWE-521) - Política de senhas (validar_politica_senha)
        # ------------------------------------------------------------------
        logger.section("3. V02 (CWE-521) - Validador de política de senha")
        validator = getattr(database_corrigido, "validar_politica_senha", None)
        if validator is None:
            logger.check("Função validar_politica_senha presente em database_corrigido", False)
        else:
            cases = [
                ("Aa@1", False, "4 caracteres (padrão antigo fraco)"),
                (TEST_VALID_PASSWORD, False, "8 caracteres (teto antigo fraco)"),
                ("12345678", False, "senha comum"),
                ("senhalongasemespeciais1", False, "sem maiúscula nem símbolo"),
                ("Seguranca@2026#UEM", True, "18 caracteres com todas as classes"),
            ]
            for pwd, expected, desc in cases:
                result = validator(pwd)
                ok = result[0] if isinstance(result, tuple) else bool(result)
                msg = result[1] if isinstance(result, tuple) and len(result) > 1 else ""
                logger.check(
                    f"Política de senha ({desc})",
                    ok is expected,
                    f"esperado={expected}, obtido={ok}" + (f", msg='{msg}'" if msg else ""),
                )

        # ------------------------------------------------------------------
        # 4. Regressão rápida (V03–V06)
        # ------------------------------------------------------------------
        logger.section("4. Regressão rápida das correções anteriores (V03–V06)")
        reset_lockout_state(app_corrigido)
        client.get("/logout")

        resp_sqli_quote = client.get(
            "/login", query_string={"email": "'", "password": "x"}
        )
        logger.check(
            "V03 (CWE-89/489): Aspa simples no login não gera HTTP 500",
            resp_sqli_quote.status_code == 200,
            f"status={resp_sqli_quote.status_code}",
        )

        resp_sqli_or = client.get(
            "/login",
            query_string={"email": "email' OR '1'='1' OR '", "password": "x"},
        )
        logger.check(
            "V03 (CWE-89): Payload OR '1'='1' no login é recusado (HTTP 200)",
            resp_sqli_or.status_code == 200,
            f"status={resp_sqli_or.status_code}",
        )

        reset_lockout_state(app_corrigido)
        client.get(
            "/login",
            query_string={"email": TEST_EMAIL, "password": TEST_VALID_PASSWORD},
        )
        discipline_id = read_student_discipline_id(temp_db, TEST_EMAIL)
        if discipline_id is not None:
            resp_empty_msg = client.post(
                f"/disciplina/{discipline_id}/mensagem", data={"body": ""}
            )
            logger.check(
                "add_message: Mensagem vazia sem anexo retorna HTTP 400",
                resp_empty_msg.status_code == 400,
                f"status={resp_empty_msg.status_code}",
            )

            resp_html_upload = client.post(
                f"/disciplina/{discipline_id}/mensagem",
                data={
                    "body": "teste",
                    "file": (io.BytesIO(b"<html></html>"), "teste.html"),
                },
                content_type="multipart/form-data",
            )
            logger.check(
                "V06 (CWE-434): Upload de arquivo .html é bloqueado (HTTP 400)",
                resp_html_upload.status_code == 400,
                f"status={resp_html_upload.status_code}",
            )

            resp_txt_upload = client.post(
                f"/disciplina/{discipline_id}/mensagem",
                data={
                    "body": "anexo valido",
                    "file": (io.BytesIO(b"conteudo"), "notas.txt"),
                },
                content_type="multipart/form-data",
            )
            logger.check(
                "V06 (CWE-434): Upload de arquivo .txt legítimo continua funcionando (HTTP 302)",
                resp_txt_upload.status_code == 302,
                f"status={resp_txt_upload.status_code}",
            )

    logger.section("Resumo")
    total = logger.passed + logger.failed
    logger.log(f"Total de verificações: {total} | Aprovadas: {logger.passed} | Falhas: {logger.failed}")
    logger.save(LOG_PATH)
    logger.log(f"\nLog salvo em: {LOG_PATH}")
    return 0 if logger.failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())