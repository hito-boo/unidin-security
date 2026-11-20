# Exploração
Este caderno contém a metodologia e os processos realizados para a análise exploratória de vulnerabilidades do código. A primeira etapa baseou-se em uma inspeção do código-fonte realizada manualmente e automaticamente por ferramentas especializadas, tal que pontenciais vulnerabilidades fossem identificadas. Posteriormente, tais vulnerabilidades foram colocadas à prova utilizando a ferramenta Zed Attack Proxy (ZAP), de forma a validá-las.

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

## Lista de CWEs
Após a verificação realizada pelas ferramentas anteriores e por meio da inspeção manual de código, a seguinte lista de CWEs foi verificada, de acordo com as modalidades de vulnerabilidades esperadas pela especificação do trabalho.

* [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)

* [CWE-79:Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)

* [CWE-307: Improper Restriction of Excessive Authentication Attempts](https://cwe.mitre.org/data/definitions/307.html)

* [CWE-521: Weak Password Requirements](https://cwe.mitre.org/data/definitions/521.html)

* [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)

* [CWE-259: Use of Hard-coded Password](https://cwe.mitre.org/data/definitions/259.html)

* [CWE-94: Improper Control of Generation of Code](https://cwe.mitre.org/data/definitions/94.html)
