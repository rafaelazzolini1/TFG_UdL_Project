from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
import nacl.secret
import nacl.utils
from nacl.encoding import Base64Encoder
from langchain_community.chat_models import ChatOllama
from langchain_community.utilities import SQLDatabase
from langchain.chains import create_sql_query_chain
from langchain_community.vectorstores import FAISS
from langchain_core.example_selectors import SemanticSimilarityExampleSelector
from langchain_core.prompts import (
    ChatPromptTemplate,
    FewShotPromptTemplate,
    PromptTemplate,
    SystemMessagePromptTemplate,
)
from langchain_huggingface import HuggingFaceEmbeddings
import re
import time

app = Flask(__name__)
CORS(app)

database_uri = "mssql+pyodbc://@DESKTOP-5CU5M7P/Teste_RAG?driver=ODBC+Driver+17+for+SQL+Server"
sql_db = SQLDatabase.from_uri(database_uri)


# Tested models
# llm = ChatOllama(model="llama3:latest", base_url="http://localhost:11434", temperature=0, max_tokens=100)  # Limite de tokens
llm = ChatOllama(model="deepseek-r1:7b", base_url="http://localhost:11434", temperature=0, max_tokens=100)  # Limite de tokens
# llm = ChatOllama(model="deepseek-r1:1.5b", base_url="http://localhost:11434", temperature=0)
# llm = ChatOllama(model="codellama:7b", base_url="http://localhost:11434", temperature=0, max_tokens=100)
# llm = ChatOllama(model="mistral-small", base_url="http://localhost:11434", temperature=0.1, max_tokens=100)  # Limite de tokens
# llm = ChatOllama(model="mistral:latest", base_url="http://localhost:11434", temperature=0, max_tokens=100)  # Limite de tokens

TABLE_INFO = sql_db.get_table_info()  # Cache do esquema
print(f"Esquema:" + TABLE_INFO)


promptValid = ChatPromptTemplate.from_messages([
        (
            "system",
            "Você é um agente inteligente cuja função é interpretar se uma informação é bloqueada ou permitida.\
             Você deve verificar se a frase contida em input se relaciona de alguma forma com temas que envolvam salário, pagamentos, dinheiro, raça, religião, orientação sexual\
            Se considerar que existe alguma relação, retorne a palavra 'Bloqueado'\
            Caso contrário apenas retorne a palavra 'Permitido'\
            ",
        ),
    ("user", "{input}"),
])
valid_chain = promptValid | llm

examples = [
    {"input": "Quanto é o saldo de salário do Usuário1?",
     "query": "SELECT (Salario/30) * DAY([DataDemissao]) AS SaldoSalario FROM [Funcionario] WHERE [Nome] = 'Usuário1'"
    },
    {"input": "Qual o valor do décimo terceiro proporcional do funcionário Carlos Almeida?",
     "query": "select (Salario/12) * DATEDIFF(month, cast(dateadd(yy, datediff(yy, 0, GETDATE()), 0) as date), cast(getdate() as date)) AS DateDiff from Funcionario where nome = 'Carlos Almeida'"
    },
    {"input": "Qual o valor do FGTS total do funcionário João Gomes?",
     "query": "select (Salario * 0.08) * DATEDIFF(month, DataAdmissao, cast(getdate() as date)) AS FGTS from Funcionario where nome = 'João Gomes'; "
    },
    {"input": "Qual o valor da multa de 40% do funcionário João Gomes?",
     "query": "select 0.4 * (Salario * 0.08) * DATEDIFF(month, DataAdmissao, cast(getdate() as date)) AS FGTS from Funcionario where nome = 'João Gomes'; "
    },
    {"input": "Qual o valor da folha de pagamento total da empresa?",
     "query": "select sum(Salario) as FolhaPagamento from Funcionario Where DataDemissao is Null"
    },
    {"input": "Qual a politica de ferias da empresa?",
     "query": "select PoliticaDescricao as Politica from Politicas Where PoliticaNome like '%Ferias%'" 
    }
]
embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-MiniLM-L6-v2")
example_selector = SemanticSimilarityExampleSelector.from_examples(examples, embeddings, FAISS, k=2, input_keys=["input"])

system_prefix = """Você é um agente desenvolvido para interagir com uma base de dados SQL.
Aqui está o esquema do banco de dados disponível:
{table_info}

Através de uma pergunta feita num input, crie uma query SQL SERVER sintaticamente correta de acordo com a informação do esquema do banco de dados fornecido, ela deve ser executada.
Use SOMENTE as colunas e tabelas listadas em {table_info}. Retorne APENAS a query SQL, sem explicações, raciocínio ou texto adicional, dentro de delimitadores ```sql ... ```.
Se a pergunta não for clara ou não puder ser respondida com base no esquema, retorne ```sql SELECT 'Eu não sei' AS Resposta ```.
Se o usuário não especificar a quantidade de exemplos de retorno, limite sua query a no máximo {top_k} resultados.
Você pode ordenar os resultados por uma coluna relevante para retornar os exemplos mais interessantes da base de dados.
Nunca faça uma busca por todas as colunas de uma tabela específica, apenas busque pelas colunas mais relevantes de acordo com a pergunta.
Você DEVE verificar duas vezes sua query antes de executá-la.
NÃO faça nenhum comando de DML (INSERT, UPDATE, DELETE, DROP etc.) na base de dados.

Aqui estão alguns exemplos de inputs de usuário e suas querys correspondentes:"""

few_shot_prompt = FewShotPromptTemplate(
    example_selector=example_selector,
    example_prompt=PromptTemplate.from_template("User input: {input}\nSQL query: {query}"),
    input_variables=["input", "top_k", "table_info"],
    prefix=system_prefix,
    suffix="",
)

full_prompt = ChatPromptTemplate.from_messages([
    SystemMessagePromptTemplate(prompt=few_shot_prompt),
    ("human", "{input}"),
])

sql_chain = create_sql_query_chain(llm, sql_db, prompt=full_prompt)

@app.route("/members")
def members():
    return {"members": ["member1", "member2", "member3"]}

@app.route("/cryptokey")
def retornaChave():
    chave = {'chave': 'q9egeDk+L1t2C8pgH/9rzE/ezPflr3cx6JLujZSiaX8='}
    return jsonify({'chave': chave})

@app.after_request
def remove_server_header(response):
    response.headers.pop('Server', None)
    return response

@app.route('/api/dados', methods=['POST'])
def receber_dados():
    dados = request.json
    print(dados)

    nome = dados.get('nome')
    print(nome)

    token = dados.get('token')
    print(token)

    keyFront = Base64Encoder.decode('q9egeDk+L1t2C8pgH/9rzE/ezPflr3cx6JLujZSiaX8=')
    encrypted_message_base64 = token
    encrypted_message = Base64Encoder.decode(encrypted_message_base64)

    nonce = encrypted_message[:nacl.secret.SecretBox.NONCE_SIZE]
    encrypted = encrypted_message[nacl.secret.SecretBox.NONCE_SIZE:]

    box = nacl.secret.SecretBox(keyFront)
    start_time = time.time()
    decrypted_message = box.decrypt(encrypted, nonce)
    print(f"Tempo de descriptografia: {time.time() - start_time:.2f} segundos")

    start_time = time.time()
    resultadoValidacao = valid_chain.invoke({"input": nome})
    validacao = resultadoValidacao.content.strip()
    print(f"Tempo de validação: {time.time() - start_time:.2f} segundos")

    if decrypted_message.decode() == 'funcionario':
        if validacao == 'Bloqueado':
            result = {'output': 'Não posso fornecer essa informação.'}
        else:
            start_time = time.time()
            raw_output = sql_chain.invoke({"question": nome, "top_k": 5, "table_info": TABLE_INFO})
            print(f"Tempo de geração da query: {time.time() - start_time:.2f} segundos")

            query_match = re.search(r'```sql\s*(.*?)\s*```', raw_output, re.DOTALL)
            if query_match:
                query = query_match.group(1).strip()
            else:
                query = raw_output.strip()
                if not query.startswith("SELECT"):  # Verifica se é uma query válida
                    query = "SELECT 'Eu não sei' AS Resposta"
            print(f"Query gerada: {query}")

            start_time = time.time()
            try:
                result_db = sql_db.run(query)
                result = {'output': result_db}
            except Exception as e:
                result = {'output': f"Erro ao executar a query: {str(e)}"}
            print(f"Tempo de execução da query: {time.time() - start_time:.2f} segundos")
    else:
        start_time = time.time()
        raw_output = sql_chain.invoke({"question": nome, "top_k": 5, "table_info": TABLE_INFO})
        print(f"Tempo de geração da query: {time.time() - start_time:.2f} segundos")

        query_match = re.search(r'```sql\s*(.*?)\s*```', raw_output, re.DOTALL)
        if query_match:
            query = query_match.group(1).strip()
        else:
            query = raw_output.strip()
        print(f"Query gerada: {query}")

        start_time = time.time()
        try:
            result_db = sql_db.run(query)
            result = {'output': result_db}
        except Exception as e:
            result = {'output': f"Erro ao executar a query: {str(e)}"}
        print(f"Tempo de execução da query: {time.time() - start_time:.2f} segundos")

    print(result)
    response = make_response(jsonify({'result': result}))
    response.headers['Content-Type'] = 'application/json'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none';"
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

if __name__ == "__main__":
    app.run(debug=True)