from langchain.agents import tool
from langchain.agents.format_scratchpad.openai_tools import (
    format_to_openai_tool_messages,
)
from langchain.agents.output_parsers.openai_tools import OpenAIToolsAgentOutputParser

@tool
def separaPalavras(texto: str) -> dict:
    """Returns a dict of words from a text string"""
    texto = texto.replace(',', '')
    split = texto.split()

    return split

tools = [separaPalavras]

promptValid = ChatPromptTemplate.from_messages(
    [
        (
            "system",
            "Você é um agente inteligente cuja função é interpretar se uma informação é bloqueada ou permitida.\
             Você deve verificar se a frase contida em input se relaciona de alguma forma com temas que envolvam salário, pagamentos ou dinheiro\
            Se considerar que existe alguma relação, retorne a palavra 'Bloqueado'\
            Caso contrário apenas retorne a palavra 'Permitido'\
            ",
        ),
        ("user", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ]
)

llm_with_tools = llm.bind_tools(tools)

agentValid = (
    {
        "input": lambda x: x["input"],
        "agent_scratchpad": lambda x: format_to_openai_tool_messages(
            x["intermediate_steps"]
        ),
    }
    | promptValid
    | llm_with_tools
    | OpenAIToolsAgentOutputParser()
)

agent_executor = AgentExecutor(agent=agentValid, tools=tools, verbose=True)