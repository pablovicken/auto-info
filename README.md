# Automação de Informações
#### Capturando Informações é uma ferramenta de coleta de informações automatizada desenvolvida para auxiliar na realização de atividades de Pentest e testes de segurança em ambientes controlados, como laboratórios acadêmicos. O objetivo desta ferramenta é simplificar o processo de coleta de informações essenciais sobre um domínio alvo, fornecendo dados como WHOIS, DNS, subdomínios, certificados SSL, e muito mais.

## 📌 Funcionalidades:

* Consultas WHOIS: Obtém informações de registro de domínio (proprietário, servidores DNS, etc.).
* Consultas DNS: Coleta registros DNS do domínio (A, MX, NS, TXT).
* Subdomínios: Pesquisa de subdomínios associados ao domínio alvo.
* Informações do Servidor Web: Recupera informações sobre o servidor web do domínio (como o cabeçalho 'Server').
* Certificado SSL/TLS: Verifica o certificado SSL do domínio.
*  Vazamentos de Dados: Verifica se o e-mail relacionado ao domínio foi exposto em vazamentos de dados usando a API "Have I Been Pwned".
*  Scan de Rede: Realiza uma varredura de rede (usando ARP) para identificar dispositivos ativos em uma rede especificada.
* Exportação de Resultados: Salva os resultados coletados em arquivos JSON ou TXT para análise posterior.

## 📝 Requisitos:
> **Python 3.6 ou superior**
### Bibliotecas Python necessárias:
```bash
* whois
* dnspython
* requests
* ssl
* socket
* beautifulsoup4 (BeautifulSoup)
* scapy
* json
```
## ⚠️ Instalação das dependências:
Para instalar as **dependências necessárias**, basta executar o seguinte comando:
```bash
pip install whois dnspython requests beautifulsoup4 scapy
```
## ✅ Como Usar:
Clone o repositório:
Clone este repositório para o seu ambiente local utilizando o comando:
```bash
git clone https://github.com/pablovicken/auto-info
```
Navegue até o diretório do projeto:
Entre no diretório do projeto com o comando:
```bash
cd auto-info
```
## 🛠 Execute a ferramenta:
Para executar o script, basta rodar o seguinte comando no terminal:
```bash
python auto-info.py
```

## Siga as instruções interativas:
O script irá solicitar que você insira um domínio alvo e realizará várias consultas, como WHOIS, DNS, subdomínios, entre outras. Além disso, você será questionado sobre alguns parâmetros, como e-mail e IP,
e poderá visualizar as informações coletadas ao final do processo.

## 🔎 Exemplos de Uso:
Ao executar o script, você verá algo assim no terminal:

```bash
Digite o domínio alvo: vizinhosite.com
Consultando WHOIS do alvo....
Consultando registros DNS do alvo...
Consultando subdomínios...
Obtendo informações sobre o servidor Web...
Obtendo informações do certificado SSL/TLS...
Verificando vazamentos de dados...
Digite o IP da rede para realizar o scan (ou pressione Enter para usar o IP do alvo):
Realizando scan de rede utilizando ARP...
Após a execução, os resultados serão salvos no arquivo informacoes.json ou informacoes.txt (dependendo da configuração). Você também pode escolher onde salvar os dados de saída.
```

## 📊 Exemplos de Resultados:
O arquivo informacoes.json gerado pode ter a seguinte aparência:

json
```bash
{
    "whois": {
        "registrar": "Example Registrar",
        "creation_date": "2000-01-01",
        "emails": ["email@exemplo.com"],
        "addresses": ["192.168.0.1"]
    },
    "dns": {
        "A": ["192.168.0.1"],
        "MX": ["mail.exemplo.com"],
        "NS": ["ns1.exemplo.com"],
        "TXT": ["v=spf1 include:_spf.google.com ~all"]
    },
    "subdominios": ["sub1.exemplo.com", "sub2.exemplo.com"],
    "ssl": {
        "issuer": "Let's Encrypt",
        "validity": "2024-01-01"
    },
    "server_info": "Apache/2.4.39"
}
```
#### 📍 Considerações Importantes:
- Esta ferramenta foi desenvolvida para fins educacionais e aprendizagem.
- O uso da ferramenta em ambientes de produção ou em redes não autorizadas pode ser ilegal e violar a privacidade de terceiros. Utilize a ferramenta de maneira ética e responsável.
- Este projeto está em constante desenvolvimento, e melhorias são bem-vindas! Sinta-se à vontade para contribuir.
