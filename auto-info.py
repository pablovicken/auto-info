import whois
import dns.resolver
import requests
import ssl
import socket
import json
import random
import time
from bs4 import BeautifulSoup
import scapy.all as scapy

# Função para gerar cabeçalhos HTTP com User-Agent aleatório
def get_random_headers():
    """
    Função que retorna um cabeçalho HTTP com um User-Agent aleatório,
    o que ajuda a evitar bloqueios durante as requisições HTTP.
    """
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:36.0) Gecko/20100101 Firefox/36.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.89 Safari/537.36',
        'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:60.0) Gecko/20100101 Firefox/60.0',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.113 Safari/537.36'
    ]
    return {'User-Agent': random.choice(user_agents)}

# Função 1: Consultar informações de WHOIS do domínio
def get_whois_info(domain):
    """
    Função que consulta informações WHOIS do domínio.
    O WHOIS é usado para obter dados sobre o dono do domínio e o registro.
    """
    try:
        print("Consultando WHOIS do alvo....")
        w = whois.whois(domain)
        return w
    except Exception as e:
        return f"Erro ao consultar WHOIS: {e}"

# Função para extrair e-mail e IP das informações WHOIS
def extract_email_and_ip(whois_info):
    """
    Função que tenta extrair o e-mail e IP do WHOIS do domínio.
    O e-mail é obtido da chave 'emails' e o IP da chave 'addresses'.
    """
    try:
        emails = whois_info.get('emails', [])
        email = emails[0] if emails else 'Não encontrado'

        ip = whois_info.get('addresses', [])
        ip = ip[0] if ip else 'Não encontrado'

        return email, ip
    except Exception as e:
        return f"Erro ao extrair e-mail ou IP: {e}", None

# Função 2: Consultar registros DNS (A, MX, NS, TXT) do domínio
def get_dns_records(domain):
    """
    Função para consultar registros DNS do domínio, incluindo A (endereços IP), MX (servidores de e-mail),
    NS (servidores DNS) e TXT (informações adicionais).
    """
    print("Consultando registros DNS do alvo...")
    resultado = {}
    try:
        resultado['A'] = dns.resolver.resolve(domain, 'A')  # Registros A: endereços IP
        try:
            resultado['MX'] = dns.resolver.resolve(domain, 'MX')  # Registros MX: servidores de e-mail
        except dns.resolver.NoAnswer:
            resultado['MX'] = 'Nenhum registro MX encontrado'

        resultado['NS'] = dns.resolver.resolve(domain, 'NS')  # Registros NS: servidores DNS
        try:
            resultado['TXT'] = dns.resolver.resolve(domain, 'TXT')  # Tentando coletar registros TXT
        except dns.resolver.NoAnswer:
            resultado['TXT'] = 'Nenhum registro TXT encontrado'
    except Exception as e:
        return f"Erro ao consultar o DNS: {e}"
    return resultado

# Função 3: Consultar subdomínios usando a API do crt.sh
def get_subdomains(domain):
    """
    Função que consulta subdomínios do domínio utilizando a API crt.sh.
    Essa API fornece subdomínios que foram incluídos em certificados SSL/TLS.
    """
    print("Consultando subdomínios...")
    try:
        subdomains = []
        response = requests.get(f"https://crt.sh/?q={domain}&output=json", headers=get_random_headers())
        data = response.json()

        for entry in data:
            subdomain = entry['name_value']
            if domain in subdomain:  # Verifica se o subdomínio pertence ao domínio principal
                subdomains.append(subdomain)

        return subdomains
    except Exception as e:
        return f"Erro ao coletar subdomínios: {e}"

# Função 4: Obter informações sobre o servidor web do domínio
def get_server_info(domain):
    """
    Função que consulta as informações sobre o servidor web do domínio.
    A consulta é feita através de um cabeçalho HTTP HEAD, que permite obter os dados do servidor sem precisar fazer o download do conteúdo da página.
    """
    print("Obtendo informações sobre o servidor Web...")
    try:
        response = requests.head(f"http://{domain}", headers=get_random_headers())  # Envia uma requisição HEAD para o servidor
        server_info = response.headers.get('Server', 'Desconhecido')  # Extrai o cabeçalho 'Server'
        return server_info
    except Exception as e:
        return f"Erro ao consultar servidor: {e}"

# Função 5: Obter informações do certificado SSL/TLS
def get_ssl_info(domain):
    """
    Função que consulta o certificado SSL/TLS do domínio.
    A função realiza uma conexão SSL na porta 443 e coleta os detalhes do certificado.
    """
    print("Obtendo informações do certificado SSL/TLS...")
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(socket.socket(), server_hostname=domain)
        conn.connect((domain, 443))  # Conecta na porta 443 (HTTPS)
        cert = conn.getpeercert()  # Obtém o certificado SSL/TLS
        return cert
    except Exception as e:
        return f"Erro ao verificar SSL: {e}"

# Função 6: Verificar se o e-mail foi vazado em bancos de dados públicos (via API Have I Been Pwned)
def verificar_email(email):
    """
    Função que consulta a API Have I Been Pwned para verificar se o e-mail foi exposto em vazamentos de dados.
    """
    print("Verificando vazamentos de dados...")
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
    try:
        response = requests.get(url, headers=get_random_headers())
        if response.status_code == 200:
            return response.json()  # Retorna o JSON com os detalhes do vazamento
        else:
            return "Nenhum vazamento encontrado."
    except Exception as e:
        return f"Erro ao verificar vazamentos: {e}"

# Função 7: Realizar um scan de rede (ARP) para descobrir hosts ativos
def scan_rede(target_ip):
    """
    Função que utiliza ARP (Address Resolution Protocol) para realizar um scan de rede e identificar dispositivos ativos na rede local.
    """
    print("Realizando scan de rede utilizando ARP...")
    try:
        arp_request = scapy.ARP(pdst=target_ip)  # Cria um pacote ARP para o IP alvo
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")  # Pacote Ethernet de broadcast
        arp_request_broadcast = broadcast / arp_request  # Combina o pacote Ethernet com a requisição ARP
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]  # Envia e recebe as respostas ARP
        devices = [element[1].psrc for element in answered_list]  # Adiciona os IPs dos dispositivos encontrados
        return devices
    except Exception as e:
        return f"Erro ao realizar scan de rede: {e}"

# Função para salvar as informações coletadas em um arquivo JSON
def save_to_json(info, filename="informacoes.json"):
    """
    Função que salva as informações coletadas em um arquivo JSON.
    O formato JSON é útil para armazenar e compartilhar os dados.
    """
    with open(filename, 'w') as f:
        json.dump(info, f, indent=4)  # Salva os dados em formato JSON com indentação para facilitar a leitura
    print(f"Informações salvas em {filename}")

# Função principal para coletar todas as informações sobre o domínio
def coletar_informacoes(domain):
    """
    Função que coleta todas as informações de segurança sobre um domínio, como WHOIS, DNS, subdomínios,
    informações de servidor, certificado SSL e dispositivos na rede.
    """
    info = {}

    # WHOIS
    whois_info = get_whois_info(domain)
    info['whois'] = str(whois_info)

    # E-mail e IP
    email, ip = extract_email_and_ip(whois_info)
    info['email'] = email
    info['ip'] = ip

    # Registros DNS
    dns_info = get_dns_records(domain)
    info['dns'] = dns_info

    # Subdomínios
    subdominios = get_subdomains(domain)
    info['subdominios'] = subdominios

    # Servidor Web
    server_info = get_server_info(domain)
    info['servidor_web'] = server_info

    # Certificado SSL
    ssl_info = get_ssl_info(domain)
    info['ssl'] = ssl_info

    # Verificação de vazamentos de dados
    email_info = verificar_email(email)
    info['email_vazamentos'] = email_info

    # Scan de rede
    target_ip = input("\nDigite o IP da rede para realizar o scan (ou pressione Enter para usar o IP do alvo): ")
    if not target_ip:
        target_ip = ip
    dispositivos = scan_rede(target_ip)
    info['dispositivos_rede'] = dispositivos

    # Salvar informações em formato JSON
    save_to_json(info)

# Execução
if __name__ == "__main__":
    domain = input('Digite o domínio alvo: ')
    coletar_informacoes(domain)
