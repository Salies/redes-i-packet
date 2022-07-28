'''
FCT-UNESP -- Redes de Computadores I
Atividade 2 - Analisar pacotes e serviços
Daniel Henrique Serezane Pereira
'''

# Implementação parcialmente baseada no tutorial disponível em:
# https://docs.python.org/3/library/socket.html

# Variáveis em Inglês para maior conformidade com a linguagem Python

import socket
import sys

# Tenta pegar empo de execução do programa
try:
    t = int(sys.argv[1])
    if t < 0: 
        print("ERRO: Número de tempo não válido.")
        sys.exit()
except ValueError:
    print("Valor não numérico inserido.")
    sys.exit()

# Pega a interface pública de rede
HOST = socket.gethostbyname(socket.gethostname())

# Criação de um socket na rede para capturar os pacotes
# O primeiro param. é a família de endereços do socket, isto é, o tipo de endereço.
# No caso, escolhemos AF_INET, para ipv4 (não defini IPV6 também pois, dada uma limitação
# do Windows, é um tanto complexo capturar pacotes V4 e V6 ao mesmo tempo).
# O segundo param. é o tipo do socket -- no caso, utilizamos SOCK_RAW, para fazer a
# leitura dos pacotes integralmente, incluindo seu header.
# Fonte: https://manned.org/packet.7
# Se Linux exclusivamente estivesse sendo utilizado, o tipo de socket poderia ser SOCK_PACKET.
# O último parâmetro refere-se aos protocolos capturados. No caso, socket.IPPROTO_IP permite
# a captura tanto de qualquer pacote que esteja trafegando, tentando adaptar-se indepedentmeente
# do protocolo de transporte.
# Em suma: este socket capturará pacotes que estiverem trafegando pela rede via TCP ou UDP, usando IPV4.
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

# Associando o socket à interface pública da rede
s.bind((HOST, 0))

# Fazendo com que o socket capture os cabeçalhos do protocolo IP
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# Chamada de sistema -- captura todos os pacotres (modo promíscuo ativado)
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# Loop para receber pacotes até o fim do tempo de execução
while True:
    # Armazena o pacote recebido -- o parâmetro de recvfrom é o tamanho do buffer -- 65535 é o máximo
    # bytes armazena os dados brutos recebidos -- adress armazena o socket que enviou estes dados
    # Fonte: https://docs.python.org/3/library/socket.html#socket.socket.recvfrom
    bytes, address = s.recvfrom(65535)
    # Os dados do pacote estão codificados. Para decodificá-los, é necessário conhecer a estrutura
    # do frame Ethernet tipo II, mais precisamente de sua parte de dados, que é o que estamos tratando.
    # (imagem Raw-Ethernet-packet-structure.png).
    # A nós interessa a estrutura do header IP e o "raw data" (dados brutos). Para saber o caráter do pacote
    # recebido, primeiramente trataremos do header do IP (no caso, IPV4),
    # que é a seguinte: https://en.wikipedia.org/wiki/IPv4#Header
    # (considerando que estamos capturando apenas pacotes trafegando via IPV4).
    # A nós, interessa apenas: o protocolo da camada de aplicação, ip de origem, ip de destino,
    # porta de origem e porta de destino. Ademais, precisamos do tamanho do cabeçalho do IP para saber onde começa
    # a sessão de dados brutos, que também nos interessa. A distância entre o fim do cabeçalho e o início dos dados
    # brutos varia conforme o protocolo de transporte.
    # O tamanho do cabeçalho do IP está na segunda metade do primeiro byte do cabeçalho do IPV4.
    version, ihl = bytes[0][:1], bytes[0][1:2]
    print(version, ihl)
    # O protocolo de transporte está localizado/contido no byte 9 do header IPV4:
    t_proto = bytes[9]

# Chamada de sistema -- desabilita o modo promísuco
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)