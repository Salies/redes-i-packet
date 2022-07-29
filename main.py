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
import struct

# Tenta pegar tempo de execução do programa
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

# Constantes relacionando porta com protocolo de aplicação, para verificação e impressão.
port_app_proto = {
    80: 'HTTP',
    21: 'FTP',
    25: 'SMTP',
    110: 'POP3',
    143: 'IMAP',
    23: 'Telnet',
    53: 'DNS',
    443: 'HTTPS' # coloquei HTTPS também para facilitar encontrar
}

# Número de protocolo de transporte (TCP e UDP, apenas)
t_proto_numbers = {
    6: 'TCP',
    17: 'UDP'
}

# Loop para receber pacotes até o fim do tempo de execução
while True:
    # Armazena o pacote recebido -- o parâmetro de recvfrom é o tamanho do buffer -- 65535 é o máximo
    # pkt_bytes armazena os dados brutos recebidos -- adress armazena o socket que enviou estes dados
    # Fonte: https://docs.python.org/3/library/socket.html#socket.socket.recvfrom
    pkt_bytes, address = s.recvfrom(65535)
    # Antes de tudo, ignoramos pacotes que não estejam trafegando via TCP ou UDP.
    # O protocolo de transporte está localizado/contido no byte 9 do header IPV4.
    # Seu número é definido por uma tabela da IANA:
    # https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    t_proto = pkt_bytes[9]
    if(t_proto != 6 and t_proto != 17):
        continue
    # Os dados do pacote estão codificados. Para decodificá-los, é necessário conhecer a estrutura
    # do frame Ethernet tipo II, mais precisamente de sua parte de dados, que é o que estamos tratando.
    # (imagem Raw-Ethernet-packet-structure.png).
    # A nós interessa a estrutura do header IP e o "raw data" (dados brutos). Para saber o caráter do pacote
    # recebido, primeiramente trataremos do header do IP (no caso, IPV4),
    # que é a seguinte: https://en.wikipedia.org/wiki/IPv4#Header
    # (considerando que estamos capturando apenas pacotes trafegando via IPV4).
    # A nós, interessa apenas: o protocolo da camada de aplicação, ip de origem, ip de destino,
    # porta de origem e porta de destino. Ademais, precisamos do tamanho do cabeçalho do IP para saber onde começa
    # a sessão de dados brutos, que também nos interessa. A distância entre o fim do cabeçalho do IP e o início dos dados
    # brutos varia conforme o protocolo de transporte, pois é o tamanho do cabeçalho deste protocolo (no nosso caso, UDP ou TCP).
    # Portanto, para pegar as portas, precisaremos saber o tamanho do cabeçalho do protocolo IP.
    # O tamanho do cabeçalho do IP está na segunda metade do primeiro byte do cabeçalho do IPV4.
    # Na enorme maioria dos casos, ihl =5, pois o cabeçalho não conterá a seção de opções. Mas é bom aferir mesmo assim.
    # O tamanho real do cabeçalho é (ihl * 32) bits. No caso, desejamos o valor em bytes, então (ihl * 4) bytes.
    # Fazendo a operação separado para evitar problemas de conversão.
    ihl = pkt_bytes[0] & 0x0F
    ihl *= 4
    # A partir disso, já conseguimos obter as portas de origem e de destino, pois localizam-se imediatamente após o cabeçalho
    # do protocolo IP, em sequência (origem, destino), com 2 bytes cada. Novamente, como não preciamos delas para nenhuma operação, já podemos
    # fazer a conversão direta com o método int.from_bytes -- os bytes estão em bid endian.
    source_port = int.from_bytes(pkt_bytes[ihl:(ihl + 2)], 'big')
    destination_port = int.from_bytes(pkt_bytes[(ihl + 2):(ihl + 4)], 'big')
    # Ignorando portas não padrão/com protocolo que não nos interessa
    if((source_port not in port_app_proto) and (destination_port not in port_app_proto)):
        continue
    # Após termos filtrados os pacotes que não nos interessam, vamos pegar o restante dos dados que queremos.
    # Cconseguimos obter os IPs de origem e destino a partir do cabeçalho.
    # Não precisamos dos IPs para nada além do registro, então já convertemos diretamente para string usando o método inet_ntoa.
    # O IP de origem está entre os bytes 12 e 16 do cabeçalho IPV4.
    source_ip_address = socket.inet_ntoa(pkt_bytes[12:16])
    # O IP de destino está entre os bytes 16 e 20 do cabeçalho IPV4.
    destination_ip_address = socket.inet_ntoa(pkt_bytes[16:20])
    # Agora basta pegarmos os dados brutos, os dados de aplicação que estão sendo de fato transmitidos.
    # A localização deles dependerá do protocolo de transporte.
    # Se for TCP, precisamos saber o tamanho do header dele, pois é variável (geralemnte entre 20 e 60 bytes).
    if t_proto == 6:
        # O tamanho do header do TCP está no primeiro nyble 12º byte de seu cabeçalho (que começa assim que o do IP termina).
        # Há novamente a questão dos 32 bits, então precisamos multiplicar por 4.
        tchpl = pkt_bytes[ihl + 12] >> 4
        tchpl *= 4
        # Os dados brutos estão logo após o cabeçalho do TCP.
        raw_data = pkt_bytes[ihl + tchpl:]
    # O cabeçalho do UDP, por sua vez, possui um tamanho fixo de 8 bytes.
    elif t_proto == 17:
        raw_data = pkt_bytes[ihl + 8:]
    # Basta então, decodificar os dados brutos.
    # Tento decoficar em UTF-8. Se não for possível, apenas salvo os dados brutos codificados no arquivo de saída.
    try:
        raw_data = raw_data.decode('utf-8')
    except:
        pass

# Chamada de sistema -- desabilita o modo promísuco
s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)