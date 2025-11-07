========================
= Integrantes do grupo =
========================

-Vinícius Martins Faria
-Tiago Campos de Andrade
-Douglas da Silva Marques

=======================================
= Instruções de compilação e execução =
=======================================

Compilação:
    gcc server_QoS.c -o nome_do_executavel

Dependências:
    - Compilador GCC (no caso de ambiente linux, instalar com: sudo apt install gcc)
    - Biblioteca pthread (inclusa por padrão em distribuições Linux)
    - Pasta "www" contendo os arquivos a serem servidos
    - Arquivo "clients.txt" com IPs e limites de banda configurados
	Exemplo de arquivo "clients.txt"(No formato: endereço ip e limite de banda):
		
		"192.168.0.5 2000 
		10.0.0.7 500"

Execução padrão:
    ./nome_do_executavel

Parâmetros opcionais:
    ./nome_do_executavel [porta] [arquivo_clients] [server_max_kbps]

Exemplo:
    "./nome_do_executavel clients.txt 10000"

!!!O servidor cria uma thread por cliente conectado, suporta conexões persistentes (keep-alive)
e aplica controle de taxa (QoS) por IP de acordo com o arquivo clients.txt.
Conteúdo .html é servido sem limitação de taxa.

Para testar:
    Abra um navegador e acesse http://localhost:8080/
ou
    Use o comando: curl http://localhost:8080/

Encerrar o servidor:
    Ctrl + C

========================
= Declaração de autoria=
========================

Este projeto foi desenvolvido integralmente pela equipe,
sem ajuda não autorizada de alunos não membros do projeto no processo de codificação.
