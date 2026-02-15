-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

Olá professor, aqui tem um ficheiro README que dá as insruções de como rodar o código.
No nosso computador nós seguimos estes passos, esperemos que funcione no seu tambem!

-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

## 1. Compilar os ficheiros Java 

javac *.java

-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

## 3. Executar o servidores 

Abrir um novo terminal e colocar: java ObliviousAuthServer
Abrir um novo terminal e colocar: java ObliviousAccessServer
Abrir um novo terminal e colocar: java BlockStorageServer

-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

## 4. Executar o cliente - Comando Default: 

Abrir um novo terminal e criar cliente 1: java "-Dp2.userKeyFile=alice.keys" Project2Client
Abrir um novo terminal e criar cliente 2: java "-Dp2.userKeyFile=bob.keys" Project2Client
Abrir um novo terminal e criar cliente 3 (se necessário): java "-Dp2.userKeyFile=thomas.keys" Project2Client

-+-+-+-+-+-++-+--+--+-++-++-++-++-++-++-++-++-+++-+-++-++-++-++-++-++-++-++-++-++-+-++-+++-++-+-++-++-++-++-+

## 5. Ações - Ordem das Ações

Cliente 1 (Quem partilha)
1. Register
2. Authenticate
3. Upload
4. Share

Cliente 2 
1. Register
2. Authenticate
3. Download
4. Search

Os testes são feito com a ajuda do menu interativo. Dentro do cliente deve ser selecionada a opçao da ação. 
