Nomes:

Felipe Bona Regis Karmann
João Martinho Schneider da Silva e Souza

-----

Olá, professor. Antes de corrigir o trabalho, por favor atente-se aos seguintes pontos:

1. Naturalmente, o arquivo do nosso trabalho é o AES.java. O AESComBiblioteca nós o usamos para testes.

2. Infelizmente, o programa não funciona. Aparentente, as funções separadas de cifragem e decifragem funcionam, mas quando tentamos usá-las sequencialmente, o resultado é sempre um arquivo ilegível. Ao usarmos o AESComBiblioteca.java com o console de debug, podemos ver que os bytes produzidos não são o esperado em nenhum caso. Acreditamos que o erro possa estar em: a) na sequência de métodos invocados nos métodos cifrar() e decifrar(), em que tentamos seguir os esquemas representados no material, que estão anexados a este repsitório (cifragem.png e decifragem.png). Acreditamos que o esquema significa que as rodadas de 1 a 9 devem invocar apenas os métodos que são peculiares a elas, e os métodos antes e depois constituem as rodadas 0 e 10 respectivamente. Testamos o algoritmo baseado em outras perspectivas mas sem sucesso; e b) nos métodos mixColumns() e/ou substituirPalavra() (e seus inversos), porque ambos são bastante complexos. Apesar de não termos cumprido a tarefa até o fim, acreditamos que o algoritmo esteja quase perfeito e esperamos que ele possa ser avaliado como está.

3. O nosso programa é executado no modo de texto. Ele pede ao usuário que digite o caminho do arquivo a ser utilizado, a partir do diretório atual. Por algum motivo, se o arquivo está no mesmo diretório que o AES.java, é necessário usar o caminho "nome_do_arquivo.txt". Para outros diretórios, basta usar "/nome_da_pasta/nome_do_arquivo.txt".

4. O programa é capaz de criar arquivos sozinho, mas não de criar novos diretórios, sendo necessário que estes já tenham sido criados antes da sua execução.

5. O programa oferece ao usuário a possibilidade de gerar uma chave automaticamente. Ao optar por isto, o usuário precisa copiar a chave do output do programa e guardá-la no clipboard ou num arquivo se quiser usá-la para decifrar o mesmo arquivo. O método gerarChaveAleatoria() usava a biblioteca security.SecureRandom, mas trocamos pela util.Random por acharmos que talvez isso descumpre o requisito de não usar bibliotecas de criptografia.

-----

Obrigado.
