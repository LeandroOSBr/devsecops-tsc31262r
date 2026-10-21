# 🧑‍💻 Guia Prático 01 — Mão na Massa com Git em Equipe (Aula 02)

Neste exercício prático, vamos simular o fluxo de trabalho real de um time de engenharia aplicando os conceitos das **4 áreas do Git** (*Working Directory*, *Staging Area*, *Repositório Local* e *Repositório Remoto*) e acionando nossa primeira esteira automatizada!

---

## 🎯 Missão 1: Configurar sua Identidade e Explorar o Repositório

No terminal (dentro do **GitHub Codespaces** ou na sua máquina local), configure seu nome e e-mail para que seus *commits* fiquem identificados:

```bash
git config --global user.name "Seu Nome Completo"
git config --global user.email "seu.email@exemplo.com"
```

Verifique se o seu repositório está limpo e veja o histórico de alterações feitas até agora:

```bash
git status
git log --oneline --graph --all
```

---

## 🌿 Missão 2: Criar a sua própria Branch de Trabalho

No mercado, nunca alteramos diretamente a branch principal (`main`) sem antes testar e revisar. Crie uma branch exclusiva com o seu nome:

```bash
git checkout -b aluno/seu-primeiro-nome
```
*(Exemplo: `git checkout -b aluno/joao-paulo` ou `git checkout -b aluno/endrick`)*

Confirme em qual branch você está:
```bash
git branch
```

---

## 📝 Missão 3: Criar seu Perfil no Mural da Turma (Working Directory $\rightarrow$ Staging $\rightarrow$ Local Repo)

1. Faça uma cópia do arquivo modelo `template-aluno.md` dentro da pasta `01-pratica-git/mural-da-turma/` usando o seu nome:
   ```bash
   cp 01-pratica-git/mural-da-turma/template-aluno.md 01-pratica-git/mural-da-turma/seu-nome.md
   ```
2. Abra o arquivo `01-pratica-git/mural-da-turma/seu-nome.md` no editor, preencha seus dados e salve (`Ctrl + S`).
3. Veja como o Git detecta que o arquivo novo está apenas no **Diretório de Trabalho (`Working Directory`)** (aparecerá em vermelho como *Untracked*):
   ```bash
   git status
   ```
4. Envie o arquivo para a **Área de Preparação (`Staging Area`)**:
   ```bash
   git add 01-pratica-git/mural-da-turma/seu-nome.md
   git status
   ```
   *(Observe que agora o arquivo aparece em verde: `Changes to be committed`!)*
5. Grave essa alteração no seu **Repositório Local** com uma mensagem descritiva:
   ```bash
   git commit -m "feat: adiciona perfil de [Seu Nome] no mural da turma"
   ```

---

## 🚀 Missão 4: Enviar para o Repositório Remoto (`git push`) e Disparar a Esteira

Agora envie a sua branch local para o servidor remoto do GitHub:

```bash
git push -u origin HEAD
```

Assim que o comando concluir:
1. Vá até a página do repositório no GitHub;
2. Clique na aba **Actions** no topo da página;
3. Veja que o seu `git push` **inicializou automaticamente a esteira de CI/CD**, executando as validações de código e de segurança!

---

## 🤝 Missão 5: Abrir um Pull Request (Revisão de Código)

1. Na página inicial do repositório no GitHub, clique no botão **`Compare & pull request`** que aparecerá em destaque amarelo;
2. Adicione um título (ex: `Adiciona perfil do aluno [Seu Nome]`) e clique em **`Create pull request`**;
3. Observe o **Quality Gate** rodando dentro do seu Pull Request antes da aprovação e *merge* pelo professor!
