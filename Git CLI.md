### Push a local repo to GitHub

1. `git init` : ran from the dir that will become a repo, or specify dir name afterwards
2. `git add .`
3. `git commit -m "initial commit"`
5. `gh auth login`  :  GitHub CLI, follow steps for login (may need to `apt-get install gh`)
6. `gh repo create my-newrepo --public --source=. --push` :  create repo, make public, set source as current dir (in local shell) and push current contents