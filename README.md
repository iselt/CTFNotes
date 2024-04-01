# CTFNotes

你可以fork这个仓库，自行保管维护作为CTF学习笔记仓库。

> **注意：** 请先fork本仓库，再将你自己的仓库克隆到本地，不要直接克隆本仓库，否则你将无法push修改。

## 使用脚本（Windows）

1. 安装Git和gh，参考手动教程
2. 下载[CTFNotes_Setup.bat](./CTFNotes_Setup.bat)，放入合适的父目录下
3. 双击运行`CTFNotes_Setup.bat`，它会自动帮你fork仓库、克隆仓库到当前目录并自动填写.env文件

## 手动教程

### 1. 安装Git和github-cli(gh)

你可以通过官网下载安装[Git](https://git-scm.com/)和[gh](https://cli.github.com/)

也可以先安装[scoop](https://scoop.sh/)（Only for Windows），随后使用命令行安装git和gh：

```bash
scoop install git
scoop install gh
```

gh主要作用是提供GitHub认证

### 2. Github认证

使用gh登录你的GitHub账号，以便为本机的Git提供Github账号认证：

```bash
gh auth login
```

### 3. fork仓库

在本仓库右上角点击`Fork`，将本仓库fork到你的账号下。

### 4. 克隆仓库

在你fork的仓库中，点击`Code`按钮，复制仓库地址，然后在本地使用以下命令克隆仓库：

```bash
git clone 你的仓库地址
```

### 5. 提交修改到你的仓库

在你更改了文件之后，你可以使用以下命令提交你的修改：

```bash
git add . # 添加所有修改
git commit -m "你的提交信息" # 提交修改
git push # 推送到远程仓库
```

如果你懒得每次打三行命令，我们也写了一个脚本`push.bat`，你可以每次做完更改后直接运行它

### 6. 提交PR到团队仓库

在你push之后，你可以在你的仓库页面点击`Pull Request`按钮，提交PR到本仓库的**以你的用户名命名的分支**，不要交到主分支。

你也可以使用脚本`pr.bat`来提交PR，注意要在.env文件中填写你的用户名（不是昵称）。

**提交PR的频率为每周一次**。