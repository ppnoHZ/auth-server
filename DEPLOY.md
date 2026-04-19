# GitHub Actions 自动化部署指南

本文档将指导您如何配置和使用 GitHub Actions，将本 FastAPI (OAuth2 Server) 项目自动部署到您的服务器。

## 1. 部署流程概览

我们建议的持续集成/持续部署 (CI/CD) 流程如下：
1. **代码推送** (Push) 到 `main` 分支。
2. **CI 阶段（代码测试）**：自动安装依赖并运行 `pytest` 进行自动化测试。
3. **CD 阶段（服务器部署）**：测试通过后，通过 SSH 自动连接到您的生产服务器，拉取最新代码，更新依赖并重启服务。

## 2. 准备工作 (配置 GitHub Secrets)

为了让 GitHub Actions 能够正常运行测试并登录部署到服务器，您需要在 GitHub 仓库中配置安全凭证（Secrets）。
进入您的仓库 -> **Settings** -> **Secrets and variables** -> **Actions** -> 点击 **New repository secret**，添加以下两组参数：

**A. 数据库连接凭证 (用于自动化测试)**
*   `DATABASE_URL`：异步数据库连接字符串（如 `mysql+aiomysql://user:pwd@host/db_test`）
*   `DATABASE_URL_SYNC`：同步数据库连接字符串（如 `mysql+pymysql://user:pwd@host/db_test`）
> *注意：强烈建议在 CI/CD 测试中使用单独的测试数据库，以免自动化测试清空或污染生产库数据。*

**B. 服务器 SSH 登录凭证 (用于自动化部署)**
*   `SERVER_HOST`：您的服务器公网 IP 地址（例如 `123.45.67.89`）
*   `SERVER_USERNAME`：服务器的 SSH 登录用户名（例如 `root` 或 `ubuntu`）
*   `SERVER_SSH_KEY`：您的 SSH 私钥。请确保对应的**公钥**已添加到服务器账号的 `~/.ssh/authorized_keys` 中。

## 3. Workflow 配置文件

在项目根目录下，我们已经为您生成了工作流配置文件：`.github/workflows/deploy.yml`。

工作流主要包含两个 Job：
*   **test**: 使用 Python 运行环境，安装项目依赖并执行 `pytest`。
*   **deploy**: 仅在 `test` 成功后运行。借助 `appleboy/ssh-action` 登录到的服务器，并在服务器上执行部署脚本（如下拉取代码、应用数据库迁移、重启守护进程）。

## 4. 服务器端的配置要求

确保您的服务器上已进行初始配置：

1. **环境准备**：克隆代码到指定目录（工作流默认假设项目在 `/var/www/oauth2-server`）。
2. **生产配置文件 `.env`**：在服务器项目**根目录**下必须存在一份用于**生产环境**的 `.env` 文件。该文件**绝不能**提交到 Git：
   ```env
   # 在服务器创建 /var/www/oauth2-server/.env
   DATABASE_URL=mysql+aiomysql://user:pwd@host/prod_db
   DATABASE_URL_SYNC=mysql+pymysql://user:pwd@host/prod_db
   JWT_SECRET_KEY=...
   ```
3. **服务管理**：（可选且推荐）使用 `systemd`、`supervisor` 或 `pm2` 等工具管理您的 FastAPI (uvicorn) 进程，使重启变得简单（例如命令为 `sudo systemctl restart oauth2-server`）。

### 服务器端部署重启逻辑：
部署脚本（在 `deploy.yml` 的 `script` 部分）目前是这样配置的：
```bash
cd /var/www/oauth2-server
git pull origin main
# 激活虚拟环境并更新依赖
source .venv/bin/activate
pip install -e .
# 执行数据库迁移
alembic upgrade head
# 重启服务 (假设您使用了 systemd)
sudo systemctl restart oauth2-server
```
**注意**：请根据您实际服务器上的路径和守护进程名称修改 `.github/workflows/deploy.yml` 中的 `script` 部分代码。

## 5. 开始部署

现在，一旦您将代码提交并 Push 到 GitHub 仓库的 `main` 分支：
```bash
git add .
git commit -m "feat: setup github actions deployment"
git push origin main
```
部署流水线就会自动触发。您可以在 GitHub 仓库的 **Actions** 标签页中实时查看部署进度和日志。
