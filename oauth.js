module.exports = {
  apps: [
    {
      name: 'oauth2-server',       // PM2 显示的名字
      script: './.venv/bin/uvicorn', // 虚拟环境里的 uvicorn
      args: 'app.main:app --host 0.0.0.0 --port 8000', // 你的启动参数
      interpreter: 'none',         // 关键：不使用 PM2 默认解释器
      cwd: '/home/zhoudd/www/oauth2-server', // 项目根目录
      exec_mode: 'fork',           // Python 必须用 fork
      instances: 1,
      autorestart: true,           // 崩溃自动重启
      watch: false,                // 不需要热更就关了
      max_memory_restart: '300M',  // 超内存自动重启
      env: {
        NODE_ENV: 'production'
      }
    }
  ]
};