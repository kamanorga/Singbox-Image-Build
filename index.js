const http = require('http');
const fs = require('fs');
const path = require('path');
const exec = require("child_process").exec;
const FILE_PATH = process.env.FILE_PATH || './.npm/sub.txt'
const SUB_PATH = process.env.SUB_PATH || 'sub'; 
const PORT = process.env.PORT || 3000; 

// Run start.sh
fs.chmod("start.sh", 0o777, (err) => {
  if (err) {
      console.error(`start.sh empowerment failed: ${err}`);
      return;
  }
  console.log(`start.sh empowerment successful`);
  const child = exec('bash start.sh');
  child.stdout.on('data', (data) => {
      console.log(data);
  });
  child.stderr.on('data', (data) => {
      console.error(data);
  });
  child.on('close', (code) => {
      console.log(`child process exited with code ${code}`);
      console.clear()
      console.log(`App is running`);
  });
});

// create HTTP server
const server = http.createServer((req, res) => {
    if (req.url === '/') {
      // 检查当前目录下是否有 app.html
      const htmlPath = 'app.html';
      if (fs.existsSync(htmlPath)) {
        // 存在则返回 HTML 文件
        fs.readFile(htmlPath, 'utf8', (err, data) => {
          if (err) {
            console.error(err);
            res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
            res.end('Error reading app.html');
          } else {
            res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
            res.end(data);
          }
        });
      } else {
        // 不存在则显示 Hello world!
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('Hello world!');
      }
    }
    // get-sub
    else if (req.url === `/${SUB_PATH}`) {
      fs.readFile(FILE_PATH, 'utf8', (err, data) => {
        if (err) {
          console.error(err);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Error reading sub.txt' }));
        } else {
          res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end(data);
        }
      });
    }
  });

server.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
