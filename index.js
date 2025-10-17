#!/usr/bin/env node

const express = require("express");
const app = express();
const axios = require("axios");
const os = require('os');
const fs = require("fs");
const path = require("path");
const { promisify } = require('util');
const exec = promisify(require('child_process').exec);
const { execSync } = require('child_process');
const UPLOAD_URL = process.env.UPLOAD_URL || '';
const PROJECT_URL = process.env.PROJECT_URL || '';
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;
const FILE_PATH = process.env.FILE_PATH || './.npm';
const SUB_PATH = process.env.SUB_PATH || 'leaflow';
const KAMAN = process.env.KAMAN || '22d73127-cc6a-4163-8081-2cafd693828c';
const YOUNGHERO_SERVER = process.env.YOUNGHERO_SERVER || 'nzag.faiz.us.kg:8008';
const YOUNGHERO_PORT = process.env.YOUNGHERO_PORT || '';
const YOUNGHERO_KEY = process.env.YOUNGHERO_KEY || 'JgARl5rWKs4k8TTuG1OgFcaxrxsjmpHl'; 
const SUIDAO_DOMAIN = process.env.SUIDAO_DOMAIN || 'leaflow.kaixa.xx.kg';
const SUIDAO_AUTH = process.env.SUIDAO_AUTH || 'eyJhIjoiNmI3MzZhMDhiMzlmNDVlMzE2ZTdlMGNkODE2Yjc2ZDIiLCJ0IjoiOWM5MDU1YmYtODJkNy00NWM0LWI0ZjAtZmY0Y2JiNjBmM2ZiIiwicyI6Ik5qSXdPRGd6WlRZdE4yVTJOaTAwWVdWa0xXSmlOamt0Tm1ReE5qRXlORFk1TkRreCJ9';
const SUIDAO_PORT = process.env.SUIDAO_PORT || 41890;
const TUIC_PORT = process.env.TUIC_PORT || '35560';
const HY2_PORT = process.env.HY2_PORT || '35561';
const REALITY_PORT = process.env.REALITY_PORT || '35562';
const CFIP = process.env.CFIP || 'rpip.kaixa.v6.navy';
const CFPORT = process.env.CFPORT || 443;
const PORT = process.env.PORT || 3000;    
const NAME = process.env.NAME || 'Leaflow';
const CHAT_ID = process.env.CHAT_ID || ''; 
const BOT_TOKEN = process.env.BOT_TOKEN || '';

require('dotenv').config();

if (!fs.existsSync(FILE_PATH)) {
  fs.mkdirSync(FILE_PATH);
  console.log(`${FILE_PATH} is created`);
} else {
  console.log(`${FILE_PATH} already exists`);
}

let privateKey = '';
let publicKey = '';
let npmPath = path.join(FILE_PATH, 'npm');
let phpPath = path.join(FILE_PATH, 'php');
let webPath = path.join(FILE_PATH, 'web');
let botPath = path.join(FILE_PATH, 'bot');
let subPath = path.join(FILE_PATH, 'sub.txt');
let listPath = path.join(FILE_PATH, 'list.txt');
let bootLogPath = path.join(FILE_PATH, 'boot.log');
let configPath = path.join(FILE_PATH, 'config.json');

function deleteNodes() {
  try {
    if (!UPLOAD_URL) return;

    const subPath = path.join(FILE_PATH, 'sub.txt');
    if (!fs.existsSync(subPath)) return;

    let fileContent;
    try {
      fileContent = fs.readFileSync(subPath, 'utf-8');
    } catch {
      return null;
    }

    const decoded = Buffer.from(fileContent, 'base64').toString('utf-8');
    const nodes = decoded.split('\n').filter(line => 
      /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line)
    );

    if (nodes.length === 0) return;

    return axios.post(`${UPLOAD_URL}/api/delete-nodes`, 
      JSON.stringify({ nodes }),
      { headers: { 'Content-Type': 'application/json' } }
    ).catch((error) => { 
      return null; 
    });
  } catch (err) {
    return null;
  }
}

function isValidPort(port) {
  try {
    if (port === null || port === undefined || port === '') return false;
    if (typeof port === 'string' && port.trim() === '') return false;
    
    const portNum = parseInt(port);
    if (isNaN(portNum)) return false;
    if (portNum < 1 || portNum > 65535) return false;
    
    return true;
  } catch (error) {
    return false;
  }
}

const pathsToDelete = [ 'web', 'bot', 'npm', 'boot.log', 'list.txt'];
function cleanupOldFiles() {
  pathsToDelete.forEach(file => {
    const filePath = path.join(FILE_PATH, file);
    fs.unlink(filePath, () => {});
  });
}


app.get("/", function(req, res) {
  const htmlPath = path.join(__dirname, 'app.html');
  if (fs.existsSync(htmlPath)) {
    res.sendFile(htmlPath);
  } else {
    res.send("Hello world!");
  }
});

function getSystemArchitecture() {
  const arch = os.arch();
  if (arch === 'arm' || arch === 'arm64' || arch === 'aarch64') {
    return 'arm';
  } else {
    return 'amd';
  }
}

function downloadFile(fileName, fileUrl, callback) {
  const filePath = path.join(FILE_PATH, fileName);
  const writer = fs.createWriteStream(filePath);

  axios({
    method: 'get',
    url: fileUrl,
    responseType: 'stream',
  })
    .then(response => {
      response.data.pipe(writer);

      writer.on('finish', () => {
        writer.close();
        console.log(`Download ${fileName} successfully`);
        callback(null, fileName);
      });

      writer.on('error', err => {
        fs.unlink(filePath, () => { });
        const errorMessage = `Download ${fileName} failed: ${err.message}`;
        console.error(errorMessage);
        callback(errorMessage);
      });
    })
    .catch(err => {
      const errorMessage = `Download ${fileName} failed: ${err.message}`;
      console.error(errorMessage);
      callback(errorMessage);
    });
}

async function downloadFilesAndRun() {
  const architecture = getSystemArchitecture();
  const filesToDownload = getFilesForArchitecture(architecture);

  if (filesToDownload.length === 0) {
    console.log(`Can't find a file for the current architecture`);
    return;
  }

  const downloadPromises = filesToDownload.map(fileInfo => {
    return new Promise((resolve, reject) => {
      downloadFile(fileInfo.fileName, fileInfo.fileUrl, (err, fileName) => {
        if (err) {
          reject(err);
        } else {
          resolve(fileName);
        }
      });
    });
  });

  try {
    await Promise.all(downloadPromises);
  } catch (err) {
    console.error('Error downloading files:', err);
    return;
  }

  function authorizeFiles(filePaths) {
    const newPermissions = 0o775;
    filePaths.forEach(relativeFilePath => {
      const absoluteFilePath = path.join(FILE_PATH, relativeFilePath);
      if (fs.existsSync(absoluteFilePath)) {
        fs.chmod(absoluteFilePath, newPermissions, (err) => {
          if (err) {
            console.error(`Empowerment failed for ${absoluteFilePath}: ${err}`);
          } else {
            console.log(`Empowerment success for ${absoluteFilePath}: ${newPermissions.toString(8)}`);
          }
        });
      }
    });
  }
  const filesToAuthorize = YOUNGHERO_PORT ? ['./npm', './web', './bot'] : ['./php', './web', './bot'];
  authorizeFiles(filesToAuthorize);

  const port = YOUNGHERO_SERVER.includes(':') ? YOUNGHERO_SERVER.split(':').pop() : '';
  const tlsPorts = new Set(['443', '8443', '2096', '2087', '2083', '2053']);
  const youngherotls = tlsPorts.has(port) ? 'tls' : 'false';

  if (YOUNGHERO_SERVER && YOUNGHERO_KEY) {
    if (!YOUNGHERO_PORT) {
      const configYaml = `
client_secret: ${YOUNGHERO_KEY}
debug: false
disable_auto_update: true
disable_command_execute: false
disable_force_update: true
disable_nat: false
disable_send_query: false
gpu: false
insecure_tls: false
ip_report_period: 1800
report_delay: 4
server: ${YOUNGHERO_SERVER}
skip_connection_count: false
skip_procs_count: false
temperature: false
tls: ${youngherotls}
use_gitee_to_upgrade: false
use_ipv6_country_code: false
uuid: ${KAMAN}`;
      
      fs.writeFileSync(path.join(FILE_PATH, 'config.yaml'), configYaml);
    }
  }
  
  const keyFilePath = path.join(FILE_PATH, 'key.txt');

  if (fs.existsSync(keyFilePath)) {
    const content = fs.readFileSync(keyFilePath, 'utf8');
    const privateKeyMatch = content.match(/PrivateKey:\s*(.*)/);
    const publicKeyMatch = content.match(/PublicKey:\s*(.*)/);
  
    privateKey = privateKeyMatch ? privateKeyMatch[1] : '';
    publicKey = publicKeyMatch ? publicKeyMatch[1] : '';
  
    if (!privateKey || !publicKey) {
      console.error('Failed to extract privateKey or publicKey from key.txt.');
      return;
    }
  
    console.log('Private Key:', privateKey);
    console.log('Public Key:', publicKey);

    continueExecution();
  } else {
    exec(`${path.join(FILE_PATH, 'web')} generate reality-keypair`, async (err, stdout, stderr) => {
      if (err) {
        console.error(`Error generating reality-keypair: ${err.message}`);
        return;
      }
    
      const privateKeyMatch = stdout.match(/PrivateKey:\s*(.*)/);
      const publicKeyMatch = stdout.match(/PublicKey:\s*(.*)/);
    
      privateKey = privateKeyMatch ? privateKeyMatch[1] : '';
      publicKey = publicKeyMatch ? publicKeyMatch[1] : '';
    
      if (!privateKey || !publicKey) {
        console.error('Failed to extract privateKey or publicKey from output.');
        return;
      }
    
      // Save keys to key.txt
      fs.writeFileSync(keyFilePath, `PrivateKey: ${privateKey}\nPublicKey: ${publicKey}\n`, 'utf8');
    
      console.log('Private Key:', privateKey);
      console.log('Public Key:', publicKey);

      continueExecution();
    });
  }

  function continueExecution() {

    exec('openssl ecparam -genkey -name prime256v1 -out "private.key"', (err, stdout, stderr) => {
      if (err) {
        console.error(`Error generating private.key: ${err.message}`);
        return;
      }
    // console.log('private.key has been generated successfully.');

      exec('openssl req -new -x509 -days 3650 -key "private.key" -out "cert.pem" -subj "/CN=bing.com"', async (err, stdout, stderr) => {
        if (err) {
          console.error(`Error generating cert.pem: ${err.message}`);
          return;
        }
      // console.log('cert.pem has been generated successfully.');

        if (!privateKey || !publicKey) {
          console.error('PrivateKey or PublicKey is missing, retrying...');
          return;
        }

        const config = {
          "log": {
            "disabled": true,
            "level": "info",
            "timestamp": true
          },
          "dns": {
            "servers": [
              {
                "address": "8.8.8.8",
                "address_resolver": "local"
              },
              {
                "tag": "local",
                "address": "local"
              }
            ]
          },
          "inbounds": [
            {
              "tag": "vmess-ws-in",
              "type": "vmess",
              "listen": "::",
              "listen_port": SUIDAO_PORT,
              "users": [
                {
                  "uuid": KAMAN
                }
              ],
              "transport": {
                "type": "ws",
                "path": "/vmess-suidao",
                "early_data_header_name": "Sec-WebSocket-Protocol"
              }
            }
          ],
          "outbounds": [
            {
              "type": "direct",
              "tag": "direct"
            },
            {
              "type": "block",
              "tag": "block"
            },
            {
              "type": "wireguard",
              "tag": "wireguard-out",
              "server": "engage.cloudflareclient.com",
              "server_port": 2408,
              "local_address": [
                "172.16.0.2/32",
                "2606:4700:110:851f:4da3:4e2c:cdbf:2ecf/128"
              ],
              "private_key": "eAx8o6MJrH4KE7ivPFFCa4qvYw5nJsYHCBQXPApQX1A=",
              "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
              "reserved": [82, 90, 51],
              "mtu": 1420
            }
          ],
          "route": {
            "rule_set": [
              {
                "tag": "netflix",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/netflix.srs",
                "download_detour": "direct"
              },
              {
                "tag": "openai",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/openai.srs",
                "download_detour": "direct"
              }
            ],
            "rules": [
              {
                "rule_set": ["openai", "netflix"],
                "outbound": "wireguard-out"
              }
            ],
            "final": "direct"
          }
        };

        try {
          if (isValidPort(REALITY_PORT)) {
            config.inbounds.push({
              "tag": "vless-in",
              "type": "vless",
              "listen": "::",
              "listen_port": parseInt(REALITY_PORT),
              "users": [
                {
                  "uuid": KAMAN,
                  "flow": "xtls-rprx-vision"
                }
              ],
              "tls": {
                "enabled": true,
                "server_name": "www.iij.ad.jp",
                "reality": {
                  "enabled": true,
                  "handshake": {
                    "server": "www.iij.ad.jp",
                    "server_port": 443
                  },
                  "private_key": privateKey, 
                  "short_id": [""]
                }
              }
            });
          }
        } catch (error) {
        }

        try {
          if (isValidPort(HY2_PORT)) {
            config.inbounds.push({
              "tag": "hysteria-in",
              "type": "hysteria2",
              "listen": "::",
              "listen_port": parseInt(HY2_PORT),
              "users": [
                {
                  "password": KAMAN
                }
              ],
              "masquerade": "https://bing.com",
              "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": "cert.pem",
                "key_path": "private.key"
              }
            });
          }
        } catch (error) {
        }

        try {
          if (isValidPort(TUIC_PORT)) {
            config.inbounds.push({
              "tag": "tuic-in",
              "type": "tuic",
              "listen": "::",
              "listen_port": parseInt(TUIC_PORT),
              "users": [
                {
                  "uuid": KAMAN
                }
              ],
              "congestion_control": "bbr",
              "tls": {
                "enabled": true,
                "alpn": ["h3"],
                "certificate_path": "cert.pem",
                "key_path": "private.key"
              }
            });
          }
        } catch (error) {
        }

        try {
          let youtubeTest = '';
          let isYouTubeAccessible = false;
          
          try {
            youtubeTest = execSync('curl -o /dev/null -m 2 -s -w "%{http_code}" https://www.youtube.com', { encoding: 'utf8' }).trim();
            isYouTubeAccessible = youtubeTest === '200';
            // console.log(`YouTube status code: ${youtubeTest}, accessable: ${isYouTubeAccessible}`);
          } catch (curlError) {
            if (curlError.output && curlError.output[1]) {
              youtubeTest = curlError.output[1].toString().trim();
              isYouTubeAccessible = youtubeTest === '200';
            } else {
              youtubeTest = '000';
              isYouTubeAccessible = false;
              // console.log('YouTube check failed, assuming YouTube is inaccessible');
            }
          }
          
          if (!isYouTubeAccessible) {
            console.log('YouTube cannot be accessed, adding outbound rules...');
            
            if (!config.route) {
              config.route = {};
            }
            if (!config.route.rule_set) {
              config.route.rule_set = [];
            }
            if (!config.route.rules) {
              config.route.rules = [];
            }
            
            const existingYoutubeRule = config.route.rule_set.find(rule => rule.tag === 'youtube');
            if (!existingYoutubeRule) {
              config.route.rule_set.push({
                "tag": "youtube",
                "type": "remote",
                "format": "binary",
                "url": "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/sing/geo/geosite/youtube.srs",
                "download_detour": "direct"
              });
              console.log('已添加YouTube规则集');
            }
            
            let wireguardRule = config.route.rules.find(rule => rule.outbound === 'wireguard-out');
            if (!wireguardRule) {
              wireguardRule = {
                "rule_set": ["openai", "netflix", "youtube"],
                "outbound": "wireguard-out"
              };
              config.route.rules.push(wireguardRule);
              // console.log('Add new wireguard-out rule');
            } else {
              if (!wireguardRule.rule_set.includes('youtube')) {
                wireguardRule.rule_set.push('youtube');
                //console.log('youtube outbound rule already exists');
              }
            }
            
            console.log('Add YouTube outbound rule');
          } else {
            // console.log('YouTube is accessible, no needs to add outbound rule');
          }
        } catch (error) {
          console.error('YouTube check error:', error);
          // ignore YouTube check error, continue running
        }


        fs.writeFileSync(path.join(FILE_PATH, 'config.json'), JSON.stringify(config, null, 2));

        let YOUNGHERO_TLS = '';
        if (YOUNGHERO_SERVER && YOUNGHERO_PORT && YOUNGHERO_KEY) {
          const tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
          if (tlsPorts.includes(YOUNGHERO_PORT)) {
            YOUNGHERO_TLS = '--tls';
          } else {
            YOUNGHERO_TLS = '';
          }
          const command = `nohup ${path.join(FILE_PATH, 'npm')} -s ${YOUNGHERO_SERVER}:${YOUNGHERO_PORT} -p ${YOUNGHERO_KEY} ${YOUNGHERO_TLS} >/dev/null 2>&1 &`;
          try {
            await execPromise(command);
            console.log('npm is running');
            await new Promise((resolve) => setTimeout(resolve, 1000));
          } catch (error) {
            console.error(`npm running error: ${error}`);
          }
        } else if (YOUNGHERO_SERVER && YOUNGHERO_KEY) {
            const command = `nohup ${FILE_PATH}/php -c "${FILE_PATH}/config.yaml" >/dev/null 2>&1 &`;
            try {
              await exec(command);
              console.log('php is running');
              await new Promise((resolve) => setTimeout(resolve, 1000));
            } catch (error) {
              console.error(`php running error: ${error}`);
            }
        } else {
          console.log('YOUNGHERO variable is empty, skipping running');
        }

        const command1 = `nohup ${path.join(FILE_PATH, 'web')} run -c ${path.join(FILE_PATH, 'config.json')} >/dev/null 2>&1 &`;
        try {
          await execPromise(command1);
          console.log('web is running');
          await new Promise((resolve) => setTimeout(resolve, 1000));
        } catch (error) {
          console.error(`web running error: ${error}`);
        }

        if (fs.existsSync(path.join(FILE_PATH, 'bot'))) {
          let args;

          if (SUIDAO_AUTH.match(/^[A-Z0-9a-z=]{120,250}$/)) {
            args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 run --token ${SUIDAO_AUTH}`;
          } else if (SUIDAO_AUTH.match(/TunnelSecret/)) {
            args = `tunnel --edge-ip-version auto --config ${path.join(FILE_PATH, 'tunnel.yml')} run`;
          } else {
            args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${path.join(FILE_PATH, 'boot.log')} --loglevel info --url http://localhost:${SUIDAO_PORT}`;
          }

          try {
            await execPromise(`nohup ${path.join(FILE_PATH, 'bot')} ${args} >/dev/null 2>&1 &`);
            console.log('bot is running');
            await new Promise((resolve) => setTimeout(resolve, 2000));
          } catch (error) {
            console.error(`Error executing command: ${error}`);
          }
        }
        await new Promise((resolve) => setTimeout(resolve, 5000));

        await extractDomains();
      });
    });
  }
}

function execPromise(command) {
  return new Promise((resolve, reject) => {
    exec(command, (error, stdout, stderr) => {
      if (error) {
        reject(error);
      } else {
        resolve(stdout || stderr);
      }
    });
  });
}

function getFilesForArchitecture(architecture) {
  let baseFiles;
  if (architecture === 'arm') {
    baseFiles = [
      { fileName: "web", fileUrl: "https://arm64.ssss.nyc.mn/sb" },
      { fileName: "bot", fileUrl: "https://arm64.ssss.nyc.mn/2go" }
    ];
  } else {
    baseFiles = [
      { fileName: "web", fileUrl: "https://amd64.ssss.nyc.mn/sb" },
      { fileName: "bot", fileUrl: "https://amd64.ssss.nyc.mn/2go" }
    ];
  }

  if (YOUNGHERO_SERVER && YOUNGHERO_KEY) {
    if (YOUNGHERO_PORT) {
      const npmUrl = architecture === 'arm' 
        ? "https://arm64.ssss.nyc.mn/agent"
        : "https://amd64.ssss.nyc.mn/agent";
        baseFiles.unshift({ 
          fileName: "npm", 
          fileUrl: npmUrl 
        });
    } else {
      const phpUrl = architecture === 'arm' 
        ? "https://arm64.ssss.nyc.mn/v1" 
        : "https://amd64.ssss.nyc.mn/v1";
      baseFiles.unshift({ 
        fileName: "php", 
        fileUrl: phpUrl
      });
    }
  }

  return baseFiles;
}

function suidaoType() {
  if (!SUIDAO_AUTH || !SUIDAO_DOMAIN) {
    console.log("SUIDAO_DOMAIN or SUIDAO_AUTH variable is empty, use quick tunnels");
    return;
  }

  if (SUIDAO_AUTH.includes('TunnelSecret')) {
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.json'), SUIDAO_AUTH);
    const tunnelYaml = `
  tunnel: ${SUIDAO_AUTH.split('"')[11]}
  credentials-file: ${path.join(FILE_PATH, 'tunnel.json')}
  protocol: http2
  
  ingress:
    - hostname: ${SUIDAO_DOMAIN}
      service: http://localhost:${SUIDAO_PORT}
      originRequest:
        noTLSVerify: true
    - service: http_status:404
  `;
    fs.writeFileSync(path.join(FILE_PATH, 'tunnel.yml'), tunnelYaml);
  } else {
    console.log("SUIDAO_AUTH mismatch TunnelSecret,use token connect to tunnel");
  }
}
suidaoType();

async function extractDomains() {
  let suidaoDomain;

  if (SUIDAO_AUTH && SUIDAO_DOMAIN) {
    suidaoDomain = SUIDAO_DOMAIN;
    console.log('SUIDAO_DOMAIN:', suidaoDomain);
    await generateLinks(suidaoDomain);
  } else {
    try {
      const fileContent = fs.readFileSync(path.join(FILE_PATH, 'boot.log'), 'utf-8');
      const lines = fileContent.split('\n');
      const suidaoDomains = [];
      lines.forEach((line) => {
        const domainMatch = line.match(/https?:\/\/([^ ]*trycloudflare\.com)\/?/);
        if (domainMatch) {
          const domain = domainMatch[1];
          suidaoDomains.push(domain);
        }
      });

      if (suidaoDomains.length > 0) {
        suidaoDomain = suidaoDomains[0];
        console.log('SuidaoDomain:', suidaoDomain);
        await generateLinks(suidaoDomain);
      } else {
        console.log('SuidaoDomain not found, re-running bot to obtain SuidaoDomain');
          fs.unlinkSync(path.join(FILE_PATH, 'boot.log'));
          async function killBotProcess() {
            try {
              await exec('pkill -f "[b]ot" > /dev/null 2>&1');
            } catch (error) {
                return null;
            }
          }
          killBotProcess();
          await new Promise((resolve) => setTimeout(resolve, 1000));
          const args = `tunnel --edge-ip-version auto --no-autoupdate --protocol http2 --logfile ${FILE_PATH}/boot.log --loglevel info --url http://localhost:${SUIDAO_PORT}`;
          try {
            await exec(`nohup ${path.join(FILE_PATH, 'bot')} ${args} >/dev/null 2>&1 &`);
            console.log('bot is running.');
            await new Promise((resolve) => setTimeout(resolve, 6000));
            await extractDomains();
          } catch (error) {
            console.error(`Error executing command: ${error}`);
          }
        }
      } catch (error) {
        console.error('Error reading boot.log:', error);
      }
    }
  
  async function generateLinks(suidaoDomain) {
    let SERVER_IP = '';
    try {
      SERVER_IP = execSync('curl -s --max-time 2 ipv4.ip.sb').toString().trim();
    } catch (err) {
      try {
        SERVER_IP = `[${execSync('curl -s --max-time 1 ipv6.ip.sb').toString().trim()}]`;
      } catch (ipv6Err) {
        console.error('Failed to get IP address:', ipv6Err.message);
      }
    }

    const metaInfo = execSync(
      'curl -s https://speed.cloudflare.com/meta | awk -F\\" \'{print $26"-"$18}\' | sed -e \'s/ /_/g\'',
      { encoding: 'utf-8' }
    );
    const ISP = metaInfo.trim();

    return new Promise((resolve) => {
      setTimeout(() => {
        const vmessNode = `vmess://${Buffer.from(JSON.stringify({ v: '2', ps: `${NAME}-${ISP}`, add: CFIP, port: CFPORT, id: KAMAN, aid: '0', scy: 'none', net: 'ws', type: 'none', host: suidaoDomain, path: '/vmess-suidao?ed=2048', tls: 'tls', sni: suidaoDomain, alpn: '' })).toString('base64')}`;

        let subTxt = vmessNode;

        if (isValidPort(TUIC_PORT)) {
          const tuicNode = `\ntuic://${KAMAN}:@${SERVER_IP}:${TUIC_PORT}?sni=www.bing.com&congestion_control=bbr&udp_relay_mode=native&alpn=h3&allow_insecure=1#${NAME}-${ISP}`;
          subTxt += tuicNode;
        }

        if (isValidPort(HY2_PORT)) {
          const hysteriaNode = `\nhysteria2://${KAMAN}@${SERVER_IP}:${HY2_PORT}/?sni=www.bing.com&insecure=1&alpn=h3&obfs=none#${NAME}-${ISP}`;
          subTxt += hysteriaNode;
        }

        if (isValidPort(REALITY_PORT)) {
          const vlessNode = `\nvless://${KAMAN}@${SERVER_IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.iij.ad.jp&fp=chrome&pbk=${publicKey}&type=tcp&headerType=none#${NAME}-${ISP}`;
          subTxt += vlessNode;
        }

        console.log(Buffer.from(subTxt).toString('base64')); 
        fs.writeFileSync(subPath, Buffer.from(subTxt).toString('base64'));
        fs.writeFileSync(listPath, subTxt, 'utf8');
        console.log(`${FILE_PATH}/sub.txt saved successfully`);
        sendTelegram();
        uplodNodes();
        app.get(`/${SUB_PATH}`, (req, res) => {
          const encodedContent = Buffer.from(subTxt).toString('base64');
          res.set('Content-Type', 'text/plain; charset=utf-8');
          res.send(encodedContent);
        });
        resolve(subTxt);
      }, 2000);
    });
  }
}
  
function cleanFiles() {
  setTimeout(() => {
    const filesToDelete = [bootLogPath, configPath, listPath, webPath, botPath, phpPath, npmPath];  
    
    if (YOUNGHERO_PORT) {
      filesToDelete.push(npmPath);
    } else if (YOUNGHERO_SERVER && YOUNGHERO_KEY) {
      filesToDelete.push(phpPath);
    }

    exec(`rm -rf ${filesToDelete.join(' ')} >/dev/null 2>&1`, (error) => {
      console.clear();
      console.log('App is running');
      console.log('Thank you for using this script, enjoy!');
    });
  }, 90000); // 90s
}

async function sendTelegram() {
  if (!BOT_TOKEN || !CHAT_ID) {
      console.log('TG variables is empty,Skipping push nodes to TG');
      return;
  }
  try {
      const message = fs.readFileSync(path.join(FILE_PATH, 'sub.txt'), 'utf8');
      const url = `https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`;
      
      const escapedName = NAME.replace(/[_*[\]()~`>#+=|{}.!-]/g, '\\$&');
      
      const params = {
          chat_id: CHAT_ID,
          text: `**${escapedName}节点推送通知**\n\`\`\`${message}\`\`\``,
          parse_mode: 'MarkdownV2'
      };

      await axios.post(url, null, { params });
      console.log('Telegram message sent successfully');
  } catch (error) {
      console.error('Failed to send Telegram message', error);
  }
}

async function uplodNodes() {
  if (UPLOAD_URL && PROJECT_URL) {
    const subscriptionUrl = `${PROJECT_URL}/${SUB_PATH}`;
    const jsonData = {
      subscription: [subscriptionUrl]
    };
    try {
        const response = await axios.post(`${UPLOAD_URL}/api/add-subscriptions`, jsonData, {
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (response.status === 200) {
            console.log('Subscription uploaded successfully');
        } else {
          return null;
          //  console.log('Unknown response status');
        }
    } catch (error) {
        if (error.response) {
            if (error.response.status === 400) {
              //  console.error('Subscription already exists');
            }
        }
    }
  } else if (UPLOAD_URL) {
      if (!fs.existsSync(listPath)) return;
      const content = fs.readFileSync(listPath, 'utf-8');
      const nodes = content.split('\n').filter(line => /(vless|vmess|trojan|hysteria2|tuic):\/\//.test(line));

      if (nodes.length === 0) return;

      const jsonData = JSON.stringify({ nodes });

      try {
          await axios.post(`${UPLOAD_URL}/api/add-nodes`, jsonData, {
              headers: { 'Content-Type': 'application/json' }
          });
          if (response.status === 200) {
            console.log('Subscription uploaded successfully');
        } else {
            return null;
        }
      } catch (error) {
          return null;
      }
  } else {
      // console.log('Skipping upload nodes');
      return;
  }
}

async function AddVisitTask() {
  if (!AUTO_ACCESS || !PROJECT_URL) {
    console.log("Skipping adding automatic access task");
    return;
  }

  try {
    const response = await axios.post('https://keep.gvrander.eu.org/add-url', {
      url: PROJECT_URL
    }, {
      headers: {
        'Content-Type': 'application/json'
      }
    });
    // console.log(`${JSON.stringify(response.data)}`);
    console.log('automatic access task added successfully');
  } catch (error) {
    console.error(`添加URL失败: ${error.message}`);
  }
}

async function startserver() {
  deleteNodes();
  cleanupOldFiles();
  await downloadFilesAndRun();
  AddVisitTask();
  cleanFiles();
}
startserver();
  
app.listen(PORT, () => console.log(`server is running on port:${PORT}!`));
