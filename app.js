(() => {
    const inputEl = document.getElementById('input');
    const outputEl = document.getElementById('output');
    const errorsEl = document.getElementById('errors');
    const nodesInputEl = document.getElementById('nodesInput');
    const nodeListEl = document.getElementById('nodeList');
    const nodePreviewEl = document.getElementById('nodePreview');
    const nodeStatusEl = document.getElementById('nodeStatus');
    const applySelectedBtn = document.getElementById('applySelected');
    const selectAllNodesBtn = document.getElementById('selectAllNodes');
    const clearNodesBtn = document.getElementById('clearNodes');

    const nodeStore = [];
    const nodeFingerprints = new Set();
    const selectedNames = new Set();
    let lastConverted = [];

    document.getElementById('convert').addEventListener('click', () => {
      const { proxies, errors } = parseLinks(inputEl.value);
      lastConverted = proxies;
      if (proxies.length) {
        addProxiesToLibrary(proxies);
      }
      outputEl.value = proxies.length ? dumpYaml({ proxies }) : '';
      errorsEl.textContent = errors.length ? errors.join('\n') : '暂无错误。';
    });

    document.getElementById('clear').addEventListener('click', () => {
      inputEl.value = '';
      outputEl.value = '';
      errorsEl.textContent = '暂无错误。';
    });

    document.getElementById('copy').addEventListener('click', async () => {
      if (!outputEl.value) return;
      try {
        await navigator.clipboard.writeText(outputEl.value);
        errorsEl.textContent = '已复制到剪贴板。';
      } catch {
        errorsEl.textContent = '复制失败，请手动复制。';
      }
    });

    document.getElementById('example').addEventListener('click', () => {
      inputEl.value = [
        'vmess://eyJ2IjoiMiIsInBzIjoiVm1lc3MtV1MiLCJhZGQiOiJ2bWVzcy5leGFtcGxlLmNvbSIsInBvcnQiOiI0NDMiLCJpZCI6IjA2ODNlOTNlLTUyYjktNGJiNy1hM2U4LTMwZmMxOGVhNmM0MSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0Ijoid3MiLCJ0bHMiOiJ0bHMiLCJob3N0Ijoid3MuZXhhbXBsZS5jb20iLCJwYXRoIjoiL2NoYXQifQ==',
        'vless://2a1d8f2f-4ae3-4c41-9e31-6edb1d9c4a47@vless.example.com:443?security=reality&encryption=none&flow=xtls-rprx-vision&pbk=publicKeyHere&sid=abcd1234&fp=chrome#VLESS-REALITY',
        'trojan://password@trojan.example.com:443?type=grpc&serviceName=gun&alpn=h2,http/1.1#Trojan-GRPC',
        'ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ=@ss.example.com:8388#SS',
        'hy2://mypassword@hy2.example.com:443?insecure=1&sni=hy2.example.com&obfs=salamander&obfs-password=obfs#HY2',
        'tuic://00000000-0000-0000-0000-000000000001:pass@tuic.example.com:443?alpn=h3&udp_relay_mode=native#TUIC',
        'anytls://password@anytls.example.com:443?peer=anytls.example.com&udp=1&alpn=h2,http/1.1#AnyTLS'
      ].join('\n');
    });

    const toConfigBtn = document.getElementById('toConfig');
    if (toConfigBtn) {
      toConfigBtn.addEventListener('click', () => {
        let nodes = lastConverted;
        if (!nodes.length && outputEl.value.trim()) {
          const parsed = parseNodesFromText(outputEl.value);
          if (parsed.error) {
            errorsEl.textContent = parsed.error;
            return;
          }
          nodes = parsed.nodes;
        }
        if (!nodes.length) {
          errorsEl.textContent = '请先转换节点。';
          return;
        }
        const merged = mergeNodesIntoInput(nodes);
        if (merged) {
          errorsEl.textContent = '已加入分流配置。';
          const builderSection = document.getElementById('builder');
          if (builderSection) {
            builderSection.scrollIntoView({ behavior: 'smooth' });
          }
        }
      });
    }

    if (applySelectedBtn) {
      applySelectedBtn.addEventListener('click', () => {
        const selected = getSelectedNodes();
        if (!selected.length) {
          setNodeStatus('请先选择节点。', true);
          return;
        }
        mergeNodesIntoInput(selected);
      });
    }

    if (selectAllNodesBtn) {
      selectAllNodesBtn.addEventListener('click', () => {
        nodeStore.forEach((node) => selectedNames.add(node.name));
        renderNodeList();
      });
    }

    if (clearNodesBtn) {
      clearNodesBtn.addEventListener('click', () => {
        selectedNames.clear();
        renderNodeList();
        setNodeStatus('已清空选择。', false);
      });
    }

    function setNodeStatus(message, isError) {
      if (!nodeStatusEl) return;
      nodeStatusEl.textContent = message || '';
      nodeStatusEl.className = isError ? 'status-lite error' : 'status-lite';
    }

    function addProxiesToLibrary(proxies) {
      if (!nodeListEl || !Array.isArray(proxies)) return;
      const nameSet = new Set(nodeStore.map((node) => node.name));
      let added = 0;
      let skipped = 0;
      let lastAdded = null;

      proxies.forEach((proxy) => {
        if (!proxy) return;
        const fingerprint = JSON.stringify(proxy);
        if (nodeFingerprints.has(fingerprint)) {
          skipped += 1;
          return;
        }
        nodeFingerprints.add(fingerprint);

        const baseName = String(proxy.name || proxy.type || 'node').trim() || 'node';
        const uniqueName = ensureUniqueName(baseName, nameSet);
        const stored = { ...proxy, name: uniqueName };
        nodeStore.push(stored);
        nameSet.add(uniqueName);
        selectedNames.add(uniqueName);
        lastAdded = stored;
        added += 1;
      });

      renderNodeList();
      if (lastAdded) {
        setPreview(lastAdded);
      }
      if (added || skipped) {
        const message = skipped
          ? `已加入 ${added} 个节点，跳过 ${skipped} 个重复节点。`
          : `已加入 ${added} 个节点。`;
        setNodeStatus(message, false);
      }
    }

    function renderNodeList() {
      if (!nodeListEl) return;
      nodeListEl.innerHTML = '';

      if (!nodeStore.length) {
        const empty = document.createElement('div');
        empty.className = 'meta';
        empty.textContent = '暂无节点，请先在上方转换链接。';
        nodeListEl.appendChild(empty);
        if (nodePreviewEl) {
          nodePreviewEl.value = '';
        }
        return;
      }

      nodeStore.forEach((node) => {
        const card = document.createElement('label');
        card.className = 'node-card';
        card.dataset.name = node.name;

        const checkbox = document.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.checked = selectedNames.has(node.name);

        const body = document.createElement('div');
        body.className = 'node-body';

        const name = document.createElement('div');
        name.className = 'node-name';
        name.textContent = node.name || '未命名节点';

        const meta = document.createElement('div');
        meta.className = 'node-meta';
        const metaParts = [node.type, node.server, node.port].filter(Boolean);
        meta.textContent = metaParts.join(' · ');

        body.appendChild(name);
        body.appendChild(meta);

        card.appendChild(checkbox);
        card.appendChild(body);

        const syncCard = () => {
          card.classList.toggle('selected', checkbox.checked);
        };

        checkbox.addEventListener('change', () => {
          if (checkbox.checked) {
            selectedNames.add(node.name);
          } else {
            selectedNames.delete(node.name);
          }
          syncCard();
          setPreview(node);
        });

        syncCard();
        nodeListEl.appendChild(card);
      });
    }

    function setPreview(node) {
      if (!nodePreviewEl || !node) return;
      nodePreviewEl.value = dumpYaml({ proxies: [node] });
    }

    function getSelectedNodes() {
      return nodeStore.filter((node) => selectedNames.has(node.name));
    }

    function mergeNodesIntoInput(newNodes) {
      if (!nodesInputEl) {
        setNodeStatus('未找到节点输入区域。', true);
        return false;
      }
      const existingResult = parseNodesFromText(nodesInputEl.value);
      if (existingResult.error) {
        setNodeStatus(existingResult.error, true);
        return false;
      }
      const baseNodes = stripSampleNodes(existingResult.nodes);
      const merged = mergeUniqueNodes(baseNodes, newNodes);
      nodesInputEl.value = dumpYaml({ proxies: merged });
      nodesInputEl.dispatchEvent(new Event('input', { bubbles: true }));
      setNodeStatus(`已加入 ${newNodes.length} 个节点。`, false);
      return true;
    }

    function stripSampleNodes(nodes) {
      if (!Array.isArray(nodes)) return [];
      return nodes.filter((node) => {
        if (!node || !node.name) return false;
        return !String(node.name).startsWith('示例-');
      });
    }

    function mergeUniqueNodes(existingNodes, incomingNodes) {
      const merged = Array.isArray(existingNodes) ? [...existingNodes] : [];
      const nameSet = new Set(merged.map((node) => node && node.name).filter(Boolean));

      incomingNodes.forEach((node) => {
        if (!node) return;
        const baseName = String(node.name || node.type || 'node').trim() || 'node';
        const uniqueName = ensureUniqueName(baseName, nameSet);
        const stored = { ...node, name: uniqueName };
        merged.push(stored);
        nameSet.add(uniqueName);
      });

      return merged;
    }

    function ensureUniqueName(baseName, nameSet) {
      let name = baseName;
      let index = 2;
      while (nameSet.has(name)) {
        name = `${baseName}-${index}`;
        index += 1;
      }
      return name;
    }

    function parseNodesFromText(text) {
      const raw = text.trim();
      if (!raw) return { nodes: [] };

      let parsed;
      let parsedAsJson = false;

      try {
        parsed = JSON.parse(raw);
        parsedAsJson = true;
      } catch {
        if (window.jsyaml && typeof window.jsyaml.load === 'function') {
          try {
            parsed = window.jsyaml.load(raw);
          } catch {
            return { error: 'YAML 解析失败，请检查格式。' };
          }
        } else {
          return { error: 'YAML 解析库未加载，请检查网络或改用 JSON。' };
        }
      }

      if (parsedAsJson && typeof parsed === 'string') {
        return { error: '检测到字符串，请输入对象或数组。' };
      }

      const nodes = resolveNodesFromParsed(parsed);
      if (!nodes.length) {
        return { error: '未找到节点，请确认输入包含 proxies 数组。' };
      }

      const missingNames = nodes.filter((node) => !node || !node.name);
      if (missingNames.length) {
        return { error: '每个节点都必须包含 name 字段。' };
      }

      return { nodes: normalizeAnyTlsNodes(nodes) };
    }

    function resolveNodesFromParsed(parsed) {
      if (Array.isArray(parsed)) return parsed;
      if (Array.isArray(parsed?.proxies)) return parsed.proxies;
      if (Array.isArray(parsed?.nodes)) return parsed.nodes;
      if (parsed && typeof parsed === 'object' && parsed.name) return [parsed];
      return [];
    }

    function normalizeAnyTlsNodes(nodes) {
      return nodes.map((node) => {
        if (!node || typeof node !== 'object') return node;
        if (String(node.type || '').toLowerCase() !== 'anytls') return node;
        if (node['skip-cert-verify'] !== undefined) return node;
        return { ...node, 'skip-cert-verify': true };
      });
    }

    renderNodeList();

    function parseLinks(text) {
      const lines = text.split(/\r?\n/)
        .map(l => normalizeLink(l.trim()))
        .filter(l => l && !l.startsWith('#') && !l.startsWith('//'));
      const proxies = [];
      const errors = [];

      for (const line of lines) {
        try {
          const lower = line.toLowerCase();
          let proxy = null;
          if (lower.startsWith('vmess://')) proxy = parseVmess(line);
          else if (lower.startsWith('vless://')) proxy = parseVless(line);
          else if (lower.startsWith('trojan://')) proxy = parseTrojan(line);
          else if (lower.startsWith('ss://')) proxy = parseSS(line);
          else if (lower.startsWith('hysteria2://') || lower.startsWith('hy2://')) proxy = parseHy2(line);
          else if (lower.startsWith('hysteria://')) proxy = parseHy1(line);
          else if (lower.startsWith('tuic://')) proxy = parseTuic(line);
          else if (lower.startsWith('anytls://')) proxy = parseAnyTLS(line);
          else if (lower.startsWith('socks5://') || lower.startsWith('socks://')) proxy = parseSocks(line);
          else if (lower.startsWith('http://') || lower.startsWith('https://')) proxy = parseHttp(line);
          else throw new Error('Unsupported scheme');

          if (!proxy) throw new Error('Parse failed');
          proxies.push(proxy);
        } catch (err) {
          errors.push(`Failed: ${line} -> ${err.message}`);
        }
      }

      return { proxies, errors };
    }

    function normalizeLink(line) {
      if (!line) return line;
      return line.replace(/？/g, '?').replace(/＆/g, '&');
    }

    function parseVmess(link) {
      const payload = link.slice('vmess://'.length);
      const json = safeJsonDecode(payload);
      if (!json || !json.add || !json.port || !json.id) throw new Error('Invalid vmess payload');

      const proxy = {
        name: json.ps || 'vmess',
        type: 'vmess',
        server: json.add,
        port: toNumber(json.port),
        uuid: json.id,
        alterId: toNumber(json.aid || 0),
        cipher: json.scy || 'auto'
      };

      if (json['packet-encoding'] !== undefined) proxy['packet-encoding'] = json['packet-encoding'];
      else if (json.packetEncoding !== undefined) proxy['packet-encoding'] = json.packetEncoding;

      if (json['global-padding'] !== undefined) proxy['global-padding'] = json['global-padding'];
      else if (json.globalPadding !== undefined) proxy['global-padding'] = json.globalPadding;

      if (json['authenticated-length'] !== undefined) proxy['authenticated-length'] = json['authenticated-length'];
      else if (json.authenticatedLength !== undefined) proxy['authenticated-length'] = json.authenticatedLength;

      if (json.udp !== undefined) proxy.udp = isTrue(json.udp);

      const pbk = json.pbk || json.publicKey || json['public-key'];
      const sid = json.sid || json.shortid || json['short-id'];
      const supportX25519 = json['support-x25519mlkem768'];
      if (pbk || sid || supportX25519 !== undefined) {
        const reality = {};
        if (pbk) reality['public-key'] = pbk;
        if (sid) reality['short-id'] = sid;
        if (supportX25519 !== undefined) reality['support-x25519mlkem768'] = isTrue(supportX25519);
        if (Object.keys(reality).length) proxy['reality-opts'] = reality;
        proxy.tls = true;
      }

      const networkRaw = json.net || json.network;
      const network = normalizeNetwork(networkRaw);
      applyNetwork(proxy, network, {
        host: json.host,
        path: json.path,
        alpn: json.alpn,
        sni: json.sni,
        fp: json.fp,
        fingerprint: json.fingerprint,
        tls: json.tls,
        allowInsecure: json.allowInsecure || json['skip-cert-verify'],
        ed: json.ed,
        eh: json.eh
      }, true, networkRaw !== undefined && networkRaw !== '');

      return proxy;
    }

    function parseVless(link) {
      const url = new URL(link);
      const params = collectParams(url.searchParams);
      const uuid = decodeURIComponent(url.username || '');
      if (!uuid) throw new Error('Missing uuid');

      const proxy = {
        name: decodeName(url.hash) || params.name || 'vless',
        type: 'vless',
        server: url.hostname,
        port: toNumber(url.port || '0'),
        uuid
      };

      const flow = pick(params, 'flow');
      if (flow) proxy.flow = flow;

      const encryption = pick(params, 'encryption');
      if (encryption !== undefined) proxy.encryption = encryption;

      const packetEncoding = pick(params, 'packet-encoding', 'packetEncoding');
      if (packetEncoding) proxy['packet-encoding'] = packetEncoding;

      const security = pick(params, 'security');
      const tlsEnabled = security === 'tls' || security === 'reality' || isTrue(pick(params, 'tls')) === true;
      if (tlsEnabled) proxy.tls = true;

      const servername = pick(params, 'sni', 'servername');
      if (servername) proxy.servername = servername;

      const alpn = splitList(pick(params, 'alpn'));
      if (alpn.length) proxy.alpn = alpn;

      const clientFp = pick(params, 'fp', 'client-fingerprint');
      if (clientFp) proxy['client-fingerprint'] = clientFp;

      const fingerprint = pick(params, 'fingerprint');
      if (fingerprint) proxy.fingerprint = fingerprint;

      const skip = isTrue(pick(params, 'allowInsecure', 'insecure', 'skip-cert-verify'));
      if (skip !== undefined) proxy['skip-cert-verify'] = skip;

      const pbk = pick(params, 'pbk', 'publicKey', 'public-key');
      const sid = pick(params, 'sid', 'shortid', 'short-id');
      const supportX25519 = isTrue(pick(params, 'support-x25519mlkem768'));
      if (security === 'reality' || pbk || sid || supportX25519 !== undefined) {
        const reality = {};
        if (pbk) reality['public-key'] = pbk;
        if (sid) reality['short-id'] = sid;
        if (supportX25519 !== undefined) reality['support-x25519mlkem768'] = supportX25519;
        if (Object.keys(reality).length) proxy['reality-opts'] = reality;
        if (!proxy.tls) proxy.tls = true;
      }

      const networkRaw = pick(params, 'type', 'network');
      const network = normalizeNetwork(networkRaw);
      applyNetwork(proxy, network, params, false, networkRaw !== undefined);

      const udp = isTrue(pick(params, 'udp'));
      if (udp !== undefined) proxy.udp = udp;

      return proxy;
    }

    function parseTrojan(link) {
      const url = new URL(link);
      const params = collectParams(url.searchParams);
      const password = decodeURIComponent(url.username || '');
      if (!password) throw new Error('Missing password');

      const proxy = {
        name: decodeName(url.hash) || params.name || 'trojan',
        type: 'trojan',
        server: url.hostname,
        port: toNumber(url.port || '0'),
        password,
        tls: true
      };

      const sni = pick(params, 'sni', 'servername');
      if (sni) proxy.sni = sni;

      const alpn = splitList(pick(params, 'alpn'));
      if (alpn.length) proxy.alpn = alpn;

      const clientFp = pick(params, 'fp', 'client-fingerprint');
      if (clientFp) proxy['client-fingerprint'] = clientFp;

      const fingerprint = pick(params, 'fingerprint');
      if (fingerprint) proxy.fingerprint = fingerprint;

      const skip = isTrue(pick(params, 'allowInsecure', 'insecure', 'skip-cert-verify'));
      if (skip !== undefined) proxy['skip-cert-verify'] = skip;

      const pbk = pick(params, 'pbk', 'publicKey', 'public-key');
      const sid = pick(params, 'sid', 'shortid', 'short-id');
      const supportX25519 = isTrue(pick(params, 'support-x25519mlkem768'));
      if (pbk || sid || supportX25519 !== undefined) {
        const reality = {};
        if (pbk) reality['public-key'] = pbk;
        if (sid) reality['short-id'] = sid;
        if (supportX25519 !== undefined) reality['support-x25519mlkem768'] = supportX25519;
        if (Object.keys(reality).length) proxy['reality-opts'] = reality;
      }

      const ssEnabled = isTrue(pick(params, 'ss'));
      const ssMethod = pick(params, 'ss-method');
      const ssPassword = pick(params, 'ss-password');
      if (ssEnabled !== undefined || ssMethod || ssPassword) {
        const ss = {};
        if (ssEnabled !== undefined) ss.enabled = ssEnabled;
        if (ssMethod) ss.method = ssMethod;
        if (ssPassword) ss.password = ssPassword;
        if (Object.keys(ss).length) proxy['ss-opts'] = ss;
      }

      const networkRaw = pick(params, 'type', 'network');
      const network = normalizeNetwork(networkRaw);
      applyNetwork(proxy, network, params, false, networkRaw !== undefined);

      const udp = isTrue(pick(params, 'udp'));
      if (udp !== undefined) proxy.udp = udp;

      return proxy;
    }

    function parseSS(link) {
      let body = link.slice('ss://'.length);
      let name = '';

      const hashIdx = body.indexOf('#');
      if (hashIdx >= 0) {
        name = decodeURIComponent(body.slice(hashIdx + 1));
        body = body.slice(0, hashIdx);
      }

      let query = '';
      const queryIdx = body.indexOf('?');
      if (queryIdx >= 0) {
        query = body.slice(queryIdx + 1);
        body = body.slice(0, queryIdx);
      }

      let method = '';
      let password = '';
      let server = '';
      let port = 0;

      if (body.includes('@')) {
        const [userInfo, hostInfo] = body.split('@');
        const [host, portStr] = hostInfo.split(':');
        server = host;
        port = toNumber(portStr || '0');

        if (userInfo.includes(':')) {
          [method, password] = userInfo.split(':');
        } else {
          const decoded = safeBase64Decode(userInfo);
          if (!decoded.includes(':')) throw new Error('Invalid ss userinfo');
          [method, password] = decoded.split(':');
        }
      } else {
        const decoded = safeBase64Decode(body);
        const atIdx = decoded.lastIndexOf('@');
        if (atIdx < 0) throw new Error('Invalid ss payload');
        const userInfo = decoded.slice(0, atIdx);
        const hostInfo = decoded.slice(atIdx + 1);
        const [host, portStr] = hostInfo.split(':');
        server = host;
        port = toNumber(portStr || '0');
        [method, password] = userInfo.split(':');
      }

      if (!method || !password || !server || !port) throw new Error('Invalid ss fields');

      const proxy = {
        name: name || 'ss',
        type: 'ss',
        server,
        port,
        cipher: method,
        password
      };

      const params = collectParams(new URLSearchParams(query));
      const pluginRaw = pick(params, 'plugin');
      if (pluginRaw) {
        const parts = pluginRaw.split(';').filter(Boolean);
        const pluginName = parts.shift();
        proxy.plugin = pluginName;
        if (parts.length) {
          const opts = {};
          for (const part of parts) {
            if (!part) continue;
            if (part.includes('=')) {
              const [k, v] = part.split('=');
              opts[k] = v;
            } else {
              opts[part] = true;
            }
          }
          if (Object.keys(opts).length) proxy['plugin-opts'] = opts;
        }
      }

      return proxy;
    }

    function parseHy2(link) {
      const url = new URL(link);
      const params = collectParams(url.searchParams);
      let auth = decodeURIComponent(url.username || '');
      if (url.password) {
        const pass = decodeURIComponent(url.password);
        auth = auth ? `${auth}:${pass}` : pass;
      }
      if (!auth) auth = pick(params, 'password') || '';
      if (!auth) throw new Error('Missing password');

      const proxy = {
        name: decodeName(url.hash) || params.name || 'hysteria2',
        type: 'hysteria2',
        server: url.hostname,
        port: toNumber(url.port || '0'),
        password: auth
      };

      const ports = pick(params, 'ports');
      if (ports) proxy.ports = ports;

      const up = pick(params, 'up', 'upmbps');
      if (up) proxy.up = formatMbps(up);

      const down = pick(params, 'down', 'downmbps');
      if (down) proxy.down = formatMbps(down);

      const obfs = pick(params, 'obfs');
      if (obfs) proxy.obfs = obfs;

      const obfsPwd = pick(params, 'obfs-password', 'obfsPassword');
      if (obfsPwd) proxy['obfs-password'] = obfsPwd;

      const sni = pick(params, 'sni');
      if (sni) proxy.sni = sni;

      const alpn = splitList(pick(params, 'alpn'));
      if (alpn.length) proxy.alpn = alpn;

      const skip = isTrue(pick(params, 'allowInsecure', 'insecure', 'skip-cert-verify'));
      if (skip !== undefined) proxy['skip-cert-verify'] = skip;

      const fingerprint = pick(params, 'fingerprint');
      if (fingerprint) proxy.fingerprint = fingerprint;

      return proxy;
    }

    function parseHy1(link) {
      const url = new URL(link);
      const params = collectParams(url.searchParams);
      let auth = decodeURIComponent(url.username || '');
      if (url.password) {
        const pass = decodeURIComponent(url.password);
        auth = auth ? `${auth}:${pass}` : pass;
      }
      if (!auth) auth = pick(params, 'auth', 'auth_str', 'auth-str') || '';
      if (!auth) throw new Error('Missing auth');

      const proxy = {
        name: decodeName(url.hash) || params.name || 'hysteria',
        type: 'hysteria',
        server: url.hostname,
        port: toNumber(url.port || '0'),
        'auth-str': auth
      };

      const ports = pick(params, 'ports');
      if (ports) proxy.ports = ports;

      const protocol = pick(params, 'protocol');
      if (protocol) proxy.protocol = protocol;

      const up = pick(params, 'up', 'upmbps');
      if (up) proxy.up = formatMbps(up);

      const down = pick(params, 'down', 'downmbps');
      if (down) proxy.down = formatMbps(down);

      const obfs = pick(params, 'obfs');
      if (obfs) proxy.obfs = obfs;

      const sni = pick(params, 'sni');
      if (sni) proxy.sni = sni;

      const alpn = splitList(pick(params, 'alpn'));
      if (alpn.length) proxy.alpn = alpn;

      const skip = isTrue(pick(params, 'allowInsecure', 'insecure', 'skip-cert-verify'));
      if (skip !== undefined) proxy['skip-cert-verify'] = skip;

      return proxy;
    }

    function parseTuic(link) {
      const url = new URL(link);
      const params = collectParams(url.searchParams);
      const uuid = decodeURIComponent(url.username || '');
      const password = decodeURIComponent(url.password || '');

      const proxy = {
        name: decodeName(url.hash) || params.name || 'tuic',
        type: 'tuic',
        server: url.hostname,
        port: toNumber(url.port || '0')
      };

      const token = pick(params, 'token');
      if (token) proxy.token = token;
      if (uuid) proxy.uuid = uuid;
      if (password) proxy.password = password;

      const ip = pick(params, 'ip');
      if (ip) proxy.ip = ip;

      const heartbeat = pick(params, 'heartbeat-interval', 'heartbeat_interval');
      if (heartbeat) proxy['heartbeat-interval'] = toNumber(heartbeat);

      const alpn = splitList(pick(params, 'alpn'));
      if (alpn.length) proxy.alpn = alpn;

      const disableSni = isTrue(pick(params, 'disable-sni', 'disable_sni'));
      if (disableSni !== undefined) proxy['disable-sni'] = disableSni;

      const reduceRtt = isTrue(pick(params, 'reduce-rtt', 'reduce_rtt'));
      if (reduceRtt !== undefined) proxy['reduce-rtt'] = reduceRtt;

      const requestTimeout = pick(params, 'request-timeout', 'request_timeout');
      if (requestTimeout) proxy['request-timeout'] = toNumber(requestTimeout);

      const udpRelay = pick(params, 'udp-relay-mode', 'udp_relay_mode');
      if (udpRelay) proxy['udp-relay-mode'] = udpRelay;

      const congestion = pick(params, 'congestion-controller', 'congestion_controller');
      if (congestion) proxy['congestion-controller'] = congestion;

      const maxUdp = pick(params, 'max-udp-relay-packet-size', 'max_udp_relay_packet_size');
      if (maxUdp) proxy['max-udp-relay-packet-size'] = toNumber(maxUdp);

      const fastOpen = isTrue(pick(params, 'fast-open', 'fast_open'));
      if (fastOpen !== undefined) proxy['fast-open'] = fastOpen;

      const maxOpenStreams = pick(params, 'max-open-streams', 'max_open_streams');
      if (maxOpenStreams) proxy['max-open-streams'] = toNumber(maxOpenStreams);

      const sni = pick(params, 'sni');
      if (sni) proxy.sni = sni;

      const skip = isTrue(pick(params, 'allowInsecure', 'insecure', 'skip-cert-verify'));
      if (skip !== undefined) proxy['skip-cert-verify'] = skip;

      return proxy;
    }

    function parseAnyTLS(link) {
      const url = new URL(link);
      const params = collectParams(url.searchParams);

      let password = decodeURIComponent(url.username || '');
      if (url.password) {
        const pass = decodeURIComponent(url.password);
        password = password ? `${password}:${pass}` : pass;
      }

      if (!password) {
        const fallback = pick(params, 'password', 'pass', 'auth');
        if (fallback) password = fallback;
      }

      if (!password) throw new Error('Missing password');

      const proxy = {
        name: decodeName(url.hash) || params.name || 'anytls',
        type: 'anytls',
        server: url.hostname,
        port: toNumber(url.port || '443'),
        password
      };

      const udp = isTrue(pick(params, 'udp'));
      if (udp !== undefined) proxy.udp = udp;

      const idleCheck = pick(params, 'idle-session-check-interval', 'idle_session_check_interval', 'idleSessionCheckInterval');
      if (idleCheck) proxy['idle-session-check-interval'] = toNumber(idleCheck);

      const idleTimeout = pick(params, 'idle-session-timeout', 'idle_session_timeout', 'idleSessionTimeout');
      if (idleTimeout) proxy['idle-session-timeout'] = toNumber(idleTimeout);

      const minIdle = pick(params, 'min-idle-session', 'min_idle_session', 'minIdleSession');
      if (minIdle) proxy['min-idle-session'] = toNumber(minIdle);

      const sni = pick(params, 'sni', 'servername', 'peer');
      if (sni) proxy.sni = sni;

      const alpn = splitList(pick(params, 'alpn'));
      if (alpn.length) proxy.alpn = alpn;

      const clientFp = pick(params, 'fp', 'client-fingerprint');
      if (clientFp) proxy['client-fingerprint'] = clientFp;

      const fingerprint = pick(params, 'fingerprint');
      if (fingerprint) proxy.fingerprint = fingerprint;

      const skip = isTrue(pick(params, 'insecure', 'allowInsecure', 'skip-cert-verify'));
      proxy['skip-cert-verify'] = skip === undefined ? true : skip;

      return proxy;
    }

    function parseSocks(link) {
      const url = new URL(link);
      const proxy = {
        name: decodeName(url.hash) || 'socks',
        type: 'socks5',
        server: url.hostname,
        port: toNumber(url.port || '0')
      };

      if (url.username) proxy.username = decodeURIComponent(url.username);
      if (url.password) proxy.password = decodeURIComponent(url.password);

      const params = collectParams(url.searchParams);
      const tls = isTrue(pick(params, 'tls'));
      if (tls !== undefined) proxy.tls = tls;

      const skip = isTrue(pick(params, 'allowInsecure', 'insecure', 'skip-cert-verify'));
      if (skip !== undefined) proxy['skip-cert-verify'] = skip;

      return proxy;
    }

    function parseHttp(link) {
      const url = new URL(link);
      const proxy = {
        name: decodeName(url.hash) || 'http',
        type: 'http',
        server: url.hostname,
        port: toNumber(url.port || (url.protocol === 'https:' ? '443' : '80'))
      };

      if (url.username) proxy.username = decodeURIComponent(url.username);
      if (url.password) proxy.password = decodeURIComponent(url.password);

      if (url.protocol === 'https:') proxy.tls = true;

      const params = collectParams(url.searchParams);
      const skip = isTrue(pick(params, 'allowInsecure', 'insecure', 'skip-cert-verify'));
      if (skip !== undefined) proxy['skip-cert-verify'] = skip;

      return proxy;
    }

    function applyNetwork(proxy, network, params, fromVmess, networkSpecified = false) {
      if (!network) {
        if (networkSpecified) proxy.network = 'tcp';
        return;
      }
      if (network === 'tcp') {
        proxy.network = 'tcp';
        return;
      }
      proxy.network = network;

      const host = pick(params, 'host');
      const path = pick(params, 'path');

      if (network === 'ws') {
        const ws = {};
        if (path) ws.path = path;
        if (host) ws.headers = { Host: host };

        const ed = pick(params, 'ed', 'max-early-data');
        if (ed) ws['max-early-data'] = toNumber(ed) || ed;

        const eh = pick(params, 'eh', 'early-data-header-name');
        if (eh) ws['early-data-header-name'] = eh;

        const upgrade = isTrue(pick(params, 'v2ray-http-upgrade'));
        if (upgrade !== undefined) ws['v2ray-http-upgrade'] = upgrade;

        const fastOpen = isTrue(pick(params, 'v2ray-http-upgrade-fast-open'));
        if (fastOpen !== undefined) ws['v2ray-http-upgrade-fast-open'] = fastOpen;

        if (Object.keys(ws).length) proxy['ws-opts'] = ws;
      }

      if (network === 'grpc') {
        const grpc = {};
        const serviceName = pick(params, 'serviceName', 'service', 'grpc-service-name', 'path');
        if (serviceName) grpc['grpc-service-name'] = serviceName;
        const userAgent = pick(params, 'grpc-user-agent', 'grpcUserAgent');
        if (userAgent) grpc['grpc-user-agent'] = userAgent;
        if (Object.keys(grpc).length) proxy['grpc-opts'] = grpc;
      }

      if (network === 'h2') {
        const h2 = {};
        if (host) h2.host = splitList(host);
        if (path) h2.path = path;
        if (Object.keys(h2).length) proxy['h2-opts'] = h2;
      }

      if (network === 'http') {
        const http = {};
        const method = pick(params, 'method');
        if (method) http.method = method;
        if (path) http.path = splitList(path);
        if (host) http.headers = { Host: host };
        if (Object.keys(http).length) proxy['http-opts'] = http;
      }

      if (fromVmess) {
        const tlsFlag = params.tls === 'tls' || isTrue(params.tls) === true;
        if (tlsFlag) proxy.tls = true;

        const sni = pick(params, 'sni');
        if (sni) proxy.servername = sni;

        const alpn = splitList(pick(params, 'alpn'));
        if (alpn.length) proxy.alpn = alpn;

        const clientFp = pick(params, 'fp', 'client-fingerprint');
        if (clientFp) proxy['client-fingerprint'] = clientFp;

        const fingerprint = pick(params, 'fingerprint');
        if (fingerprint) proxy.fingerprint = fingerprint;

        const skip = isTrue(pick(params, 'allowInsecure', 'insecure', 'skip-cert-verify'));
        if (skip !== undefined) proxy['skip-cert-verify'] = skip;
      } else {
        const alpn = splitList(pick(params, 'alpn'));
        if (alpn.length) proxy.alpn = alpn;

        const clientFp = pick(params, 'fp', 'client-fingerprint');
        if (clientFp) proxy['client-fingerprint'] = clientFp;

        const fingerprint = pick(params, 'fingerprint');
        if (fingerprint) proxy.fingerprint = fingerprint;

        const skip = isTrue(pick(params, 'allowInsecure', 'insecure', 'skip-cert-verify'));
        if (skip !== undefined) proxy['skip-cert-verify'] = skip;
      }
    }

    function safeJsonDecode(payload) {
      const decoded = safeBase64Decode(payload);
      try {
        return JSON.parse(decoded);
      } catch {
        return null;
      }
    }

    function safeBase64Decode(input) {
      let str = input.replace(/-/g, '+').replace(/_/g, '/');
      const pad = str.length % 4;
      if (pad === 2) str += '==';
      else if (pad === 3) str += '=';
      else if (pad === 1) str += '===';

      const bin = atob(str);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      return new TextDecoder('utf-8').decode(bytes);
    }

    function collectParams(searchParams) {
      const obj = {};
      for (const [key, value] of searchParams.entries()) {
        if (obj[key]) {
          if (Array.isArray(obj[key])) obj[key].push(value);
          else obj[key] = [obj[key], value];
        } else {
          obj[key] = value;
        }
      }
      return obj;
    }

    function pick(obj, ...keys) {
      for (const key of keys) {
        if (obj && obj[key] !== undefined) return obj[key];
      }
      return undefined;
    }

    function normalizeNetwork(network) {
      if (!network) return '';
      const value = network.toLowerCase();
      if (value === 'websocket') return 'ws';
      if (value === 'http2') return 'h2';
      return value;
    }

    function splitList(value) {
      if (!value) return [];
      if (Array.isArray(value)) return value.flatMap(v => String(v).split(',')).map(v => v.trim()).filter(Boolean);
      return String(value).split(',').map(v => v.trim()).filter(Boolean);
    }

    function formatMbps(value) {
      const str = String(value).trim();
      if (/[a-zA-Z]/.test(str)) return str;
      return `${str} Mbps`;
    }

    function decodeName(hash) {
      if (!hash) return '';
      const name = hash.startsWith('#') ? hash.slice(1) : hash;
      return decodeURIComponent(name);
    }

    function isTrue(value) {
      if (value === undefined || value === null) return undefined;
      const str = String(value).toLowerCase();
      if (str === '' || str === '1' || str === 'true' || str === 'yes' || str === 'on') return true;
      if (str === '0' || str === 'false' || str === 'no' || str === 'off') return false;
      return undefined;
    }

    function toNumber(value) {
      const num = Number(value);
      return Number.isFinite(num) ? num : 0;
    }

    function dumpYaml(obj) {
      return dumpValue(obj, 0).trimEnd() + '\n';
    }

    function dumpValue(value, indent) {
      const pad = ' '.repeat(indent);
      if (Array.isArray(value)) {
        if (!value.length) return pad + '[]';
        return value.map(item => {
          if (isScalar(item)) {
            return `${pad}- ${formatScalar(item)}`;
          }
          return `${pad}-\n${dumpValue(item, indent + 2)}`;
        }).join('\n');
      }

      if (value && typeof value === 'object') {
        const lines = [];
        for (const [key, val] of Object.entries(value)) {
          if (val === undefined) continue;
          if (isScalar(val)) {
            lines.push(`${pad}${key}: ${formatScalar(val)}`);
          } else if (Array.isArray(val) && val.length === 0) {
            lines.push(`${pad}${key}: []`);
          } else {
            lines.push(`${pad}${key}:`);
            lines.push(dumpValue(val, indent + 2));
          }
        }
        return lines.join('\n');
      }

      return pad + formatScalar(value);
    }

    function isScalar(value) {
      return value === null || ['string', 'number', 'boolean'].includes(typeof value);
    }

    function formatScalar(value) {
      if (value === null) return 'null';
      if (typeof value === 'number') return String(value);
      if (typeof value === 'boolean') return value ? 'true' : 'false';
      return quoteString(String(value));
    }

    function quoteString(value) {
      if (value === '') return '""';
      if (/^[A-Za-z0-9._-]+$/.test(value)) return value;
      const escaped = value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
      return `"${escaped}"`;
    }

})();

(() => {
const RULE_LIBRARY = [
  {
    id: "china",
    key: "China",
    title: "中国大陆直连",
    desc: "国内常见站点与服务",
    path: "rule/Clash/China/China.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "DIRECT",
    required: true,
    group: "基础"
  },
  {
    id: "global",
    key: "Global",
    title: "国际/默认代理",
    desc: "常见海外站点",
    path: "rule/Clash/Global/Global.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "Proxy",
    required: true,
    group: "基础"
  },
  {
    id: "global-media",
    key: "GlobalMedia",
    title: "国际媒体",
    desc: "海外流媒体合集",
    path: "rule/Clash/GlobalMedia/GlobalMedia_Classical.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "Proxy",
    required: false,
    group: "影音"
  },
  {
    id: "netflix",
    key: "Netflix",
    title: "Netflix",
    desc: "奈飞视频",
    path: "rule/Clash/Netflix/Netflix.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "Proxy",
    required: false,
    group: "影音"
  },
  {
    id: "youtube",
    key: "YouTube",
    title: "YouTube",
    desc: "YouTube 视频",
    path: "rule/Clash/YouTube/YouTube.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "Proxy",
    required: false,
    group: "影音"
  },
  {
    id: "disney",
    key: "Disney",
    title: "Disney+",
    desc: "迪士尼流媒体",
    path: "rule/Clash/Disney/Disney.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "Proxy",
    required: false,
    group: "影音"
  },
  {
    id: "spotify",
    key: "Spotify",
    title: "Spotify",
    desc: "音乐流媒体",
    path: "rule/Clash/Spotify/Spotify.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "Proxy",
    required: false,
    group: "影音"
  },
  {
    id: "tiktok",
    key: "TikTok",
    title: "TikTok",
    desc: "海外短视频",
    path: "rule/Clash/TikTok/TikTok.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "Proxy",
    required: false,
    group: "社交"
  },
  {
    id: "telegram",
    key: "Telegram",
    title: "Telegram",
    desc: "电报消息",
    path: "rule/Clash/Telegram/Telegram.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "Proxy",
    required: false,
    group: "社交"
  },
  {
    id: "twitter",
    key: "Twitter",
    title: "X / Twitter",
    desc: "社交平台",
    path: "rule/Clash/Twitter/Twitter.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "Proxy",
    required: false,
    group: "社交"
  },
  {
    id: "github",
    key: "GitHub",
    title: "GitHub",
    desc: "代码托管与访问",
    path: "rule/Clash/GitHub/GitHub.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "Proxy",
    required: false,
    group: "效率"
  },
  {
    id: "google",
    key: "Google",
    title: "Google",
    desc: "谷歌服务",
    path: "rule/Clash/Google/Google.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "Proxy",
    required: false,
    group: "效率"
  },
  {
    id: "microsoft",
    key: "Microsoft",
    title: "Microsoft",
    desc: "微软服务",
    path: "rule/Clash/Microsoft/Microsoft.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "DIRECT",
    required: false,
    group: "效率"
  },
  {
    id: "apple",
    key: "Apple",
    title: "Apple",
    desc: "苹果服务",
    path: "rule/Clash/Apple/Apple_Classical.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "DIRECT",
    required: false,
    group: "系统"
  },
  {
    id: "bilibili",
    key: "BiliBili",
    title: "哔哩哔哩",
    desc: "国内视频",
    path: "rule/Clash/BiliBili/BiliBili.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "DIRECT",
    required: false,
    group: "国内"
  },
  {
    id: "game",
    key: "Game",
    title: "游戏平台",
    desc: "Steam/Epic 等",
    path: "rule/Clash/Game/Game.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "Proxy",
    required: false,
    group: "游戏"
  },
  {
    id: "openai",
    key: "OpenAI",
    title: "AI 服务",
    desc: "OpenAI/Claude 等",
    path: "rule/Clash/OpenAI/OpenAI.yaml",
    behavior: "classical",
    format: "yaml",
    policy: "Proxy",
    required: false,
    group: "AI"
  }
];

  const elements = {
    configName: document.getElementById("configName"),
    mixedPort: document.getElementById("mixedPort"),
    allowLan: document.getElementById("allowLan"),
  mode: document.getElementById("mode"),
  logLevel: document.getElementById("logLevel"),
  ipv6: document.getElementById("ipv6"),
  mainGroupName: document.getElementById("mainGroupName"),
  autoGroupName: document.getElementById("autoGroupName"),
  autoTestUrl: document.getElementById("autoTestUrl"),
    autoInterval: document.getElementById("autoInterval"),
    autoTolerance: document.getElementById("autoTolerance"),
    extraGroups: document.getElementById("extraGroups"),
    nodesInput: document.getElementById("nodesInput"),
    clearNodesInput: document.getElementById("clearNodesInput"),
    rawBase: document.getElementById("rawBase"),
    ghPrefix: document.getElementById("ghPrefix"),
    applyGhPrefix: document.getElementById("applyGhPrefix"),
    ruleInterval: document.getElementById("ruleInterval"),
    ruleSearch: document.getElementById("ruleSearch"),
    searchRepo: document.getElementById("searchRepo"),
    repoPanel: document.getElementById("repoPanel"),
    repoResults: document.getElementById("repoResults"),
    repoStatus: document.getElementById("repoStatus"),
    ruleGrid: document.getElementById("ruleGrid"),
  selectAll: document.getElementById("selectAll"),
  clearOptional: document.getElementById("clearOptional"),
  extraRules: document.getElementById("extraRules"),
  addGeoip: document.getElementById("addGeoip"),
  finalPolicy: document.getElementById("finalPolicy"),
  generateBtn: document.getElementById("generateBtn"),
  copyBtn: document.getElementById("copyBtn"),
    downloadBtn: document.getElementById("downloadBtn"),
    uploadBtn: document.getElementById("uploadBtn"),
    webdavUrl: document.getElementById("webdavUrl"),
    webdavUser: document.getElementById("webdavUser"),
    webdavPass: document.getElementById("webdavPass"),
    webdavPath: document.getElementById("webdavPath"),
    webdavToggle: document.getElementById("webdavToggle"),
    webdavPanel: document.getElementById("webdavPanel"),
    outputYaml: document.getElementById("outputYaml"),
    status: document.getElementById("status"),
    ruleCount: document.getElementById("ruleCount"),
  ruleSelected: document.getElementById("ruleSelected"),
  nodeCount: document.getElementById("nodeCount")
};

const sampleYaml = `proxies:
  - name: 示例-VMess
    type: vmess
    server: example.com
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 0
    cipher: auto
    tls: true
    udp: true
  - name: 示例-Trojan
    type: trojan
    server: example.net
    port: 443
    password: password
    sni: example.net
    udp: true
`;

  if (!elements.nodesInput.value.trim()) {
    elements.nodesInput.placeholder = sampleYaml;
  }

  elements.ruleCount.textContent = String(RULE_LIBRARY.length);
  if (elements.repoPanel) {
    elements.repoPanel.style.display = "none";
  }

function setStatus(message, isError) {
  elements.status.textContent = message || "";
  elements.status.className = "status" + (isError ? " error" : "");
}

function updatePolicyLabels() {
  const proxyName = elements.mainGroupName.value.trim() || "Proxy";
  document.querySelectorAll(".rule-policy option[value='Proxy']").forEach((opt) => {
    opt.textContent = `代理组(${proxyName})`;
  });

  if (!elements.finalPolicy.value.trim() || elements.finalPolicy.value === "Proxy") {
    elements.finalPolicy.value = proxyName;
  }
}

  function buildRuleCard(rule) {
    const card = document.createElement("div");
    card.className = `rule-card${rule.required ? " required" : ""}`;
    card.dataset.ruleId = rule.id;
    card.dataset.search = buildRuleSearchIndex(rule);

    const checkbox = document.createElement("input");
    checkbox.type = "checkbox";
    checkbox.className = "rule-check";
    checkbox.checked = Boolean(rule.required || rule.prechecked);
    checkbox.disabled = rule.required;

  const body = document.createElement("div");
  body.className = "rule-body";

  const title = document.createElement("div");
  title.className = "rule-title";

  const name = document.createElement("span");
  name.className = "rule-name";
  name.textContent = rule.title;

  const tag = document.createElement("span");
  tag.className = "rule-tag";
  tag.textContent = rule.group || "";

  title.appendChild(name);
  title.appendChild(tag);

  const desc = document.createElement("p");
  desc.className = "rule-desc";
  desc.textContent = rule.desc || "";

  const policy = document.createElement("select");
  policy.className = "rule-policy";
  ["Proxy", "DIRECT", "REJECT"].forEach((value) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    policy.appendChild(option);
  });
  policy.value = rule.policy || "Proxy";
  policy.disabled = rule.required;

  body.appendChild(title);
  body.appendChild(desc);
  body.appendChild(policy);

  card.appendChild(checkbox);
  card.appendChild(body);

  const setSelected = () => {
    card.classList.toggle("selected", checkbox.checked || rule.required);
  };

  checkbox.addEventListener("change", () => {
    setSelected();
    updateRuleStats();
  });

  card.addEventListener("click", (event) => {
    const tag = event.target.tagName;
    if (tag === "INPUT" || tag === "SELECT" || tag === "OPTION") {
      return;
    }
    if (!checkbox.disabled) {
      checkbox.checked = !checkbox.checked;
      checkbox.dispatchEvent(new Event("change"));
    }
  });

  setSelected();

    return card;
  }

  function renderRuleCards() {
    elements.ruleGrid.innerHTML = "";
    RULE_LIBRARY.forEach((rule) => {
      elements.ruleGrid.appendChild(buildRuleCard(rule));
    });
    updatePolicyLabels();
    updateRuleStats();
  }

  function buildRuleSearchIndex(rule) {
    const parts = [
      rule.id,
      rule.key,
      rule.title,
      rule.desc,
      rule.group,
      rule.path
    ]
      .filter(Boolean)
      .map((value) => String(value).toLowerCase());
    return parts.join(" ");
  }

  function filterRuleCards(query) {
    const normalized = normalizeQuery(query);
    const tokens = expandQueryTokens(normalized);
    const cards = Array.from(elements.ruleGrid.querySelectorAll(".rule-card"));
    if (!tokens.length) {
      cards.forEach((card) => {
        card.style.display = "";
      });
      return;
    }
    cards.forEach((card) => {
      const haystack = card.dataset.search || "";
      const match = tokens.some((token) => haystack.includes(token));
      card.style.display = match ? "" : "none";
    });
  }

  function normalizeQuery(value) {
    return String(value || "")
      .trim()
      .toLowerCase();
  }

  function expandQueryTokens(query) {
    if (!query) return [];
    const tokens = query.split(/\s+/).filter(Boolean);
    const aliasMap = {
      "抖音": ["douyin", "tiktok"],
      "douyin": ["抖音", "tiktok"],
      "tiktok": ["抖音", "douyin"]
    };
    const expanded = new Set(tokens);
    tokens.forEach((token) => {
      const aliases = aliasMap[token];
      if (aliases) {
        aliases.forEach((alias) => expanded.add(alias));
      }
    });
    return Array.from(expanded).map((token) => token.toLowerCase());
  }

  let repoRuleFiles = [];
  let repoLoaded = false;

  async function fetchRepoRules() {
    if (repoLoaded) return repoRuleFiles;
    const response = await fetch(
      "https://api.github.com/repos/blackmatrix7/ios_rule_script/git/trees/master?recursive=1"
    );
    if (!response.ok) {
      throw new Error("无法访问 GitHub 仓库，请稍后再试。");
    }
    const data = await response.json();
    const files = (data.tree || [])
      .filter((item) => item.type === "blob")
      .map((item) => item.path)
      .filter((path) => path.startsWith("rule/Clash/"))
      .filter((path) => /\.(yaml|yml|list|txt)$/i.test(path));
    repoRuleFiles = files;
    repoLoaded = true;
    return files;
  }

  function guessRuleFromPath(path) {
    const parts = path.split("/");
    const file = parts[parts.length - 1];
    const base = file.replace(/\.(yaml|yml|list|txt)$/i, "");
    const title = base.replace(/[_-]+/g, " ");
    const key = base.replace(/[^A-Za-z0-9]/g, "");
    const behavior = /classical/i.test(file) ? "classical" : "classical";
    const format = /\.(list|txt)$/i.test(file) ? "text" : "yaml";
    return { title, key, behavior, format };
  }

  function ensureUniqueRuleKey(baseKey) {
    const existing = new Set(RULE_LIBRARY.map((rule) => rule.key));
    let key = baseKey || "Rule";
    let index = 2;
    while (existing.has(key)) {
      key = `${baseKey}${index}`;
      index += 1;
    }
    return key;
  }

  function ensureUniqueRuleId(baseId) {
    const existing = new Set(RULE_LIBRARY.map((rule) => rule.id));
    let id = baseId || "rule";
    let index = 2;
    while (existing.has(id)) {
      id = `${baseId}-${index}`;
      index += 1;
    }
    return id;
  }

  function addRuleToLibrary(rule) {
    RULE_LIBRARY.push(rule);
    const card = buildRuleCard(rule);
    elements.ruleGrid.appendChild(card);
    elements.ruleCount.textContent = String(RULE_LIBRARY.length);
    updatePolicyLabels();
    updateRuleStats();
    if (rule.prechecked) {
      const checkbox = card.querySelector(".rule-check");
      if (checkbox) {
        checkbox.checked = true;
        checkbox.dispatchEvent(new Event("change"));
      }
    }
  }

  function renderRepoResults(matches, query) {
    if (!elements.repoResults || !elements.repoPanel) return;
    elements.repoResults.innerHTML = "";
    elements.repoPanel.style.display = "block";

    if (!query) {
      elements.repoStatus.textContent = "请输入关键词再检索。";
      return;
    }

    if (!matches.length) {
      elements.repoStatus.textContent = "没有找到匹配的规则。";
      return;
    }

    elements.repoStatus.textContent = `找到 ${matches.length} 条结果（最多展示 40 条）。`;
    matches.slice(0, 40).forEach((path) => {
      const guess = guessRuleFromPath(path);
      const item = document.createElement("div");
      item.className = "repo-item";

      const title = document.createElement("div");
      title.className = "repo-title";
      title.textContent = guess.title;

      const meta = document.createElement("div");
      meta.className = "repo-meta";
      meta.textContent = path;

      const actions = document.createElement("div");
      actions.className = "repo-actions";
      const addBtn = document.createElement("button");
      addBtn.className = "btn ghost";
      addBtn.textContent = "添加并选中";
      addBtn.addEventListener("click", () => {
        const key = ensureUniqueRuleKey(guess.key || guess.title.replace(/\s+/g, ""));
        const id = ensureUniqueRuleId(key.toLowerCase());
        addRuleToLibrary({
          id,
          key,
          title: guess.title,
          desc: "来自仓库检索",
          path,
          behavior: guess.behavior,
          format: guess.format,
          policy: "Proxy",
          required: false,
          group: "仓库",
          prechecked: true
        });
      });
      actions.appendChild(addBtn);

      item.appendChild(title);
      item.appendChild(meta);
      item.appendChild(actions);
      elements.repoResults.appendChild(item);
    });
  }

function updateRuleStats() {
  const cards = Array.from(elements.ruleGrid.querySelectorAll(".rule-card"));
  const selected = cards.filter((card) => {
    const checkbox = card.querySelector(".rule-check");
    return checkbox.checked || checkbox.disabled;
  });
  elements.ruleSelected.textContent = String(selected.length);
}

function updateNodeCount() {
  const result = parseNodes(true);
  if (result.error) {
    elements.nodeCount.textContent = "--";
    return;
  }
  elements.nodeCount.textContent = String(result.nodes.length);
}

function normalizeBaseUrl(base) {
  const trimmed = base.trim();
  if (!trimmed) return "";
  return trimmed.endsWith("/") ? trimmed : `${trimmed}/`;
}

function buildUrl(path) {
  const base = normalizeBaseUrl(elements.rawBase.value) || "";
  const cleanedPath = path.replace(/^\/+/, "");
  let url = base + cleanedPath;

  if (elements.applyGhPrefix.checked) {
    const prefix = elements.ghPrefix.value.trim();
    if (prefix && !url.startsWith(prefix)) {
      url = prefix + url;
    }
  }

  return url;
}

function parseNodes(silent) {
  const raw = elements.nodesInput.value.trim();
  if (!raw) return { error: "节点内容为空。" };

  let parsed;
  let parsedAsJson = false;

  try {
    parsed = JSON.parse(raw);
    parsedAsJson = true;
  } catch (err) {
    if (window.jsyaml && typeof window.jsyaml.load === "function") {
      try {
        parsed = window.jsyaml.load(raw);
      } catch (yamlErr) {
        return { error: "YAML 解析失败，请检查格式。" };
      }
    } else {
      return { error: "YAML 解析库未加载，请检查网络或改用 JSON。" };
    }
  }

  if (parsedAsJson && typeof parsed === "string") {
    return { error: "检测到字符串，请输入对象或数组。" };
  }

  let nodes = [];
  if (Array.isArray(parsed)) {
    nodes = parsed;
  } else if (Array.isArray(parsed?.proxies)) {
    nodes = parsed.proxies;
  } else if (Array.isArray(parsed?.nodes)) {
    nodes = parsed.nodes;
  } else if (parsed && typeof parsed === "object" && parsed.name) {
    nodes = [parsed];
  }

  if (!nodes.length) {
    return { error: "未找到节点，请确认输入包含 proxies 数组。" };
  }

  const missingNames = nodes.filter((n) => !n || !n.name);
  if (missingNames.length) {
    return { error: "每个节点都必须包含 name 字段。" };
  }

  return { nodes: normalizeAnyTlsNodes(nodes) };
}

function normalizeAnyTlsNodes(nodes) {
  return nodes.map((node) => {
    if (!node || typeof node !== "object") return node;
    if (String(node.type || "").toLowerCase() !== "anytls") return node;
    if (node["skip-cert-verify"] !== undefined) return node;
    return { ...node, "skip-cert-verify": true };
  });
}

function parseExtraGroups() {
  const text = elements.extraGroups.value.trim();
  if (!text) return { groups: [] };
  try {
    const parsed = JSON.parse(text);
    if (!Array.isArray(parsed)) {
      return { error: "额外代理组必须是 JSON 数组。" };
    }
    return { groups: parsed };
  } catch (err) {
    return { error: "额外代理组 JSON 格式错误。" };
  }
}

function parseExtraRules() {
  const lines = elements.extraRules.value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#") && !line.startsWith("//"));
  return lines;
}

function getSelectedRuleItems() {
  const cards = Array.from(elements.ruleGrid.querySelectorAll(".rule-card"));
  return cards
    .map((card) => {
      const ruleId = card.dataset.ruleId;
      const rule = RULE_LIBRARY.find((item) => item.id === ruleId);
      if (!rule) return null;
      const checked = card.querySelector(".rule-check").checked || rule.required;
      if (!checked) return null;
      const policy = card.querySelector(".rule-policy").value;
      return { ...rule, policy };
    })
    .filter(Boolean);
}

function resolvePolicy(policy) {
  if (policy === "Proxy") {
    return elements.mainGroupName.value.trim() || "Proxy";
  }
  return policy;
}

function sanitizeName(name) {
  const base = String(name || "provider").trim() || "provider";
  return base.replace(/[^a-zA-Z0-9_-]/g, "_");
}

function buildRuleProviders(selectedRules) {
  const ruleProviders = {};
  const rules = [];
  const interval = Number(elements.ruleInterval.value) || 86400;

  selectedRules.forEach((rule) => {
    const key = rule.key;
    const ext = rule.format === "text" ? "list" : "yaml";
    ruleProviders[key] = {
      type: "http",
      behavior: rule.behavior,
      format: rule.format,
      url: buildUrl(rule.path),
      interval,
      path: `./ruleset/${sanitizeName(key)}.${ext}`
    };

    rules.push(`RULE-SET,${key},${resolvePolicy(rule.policy)}`);
  });

  return { ruleProviders, rules };
}

function isScalar(value) {
  return value === null || ["string", "number", "boolean"].includes(typeof value);
}

function yamlScalar(value) {
  if (value === null) return "null";
  if (typeof value === "number" || typeof value === "boolean") return String(value);
  const str = String(value);
  if (str === "") return "''";
  const needsQuote = /[:\n#\[\]{}&,*>!|%@`]/.test(str) || /^\s|\s$/.test(str);
  if (!needsQuote) return str;
  return `'${str.replace(/'/g, "''")}'`;
}

function yamlStringify(value, indent = 0) {
  const pad = "  ".repeat(indent);
  if (Array.isArray(value)) {
    if (value.length === 0) return "[]";
    return value
      .map((item) => {
        if (isScalar(item)) {
          return `${pad}- ${yamlScalar(item)}`;
        }
        const rendered = yamlStringify(item, indent + 1);
        return `${pad}-\n${rendered}`;
      })
      .join("\n");
  }

  if (value && typeof value === "object") {
    const keys = Object.keys(value);
    if (keys.length === 0) return "{}";
    return keys
      .map((key) => {
        const val = value[key];
        if (isScalar(val)) {
          return `${pad}${key}: ${yamlScalar(val)}`;
        }
        const rendered = yamlStringify(val, indent + 1);
        return `${pad}${key}:\n${rendered}`;
      })
      .join("\n");
  }

  return yamlScalar(value);
}

function buildConfig() {
  const nodesResult = parseNodes(false);
  if (nodesResult.error) return { error: nodesResult.error };

  const extraGroupsResult = parseExtraGroups();
  if (extraGroupsResult.error) return { error: extraGroupsResult.error };

  const nodes = nodesResult.nodes;
  const proxyNames = nodes.map((n) => n.name);

  const mainGroupName = elements.mainGroupName.value.trim() || "Proxy";
  const autoGroupName = elements.autoGroupName.value.trim() || "Auto";

  const proxyGroups = [
    {
      name: mainGroupName,
      type: "select",
      proxies: [autoGroupName, "DIRECT", "REJECT", ...proxyNames]
    },
    {
      name: autoGroupName,
      type: "url-test",
      url: elements.autoTestUrl.value.trim() || "https://www.gstatic.com/generate_204",
      interval: Number(elements.autoInterval.value) || 300,
      tolerance: Number(elements.autoTolerance.value) || 50,
      proxies: proxyNames
    }
  ];

  proxyGroups.push(...extraGroupsResult.groups);

  const selectedRules = getSelectedRuleItems();
  const providersResult = buildRuleProviders(selectedRules);

  const rules = [...providersResult.rules, ...parseExtraRules()];

  if (elements.addGeoip.checked) {
    rules.push("GEOIP,CN,DIRECT");
  }

  const finalPolicy = elements.finalPolicy.value.trim() || mainGroupName;
  rules.push(`MATCH,${finalPolicy}`);

  const config = {
    "mixed-port": Number(elements.mixedPort.value) || 7890,
    "allow-lan": elements.allowLan.checked,
    mode: elements.mode.value,
    "log-level": elements.logLevel.value,
    ipv6: elements.ipv6.checked,
    proxies: nodes,
    "proxy-groups": proxyGroups,
    rules
  };

  if (Object.keys(providersResult.ruleProviders).length) {
    config["rule-providers"] = providersResult.ruleProviders;
  }

  return { config };
}

function generateYaml() {
  const result = buildConfig();
  if (result.error) {
    setStatus(result.error, true);
    return;
  }
  const yaml = yamlStringify(result.config);
  elements.outputYaml.value = yaml;
  setStatus("已生成 YAML。", false);
}

function copyYaml() {
  const text = elements.outputYaml.value.trim();
  if (!text) {
    setStatus("暂无内容可复制。", true);
    return;
  }
  navigator.clipboard.writeText(text).then(
    () => setStatus("已复制到剪贴板。", false),
    () => setStatus("复制失败，请手动复制。", true)
  );
}

  function downloadYaml() {
    const text = elements.outputYaml.value.trim();
    if (!text) {
      setStatus("暂无内容可下载。", true);
      return;
    }
  const name = (elements.configName.value.trim() || "mihomo-config") + ".yaml";
  const blob = new Blob([text], { type: "text/yaml" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
    setStatus("已开始下载。", false);
  }

  function buildWebdavUrl(base, folder, filename) {
    const baseTrim = String(base || "").trim();
    if (!baseTrim) return "";
    let url = baseTrim.endsWith("/") ? baseTrim : `${baseTrim}/`;
    const folderTrim = String(folder || "").trim();
    if (folderTrim) {
      const cleaned = folderTrim.replace(/^\/+/, "").replace(/\/+$/, "");
      if (cleaned) {
        url += `${cleaned}/`;
      }
    }
    return url + filename;
  }

  async function uploadYaml() {
    const text = elements.outputYaml.value.trim();
    if (!text) {
      setStatus("暂无内容可上传，请先生成 YAML。", true);
      return;
    }
    const url = elements.webdavUrl.value.trim();
    const user = elements.webdavUser.value.trim();
    const pass = elements.webdavPass.value;
    if (!url) {
      setStatus("请填写 WebDAV 地址。", true);
      return;
    }
    if ((user && !pass) || (!user && pass)) {
      setStatus("用户名和密码要同时填写，或都留空。", true);
      return;
    }
    const name = (elements.configName.value.trim() || "mihomo-config") + ".yaml";
    const target = buildWebdavUrl(url, elements.webdavPath.value, name);
    try {
      setStatus("正在上传到 WebDAV...", false);
      const headers = {
        "Content-Type": "text/yaml"
      };
      if (user && pass) {
        headers.Authorization = `Basic ${btoa(`${user}:${pass}`)}`;
      }
      const resp = await fetch(target, {
        method: "PUT",
        headers,
        body: text
      });
      if (!resp.ok) {
        setStatus(`上传失败：${resp.status} ${resp.statusText}`, true);
        return;
      }
      setStatus("上传成功。", false);
      if (elements.webdavPanel && elements.webdavToggle) {
        elements.webdavPanel.classList.remove("is-open");
        elements.webdavToggle.setAttribute("aria-expanded", "false");
      }
    } catch (err) {
      setStatus("上传失败，请检查 WebDAV 地址或跨域设置。", true);
    }
  }

function selectAllOptional() {
  const cards = Array.from(elements.ruleGrid.querySelectorAll(".rule-card"));
  cards.forEach((card) => {
    const checkbox = card.querySelector(".rule-check");
    if (!checkbox.disabled) {
      checkbox.checked = true;
      card.classList.add("selected");
    }
  });
  updateRuleStats();
}

function clearOptional() {
  const cards = Array.from(elements.ruleGrid.querySelectorAll(".rule-card"));
  cards.forEach((card) => {
    const checkbox = card.querySelector(".rule-check");
    if (!checkbox.disabled) {
      checkbox.checked = false;
      card.classList.remove("selected");
    }
  });
  updateRuleStats();
}

  function init() {
    renderRuleCards();
    updateNodeCount();

    elements.selectAll.addEventListener("click", selectAllOptional);
    elements.clearOptional.addEventListener("click", clearOptional);
    elements.generateBtn.addEventListener("click", generateYaml);
    elements.copyBtn.addEventListener("click", copyYaml);
    elements.downloadBtn.addEventListener("click", downloadYaml);
    if (elements.uploadBtn) {
      elements.uploadBtn.addEventListener("click", uploadYaml);
    }
    if (elements.webdavToggle && elements.webdavPanel) {
      elements.webdavPanel.classList.remove("is-open");
      elements.webdavToggle.addEventListener("click", () => {
        const isOpen = elements.webdavPanel.classList.toggle("is-open");
        elements.webdavToggle.setAttribute("aria-expanded", String(isOpen));
      });
    }
    elements.nodesInput.addEventListener("input", updateNodeCount);
    elements.mainGroupName.addEventListener("input", updatePolicyLabels);
    if (elements.ruleSearch) {
      elements.ruleSearch.addEventListener("input", (event) => {
        filterRuleCards(event.target.value);
      });
    }
    if (elements.searchRepo) {
      elements.searchRepo.addEventListener("click", async () => {
        const query = elements.ruleSearch ? elements.ruleSearch.value : "";
        try {
          elements.repoStatus.textContent = "正在从仓库检索...";
          const files = await fetchRepoRules();
          const normalized = normalizeQuery(query);
          const tokens = expandQueryTokens(normalized);
          const matches = files.filter((path) => {
            const haystack = path.toLowerCase();
            return tokens.length ? tokens.some((token) => haystack.includes(token)) : false;
          });
          renderRepoResults(matches, normalized);
        } catch (err) {
          elements.repoPanel.style.display = "block";
          elements.repoStatus.textContent = err.message || "检索失败，请稍后再试。";
        }
      });
    }
    if (elements.clearNodesInput) {
      elements.clearNodesInput.addEventListener("click", () => {
        elements.nodesInput.value = "";
        updateNodeCount();
        setStatus("已清空节点输入。", false);
      });
    }
  }

init();
})();
