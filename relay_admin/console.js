  // Runs in the main controller scope, using the existing accessible modal and pagination.
  const consoleFilters = {nodes: {query:'', status:'all', sort:'default'}, forward: {query:'', status:'all', sort:'default'}};
  function rowStatus(row, kind) {
    const cell = kind === 'nodes' ? row.querySelector('[data-metric="status"]') : row.cells[8];
    return cell?.textContent.trim() || '';
  }
  function rowExpiry(row, kind) { return row.cells[kind === 'nodes' ? 1 : 7]?.textContent.trim() || ''; }
  function filterConsoleRows(selector, kind) {
    const all = [...document.querySelectorAll(selector)];
    const filter = consoleFilters[kind];
    const today = new Date(); today.setHours(0,0,0,0);
    const rows = all.filter(row => {
      row.hidden = true;
      const status = rowStatus(row, kind);
      const date = new Date(rowExpiry(row, kind) + 'T00:00:00');
      const days = (date - today) / 86400000;
      const match = filter.status === 'all' ||
        (filter.status === 'ok' && /可用|正常|生效|运行|有效|启用/.test(status) && !/未|异常|停用|过期/.test(status)) ||
        (filter.status === 'issue' && /失败|异常|过期|到期|超额|停用|禁用|耗尽|用尽/.test(status)) ||
        (filter.status === 'unknown' && /未检测|未设置/.test(status)) ||
        (filter.status === 'soon' && days >= 0 && days <= 7) ||
        (filter.status === 'expired' && days < 0);
      const text = [...row.cells].slice(0, kind === 'nodes' ? 8 : 9).map(c => c.textContent).join(' ').toLowerCase();
      return match && filter.query.toLowerCase().trim().split(/\s+/).every(word => text.includes(word));
    });
    all.forEach((row,index)=>{if(row.dataset.consoleOrder === undefined)row.dataset.consoleOrder=String(index);});
    if (filter.sort === 'default') rows.sort((a,b)=>Number(a.dataset.consoleOrder)-Number(b.dataset.consoleOrder));
    if (filter.sort !== 'default') rows.sort((a,b) => {
      if (filter.sort === 'name') return a.cells[0].textContent.localeCompare(b.cells[0].textContent, 'zh-CN');
      if (filter.sort === 'expiry') return (rowExpiry(a,kind).match(/^\d{4}-/) ? rowExpiry(a,kind) : '9999').localeCompare(rowExpiry(b,kind).match(/^\d{4}-/) ? rowExpiry(b,kind) : '9999');
      const metric = row => { const n = parseFloat(row.cells[filter.sort === 'latency' ? 5 : 6].textContent); return Number.isFinite(n) ? n : (filter.sort === 'latency' ? Infinity : -Infinity); };
      return filter.sort === 'latency' ? metric(a)-metric(b) : metric(b)-metric(a);
    });
    const tbody = all[0]?.parentElement;
    if (tbody) rows.forEach(row => tbody.append(row));
    const empty = document.querySelector(`[data-console-empty="${kind}"]`);
    const panel = document.querySelector(kind === 'nodes' ? '.nodes-panel' : '.forward-list');
    if (panel) {
      panel.classList.toggle('console-no-results', rows.length === 0);
      const exportButton = panel.querySelector('.console-toolbar button');
      if (exportButton) exportButton.disabled = rows.length === 0;
    }
    if (empty) {
      empty.hidden = rows.length !== 0;
      const noRecords = all.length === 0;
      empty.querySelector('b').textContent = noRecords ? (kind === 'nodes' ? '尚未添加节点' : '尚未创建转发') : '没有匹配的记录';
      empty.querySelector('p').textContent = noRecords ? (kind === 'nodes' ? '添加第一个上游节点，开始管理你的中转连接。' : '选择一个上游节点，即可创建 SOCKS5、VLESS 或订阅转发。') : '试试其他关键词，或清除筛选条件查看全部记录。';
      empty.querySelector('button').textContent = noRecords ? (kind === 'nodes' ? '添加节点' : '创建转发') : '清除筛选';
    }
    const count = document.querySelector(`[data-console-count="${kind}"]`);
    if (count) count.textContent = `匹配 ${rows.length} / ${all.length} 条`;
    return rows;
  }
  let toastTimer;
  const consoleToast = message => {
    let el = document.querySelector('.console-toast');
    if (!el) { el = document.createElement('div'); el.className = 'console-toast'; el.setAttribute('role','status'); document.body.append(el); }
    el.textContent = message; el.hidden = false;
    clearTimeout(toastTimer); toastTimer = setTimeout(() => { el.hidden = true; }, 5000);
  };
  function consoleCSV(kind) {
    const rows = filterConsoleRows(kind === 'nodes' ? '.node-row' : '.forward-row', kind);
    const table = document.querySelector(kind === 'nodes' ? '.nodes-panel table' : '.forward-list table');
    if (!table || !rows.length) { consoleToast('没有可导出的记录'); return; }
    const count = kind === 'nodes' ? 8 : 9;
    const cell = value => '"' + (/^[\s]*[=+@\-]/.test(value) ? "'" : '') + value.replaceAll('"','""') + '"';
    const data = [ [...table.querySelectorAll('thead th')].slice(0,count).map(x=>x.textContent), ...rows.map(row => [...row.cells].slice(0,count).map(x=>x.textContent.trim())) ];
    const url = URL.createObjectURL(new Blob(['\ufeff' + data.map(row=>row.map(cell).join(',')).join('\r\n')], {type:'text/csv;charset=utf-8'}));
    const link = document.createElement('a'); link.href=url; link.download=`relay-${kind}-${new Date().toISOString().slice(0,10)}.csv`; document.body.append(link); link.click(); link.remove(); setTimeout(()=>URL.revokeObjectURL(url),1000);
    (kind === 'nodes' ? renderNodePagination : renderForwardPagination)();
    consoleToast('已导出筛选结果，不包含密码、UUID 或订阅链接');
  }
  ['nodes','forward'].forEach(kind => {
    const panel = document.querySelector(kind === 'nodes' ? '.nodes-panel' : '.forward-list');
    if (!panel) return;
    const headings=[...panel.querySelectorAll('thead th')].map(th=>th.textContent);
    panel.querySelectorAll('tbody tr').forEach(row=>[...row.cells].forEach((cell,index)=>{cell.dataset.consoleLabel=headings[index]||'';}));
    const toolbar = document.createElement('div'); toolbar.className='console-toolbar';
    toolbar.innerHTML = `<input type="search" aria-label="搜索${kind === 'nodes' ? '节点' : '转发'}" placeholder="搜索用户、地区、地址或名称…"><select aria-label="筛选状态"><option value="all">全部状态</option><option value="ok">可用 / 正常</option><option value="issue">需要关注</option><option value="soon">7 天内到期</option><option value="expired">已到期</option><option value="unknown">尚未检测 / 设置</option></select><select aria-label="排序"><option value="default">默认排序</option><option value="name">名称排序</option><option value="expiry">到期时间优先</option>${kind === 'nodes' ? '<option value="latency">延迟从低到高</option><option value="speed">速度从高到低</option>' : ''}</select><select aria-label="每页数量"><option value="10">10 条 / 页</option><option value="25">25 条 / 页</option><option value="50">50 条 / 页</option><option value="100">100 条 / 页</option></select><button type="button" class="secondary" title="导出元数据，不包含访问凭据">导出 CSV</button><span class="console-count" data-console-count="${kind}" aria-live="polite"></span>`;
    panel.prepend(toolbar);
    const empty = document.createElement('div'); empty.className='console-empty'; empty.dataset.consoleEmpty=kind; empty.hidden=true;
    empty.innerHTML='<span class="console-empty-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h2m-2 10h2m7-10h1m-1 10h1"/></svg></span><b></b><p></p><button type="button" class="secondary"></button>';
    panel.querySelector('.tablewrap').after(empty);
    empty.querySelector('button').addEventListener('click', event => {
      if (!panel.querySelector(kind === 'nodes' ? '.node-row' : '.forward-row')) {
        openModal(document.getElementById(kind === 'nodes' ? 'add-node-modal' : 'create-forward-modal'), event.currentTarget);
        return;
      }
      Object.assign(consoleFilters[kind], {query:'', status:'all', sort:'default'});
      toolbar.querySelector('input').value='';
      status.value='all'; sort.value='default'; pager.page=1; renderPage();
      toolbar.querySelector('input').focus();
    });
    const [status,sort,size] = toolbar.querySelectorAll('select');
    const pager = kind === 'nodes' ? pagination : forwardPagination;
    const renderPage = kind === 'nodes' ? renderNodePagination : renderForwardPagination;
    try { const saved = Number(localStorage.getItem(`relay-page-size-${kind}`)); if ([10,25,50,100].includes(saved)) { pager.pageSize=saved; size.value=String(saved); } } catch(_) {}
    toolbar.querySelector('input').addEventListener('input', event=>{ consoleFilters[kind].query=event.target.value; pager.page=1; renderPage(); });
    status.addEventListener('change',()=>{consoleFilters[kind].status=status.value;pager.page=1;renderPage();});
    sort.addEventListener('change',()=>{consoleFilters[kind].sort=sort.value;pager.page=1;renderPage();});
    size.addEventListener('change',()=>{pager.pageSize=Number(size.value);pager.page=1;try{localStorage.setItem(`relay-page-size-${kind}`,size.value);}catch(_){}renderPage();});
    toolbar.querySelector('button').addEventListener('click',()=>consoleCSV(kind));
  });
  document.addEventListener('keydown',event=>{
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase()==='k' && !document.querySelector('.modal:not([hidden])')) { const search=document.querySelector('.view:not([hidden]) .console-toolbar input');if(search){event.preventDefault();search.focus();search.select();} }
  });
  const opsHost = document.querySelector('#host-view');
  if (opsHost) {
    const panel = document.createElement('section'); panel.className='panel console-ops';
    panel.innerHTML='<h3>安全与维护</h3><p>备份仅保存在服务器，不向浏览器传输密钥。保留最近 10 份，升级前备份不参与清理。</p><div class="actions"><button type="button" data-console-op="backup">创建安全备份</button><button type="button" class="secondary" data-console-op="sessions/revoke">退出其他会话</button><button type="button" class="secondary" data-console-op="refresh">刷新记录</button><button type="button" class="secondary" data-console-op="logout">安全退出</button></div><div class="console-op-status" role="status"></div><details><summary>服务器备份记录</summary><div data-console-backups class="console-note"></div></details><h3 style="margin-top:24px">最近操作</h3><p>记录管理操作的时间、类型与结果，不记录密码和订阅链接。</p><div class="tablewrap"><table><thead><tr><th>时间</th><th>操作</th><th>结果</th></tr></thead><tbody data-console-events></tbody></table></div>';
    opsHost.append(panel);
    let loading=false;
    const loadOps=async()=>{
      if(loading)return;loading=true;
      try {
        const response=await fetch('/ops/status',{headers:{Accept:'application/json'}});const data=await response.json();if(!response.ok||!data.ok)throw new Error(data.error||'读取失败');
        const body=panel.querySelector('[data-console-events]');body.replaceChildren();
        for(const item of data.events){const row=document.createElement('tr');for(const text of [new Date(item.time*1000).toLocaleString('zh-CN'),item.action,item.ok?'成功':'未完成']){const td=document.createElement('td');td.textContent=text;row.append(td);}body.append(row);}
        if(!data.events.length){const row=body.insertRow();const td=row.insertCell();td.colSpan=3;td.textContent='暂无操作记录，后续管理操作将在这里显示。';}
        const list=panel.querySelector('[data-console-backups]');list.replaceChildren();
        for(const item of data.backups){const line=document.createElement('p');line.textContent=`${item.name} · ${(item.size/1024).toFixed(1)} KB`;list.append(line);}
        if(!data.backups.length)list.textContent='尚无手动备份。升级前备份已另行保存。';
        panel.querySelector('.console-op-status').textContent='更新于 '+new Date().toLocaleTimeString('zh-CN');
      }catch(error){panel.querySelector('.console-op-status').textContent=error.message;}finally{loading=false;}
    };
    const modal=document.createElement('div');modal.className='modal';modal.id='console-confirm';modal.hidden=true;modal.setAttribute('role','dialog');modal.setAttribute('aria-modal','true');modal.setAttribute('aria-labelledby','console-confirm-title');
    modal.innerHTML='<div class="modal-backdrop"></div><section class="modal-panel"><div class="modal-head"><h2 id="console-confirm-title">退出其他会话？</h2><button type="button" class="modal-close" data-modal-close aria-label="关闭">×</button></div><p>其他浏览器和设备将需要重新登录，当前会话不受影响。</p><div class="actions"><button type="button" data-console-confirm>确认退出</button><button type="button" class="secondary" data-modal-close>取消</button></div></section>';
    document.querySelector('.workspace').append(modal);
    const runOp=async(action,button)=>{
      if(button.disabled)return;button.disabled=true;
      try{const csrf=document.querySelector('[name="csrf"]').value;const response=await fetch('/ops/'+action,{method:'POST',headers:{Accept:'application/json'},body:new URLSearchParams({csrf})});const data=await response.json();if(!response.ok||!data.ok)throw new Error(data.error||'操作失败');consoleToast(data.message);await loadOps();}catch(error){consoleToast(error.message);}finally{button.disabled=false;}
    };
    panel.addEventListener('click',event=>{const button=event.target.closest('[data-console-op]');if(!button)return;const action=button.dataset.consoleOp;if(action==='logout'){document.querySelector('.confirm-logout-form')?.requestSubmit();return;}if(action==='refresh'){loadOps();return;}if(action==='sessions/revoke'){openModal(modal,button);return;}runOp(action,button);});
    modal.querySelector('[data-console-confirm]').addEventListener('click',event=>{closeModal(modal);runOp('sessions/revoke',panel.querySelector('[data-console-op="sessions/revoke"]'));});
    let loaded=false;const maybeLoad=()=>{if(!opsHost.hidden&&!loaded){loaded=true;loadOps();}};
    new MutationObserver(maybeLoad).observe(opsHost,{attributes:true,attributeFilter:['hidden']});maybeLoad();
  }
