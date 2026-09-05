  let deleteContext = null;
  const deleteElements = () => {
    const modal = document.getElementById('delete-node-modal');
    return {modal, button: modal.querySelector('button[type="submit"]'), error: modal.querySelector('.form-error'), progress: modal.querySelector('[data-delete-progress]')};
  };
  const checkDeleteDependencies = async (context) => {
    const {modal, button, error, progress} = deleteElements();
    context.checking = true; context.ready = false;
    button.disabled = true; button.textContent = '检查关联中…'; error.hidden = true;
    progress.textContent = '正在检查节点关联的转发服务，不会执行删除。';
    try {
      const body = new URLSearchParams(context.body); body.set('confirm', '0');
      const response = await fetch(context.action, {method:'POST', body, headers:{Accept:'application/json'}});
      const data = await response.json();
      if (!data.requires_confirmation) throw new Error(data.error || '无法确认关联服务，请稍后重试');
      if (deleteContext !== context || modal.hidden) return;
      const forwards = data.forwards || [];
      const list = modal.querySelector('[data-delete-list]');
      list.replaceChildren(...forwards.map(item => {
        const li = document.createElement('li');
        const name = document.createElement('b'); name.textContent = item.label || item.id;
        const detail = document.createElement('span'); detail.textContent = `${item.mode || '转发'} · ${item.status || '状态未知'}`;
        li.append(name, detail); return li;
      }));
      list.hidden = !forwards.length;
      modal.querySelector('[data-delete-message]').textContent = forwards.length
        ? `该节点关联 ${forwards.length} 个转发服务，删除时会一并清理，相关访问链接将失效。`
        : '删除后将移除此上游节点。如它是默认出口，系统将按现有规则切换出口。';
      context.ready = true;
      context.confirmText = forwards.length ? `删除并清理 ${forwards.length} 个转发` : '确认删除节点';
      button.textContent = context.confirmText;
      progress.textContent = '关联检查完成，请核对后再删除。';
    } catch (failure) {
      if (deleteContext !== context || modal.hidden) return;
      error.textContent = failure.message; error.hidden = false;
      button.textContent = '重新检查'; progress.textContent = '';
    } finally {
      context.checking = false;
      if (deleteContext === context && !modal.hidden) button.disabled = false;
    }
  };
  const openDeleteDialog = (form, isNode) => {
    const {modal, button, error, progress} = deleteElements();
    if (modal.dataset.busy === '1') return;
    const label = form.closest('tr')?.cells[0]?.textContent.trim() || (isNode ? '未命名节点' : '未命名转发');
    const context = {action:form.action, body:new URLSearchParams(new FormData(form)), isNode, ready:!isNode, checking:false, pending:false, uncertain:false, confirmText:isNode ? '确认删除节点' : '确认删除转发'};
    deleteContext = context;
    modal.querySelector('#delete-node-title').textContent = isNode ? '删除这个节点？' : '删除这个转发？';
    modal.querySelector('[data-delete-kind]').textContent = isNode ? '上游节点' : '转发服务';
    modal.querySelector('[data-delete-target]').textContent = isNode && form.dataset.nodeLabel ? `${label} · ${form.dataset.nodeLabel}` : label;
    modal.querySelector('[data-delete-message]').textContent = isNode ? '正在确认关联影响…' : '删除后，相关访问链接或订阅将失效，已连接的客户端可能中断。';
    modal.querySelector('[data-delete-list]').hidden = true;
    modal.querySelector('[data-delete-list]').replaceChildren();
    error.hidden = true; error.textContent = ''; progress.textContent = '';
    button.disabled = false; button.textContent = context.confirmText;
    modal.querySelectorAll('[data-modal-close]').forEach(b=>{b.disabled=false;});
    openModal(modal, form.querySelector('button'));
    modal.querySelector('.actions [data-modal-close]').focus();
    if (isNode) checkDeleteDependencies(context);
  };
  const confirmConsoleDelete = async () => {
    const context = deleteContext;
    if (!context || context.pending || context.checking || context.uncertain) return;
    if (!context.ready) { await checkDeleteDependencies(context); return; }
    const {modal, button, error, progress} = deleteElements();
    context.pending = true; modal.dataset.busy = '1'; modal.setAttribute('aria-busy','true');
    modal.querySelectorAll('button').forEach(b=>{b.disabled=true;});
    error.hidden = true; button.textContent = '正在删除…'; progress.textContent = '正在提交删除并校验配置，请勿关闭或重复操作。';
    try {
      const body = new URLSearchParams(context.body); body.set('confirm','1');
      const response = await fetch(context.action, {method:'POST',body,headers:{Accept:'application/json'}});
      let data;
      try { data = await response.json(); } catch (_) { context.uncertain=true; throw new Error('未能确认删除结果，请刷新列表核实，勿重复提交。'); }
      if (!response.ok || !data.ok) throw new Error(data.error || '删除未完成，请稍后重试');
      progress.textContent = '删除成功，正在更新列表…';
      window.location.replace(context.isNode ? '/nodes' : '/forward');
    } catch (failure) {
      if (failure instanceof TypeError || failure.name === 'TimeoutError' || failure.name === 'AbortError') {
        context.uncertain = true;
        error.textContent = '连接中断，删除结果暂时无法确认。请关闭弹窗并刷新列表核实，勿重复提交。';
      } else { error.textContent = failure.message; }
      error.hidden = false; error.focus(); progress.textContent = '';
      delete modal.dataset.busy; modal.removeAttribute('aria-busy'); context.pending = false;
      modal.querySelectorAll('[data-modal-close]').forEach(b=>{b.disabled=false;});
      button.disabled = context.uncertain; button.textContent = context.uncertain ? '请刷新核实结果' : context.confirmText;
    }
  };
