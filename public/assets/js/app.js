async function api(url, opt = {}) {
  opt.headers = opt.headers || {};
  if (opt.body && typeof opt.body !== 'string') {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(opt.body);
  }
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes((opt.method || 'GET').toUpperCase())) {
    try {
      if (!window.__CSRF) {
        window.__CSRF = (await fetch('/csrf').then(r => r.json())).token;
      }
      opt.headers['x-csrf-token'] = window.__CSRF || '';
    } catch {}
  }
  const r = await fetch(url, opt);
  if (!r.ok) {
    let msg;
    try { msg = await r.json(); } catch { msg = { error: await r.text() }; }
    const err = new Error(msg && msg.error ? msg.error : (r.status + ''));
    err.status = r.status;
    throw err;
  }
  const ct = r.headers.get('content-type') || '';
  if (ct.includes('application/json')) return r.json();
  return r.text();
}

// Formato de fecha para la tabla (DD-MM-YYYY [HH:MM])
function formatDateForTable(value, withTime = false) {
  if (!value) return '';
  const d = new Date(value);
  if (!isNaN(d.getTime())) {
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const yy = d.getFullYear();
    if (withTime) {
      const hh = String(d.getHours()).padStart(2, '0');
      const mi = String(d.getMinutes()).padStart(2, '0');
      if (hh !== '00' || mi !== '00') {
        return `${dd}-${mm}-${yy} ${hh}:${mi}`;
      }
    }
    return `${dd}-${mm}-${yy}`;
  }
  // fallback: si no se puede parsear, devolvemos lo que venga
  return String(value);
}

// Estado global para saber si estamos editando algo
window.__editing = { scope: null, id: null };

function setEditing(scope, id) {
  window.__editing = { scope, id };
}

function clearEditing() {
  window.__editing = { scope: null, id: null };
}

// Rellena el formulario correspondiente con los datos del registro
function fillForm(scope, record) {
  const form = document.querySelector(`form[data-form="${scope}"]`);
  if (!form) return;

  if (scope === 'recepciones') {
    if (form.fecha) form.fecha.value = record.fecha || '';
    if (form.tipo) form.tipo.value = record.tipo || '';
    if (form.cantidad) form.cantidad.value = record.cantidad || '';
    if (form.unidad) form.unidad.value = record.unidad || '';
  }

  if (scope === 'produccion') {
    if (form.fecha_ini) form.fecha_ini.value = record.fecha_ini || '';
    if (form.tipo) form.tipo.value = record.tipo || '';
    if (form.cantidad) form.cantidad.value = record.cantidad || '';
    if (form.unidad) form.unidad.value = record.unidad || '';
  }

  if (scope === 'defectuosos') {
    if (form.fecha) form.fecha.value = record.fecha || '';
    if (form.tipo) form.tipo.value = record.tipo || '';
    if (form.cantidad) form.cantidad.value = record.cantidad || '';
    if (form.unidad) form.unidad.value = record.unidad || '';
    if (form.razon) form.razon.value = record.razon || '';
  }

  if (scope === 'envios') {
    if (form.fecha) form.fecha.value = record.fecha || '';
    if (form.cliente) form.cliente.value = record.cliente || '';
    if (form.tipo) form.tipo.value = record.tipo || '';
    if (form.descripcion) form.descripcion.value = record.descripcion || '';
    if (form.cantidad) form.cantidad.value = record.cantidad || '';
    if (form.unidad) form.unidad.value = record.unidad || '';
  }
}

function hookForm(scope) {
  const form = document.querySelector(`form[data-form="${scope}"]`);
  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (window.__ROLE === 'operario') {
      alert('Solo visualización para Operario.');
      return;
    }

    const formData = new FormData(form);
    const payload = Object.fromEntries(formData.entries());

    const editing = window.__editing && window.__editing.scope === scope && window.__editing.id;

    try {
      if (editing) {
        await api(`/api/${scope}/${window.__editing.id}`, {
          method: 'PUT',
          body: payload
        });
      } else {
        await api(`/api/${scope}`, {
          method: 'POST',
          body: payload
        });
      }
      form.reset();
      clearEditing();
      await renderTable(scope);
    } catch (err) {
      console.error(err);
      alert('Error guardando datos');
    }
  });
}

async function renderTable(scope) {
  const tbl = document.querySelector(`table[data-table="${scope}"]`);
  if (!tbl) return;
  const data = await api(`/api/${scope}`);
  const tbody = tbl.querySelector('tbody');
  tbody.innerHTML = '';

  data.items.forEach(r => {
    const tr = document.createElement('tr');

    const addCell = (value) => {
      const td = document.createElement('td');
      td.textContent = value == null ? '' : String(value);
      tr.appendChild(td);
    };

    if (scope === 'recepciones') {
      const fechaText = formatDateForTable(r.fecha, true);
      addCell(fechaText);
      addCell(r.tipo);
      addCell(r.cantidad);
      addCell(r.unidad || '');
    }

    if (scope === 'produccion') {
      const fechaText = formatDateForTable(r.fecha_ini, true);
      addCell(fechaText);
      addCell(r.tipo || '');
      addCell(r.cantidad);
      addCell(r.unidad || '');
    }

    if (scope === 'defectuosos') {
      const fechaText = formatDateForTable(r.fecha, false);
      addCell(fechaText);
      addCell(r.tipo);
      addCell(r.cantidad);
      addCell(r.unidad || '');
      addCell(r.razon || '');
    }

    if (scope === 'envios') {
      const fechaText = formatDateForTable(r.fecha, false);
      addCell(fechaText);
      addCell(r.cliente);
      addCell(r.tipo);
      addCell(r.descripcion || '');
      addCell(r.cantidad);
      addCell(r.unidad || '');
    }

    // Columna de acciones (Editar / Eliminar)
    const tdActions = document.createElement('td');
    tdActions.className = 'actions-row';

    const btnEdit = document.createElement('button');
    btnEdit.type = 'button';
    btnEdit.className = 'btn-small btn-edit';
    btnEdit.dataset.id = r.id;
    btnEdit.textContent = 'Editar';

    const btnDel = document.createElement('button');
    btnDel.type = 'button';
    btnDel.className = 'btn-small btn-del';
    btnDel.dataset.id = r.id;
    btnDel.textContent = 'Eliminar';

    tdActions.appendChild(btnEdit);
    tdActions.appendChild(btnDel);
    tr.appendChild(tdActions);

    tbody.appendChild(tr);
  });

  // Botones eliminar
  tbody.querySelectorAll('.btn-del').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      e.preventDefault();
      if (window.__ROLE === 'operario') {
        alert('Solo visualización para Operario.');
        return;
      }
      if (!confirm('¿Eliminar registro?')) return;
      const id = btn.dataset.id;
      try {
        await api(`/api/${scope}/${id}`, { method: 'DELETE' });
        await renderTable(scope);
      } catch (err) {
        console.error(err);
        alert('Error eliminando registro');
      }
    });
  });

  // Botones editar
  tbody.querySelectorAll('.btn-edit').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      if (window.__ROLE === 'operario') {
        alert('Solo visualización para Operario.');
        return;
      }
      const id = btn.dataset.id;
      const rec = data.items.find(x => String(x.id) === String(id));
      if (!rec) return;
      setEditing(scope, id);
      fillForm(scope, rec);
      // ya no hacemos scroll hacia arriba para evitar el salto molesto
    });
  });
}

async function renderUsers() {
  const tbl = document.getElementById('usersTable');
  if (!tbl) return;
  const data = await api('/api/users');
  const tbody = tbl.querySelector('tbody');
  tbody.innerHTML = '';

  data.items.forEach(u => {
    const tr = document.createElement('tr');

    // Columna usuario
    const tdUser = document.createElement('td');
    tdUser.textContent = u.username;
    tr.appendChild(tdUser);

    // Columna rol (select)
    const tdRole = document.createElement('td');
    const sel = document.createElement('select');
    sel.className = 'input inline-edit roleSel';
    sel.dataset.id = u.id;

    ['operario', 'supervisor', 'administrador'].forEach(role => {
      const opt = document.createElement('option');
      opt.value = role;
      opt.textContent = role;
      if (u.role === role) opt.selected = true;
      sel.appendChild(opt);
    });

    tdRole.appendChild(sel);
    tr.appendChild(tdRole);

    // Columna acciones
    const tdActions = document.createElement('td');
    tdActions.className = 'actions-row';

    const btnReset = document.createElement('button');
    btnReset.type = 'button';
    btnReset.className = 'btn-small reset';
    btnReset.dataset.id = u.id;
    btnReset.textContent = 'Reset Pass';

    const btnDel = document.createElement('button');
    btnDel.type = 'button';
    btnDel.className = 'btn-small del';
    btnDel.dataset.id = u.id;
    btnDel.textContent = 'Eliminar';

    tdActions.appendChild(btnReset);
    tdActions.appendChild(btnDel);
    tr.appendChild(tdActions);

    tbody.appendChild(tr);
  });

  tbody.querySelectorAll('.roleSel').forEach(sel => {
    sel.addEventListener('change', async () => {
      await api('/api/users/' + sel.dataset.id, {
        method: 'PUT',
        body: { role: sel.value }
      });
      alert('Rol actualizado');
    });
  });

  tbody.querySelectorAll('.del').forEach(btn => {
    btn.addEventListener('click', async () => {
      if (!confirm('¿Eliminar usuario?')) return;
      await api('/api/users/' + btn.dataset.id, { method: 'DELETE' });
      renderUsers();
    });
  });

  tbody.querySelectorAll('.reset').forEach(btn => {
    btn.addEventListener('click', async () => {
      const p = prompt('Nueva contraseña', 'admin');
      if (!p) return;
      await api('/api/users/' + btn.dataset.id + '/password', {
        method: 'PATCH',
        body: { password: p }
      });
      alert('Contraseña cambiada');
    });
  });
}

async function initPanel() {
  const me = await api('/me');
  if (!me.user) {
    location.href = '/';
    return;
  }

  document.getElementById('whoami').textContent =
    me.user.username + ' (' + me.user.role + ')';

  window.__ROLE = me.user.role;

  if (me.user.role === 'operario') {
    document.body.classList.add('readonly');
  }

  // Mostrar secciones solo-supervisor para supervisor y administrador
  if (me.user.role === 'supervisor' || me.user.role === 'administrador') {
    document.querySelectorAll('.only-supervisor').forEach(e => {
      e.style.display = 'block';
    });
  }

  ['recepciones', 'produccion', 'defectuosos', 'envios'].forEach(scope => {
    hookForm(scope);
    renderTable(scope);
  });

  // Botones PDF
  document.querySelectorAll('[data-pdf]').forEach(btn => {
    btn.addEventListener('click', () => {
      const type = btn.dataset.pdf;
      window.open(`/api/${type}.pdf`, '_blank');
    });
  });

  // Gestión de usuarios: SOLO supervisor o administrador
  const add = document.getElementById('addUser');
  const canManageUsers =
    me.user.role === 'supervisor' || me.user.role === 'administrador';

  if (add && canManageUsers) {
    add.addEventListener('click', async () => {
      const uname = document.getElementById('nu_user').value.trim();
      const role = document.getElementById('nu_role').value;
      const pass = document.getElementById('nu_pass').value;
      await api('/api/users', {
        method: 'POST',
        body: { username: uname, role, password: pass }
      });
      document.getElementById('nu_user').value = '';
      await renderUsers();
    });

    // Carga inicial de usuarios protegida por rol
    try {
      await renderUsers();
    } catch (err) {
      console.error('Error cargando usuarios:', err);
    }
  }

  // Botón Salir: debe funcionar PARA TODOS LOS ROLES
  const lo = document.getElementById('logoutBtn');
  if (lo) {
    lo.addEventListener('click', async () => {
      try {
        await api('/api/auth/logout', { method: 'POST' });
      } catch (err) {
        console.error('Error en logout:', err);
      }
      location.href = '/';
    });
  }
}

document.addEventListener('DOMContentLoaded', () => {
  if (location.pathname === '/panel.html') initPanel();
});
