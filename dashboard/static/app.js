'use strict';
let state = null, page = 0;
const size = 100;
const el = id => document.getElementById(id);
const show = value => value === null || value === undefined ? '—' : String(value);
function node(tag, text) { const n = document.createElement(tag); n.textContent = show(text); return n; }
function render() {
  const s = state || {};
  el('status').textContent = show(s.status);
  el('status').className = 'badge' + (s.status === 'CONNECTED' ? ' live' : '');
  el('interface').textContent = show(s.interface);
  el('mode').textContent = show(s.mode);
  el('updated').textContent = show(s.collected_utc);
  el('hooks').textContent = ['ingress','egress'].map(h => s.hooks && s.hooks[h] ?
    `${s.hooks[h].attached && s.status === 'CONNECTED' ? 'attached' : 'not confirmed live'} #${s.hooks[h].program_id}` : 'unknown').join(' / ');
  el('errors').textContent = (s.errors || []).join('\n');
  const metrics = [['Ingress packets','packets'],['Ingress bytes','bytes'],['Egress packets','egress_packets'],
    ['Egress bytes','egress_bytes'],['Tracked TCP connections','tracked_flows'],['Completed predictions','predictions'],
    ['Inference failures','inference_failures'],['Tail-call failures','tail_failures']];
  el('metrics').replaceChildren(...metrics.map(([label,key]) => {
    const box = node('div',''); box.className = 'metric';
    box.append(node('span',label),node('strong',s.aggregate && s.aggregate[key])); return box;
  }));
  const filter = el('filter').value.toLowerCase();
  const flows = (s.flows || []).filter(f => `${f.id} ${f.state}`.toLowerCase().includes(filter));
  page = Math.max(0,Math.min(page,Math.ceil(flows.length / size)-1));
  const rows = flows.slice(page*size,(page+1)*size).map(f => {
    const tr = node('tr',''), who = node('td',`${show(f.client_ip)}:${show(f.client_port)} → ${show(f.server_ip)}:${show(f.server_port)}`);
    who.append(node('small',f.id)); who.title = f.role_basis;
    const counts = hook => { const h = f.hooks && f.hooks[hook]; return h ? `${h.packets} / ${h.bytes}` : '—'; };
    tr.append(who,node('td',counts('ingress')),node('td',counts('egress')),node('td',f.state),
      node('td',f.label === null ? null : `class ${f.label}`),
      node('td',f.logits ? `[${f.logits.join(', ')}] / 2^${f.logit_q}` : null),node('td',f.completed_ns));
    return tr;
  });
  if (!rows.length) { const row=node('tr',''),cell=node('td','No matching flows observed.');cell.colSpan=7;row.append(cell);rows.push(row); }
  el('flows').replaceChildren(...rows);
  el('page').textContent = `${flows.length} connections · page ${page+1} / ${Math.max(1,Math.ceil(flows.length/size))}`;
  el('previous').disabled = page===0; el('next').disabled = (page+1)*size>=flows.length;
  el('predictions').textContent = (s.recent_predictions || []).slice(-10).reverse().map(r =>
    `${r.flow_id}\n  ${r.mode}: class ${r.label}; logits [${r.logits.join(', ')}] at q${r.logit_q}; kernel ns ${r.inference_monotonic_ns}`).join('\n\n') || 'No completed inferences observed.';
}
el('filter').addEventListener('input',() => { page=0;render(); });
el('previous').addEventListener('click',() => { page--;render(); });
el('next').addEventListener('click',() => { page++;render(); });
async function refresh() {
  try { const r = await fetch('/api/state',{cache:'no-store'});if (!r.ok) throw new Error(`HTTP ${r.status}`);state=await r.json(); }
  catch (e) { state={...(state||{}),status:'DISCONNECTED',errors:[`Dashboard fetch failed: ${e.message}`]}; }
  render(); setTimeout(refresh,1000);
}
refresh();
