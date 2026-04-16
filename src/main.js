import { decryptLink } from './decrypt.js';
import './style.css';

const btn     = document.getElementById('decryptBtn');
const input   = document.getElementById('linkInput');
const box     = document.getElementById('resultBox');
const content = document.getElementById('resultContent');

async function run() {
  const link = input.value.trim();
  if (!link) return;

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Decrypting…';
  box.classList.remove('visible');

  try {
    const url = await decryptLink(link);
    content.className = 'result-content success';
    if (/^https?:\/\//i.test(url)) {
      const a = document.createElement('a');
      a.href = url;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      a.textContent = url;
      content.textContent = '';
      content.appendChild(a);
    } else {
      content.textContent = url;
    }
  } catch (err) {
    content.className = 'result-content error';
    content.textContent = `Error: ${err.message}`;
  } finally {
    box.classList.add('visible');
    btn.disabled = false;
    btn.textContent = 'Decrypt';
  }
}

btn.addEventListener('click', run);
input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) run();
});
