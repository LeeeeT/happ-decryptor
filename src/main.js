import { decryptLink } from './decrypt.js';
import './style.css';

const btn     = document.getElementById('decryptBtn');
const input   = document.getElementById('linkInput');
const box     = document.getElementById('resultBox');
const content = document.getElementById('resultContent');
const copyBtn = document.getElementById('copyBtn');

let lastResult = '';

function resetCopyButton() {
  copyBtn.disabled = !lastResult;
  copyBtn.textContent = 'Copy';
}

async function run() {
  const link = input.value.trim();
  if (!link) return;

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Decrypting…';
  box.classList.remove('visible');
  lastResult = '';
  resetCopyButton();

  try {
    const url = await decryptLink(link);
    lastResult = url;
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
    resetCopyButton();
  }
}

async function copyResult() {
  if (!lastResult) return;
  try {
    await navigator.clipboard.writeText(lastResult);
    copyBtn.textContent = 'Copied';
  } catch {
    copyBtn.textContent = 'Copy failed';
  }
}

btn.addEventListener('click', run);
copyBtn.addEventListener('click', copyResult);
input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) run();
});
